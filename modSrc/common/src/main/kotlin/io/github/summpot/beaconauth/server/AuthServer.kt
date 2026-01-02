package io.github.summpot.beaconauth.server

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.RemoteJWKSet
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.DefaultResourceRetriever
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import io.github.summpot.beaconauth.config.BeaconAuthConfig
import io.github.summpot.beaconauth.util.PKCEUtils
import org.slf4j.LoggerFactory
import java.net.IDN
import java.net.URL
import java.security.Key
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Server-side authentication handler
 * Validates JWT tokens and PKCE challenges (stateless)
 */
object AuthServer {
    private val logger = LoggerFactory.getLogger("BeaconAuth/Server")

    // JWT Processor (handles JWKS fetching, caching, and validation)
    private var jwtProcessor: ConfigurableJWTProcessor<SecurityContext>? = null

    // Authenticated players tracking (only state maintained by server)
    private val authenticatedPlayers = mutableSetOf<UUID>()

    // Initialization flag to prevent double initialization
    private var initialized = false

    private fun ipv4FriendlyUrlString(raw: String): String = raw.replace("localhost", "127.0.0.1")

    private fun isJkuEnabled(): Boolean = BeaconAuthConfig.getJkuAllowedHostPatterns().isNotEmpty()

    private fun normalizeHost(host: String): String {
        // We intentionally avoid locale-sensitive lowercasing.
        return IDN.toASCII(host.trim().lowercase())
    }

    private fun effectiveAllowedJkuHostPatterns(): Set<String> = BeaconAuthConfig.getJkuAllowedHostPatterns()

    private fun isHostAllowedByPatterns(host: String, patterns: Set<String>): Boolean {
        val h = normalizeHost(host)
        return patterns.any { rawPattern ->
            val p = rawPattern.trim()
            if (p.isEmpty()) {
                false
            } else if (p == "*") {
                // Too dangerous for SSRF; don't allow a blanket wildcard.
                false
            } else if (p.contains('*') && !p.startsWith("*.") ) {
                // Only support leading "*." wildcards.
                false
            } else {
                val normalized = normalizeHost(p.trimStart('.').removePrefix("*.") )
                h == normalized || h.endsWith(".$normalized")
            }
        }
    }

    private fun validateJkuOrThrow(jku: URL) {
        // When JKU is enabled, we ALWAYS require https.
        if (!jku.protocol.equals("https", ignoreCase = true)) {
            throw SecurityException("JKU must use https:// (got '${jku.protocol}://')")
        }

        val host = jku.host ?: throw SecurityException("JKU URL missing host")
        val allowed = effectiveAllowedJkuHostPatterns()
        if (allowed.isEmpty()) {
            throw SecurityException("JKU is enabled but no allowed hosts are configured")
        }
        if (!isHostAllowedByPatterns(host, allowed)) {
            throw SecurityException(
                "Untrusted JKU host '$host' (allowed patterns: ${allowed.joinToString(",")})"
            )
        }
    }

    private class JkuAwareKeySelector(
        private val expectedAlgorithms: Set<JWSAlgorithm>,
        private val resourceRetriever: DefaultResourceRetriever,
    ) : JWSKeySelector<SecurityContext> {
        private val jwkSources = ConcurrentHashMap<String, RemoteJWKSet<SecurityContext>>()

        private fun jwksUrlForHeader(header: JWSHeader): URL {
            val jku = header.getJWKURL()
            val useJku = isJkuEnabled() && jku != null

            val selected = if (useJku) {
                // Header was already validated in verifyForProfile(), but keep a defense-in-depth check.
                val url = URL(ipv4FriendlyUrlString(jku.toString()))
                validateJkuOrThrow(url)
                url
            } else {
                // No usable JKU -> trust the configured JWKS URL.
                // If jwks_url is empty in config, BeaconAuthConfig derives it from authBaseUrl.
                URL(ipv4FriendlyUrlString(BeaconAuthConfig.getJwksUrl()))
            }

            return URL(ipv4FriendlyUrlString(selected.toString()))
        }

        override fun selectJWSKeys(header: JWSHeader, context: SecurityContext?): List<Key> {
            val jwksUrl = jwksUrlForHeader(header)
            val key = jwksUrl.toString()
            val jwkSource = jwkSources.computeIfAbsent(key) { urlString ->
                RemoteJWKSet<SecurityContext>(URL(urlString), resourceRetriever)
            }
            val delegate = JWSVerificationKeySelector(expectedAlgorithms, jwkSource)
            return delegate.selectJWSKeys(header, context)
        }
    }

    /**
     * Deterministically derive a stable UUID for a BeaconAuth user.
     *
     * IMPORTANT: This MUST NOT depend on the Minecraft in-game username, otherwise a player could
     * impersonate another player by changing their username on offline-mode servers.
     */
    private fun stableUuidForSubject(subject: String): UUID {
        // Using Java's name-based UUID (v3) gives us a deterministic mapping without extra deps.
        // Collisions are practically irrelevant here because the input space is the BeaconAuth user id.
        val name = "beaconauth:user:$subject"
        return UUID.nameUUIDFromBytes(name.toByteArray(Charsets.UTF_8))
    }

    /**
     * Initialize server-side authentication
     * Loads configuration and sets up JWT key provider
     * Safe to call multiple times - will only initialize once
     */
    fun init() {
        ensureInitialized()
    }

    /**
     * Ensure the server is initialized (lazy initialization)
     * This is called internally before any operation that requires JWT processor
     */
    private fun ensureInitialized() {
        // Prevent double initialization
        if (initialized) {
            return
        }

        synchronized(this) {
            // Double-check after acquiring lock
            if (initialized) {
                return
            }

            logger.info("Initializing BeaconAuth server...")

            // Setup JWT key provider
            initializeJwtProcessor()

            // Mark as initialized
            initialized = true

            logger.info("BeaconAuth server initialization complete")
        }
    }

    /**
     * Initialize JWT processor with remote JWKS endpoint
     * Uses Nimbus JOSE JWT library for automatic JWKS fetching, caching, and validation
     */
    private fun initializeJwtProcessor() {
        try {
            // Force IPv4 for better compatibility with localhost connections
            System.setProperty("java.net.preferIPv4Stack", "true")

            // Step 1: Configure resource retriever with appropriate timeouts
            // Increase timeouts to handle slow network connections
            val resourceRetriever = DefaultResourceRetriever(
                10000,  // Connect timeout: 10 seconds
                10000   // Read timeout: 10 seconds
            )

            // Step 2: Test connection to JWKS endpoint before creating processor
            logger.info("Testing connection to JWKS endpoint...")
            try {
                // Replace "localhost" with "127.0.0.1" to force IPv4
                val testUrlString = BeaconAuthConfig.getJwksUrl().replace("localhost", "127.0.0.1")
                val testUrl = URL(testUrlString)
                val connection = testUrl.openConnection()
                connection.connectTimeout = 5000
                connection.readTimeout = 5000
                connection.connect()
                connection.getInputStream().close()
                logger.info("✓ JWKS endpoint is reachable")
            } catch (e: Exception) {
				if (isJkuEnabled()) {
                    logger.warn("✗ Cannot reach configured fallback JWKS endpoint: ${e.message}")
                    logger.warn("  URL: ${BeaconAuthConfig.getJwksUrl()}")
                    logger.warn("  JKU is enabled, so this may be OK if your tokens always include a valid 'jku' header")
                    logger.warn("  Note: If using 'localhost', try '127.0.0.1' instead in your config")
                } else {
                    logger.error("✗ Cannot reach JWKS endpoint: ${e.message}")
                    logger.error("  URL: ${BeaconAuthConfig.getJwksUrl()}")
                    logger.error("  Please ensure the authentication server is running")
                    logger.error("  Note: If using 'localhost', try '127.0.0.1' instead in your config")
                    throw RuntimeException("JWKS endpoint is not reachable", e)
                }
            }

            // Step 3: Create RemoteJWKSet that will fetch and cache keys
            // Replace "localhost" with "127.0.0.1" to force IPv4 for better compatibility
            val jwkSetUrlString = BeaconAuthConfig.getJwksUrl().replace("localhost", "127.0.0.1")
            val jwkSetURL = URL(jwkSetUrlString)

            // Best-effort: Log a short JWKS summary to help diagnose signature mismatches.
            // (e.g. multiple server instances generating different keys behind the same URL).
            try {
                val jwksJson = resourceRetriever.retrieveResource(jwkSetURL).content
                val jwkSet = JWKSet.parse(jwksJson)
                val keySummaries = jwkSet.keys
                    .take(5)
                    .joinToString(", ") { k ->
                        val kid = k.keyID ?: "<no-kid>"
                        val kty = k.keyType.value
                        val alg = k.algorithm?.name ?: "<no-alg>"
                        "kid=$kid kty=$kty alg=$alg"
                    }
                logger.info(
                    "JWKS summary: keys=${jwkSet.keys.size}${if (keySummaries.isNotBlank()) "; $keySummaries" else ""}"
                )
            } catch (e: Exception) {
                logger.warn("Unable to parse JWKS for diagnostics: ${e.message}")
            }

            // Step 4: Create JWT processor
            val processor = DefaultJWTProcessor<SecurityContext>()

            // Step 5: Configure JWS key selector (for signature verification)
            // Support both ES256 (ECDSA) and RS256 (RSA) for smooth migration
            val expectedAlgorithms = setOf(JWSAlgorithm.ES256, JWSAlgorithm.RS256)
			processor.jwsKeySelector = JkuAwareKeySelector(expectedAlgorithms, resourceRetriever)

            // Step 6: Configure claims verifier (for iss, aud, exp validation)
            // RequiredClaims: iss, aud must match expected values
            // ProhibitedClaims: none
            val claimsVerifier = DefaultJWTClaimsVerifier<SecurityContext>(
                BeaconAuthConfig.getExpectedAudience(),
                JWTClaimsSet.Builder()
					// Issuer is derived from authentication.base_url (BASE_URL).
					.issuer(BeaconAuthConfig.getExpectedIssuer())
                    .build(),
                setOf("challenge") // Required custom claims
            )
            processor.jwtClaimsSetVerifier = claimsVerifier

            // Store the processor
            jwtProcessor = processor

            logger.info("✓ JWT processor initialized successfully")
            logger.info("  JWKS URL: ${BeaconAuthConfig.getJwksUrl()}")
            logger.info("  Expected Issuer (derived): ${BeaconAuthConfig.getExpectedIssuer()}")
            logger.info("  Expected Audience: ${BeaconAuthConfig.getExpectedAudience()}")
            logger.info(
                "  JKU: enabled=${isJkuEnabled()} requireHttps=${isJkuEnabled()} " +
                    "allowedPatterns=${effectiveAllowedJkuHostPatterns().joinToString(",").ifEmpty { "<none>" }}"
			)
            logger.info("  Supported Algorithms: ES256, RS256")
            logger.info("  Connection timeout: 10s, Read timeout: 10s")

        } catch (e: Exception) {
            logger.error("CRITICAL: Failed to initialize JWT processor: ${e.message}", e)
            throw RuntimeException("Failed to initialize BeaconAuth server", e)
        }
    }

    /**
     * Build login URL with PKCE challenge and redirect port
     * This URL points to the external React authentication app
     */
    @JvmStatic
    fun buildLoginUrl(challenge: String, redirectPort: Int): String {
        ensureInitialized()
        return "${BeaconAuthConfig.getAuthBaseUrl()}/login?challenge=$challenge&redirect_port=$redirectPort"
    }

    data class VerificationResult(
        val success: Boolean,
        val message: String,
        val username: String? = null,
        val stableUuid: UUID? = null,
    )

    /**
     * Verify JWT and PKCE data for a player profile during the login phase.
     */
    @JvmStatic
    fun verifyForProfile(profileName: String, jwt: String, verifier: String): VerificationResult {
        return try {
            ensureInitialized()

            val parsedJwt = try {
                SignedJWT.parse(jwt)
            } catch (e: Exception) {
                throw SecurityException("Invalid JWT format")
            }

			// Optional JKU validation (reject untrusted JWKS URLs early, before any HTTP fetch).
            val jku = parsedJwt.header.getJWKURL()
            if (jku != null && isJkuEnabled()) {
                validateJkuOrThrow(URL(ipv4FriendlyUrlString(jku.toString())))
			}

            val processor = jwtProcessor ?: throw SecurityException("JWT processor not initialized")

            val claims: JWTClaimsSet = try {
                processor.process(jwt, null)
            } catch (e: com.nimbusds.jose.proc.BadJOSEException) {
                // If the signature fails, attempt a one-time JWKS refresh and retry.
                // This helps with key rotation and misconfigured deployments that serve different keys
                // behind the same JWKS URL.
                val message = e.message ?: ""
                val alg = parsedJwt.header.algorithm?.name ?: "<unknown>"
                val kid = parsedJwt.header.keyID ?: "<no-kid>"
                val headerJku = parsedJwt.header.getJWKURL()?.toString() ?: "<no-jku>"

                if (message.contains("Invalid signature", ignoreCase = true)) {
                    logger.warn(
						"JWT signature verification failed for $profileName (alg=$alg, kid=$kid, jku=$headerJku). " +
                            "Refreshing JWKS and retrying once..."
                    )

                    synchronized(this) {
                        // Recreate the processor to drop any cached JWKS.
                        initializeJwtProcessor()
                    }

                    val refreshed = jwtProcessor ?: throw SecurityException("JWT processor not initialized")
                    refreshed.process(jwt, null)
                } else {
                    throw e
                }
            }
            val jwtChallenge = claims.getStringClaim("challenge")
                ?: throw SecurityException("JWT missing 'challenge' claim")
            val computedChallenge = PKCEUtils.generateCodeChallenge(verifier)
            if (computedChallenge != jwtChallenge) {
                throw SecurityException("PKCE verification failed - verifier does not match challenge")
            }

            val username = claims.getStringClaim("username") ?: profileName
            val subject = claims.subject ?: throw SecurityException("JWT missing subject")
            val stableUuid = stableUuidForSubject(subject)
            authenticatedPlayers.add(stableUuid)
            logger.info(
                "✓ Authentication successful for $profileName (user: $username, subject: $subject, stableUuid: $stableUuid)"
            )
            VerificationResult(true, "Welcome, $username!", username, stableUuid)
        } catch (e: com.nimbusds.jose.RemoteKeySourceException) {
            logger.error("✗ Failed to fetch JWKS for $profileName: ${e.message}")
            VerificationResult(false, "Cannot contact authentication server")
        } catch (e: SecurityException) {
            logger.warn("✗ Authentication failed for $profileName: ${e.message}")
            VerificationResult(false, e.message ?: "Authentication failed")
        } catch (e: com.nimbusds.jose.proc.BadJOSEException) {
            val alg = try {
                SignedJWT.parse(jwt).header.algorithm?.name
            } catch (_: Exception) {
                null
            } ?: "<unknown>"

            val kid = try {
                SignedJWT.parse(jwt).header.keyID
            } catch (_: Exception) {
                null
            } ?: "<no-kid>"

            logger.warn(
                "✗ JWT validation failed for $profileName (alg=$alg, kid=$kid, jwksUrl=${BeaconAuthConfig.getJwksUrl()}): ${e.message}"
            )

            // Diagnostics only: decode claims WITHOUT verification to help identify mismatched environments.
            // This MUST NOT be used for authorization decisions.
            try {
                val unverified = SignedJWT.parse(jwt).jwtClaimsSet
                val unverifiedIssuer = unverified.issuer ?: "<missing>"
                val unverifiedAudience = unverified.audience?.joinToString(",") ?: "<missing>"
                val unverifiedSubject = unverified.subject ?: "<missing>"
                logger.warn(
                    "  Unverified claims: iss=$unverifiedIssuer aud=$unverifiedAudience sub=$unverifiedSubject"
                )
            } catch (_: Exception) {
                // ignore
            }

            logger.warn(
                "  If this persists, ensure the auth service that issues the Minecraft JWT is using the same ES256 key that it serves via jwks_url. " +
                    "If you run multiple instances, key rotation must keep old keys available until issued tokens expire."
            )
            VerificationResult(false, "JWT validation failed")
        } catch (e: com.nimbusds.jwt.proc.BadJWTException) {
            logger.warn("✗ JWT claims validation failed for $profileName: ${e.message}")
            VerificationResult(false, "JWT claims validation failed")
        } catch (e: Exception) {
            logger.error("Error verifying authentication for $profileName: ${e.message}", e)
            VerificationResult(false, "Server error: ${e.message}")
        }
    }

    fun isPlayerAuthenticated(playerUuid: UUID): Boolean = authenticatedPlayers.contains(playerUuid)

    fun removeAuthenticatedPlayer(playerUuid: UUID) {
        if (authenticatedPlayers.remove(playerUuid)) {
            logger.info("Removed player from authenticated set (remaining: ${authenticatedPlayers.size})")
        }
    }
}
