package io.github.summpot.beaconauth.config

import org.slf4j.LoggerFactory
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.Properties
import kotlin.text.toBooleanStrictOrNull

/**
 * Server-side configuration manager for BeaconAuth
 * Loads configuration from config/beaconauth-server.properties
 */
object ServerConfig {
    private val logger = LoggerFactory.getLogger("BeaconAuth/Config")
    
    // Default values
    private const val DEFAULT_AUTH_BASE_URL = "https://beaconauth.pages.dev"
    private const val DEFAULT_JWKS_URL = "$DEFAULT_AUTH_BASE_URL/.well-known/jwks.json"
    private const val DEFAULT_ISSUER = "https://beaconauth.pages.dev"
    private const val DEFAULT_AUDIENCE = "minecraft-client"
    private const val DEFAULT_BYPASS_ONLINE_MODE = true
    private const val DEFAULT_FORCE_AUTH_OFFLINE = true
    private const val DEFAULT_ALLOW_VANILLA_OFFLINE = false
    
    // Configuration values (loaded from file)
    var authBaseUrl: String = DEFAULT_AUTH_BASE_URL
        private set
    var jwksUrl: String = DEFAULT_JWKS_URL
        private set
    var expectedIssuer: String = DEFAULT_ISSUER
        private set
    var expectedAudience: String = DEFAULT_AUDIENCE
        private set
    var bypassIfOnlineModeVerified: Boolean = DEFAULT_BYPASS_ONLINE_MODE
        private set
    var forceAuthIfOfflineMode: Boolean = DEFAULT_FORCE_AUTH_OFFLINE
        private set
    var allowVanillaOfflineClients: Boolean = DEFAULT_ALLOW_VANILLA_OFFLINE
        private set
    package io.github.summpot.beaconauth.config

    import org.slf4j.LoggerFactory
    import java.nio.file.Path

    /**
     * Deprecated compatibility shim.
     *
     * BeaconAuth server configuration is now provided via Forge config (ForgeConfigSpec) and
     * ForgeConfigApiPort on Fabric.
     *
     * This wrapper keeps the old name available (if referenced) but does NOT read/write any
     * `.properties` file.
     */
    @Deprecated(
        message = "BeaconAuth no longer uses beaconauth-server.properties. Use BeaconAuthConfig (Forge config) instead.",
        replaceWith = ReplaceWith("BeaconAuthConfig")
    )
    object ServerConfig {
        private val logger = LoggerFactory.getLogger("BeaconAuth/Config")

        /**
         * No-op: configuration is loaded by the platform config system.
         */
        fun load(@Suppress("UNUSED_PARAMETER") configDir: Path) {
            logger.info("ServerConfig.load() is deprecated and ignored. Configuration comes from Forge config.")
        }

        val authBaseUrl: String
            get() = BeaconAuthConfig.getAuthBaseUrl()
        val jwksUrl: String
            get() = BeaconAuthConfig.getJwksUrl()
        val expectedIssuer: String
            get() = BeaconAuthConfig.getExpectedIssuer()
        val expectedAudience: String
            get() = BeaconAuthConfig.getExpectedAudience()
        val bypassIfOnlineModeVerified: Boolean
            get() = BeaconAuthConfig.shouldBypassIfOnlineModeVerified()
        val forceAuthIfOfflineMode: Boolean
            get() = BeaconAuthConfig.shouldForceAuthIfOfflineMode()
        val allowVanillaOfflineClients: Boolean
            get() = BeaconAuthConfig.shouldAllowVanillaOfflineClients()
    }
            logger.info("Configuration loaded successfully")
