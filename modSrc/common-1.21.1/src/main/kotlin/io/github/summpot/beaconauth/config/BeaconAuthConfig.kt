package io.github.summpot.beaconauth.config

/**
 * BeaconAuth configuration values used by common code.
 *
 * For 1.21.x targets, common code is shared across Fabric + NeoForge.
 * The underlying config systems differ, so platform modules are responsible for:
 *  - registering a config spec
 *  - reading the loaded values
 *  - applying them here via [apply].
 */
object BeaconAuthConfig {
    // Defaults are development-friendly. Platform config should overwrite these on load.
    @Volatile private var authBaseUrl: String = "http://localhost:8080"
    @Volatile private var jwksUrl: String = "http://localhost:8080/.well-known/jwks.json"
    @Volatile private var expectedIssuer: String = "http://localhost:8080"
    @Volatile private var expectedAudience: String = "minecraft-client"
    @Volatile private var bypassIfOnlineModeVerified: Boolean = true
    @Volatile private var forceAuthIfOfflineMode: Boolean = true
    @Volatile private var allowVanillaOfflineClients: Boolean = false

    @JvmStatic
    fun apply(
        authBaseUrl: String,
        jwksUrl: String,
        expectedIssuer: String,
        expectedAudience: String,
        bypassIfOnlineModeVerified: Boolean,
        forceAuthIfOfflineMode: Boolean,
        allowVanillaOfflineClients: Boolean
    ) {
        this.authBaseUrl = authBaseUrl
        this.jwksUrl = jwksUrl
        this.expectedIssuer = expectedIssuer
        this.expectedAudience = expectedAudience
        this.bypassIfOnlineModeVerified = bypassIfOnlineModeVerified
        this.forceAuthIfOfflineMode = forceAuthIfOfflineMode
        this.allowVanillaOfflineClients = allowVanillaOfflineClients
    }

    fun getAuthBaseUrl(): String = authBaseUrl
    fun getJwksUrl(): String = jwksUrl
    fun getExpectedIssuer(): String = expectedIssuer
    fun getExpectedAudience(): String = expectedAudience
    fun shouldBypassIfOnlineModeVerified(): Boolean = bypassIfOnlineModeVerified
    fun shouldForceAuthIfOfflineMode(): Boolean = forceAuthIfOfflineMode
    fun shouldAllowVanillaOfflineClients(): Boolean = allowVanillaOfflineClients
}
