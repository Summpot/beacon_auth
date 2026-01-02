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

	val jkuEnabled: Boolean
        get() = BeaconAuthConfig.getJkuAllowedHostPatterns().isNotEmpty()
    val jkuAllowedHostPatterns: Set<String>
        get() = BeaconAuthConfig.getJkuAllowedHostPatterns()
    val bypassIfOnlineModeVerified: Boolean
        get() = BeaconAuthConfig.shouldBypassIfOnlineModeVerified()
    val forceAuthIfOfflineMode: Boolean
        get() = BeaconAuthConfig.shouldForceAuthIfOfflineMode()
    val allowVanillaOfflineClients: Boolean
        get() = BeaconAuthConfig.shouldAllowVanillaOfflineClients()
}
