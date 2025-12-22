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
    private const val DEFAULT_AUTH_BASE_URL = "http://localhost:8080"
    private const val DEFAULT_JWKS_URL = "$DEFAULT_AUTH_BASE_URL/.well-known/jwks.json"
    private const val DEFAULT_ISSUER = "http://localhost:8080"
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
    
    /**
     * Load configuration from file
     * Creates default config if it doesn't exist
     */
    fun load(configDir: Path) {
        val configFile = configDir.resolve("beaconauth-server.properties")
        
        try {
            // Create config directory if it doesn't exist
            if (!Files.exists(configDir)) {
                Files.createDirectories(configDir)
                logger.info("Created config directory: $configDir")
            }
            
            // Create default config if it doesn't exist
            if (!Files.exists(configFile)) {
                createDefaultConfig(configFile)
                logger.warn("Created default config file: $configFile")
                logger.warn("Please edit the config file and restart the server!")
            }
            
            // Load configuration
            val props = Properties()
            Files.newInputStream(configFile).use { input ->
                props.load(input)
            }
            
            // Read values
            authBaseUrl = props.getProperty("auth.base_url", DEFAULT_AUTH_BASE_URL)
            jwksUrl = props.getProperty("auth.jwks_url", DEFAULT_JWKS_URL)
            expectedIssuer = props.getProperty("jwt.issuer", DEFAULT_ISSUER)
            expectedAudience = props.getProperty("jwt.audience", DEFAULT_AUDIENCE)
            bypassIfOnlineModeVerified = props.getProperty("auth.bypass_if_online_mode_verified", DEFAULT_BYPASS_ONLINE_MODE.toString()).toBooleanStrictOrNull()
                ?: DEFAULT_BYPASS_ONLINE_MODE
            forceAuthIfOfflineMode = props.getProperty("auth.force_auth_if_offline_mode", DEFAULT_FORCE_AUTH_OFFLINE.toString()).toBooleanStrictOrNull()
                ?: DEFAULT_FORCE_AUTH_OFFLINE
            allowVanillaOfflineClients = props.getProperty("auth.allow_vanilla_offline_clients", DEFAULT_ALLOW_VANILLA_OFFLINE.toString()).toBooleanStrictOrNull()
                ?: DEFAULT_ALLOW_VANILLA_OFFLINE
            
            // Save config to ensure it exists with current values
            save(configFile, props)
            
            logger.info("Configuration loaded successfully")
            logger.info("  Auth Base URL: $authBaseUrl")
            logger.info("  JWKS URL: $jwksUrl")
            logger.info("  Expected Issuer: $expectedIssuer")
            logger.info("  Expected Audience: $expectedAudience")
            logger.info("  Bypass if Mojang verified: $bypassIfOnlineModeVerified")
            logger.info("  Force auth when offline-mode: $forceAuthIfOfflineMode")
            logger.info("  Allow vanilla offline clients: $allowVanillaOfflineClients")
            
            // Validate configuration
            validateConfig()
            
        } catch (e: Exception) {
            logger.error("Failed to load configuration: ${e.message}", e)
            logger.warn("Using default configuration values")
        }
    }
    
    /**
     * Save configuration to file
     * Ensures the config file always exists with current values
     */
    private fun save(configFile: Path, props: Properties) {
        try {
            // Update properties with current values
            props.setProperty("auth.base_url", authBaseUrl)
            props.setProperty("auth.jwks_url", jwksUrl)
            props.setProperty("jwt.issuer", expectedIssuer)
            props.setProperty("jwt.audience", expectedAudience)
            props.setProperty("auth.bypass_if_online_mode_verified", bypassIfOnlineModeVerified.toString())
            props.setProperty("auth.force_auth_if_offline_mode", forceAuthIfOfflineMode.toString())
            props.setProperty("auth.allow_vanilla_offline_clients", allowVanillaOfflineClients.toString())
            
            // Save to file
            Files.newOutputStream(configFile).use { output ->
                props.store(output, """
BeaconAuth Server Configuration

IMPORTANT: You MUST configure these values before using the mod!
Replace the example URLs with your actual authentication server URLs.

Security Notes:
- Always use HTTPS for production environments
- The JWKS URL should be publicly accessible
- Make sure the issuer and audience values match your auth server's configuration
                """.trimIndent())
            }
            
            logger.debug("Configuration saved successfully")
            
        } catch (e: Exception) {
            logger.error("Failed to save configuration: ${e.message}", e)
        }
    }
    
    /**
     * Create default configuration file
     */
    private fun createDefaultConfig(configFile: Path) {
        val defaultConfig = """
# BeaconAuth Server Configuration
# 
# IMPORTANT: You MUST configure these values before using the mod!
# Replace the example URLs with your actual authentication server URLs.

# Base URL of your authentication server
auth.base_url=$DEFAULT_AUTH_BASE_URL

# JWKS (JSON Web Key Set) URL for JWT signature verification
# This endpoint must provide the public keys used to sign JWTs
auth.jwks_url=$DEFAULT_JWKS_URL

# Expected JWT issuer (iss claim)
# This must match the 'iss' claim in the JWT token
jwt.issuer=$DEFAULT_ISSUER

# Expected JWT audience (aud claim)
# This must match the 'aud' claim in the JWT token
jwt.audience=$DEFAULT_AUDIENCE

# Whether players that pass Mojang online-mode verification should bypass BeaconAuth
auth.bypass_if_online_mode_verified=$DEFAULT_BYPASS_ONLINE_MODE

# When the server runs in offline-mode, require BeaconAuth for modded clients
auth.force_auth_if_offline_mode=$DEFAULT_FORCE_AUTH_OFFLINE

# When the server runs in offline-mode, allow vanilla clients (without the mod) to join without BeaconAuth
auth.allow_vanilla_offline_clients=$DEFAULT_ALLOW_VANILLA_OFFLINE

# 
# Security Notes:
# - Always use HTTPS for production environments
# - The JWKS URL should be publicly accessible
# - Make sure the issuer and audience values match your auth server's configuration
#
        """.trimIndent()
        
        Files.writeString(configFile, defaultConfig)
    }
    
    /**
     * Validate configuration values
     */
    private fun validateConfig() {
        // Check if using default values
        if (authBaseUrl == DEFAULT_AUTH_BASE_URL) {
            logger.warn("⚠ Using default auth.base_url! Please configure your authentication server URL.")
        }
        
        // Validate HTTPS in production
        if (!authBaseUrl.startsWith("https://") && !authBaseUrl.startsWith("http://localhost")) {
            logger.warn("⚠ auth.base_url is not using HTTPS! This is insecure for production.")
        }
        
        // Validate URL format
        try {
            java.net.URL(authBaseUrl)
            java.net.URL(jwksUrl)
        } catch (e: Exception) {
            logger.error("Invalid URL in configuration: ${e.message}")
            throw IllegalArgumentException("Invalid URL in configuration", e)
        }
    }
}
