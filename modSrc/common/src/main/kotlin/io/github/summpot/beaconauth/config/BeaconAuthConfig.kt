package io.github.summpot.beaconauth.config

import net.minecraftforge.common.ForgeConfigSpec
import org.apache.commons.lang3.tuple.Pair

/**
 * Server-side configuration for BeaconAuth using Forge Config API
 * 
 * This config uses ForgeConfigSpec and works across Fabric (via forgeconfigapiport) and Forge.
 * Configuration file will be automatically generated at config/beaconauth-server.toml
 */
object BeaconAuthConfig {
    
    // Config values
    lateinit var authBaseUrl: ForgeConfigSpec.ConfigValue<String>
        private set
    lateinit var jwksUrl: ForgeConfigSpec.ConfigValue<String>
        private set
    lateinit var expectedIssuer: ForgeConfigSpec.ConfigValue<String>
        private set
    lateinit var expectedAudience: ForgeConfigSpec.ConfigValue<String>
        private set
    lateinit var bypassIfOnlineModeVerified: ForgeConfigSpec.BooleanValue
        private set
    lateinit var forceAuthIfOfflineMode: ForgeConfigSpec.BooleanValue
        private set
    lateinit var allowVanillaOfflineClients: ForgeConfigSpec.BooleanValue
        private set
    
    // The actual config spec
    lateinit var spec: ForgeConfigSpec
        private set
    
    /**
     * Build the configuration specification
     * This is called during mod initialization
     */
    fun buildConfig(): Pair<BeaconAuthConfig, ForgeConfigSpec> {
        val builder = ForgeConfigSpec.Builder()
        
        // Authentication Server Settings
        builder.comment(
            "BeaconAuth Server Configuration",
            "",
            "IMPORTANT: Configure these values to match your authentication server!",
            "The default values point to localhost:8080 for development."
        ).push("authentication")
        
        authBaseUrl = builder
            .comment(
                "Base URL of your authentication server",
                "Example: http://localhost:8080 (development) or https://auth.example.com (production)",
                "WARNING: Always use HTTPS in production!"
            )
            .define("base_url", "http://localhost:8080")
        
        jwksUrl = builder
            .comment(
                "JWKS (JSON Web Key Set) URL for JWT signature verification",
                "This endpoint must provide the public keys used to sign JWTs",
                "Usually: <base_url>/.well-known/jwks.json"
            )
            .define("jwks_url", "http://localhost:8080/.well-known/jwks.json")
        
        builder.pop()
        
        // JWT Validation Settings
        builder.comment(
            "JWT Token Validation Settings",
            "These values must match your authentication server's configuration"
        ).push("jwt")
        
        expectedIssuer = builder
            .comment(
                "Expected JWT issuer (iss claim)",
                "This must match the 'iss' claim in the JWT token"
            )
            .define("issuer", "http://localhost:8080")
        
        expectedAudience = builder
            .comment(
                "Expected JWT audience (aud claim)",
                "This must match the 'aud' claim in the JWT token"
            )
            .define("audience", "minecraft-client")
        
        builder.pop()
        
        // Authentication Behavior Settings
        builder.comment(
            "Authentication Behavior Settings",
            "Configure how BeaconAuth interacts with Minecraft's authentication system"
        ).push("behavior")
        
        bypassIfOnlineModeVerified = builder
            .comment(
                "Bypass BeaconAuth for players verified by Mojang online-mode",
                "If true: Players with valid Mojang accounts skip BeaconAuth when server is in online-mode",
                "If false: All players must authenticate with BeaconAuth, even in online-mode",
                "Recommended: true (allows seamless integration with existing authentication)"
            )
            .define("bypass_if_online_mode_verified", true)
        
        forceAuthIfOfflineMode = builder
            .comment(
                "Force BeaconAuth for modded clients when server is in offline-mode",
                "If true: Modded clients (with BeaconAuth installed) MUST authenticate when server is offline",
                "If false: Modded clients can join without BeaconAuth when server is offline",
                "Recommended: true (provides security for offline-mode servers)"
            )
            .define("force_auth_if_offline_mode", true)
        
        allowVanillaOfflineClients = builder
            .comment(
                "Allow vanilla clients (without BeaconAuth mod) in offline-mode",
                "If true: Vanilla clients can join without BeaconAuth when server is offline",
                "If false: All clients must have BeaconAuth mod installed when server is offline",
                "Recommended: false (ensures all players are authenticated)",
                "Note: Only applies when force_auth_if_offline_mode is true"
            )
            .define("allow_vanilla_offline_clients", false)
        
        builder.pop()
        
        spec = builder.build()
        return Pair.of(this, spec)
    }
    
    /**
     * Get the authentication base URL
     */
    fun getAuthBaseUrl(): String = authBaseUrl.get()
    
    /**
     * Get the JWKS URL
     */
    fun getJwksUrl(): String = jwksUrl.get()
    
    /**
     * Get the expected JWT issuer
     */
    fun getExpectedIssuer(): String = expectedIssuer.get()
    
    /**
     * Get the expected JWT audience
     */
    fun getExpectedAudience(): String = expectedAudience.get()
    
    /**
     * Check if BeaconAuth should be bypassed for Mojang-verified players
     */
    fun shouldBypassIfOnlineModeVerified(): Boolean = bypassIfOnlineModeVerified.get()
    
    /**
     * Check if BeaconAuth should be forced for offline-mode
     */
    fun shouldForceAuthIfOfflineMode(): Boolean = forceAuthIfOfflineMode.get()
    
    /**
     * Check if vanilla clients are allowed in offline-mode
     */
    fun shouldAllowVanillaOfflineClients(): Boolean = allowVanillaOfflineClients.get()
}
