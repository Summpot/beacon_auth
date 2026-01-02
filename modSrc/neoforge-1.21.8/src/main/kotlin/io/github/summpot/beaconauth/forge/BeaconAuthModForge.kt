package io.github.summpot.beaconauth.neoforge

import io.github.summpot.beaconauth.BeaconAuthMod
import io.github.summpot.beaconauth.config.BeaconAuthConfig
import net.neoforged.api.distmarker.Dist
import net.neoforged.bus.api.IEventBus
import net.neoforged.fml.ModContainer
import net.neoforged.fml.common.Mod
import net.neoforged.fml.config.ModConfig
import net.neoforged.fml.event.config.ModConfigEvent
import net.neoforged.neoforge.common.ModConfigSpec

@Mod(BeaconAuthMod.MOD_ID)
class BeaconAuthModNeoForge(
    private val modEventBus: IEventBus,
    private val dist: Dist,
    private val container: ModContainer
) {
    private var serverInitialized = false

    init {
        // Register configuration (SERVER config loads during world loading)
        container.registerConfig(ModConfig.Type.SERVER, BeaconAuthServerConfig.SPEC)

        // Run common setup (network packet registration)
        BeaconAuthMod.init()

        // Listen for config loading and reloading events.
        // NeoForge configs are not immediately available upon registration.
        modEventBus.addListener(this::onConfigLoading)
        modEventBus.addListener(this::onConfigReloading)

        // Initialize client-side immediately (doesn't need config)
        if (dist == Dist.CLIENT) {
            BeaconAuthMod.initClient()
        }
    }

    private fun onConfigLoading(event: ModConfigEvent.Loading) {
        // Only initialize when our SERVER config is loaded
        if (event.config.modId == BeaconAuthMod.MOD_ID &&
            event.config.type == ModConfig.Type.SERVER &&
            !serverInitialized) {
            BeaconAuthServerConfig.applyToCommon()
            serverInitialized = true
            BeaconAuthMod.initServer()
        }
    }

    private fun onConfigReloading(event: ModConfigEvent.Reloading) {
        // If server config is reloaded and server was already initialized, reinitialize
        if (event.config.modId == BeaconAuthMod.MOD_ID &&
            event.config.type == ModConfig.Type.SERVER &&
            serverInitialized) {
            BeaconAuthServerConfig.applyToCommon()
            BeaconAuthMod.initServer()
        }
    }
}

private class BeaconAuthServerConfig(builder: ModConfigSpec.Builder) {
    private val authBaseUrl: ModConfigSpec.ConfigValue<String>
    private val jwksUrl: ModConfigSpec.ConfigValue<String>
    private val expectedIssuer: ModConfigSpec.ConfigValue<String>
    private val expectedAudience: ModConfigSpec.ConfigValue<String>
    private val bypassIfOnlineModeVerified: ModConfigSpec.BooleanValue
    private val forceAuthIfOfflineMode: ModConfigSpec.BooleanValue
    private val allowVanillaOfflineClients: ModConfigSpec.BooleanValue

    init {
        builder.comment(
            "BeaconAuth Server Configuration",
            "",
            "IMPORTANT: Configure these values to match your authentication server!",
            "The default values point to https://beaconauth.pages.dev."
        ).push("authentication")

        authBaseUrl = builder
            .comment(
                "Base URL of your authentication server",
                "Example: http://localhost:8080 (development) or https://auth.example.com (production)",
                "WARNING: Always use HTTPS in production!"
            )
            .define("base_url", "https://beaconauth.pages.dev")

        jwksUrl = builder
            .comment(
                "JWKS (JSON Web Key Set) URL for JWT signature verification",
                "This endpoint must provide the public keys used to sign JWTs",
                "Usually: <base_url>/.well-known/jwks.json"
            )
            .define("jwks_url", "https://beaconauth.pages.dev/.well-known/jwks.json")

        builder.pop()

        builder.comment(
            "JWT Token Validation Settings",
            "These values must match your authentication server's configuration"
        ).push("jwt")

        expectedIssuer = builder
            .comment(
                "Expected JWT issuer (iss claim)",
                "This must match the 'iss' claim in the JWT token"
            )
            .define("issuer", "https://beaconauth.pages.dev")

        expectedAudience = builder
            .comment(
                "Expected JWT audience (aud claim)",
                "This must match the 'aud' claim in the JWT token"
            )
            .define("audience", "minecraft-client")

        builder.pop()

        builder.comment(
            "Authentication Behavior Settings",
            "Configure how BeaconAuth interacts with Minecraft's authentication system"
        ).push("behavior")

        bypassIfOnlineModeVerified = builder
            .comment(
                "Bypass BeaconAuth for players verified by Mojang online-mode",
                "Recommended: true"
            )
            .define("bypass_if_online_mode_verified", true)

        forceAuthIfOfflineMode = builder
            .comment(
                "Force BeaconAuth for modded clients when server is in offline-mode",
                "Recommended: true"
            )
            .define("force_auth_if_offline_mode", true)

        allowVanillaOfflineClients = builder
            .comment(
                "Allow vanilla clients (without BeaconAuth mod) in offline-mode",
                "Only applies when force_auth_if_offline_mode is true"
            )
            .define("allow_vanilla_offline_clients", false)

        builder.pop()
    }

    fun applyToCommon() {
        BeaconAuthConfig.apply(
            authBaseUrl.get(),
            jwksUrl.get(),
            expectedIssuer.get(),
            expectedAudience.get(),
            bypassIfOnlineModeVerified.getAsBoolean(),
            forceAuthIfOfflineMode.getAsBoolean(),
            allowVanillaOfflineClients.getAsBoolean()
        )
    }

    companion object {
        val SPEC: ModConfigSpec
        private val INSTANCE: BeaconAuthServerConfig

        init {
            val specPair = ModConfigSpec.Builder().configure(::BeaconAuthServerConfig)
            SPEC = specPair.right
            INSTANCE = specPair.left
        }

        fun applyToCommon() {
            INSTANCE.applyToCommon()
        }
    }
}
