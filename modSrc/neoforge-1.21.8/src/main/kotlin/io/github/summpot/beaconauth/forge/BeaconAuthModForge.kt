package io.github.summpot.beaconauth.neoforge

import dev.architectury.platform.neoforge.EventBuses
import io.github.summpot.beaconauth.BeaconAuthMod
import io.github.summpot.beaconauth.config.BeaconAuthConfig
import net.neoforged.api.distmarker.Dist
import net.neoforged.fml.ModLoadingContext
import net.neoforged.fml.common.Mod
import net.neoforged.fml.config.ModConfig
import net.neoforged.fml.event.config.ModConfigEvent
import net.neoforged.fml.javafmlmod.FMLJavaModLoadingContext
import net.neoforged.fml.loading.FMLEnvironment

@Mod(BeaconAuthMod.MOD_ID)
class BeaconAuthModNeoForge {
    private var serverInitialized = false

    init {
        // Submit our event bus to let Architectury API register our content at the right time.
        EventBuses.registerModEventBus(BeaconAuthMod.MOD_ID, FMLJavaModLoadingContext.get().modEventBus)

        // Register configuration (SERVER config loads during world loading)
        val configPair = BeaconAuthConfig.buildConfig()
        ModLoadingContext.get().registerConfig(ModConfig.Type.SERVER, configPair.right)

        // Run common setup (network packet registration)
        BeaconAuthMod.init()

        // Listen for config loading and reloading events.
        // NeoForge configs are not immediately available upon registration.
        val modBus = FMLJavaModLoadingContext.get().modEventBus
        modBus.addListener(this::onConfigLoading)
        modBus.addListener(this::onConfigReloading)

        // Initialize client-side immediately (doesn't need config)
        if (FMLEnvironment.dist == Dist.CLIENT) {
            BeaconAuthMod.initClient()
        }
    }

    private fun onConfigLoading(event: ModConfigEvent.Loading) {
        // Only initialize when our SERVER config is loaded
        if (event.config.modId == BeaconAuthMod.MOD_ID &&
            event.config.type == ModConfig.Type.SERVER &&
            !serverInitialized) {
            serverInitialized = true
            BeaconAuthMod.initServer()
        }
    }

    private fun onConfigReloading(event: ModConfigEvent.Reloading) {
        // If server config is reloaded and server was already initialized, reinitialize
        if (event.config.modId == BeaconAuthMod.MOD_ID &&
            event.config.type == ModConfig.Type.SERVER &&
            serverInitialized) {
            BeaconAuthMod.initServer()
        }
    }
}
