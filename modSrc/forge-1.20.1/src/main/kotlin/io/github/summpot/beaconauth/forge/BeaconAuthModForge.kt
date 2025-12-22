package io.github.summpot.beaconauth.forge

import dev.architectury.platform.forge.EventBuses
import io.github.summpot.beaconauth.BeaconAuthMod
import io.github.summpot.beaconauth.config.BeaconAuthConfig
import net.minecraftforge.api.distmarker.Dist
import net.minecraftforge.fml.common.Mod
import net.minecraftforge.fml.event.config.ModConfigEvent
import net.minecraftforge.fml.loading.FMLEnvironment
import net.minecraftforge.fml.ModLoadingContext
import net.minecraftforge.fml.config.ModConfig
import thedarkcolour.kotlinforforge.forge.MOD_BUS
import thedarkcolour.kotlinforforge.forge.MOD_CONTEXT

@Mod(BeaconAuthMod.MOD_ID)
object BeaconAuthModForge {
    private var serverInitialized = false

    init {
        // Submit our event bus to let Architectury API register our content on the right time.
        EventBuses.registerModEventBus(BeaconAuthMod.MOD_ID, MOD_CONTEXT.getKEventBus())
        
        // Register configuration
        val configPair = BeaconAuthConfig.buildConfig()
        ModLoadingContext.get().registerConfig(
            ModConfig.Type.SERVER, 
            configPair.right
        )

        // Run common setup (network packet registration)
        BeaconAuthMod.init()

        // Listen for config loading and reloading events
        MOD_BUS.addListener(::onConfigLoading)
        MOD_BUS.addListener(::onConfigReloading)

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
