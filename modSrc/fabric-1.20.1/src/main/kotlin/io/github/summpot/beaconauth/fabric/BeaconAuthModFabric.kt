package io.github.summpot.beaconauth.fabric

import net.fabricmc.api.ModInitializer
import net.fabricmc.api.DedicatedServerModInitializer
import net.fabricmc.api.EnvType
import net.fabricmc.loader.api.FabricLoader
import io.github.summpot.beaconauth.BeaconAuthMod
import io.github.summpot.beaconauth.config.BeaconAuthConfig
import fuzs.forgeconfigapiport.api.config.v2.ForgeConfigRegistry
import net.minecraftforge.fml.config.ModConfig

object BeaconAuthModFabric : ModInitializer, DedicatedServerModInitializer {
    override fun onInitialize() {
        // Register configuration
        val configPair = BeaconAuthConfig.buildConfig()
        ForgeConfigRegistry.INSTANCE.register(
            BeaconAuthMod.MOD_ID, 
            ModConfig.Type.SERVER, 
            configPair.right
        )
        
        // Run common setup (network packet registration)
        BeaconAuthMod.init()
        
        // Initialize client-side logic (HTTP server for OAuth callback)
        if (FabricLoader.getInstance().environmentType == EnvType.CLIENT) {
            BeaconAuthMod.initClient()
        }
        
        // Note: Server-side initialization uses lazy loading and will
        // be triggered automatically when first needed (e.g., when a player
        // tries to authenticate). This ensures it works for both dedicated
        // servers and integrated servers.
    }

    override fun onInitializeServer() {
        // Initialize server-side logic (JWT validation) for dedicated servers
        // For integrated servers, lazy initialization will handle it
        BeaconAuthMod.initServer()
    }
}
