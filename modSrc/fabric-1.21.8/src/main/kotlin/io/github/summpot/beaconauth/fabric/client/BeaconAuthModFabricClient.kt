package io.github.summpot.beaconauth.fabric.client

import net.fabricmc.api.ClientModInitializer
import io.github.summpot.beaconauth.BeaconAuthMod

object BeaconAuthModFabricClient : ClientModInitializer {
    override fun onInitializeClient() {
        // Initialize client-side logic (HTTP server for OAuth callback)
        BeaconAuthMod.initClient()
    }
}
