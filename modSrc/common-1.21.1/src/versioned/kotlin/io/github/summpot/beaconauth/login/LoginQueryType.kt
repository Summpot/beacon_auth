package io.github.summpot.beaconauth.login

import io.github.summpot.beaconauth.BeaconAuthMod
import net.minecraft.resources.ResourceLocation

/**
 * Identifiers for BeaconAuth cookie request keys (1.21.x).
 */
enum class LoginQueryType(private val path: String) {
    PROBE("probe"),
    INIT("init"),
    LOGIN_URL("login_url"),
    VERIFY("verify");

    fun id(): ResourceLocation = ResourceLocation.fromNamespaceAndPath(BeaconAuthMod.MOD_ID, path)
}
