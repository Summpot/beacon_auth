package io.github.summpot.beaconauth.login

import io.github.summpot.beaconauth.BeaconAuthMod
import net.minecraft.resources.ResourceLocation

/**
 * Identifiers for BeaconAuth login-phase custom query packets (1.20.1).
 */
enum class LoginQueryType(private val path: String) {
    PROBE("probe"),
    INIT("init"),
    LOGIN_URL("login_url"),
    VERIFY("verify");

    fun id(): ResourceLocation = ResourceLocation(BeaconAuthMod.MOD_ID, path)
}
