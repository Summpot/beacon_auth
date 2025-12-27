package io.github.summpot.beaconauth.login

import net.minecraft.resources.ResourceLocation

/**
 * Tracks BeaconAuth negotiation state for a single Login listener instance.
 *
 * 1.21.x uses cookie request/response where the key is a ResourceLocation.
 */
class ServerLoginNegotiation {
    enum class Phase {
        PROBE,
        INIT,
        LOGIN_URL,
        VERIFY,
        COMPLETE
    }

    private val transactions: MutableMap<ResourceLocation, LoginQueryType> = HashMap()

    var phase: Phase = Phase.PROBE

    private var modded: Boolean = false
    private var requiresBeaconAuth: Boolean = false

    private var pendingChallenge: String? = null
    private var pendingPort: Int = 0

    var ticks: Int = 0
        private set

    private var finished: Boolean = false

    fun registerTransaction(key: ResourceLocation, type: LoginQueryType) {
        transactions[key] = type
    }

    fun consume(key: ResourceLocation): LoginQueryType? = transactions.remove(key)

    fun markModded(modded: Boolean) {
        this.modded = modded
    }

    fun isModded(): Boolean = modded

    fun requireBeaconAuth(requires: Boolean) {
        this.requiresBeaconAuth = requires
    }

    fun requiresBeaconAuth(): Boolean = requiresBeaconAuth

    fun setChallenge(challenge: String, port: Int) {
        this.pendingChallenge = challenge
        this.pendingPort = port
    }

    fun getPendingChallenge(): String? = pendingChallenge

    fun getPendingPort(): Int = pendingPort

    fun incrementTick() {
        ticks++
    }

    fun resetTick() {
        ticks = 0
    }

    fun markFinished() {
        finished = true
    }

    fun isFinished(): Boolean = finished
}
