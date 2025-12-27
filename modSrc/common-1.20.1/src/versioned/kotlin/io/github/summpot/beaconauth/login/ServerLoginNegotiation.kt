package io.github.summpot.beaconauth.login

/**
 * Tracks BeaconAuth negotiation state for a single Login listener instance.
 *
 * 1.20.1 uses login-phase custom query packets where the transaction key is an int.
 */
class ServerLoginNegotiation {
    enum class Phase {
        PROBE,
        INIT,
        LOGIN_URL,
        VERIFY,
        COMPLETE
    }

    private val transactions: MutableMap<Int, LoginQueryType> = HashMap()

    var phase: Phase = Phase.PROBE

    private var modded: Boolean = false
    private var requiresBeaconAuth: Boolean = false

    private var pendingChallenge: String? = null
    private var pendingPort: Int = 0

    var ticks: Int = 0
        private set

    private var finished: Boolean = false

    fun registerTransaction(transactionId: Int, type: LoginQueryType): Int {
        transactions[transactionId] = type
        return transactionId
    }

    fun consume(transactionId: Int): LoginQueryType? = transactions.remove(transactionId)

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
