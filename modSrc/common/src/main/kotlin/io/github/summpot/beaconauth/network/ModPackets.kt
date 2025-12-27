package io.github.summpot.beaconauth.network

/**
 * Central registry for all mod network packets using Architectury Network API.
 *
 * NOTE: As of the login-phase refactor, all BeaconAuth handshake logic now uses
 * Minecraft's built-in login custom query packets (handled via mixins).
 * This file is retained for potential future play-phase extensions but currently
 * has no active packet registrations.
 */
object ModPackets {
    /**
     * Register all network packets.
     * Must be called during mod initialization.
     * Currently no-op; login-phase uses custom queries instead.
     */
    fun register() {
        // All authentication logic moved to login-phase custom queries
        // See: ServerLoginPacketListenerImplMixin & ClientHandshakePacketListenerImplMixin
    }
}
