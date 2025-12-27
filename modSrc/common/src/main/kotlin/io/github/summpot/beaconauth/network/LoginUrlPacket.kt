package io.github.summpot.beaconauth.network

import net.minecraft.network.FriendlyByteBuf

/**
 * S2C Packet: Server sends login URL to client
 * Contains the full URL for web-based authentication
 */
data class LoginUrlPacket(
    val loginUrl: String
) {
    companion object {
        fun encode(packet: LoginUrlPacket, buf: FriendlyByteBuf) {
            buf.writeUtf(packet.loginUrl, 1024)
        }

        fun decode(buf: FriendlyByteBuf): LoginUrlPacket {
            val loginUrl = buf.readUtf(1024)
            return LoginUrlPacket(loginUrl)
        }
    }
}
