package io.github.summpot.beaconauth.network

import net.minecraft.network.FriendlyByteBuf

/**
 * C2S Packet: Client requests login URL from server
 * Contains PKCE challenge and client's bound port
 */
data class RequestLoginUrlPacket(
    val codeChallenge: String,
    val boundPort: Int
) {
    companion object {
        fun encode(packet: RequestLoginUrlPacket, buf: FriendlyByteBuf) {
            buf.writeUtf(packet.codeChallenge, 256)
            buf.writeInt(packet.boundPort)
        }

        fun decode(buf: FriendlyByteBuf): RequestLoginUrlPacket {
            val codeChallenge = buf.readUtf(256)
            val boundPort = buf.readInt()
            return RequestLoginUrlPacket(codeChallenge, boundPort)
        }
    }
}
