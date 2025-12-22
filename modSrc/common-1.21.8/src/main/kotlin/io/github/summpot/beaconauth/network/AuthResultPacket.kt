package io.github.summpot.beaconauth.network

import net.minecraft.network.FriendlyByteBuf

/**
 * S2C Packet: Server notifies client of authentication result
 * Contains success status and a message
 */
data class AuthResultPacket(
    val success: Boolean,
    val message: String
) {
    companion object {
        fun encode(packet: AuthResultPacket, buf: FriendlyByteBuf) {
            buf.writeBoolean(packet.success)
            buf.writeUtf(packet.message, 512)
        }

        fun decode(buf: FriendlyByteBuf): AuthResultPacket {
            val success = buf.readBoolean()
            val message = buf.readUtf(512)
            return AuthResultPacket(success, message)
        }
    }
}
