package io.github.summpot.beaconauth.network

import net.minecraft.network.FriendlyByteBuf

/**
 * S2C Packet: Request client to start login process
 * Sent from server to client to trigger automatic authentication
 *
 * This packet is empty - it's just a trigger signal
 */
data class RequestClientLoginPacket(
    val dummy: Boolean = true // Empty packets need at least one field
) {
    companion object {
        /**
         * Encode packet to buffer
         */
        fun encode(packet: RequestClientLoginPacket, buf: FriendlyByteBuf) {
            buf.writeBoolean(packet.dummy)
        }

        /**
         * Decode packet from buffer
         */
        fun decode(buf: FriendlyByteBuf): RequestClientLoginPacket {
            val dummy = buf.readBoolean()
            return RequestClientLoginPacket(dummy)
        }
    }
}
