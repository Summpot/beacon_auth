package io.github.summpot.beaconauth.network

import net.minecraft.network.FriendlyByteBuf

/**
 * C2S Packet: Client sends JWT and PKCE verifier for validation
 * Server will verify both JWT signature and PKCE challenge
 */
data class VerifyAuthPacket(
    val jwt: String,
    val codeVerifier: String
) {
    companion object {
        fun encode(packet: VerifyAuthPacket, buf: FriendlyByteBuf) {
            buf.writeUtf(packet.jwt, 4096)
            buf.writeUtf(packet.codeVerifier, 256)
        }

        fun decode(buf: FriendlyByteBuf): VerifyAuthPacket {
            val jwt = buf.readUtf(4096)
            val codeVerifier = buf.readUtf(256)
            return VerifyAuthPacket(jwt, codeVerifier)
        }
    }
}
