package io.github.summpot.beaconauth.client

import io.github.summpot.beaconauth.login.LoginVerificationStatus
import io.github.summpot.beaconauth.util.TranslationHelper
import io.netty.buffer.Unpooled
import net.minecraft.Util
import net.minecraft.client.Minecraft
import net.minecraft.client.gui.screens.ConfirmLinkScreen
import net.minecraft.network.Connection
import net.minecraft.network.FriendlyByteBuf
import net.minecraft.network.protocol.login.ServerboundCustomQueryPacket
import org.slf4j.LoggerFactory

/**
 * Kotlin helper for handling BeaconAuth login-phase custom queries on the client.
 * Called by ClientHandshakePacketListenerImplMixin (Java).
 */
object ClientLoginHandler {
    private val logger = LoggerFactory.getLogger("BeaconAuth/ClientLogin")

    private var pendingVerifyTransaction: Int = -1
    private var cancelledBeforeVerify: Boolean = false
    private var cancelReason: String = ""

    @JvmStatic
    fun respondProbe(connection: Connection, transactionId: Int) {
        val buf = FriendlyByteBuf(Unpooled.buffer())
        buf.writeBoolean(true)
        buf.writeUtf("beaconauth", 64)
        connection.send(ServerboundCustomQueryPacket(transactionId, buf))
        logger.debug("Sent probe response (mod detected)")
    }

    @JvmStatic
    fun respondInit(connection: Connection, transactionId: Int) {
        val payload = AuthClient.prepareLoginPhaseCredentials()
        val buf = FriendlyByteBuf(Unpooled.buffer())
        buf.writeUtf(payload.codeChallenge, 512)
        buf.writeVarInt(payload.boundPort)
        connection.send(ServerboundCustomQueryPacket(transactionId, buf))
        logger.debug("Sent init response with challenge and port")
    }

    @JvmStatic
    fun handleLoginUrl(connection: Connection, transactionId: Int, data: FriendlyByteBuf?) {
        val loginUrl = data?.readUtf(2048) ?: ""

        // Acknowledge receipt immediately
        val ack = FriendlyByteBuf(Unpooled.buffer())
        ack.writeBoolean(true)
        connection.send(ServerboundCustomQueryPacket(transactionId, ack))
        logger.debug("Acknowledged login URL, showing UI confirmation")

        AuthClient.showLoginConfirmation(
            loginUrl,
            onConfirm = { },
            onCancel = { reason -> cancelDuringVerify(reason) }
        )
    }

    @JvmStatic
    fun handleVerifyRequest(connection: Connection, transactionId: Int) {
        if (cancelledBeforeVerify) {
            sendVerifyResponse(connection, transactionId, LoginVerificationStatus.CANCELLED, null, null, cancelReason)
            cancelledBeforeVerify = false
            cancelReason = ""
            logger.info("User cancelled before verify; sent CANCELLED status")
            return
        }

        pendingVerifyTransaction = transactionId
        logger.debug("Waiting for OAuth callback to complete verification...")

        AuthClient.registerLoginPhaseCallback(object : AuthClient.LoginPhaseCallback {
            override fun onAuthSuccess(jwt: String, verifier: String) {
                sendVerifyResponse(connection, transactionId, LoginVerificationStatus.SUCCESS, jwt, verifier, null)
                logger.info("OAuth flow succeeded; sent JWT & verifier")
            }

            override fun onAuthError(message: String) {
                sendVerifyResponse(connection, transactionId, LoginVerificationStatus.ERROR, null, null, message)
                logger.error("OAuth flow failed: $message")
            }
        })
    }

    private fun cancelDuringVerify(reason: String) {
        if (pendingVerifyTransaction >= 0) {
            // Already in verify phase, send immediately
            logger.warn("User cancelled during verify phase")
        } else {
            // Not yet in verify, store for later
            cancelledBeforeVerify = true
            cancelReason = reason
            logger.warn("User cancelled before verify phase; will report on next verify query")
        }
    }

    private fun sendVerifyResponse(
        connection: Connection,
        transactionId: Int,
        status: LoginVerificationStatus,
        jwt: String?,
        verifier: String?,
        message: String?
    ) {
        val buf = FriendlyByteBuf(Unpooled.buffer())
        buf.writeVarInt(status.ordinal)
        when (status) {
            LoginVerificationStatus.SUCCESS -> {
                buf.writeUtf(jwt ?: "", 4096)
                buf.writeUtf(verifier ?: "", 512)
            }
            LoginVerificationStatus.CANCELLED, LoginVerificationStatus.ERROR -> {
                buf.writeUtf(message ?: "", 256)
            }
        }
        connection.send(ServerboundCustomQueryPacket(transactionId, buf))
        pendingVerifyTransaction = -1
        cancelledBeforeVerify = false
        cancelReason = ""
        AuthClient.registerLoginPhaseCallback(null)
    }
}
