package io.github.summpot.beaconauth.client

import io.github.summpot.beaconauth.config.BeaconAuthConfig
import io.github.summpot.beaconauth.login.LoginVerificationStatus
import io.github.summpot.beaconauth.login.LoginQueryType
import io.github.summpot.beaconauth.util.TranslationHelper
import io.netty.buffer.Unpooled
import net.minecraft.network.Connection
import net.minecraft.network.FriendlyByteBuf
import net.minecraft.network.protocol.cookie.ServerboundCookieResponsePacket
import net.minecraft.resources.ResourceLocation
import org.slf4j.LoggerFactory

/**
 * Kotlin helper for handling BeaconAuth login-phase custom queries on the client.
 * Called by ClientHandshakePacketListenerImplMixin (Java).
 */
object ClientLoginHandler {
    private val logger = LoggerFactory.getLogger("BeaconAuth/ClientLogin")

    private var verifyRequested: Boolean = false
    private var cancelledBeforeVerify: Boolean = false
    private var cancelReason: String = ""

    @JvmStatic
    fun handleCookieRequest(connection: Connection, key: ResourceLocation): Boolean {
        BeaconAuthClientSession.noteHandshake(connection)

        return when (key) {
            LoginQueryType.PROBE.id() -> {
                respondProbe(connection)
                true
            }
            LoginQueryType.INIT.id() -> {
                respondInit(connection)
                true
            }
            LoginQueryType.VERIFY.id() -> {
                handleVerifyRequest(connection)
                true
            }
            else -> false
        }
    }

    private fun respondProbe(connection: Connection) {
        sendCookieResponse(connection, LoginQueryType.PROBE.id()) { buf ->
            buf.writeBoolean(true)
            buf.writeUtf("beaconauth", 64)
        }
        logger.debug("Sent probe response (mod detected)")
    }

    private fun respondInit(connection: Connection) {
        val payload = AuthClient.prepareLoginPhaseCredentials()

        sendCookieResponse(connection, LoginQueryType.INIT.id()) { buf ->
            buf.writeUtf(payload.codeChallenge, 512)
            buf.writeVarInt(payload.boundPort)
        }
        logger.debug("Sent init response with challenge and port")

        val loginUrl = "${BeaconAuthConfig.getAuthBaseUrl()}/login?challenge=${payload.codeChallenge}&redirect_port=${payload.boundPort}"
        AuthClient.showLoginConfirmation(
            loginUrl,
            onConfirm = { },
            onCancel = { reason -> cancelDuringVerify(connection, reason) }
        )
    }

    @JvmStatic
    fun handleVerifyRequest(connection: Connection) {
        if (cancelledBeforeVerify) {
            sendVerifyResponse(connection, LoginVerificationStatus.CANCELLED, null, null, cancelReason)
            cancelledBeforeVerify = false
            cancelReason = ""
            logger.info("User cancelled before verify; sent CANCELLED status")
            return
        }

        verifyRequested = true
        logger.debug("Waiting for OAuth callback to complete verification...")

        AuthClient.registerLoginPhaseCallback(object : AuthClient.LoginPhaseCallback {
            override fun onAuthSuccess(jwt: String, verifier: String) {
                BeaconAuthClientSession.markAuthenticated(connection)
                sendVerifyResponse(connection, LoginVerificationStatus.SUCCESS, jwt, verifier, null)
                logger.info("OAuth flow succeeded; sent JWT & verifier")
            }

            override fun onAuthError(message: String) {
                sendVerifyResponse(connection, LoginVerificationStatus.ERROR, null, null, message)
                logger.error("OAuth flow failed: $message")
            }
        })
    }

    private fun cancelDuringVerify(connection: Connection, reason: String) {
        if (verifyRequested) {
            logger.warn("User cancelled during verify phase; sending CANCELLED")
            sendVerifyResponse(connection, LoginVerificationStatus.CANCELLED, null, null, reason)
        } else {
            // Not yet in verify, store for later
            cancelledBeforeVerify = true
            cancelReason = reason
            logger.warn("User cancelled before verify phase; will report on next verify query")
        }
    }

    private fun sendCookieResponse(
        connection: Connection,
        key: ResourceLocation,
        writer: (FriendlyByteBuf) -> Unit
    ) {
        val buf = FriendlyByteBuf(Unpooled.buffer())
        writer(buf)
        val bytes = ByteArray(buf.readableBytes())
        buf.getBytes(0, bytes)
        connection.send(ServerboundCookieResponsePacket(key, bytes))
    }

    private fun sendVerifyResponse(
        connection: Connection,
        status: LoginVerificationStatus,
        jwt: String?,
        verifier: String?,
        message: String?
    ) {
        sendCookieResponse(connection, LoginQueryType.VERIFY.id()) { buf ->
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
        }
        verifyRequested = false
        cancelledBeforeVerify = false
        cancelReason = ""
        AuthClient.registerLoginPhaseCallback(null)
    }
}
