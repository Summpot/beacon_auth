package io.github.summpot.beaconauth.server

import com.mojang.authlib.GameProfile
import io.github.summpot.beaconauth.config.BeaconAuthConfig
import io.github.summpot.beaconauth.login.LoginQueryType
import io.github.summpot.beaconauth.login.LoginVerificationStatus
import io.github.summpot.beaconauth.login.ServerLoginNegotiation
import io.github.summpot.beaconauth.server.AuthServer.VerificationResult
import io.netty.buffer.Unpooled
import net.minecraft.network.Connection
import net.minecraft.network.FriendlyByteBuf
import net.minecraft.network.chat.Component
import net.minecraft.network.protocol.login.ClientboundCustomQueryPacket
import net.minecraft.server.MinecraftServer
import org.slf4j.LoggerFactory
import java.util.*
import java.util.function.Consumer

/**
 * Kotlin helper for server-side login-phase custom query negotiation.
 * Called by ServerLoginPacketListenerImplMixin (Java).
 */
class ServerLoginHandler @JvmOverloads constructor(
    private val server: MinecraftServer,
    private val connection: Connection,
    private var gameProfile: GameProfile?,
    private val disconnectCallback: (Component) -> Unit,
    private val finishCallback: () -> Unit,
    /**
     * True if BeaconAuth intercepted HELLO on an online-mode server and skipped Mojang auth.
     * In that case, the profile UUID is only a placeholder and MUST NOT be treated as Mojang-verified.
     */
    private val helloWasIntercepted: Boolean = false,
) {
    companion object {
        private val logger = LoggerFactory.getLogger("BeaconAuth/ServerLogin")
        const val NEGOTIATION_TIMEOUT_TICKS = 20 * 90 // 90 seconds
    }

    private val negotiation = ServerLoginNegotiation()
    private var transactionCounter = 0

    /**
     * Expose the current GameProfile (potentially updated with a stable UUID) back to the mixin.
     */
    val currentGameProfile: GameProfile?
        get() = gameProfile

    fun tick() {
        negotiation.incrementTick()
        if (negotiation.ticks > NEGOTIATION_TIMEOUT_TICKS) {
            fail(Component.translatable("disconnect.beaconauth.timeout"))
        }
    }

    fun start() {
        if (gameProfile == null) {
            logger.warn("Cannot start negotiation: gameProfile is null")
            return
        }
        logger.info("Starting login-phase negotiation for ${gameProfile?.name}")
        negotiation.resetTick()
        sendQuery(LoginQueryType.PROBE) { }
    }

    fun handleCustomQuery(transactionId: Int, data: FriendlyByteBuf?): Boolean {
        val type = negotiation.consume(transactionId) ?: return false
        when (type) {
            LoginQueryType.PROBE -> handleProbeResponse(data)
            LoginQueryType.INIT -> handleInitResponse(data)
            LoginQueryType.LOGIN_URL -> handleLoginUrlAck(data)
            LoginQueryType.VERIFY -> handleVerifyResponse(data)
        }
        return true
    }

    private fun handleProbeResponse(data: FriendlyByteBuf?) {
        val modded = data?.readBoolean() ?: false
        negotiation.markModded(modded)
        logger.info("Client modded status: $modded")

        val onlineMode = server.usesAuthentication()
        logger.info("Server online-mode: $onlineMode")
        
        if (!modded) {
            if (onlineMode || BeaconAuthConfig.shouldAllowVanillaOfflineClients()) {
                logger.info("Vanilla client allowed; finishing negotiation")
                finish()
            } else {
                logger.warn("Vanilla client rejected (offline mode, mod required)")
                fail(Component.translatable("disconnect.beaconauth.mod_required"))
            }
            return
        }

        // Determine if we should bypass BeaconAuth
        // Note: When BeaconAuth intercepts handleHello on online-mode servers,
        // the gameProfile.id will be null because Mojang authentication was skipped.
        // A non-null UUID indicates the player passed through Mojang verification
        // (either because BeaconAuth didn't intercept, or on offline-mode servers).
        val hasMojangVerifiedUUID = !helloWasIntercepted && gameProfile?.id != null
        
        val bypassOnlineMode = onlineMode && BeaconAuthConfig.shouldBypassIfOnlineModeVerified() && hasMojangVerifiedUUID
        val bypassOfflineMode = !onlineMode && !BeaconAuthConfig.shouldForceAuthIfOfflineMode()
        val bypass = bypassOnlineMode || bypassOfflineMode
        
        logger.info("Bypass check: bypassOnlineMode=$bypassOnlineMode, bypassOfflineMode=$bypassOfflineMode, finalBypass=$bypass, hasMojangUUID=$hasMojangVerifiedUUID")
        logger.info("Config values: bypass_if_online_mode_verified=${BeaconAuthConfig.shouldBypassIfOnlineModeVerified()}, force_auth_if_offline_mode=${BeaconAuthConfig.shouldForceAuthIfOfflineMode()}")
        
        if (bypass) {
            logger.info("Bypass triggered; finishing negotiation without BeaconAuth")
            finish()
        } else {
            logger.info("Starting BeaconAuth flow")
            startBeaconFlow()
        }
    }

    private fun handleInitResponse(data: FriendlyByteBuf?) {
        if (data == null || data.readableBytes() <= 0) {
            logger.error("Invalid INIT response: no data")
            fail(Component.translatable("disconnect.beaconauth.invalid_init"))
            return
        }
        val challenge = data.readUtf(512)
        val redirectPort = data.readVarInt()
        negotiation.setChallenge(challenge, redirectPort)
        logger.info("Received INIT: challenge length=${challenge.length}, port=$redirectPort")

        try {
            val loginUrl = AuthServer.buildLoginUrl(challenge, redirectPort)
            negotiation.phase = ServerLoginNegotiation.Phase.LOGIN_URL
            sendQuery(LoginQueryType.LOGIN_URL) { buf -> buf.writeUtf(loginUrl, 2048) }
            negotiation.resetTick()
            sendQuery(LoginQueryType.VERIFY) { }
            negotiation.phase = ServerLoginNegotiation.Phase.VERIFY
            logger.debug("Sent LOGIN_URL & VERIFY queries")
        } catch (e: Exception) {
            logger.error("Error building login URL: ${e.message}", e)
            fail(Component.translatable("disconnect.beaconauth.server_error"))
        }
    }

    private fun handleLoginUrlAck(data: FriendlyByteBuf?) {
        logger.debug("Received LOGIN_URL acknowledgement")
    }

    private fun handleVerifyResponse(data: FriendlyByteBuf?) {
        if (data == null) {
            logger.error("Invalid VERIFY response: no data")
            fail(Component.translatable("disconnect.beaconauth.invalid_verify"))
            return
        }
        val profile = gameProfile
        if (profile == null) {
            logger.error("Invalid VERIFY: gameProfile is null")
            fail(Component.translatable("disconnect.beaconauth.invalid_verify"))
            return
        }

        val statusOrdinal = data.readVarInt()

        val status = LoginVerificationStatus.values()[
            statusOrdinal.coerceIn(0, LoginVerificationStatus.values().size - 1)
        ]
        logger.info("Received VERIFY status: $status")

        when (status) {
            LoginVerificationStatus.SUCCESS -> {
                val jwt = data.readUtf(4096)
                val verifier = data.readUtf(512)
                val result = AuthServer.verifyForProfile(profile.name, jwt, verifier)
                if (result.success) {
                    val stableUuid = result.stableUuid
                    if (stableUuid != null) {
                        // Replace the login profile UUID with a stable per-account UUID.
                        // This prevents account takeover on offline-mode servers via username changes.
                        gameProfile = GameProfile(stableUuid, profile.name)
                        logger.info("Using stable UUID for ${profile.name}: $stableUuid")
                    }
                    logger.info("✓ Verification successful for ${profile.name}")
                    finish()
                } else {
                    logger.error("✗ Verification failed: ${result.message}")
                    fail(Component.translatable("disconnect.beaconauth.failure", result.message))
                }
            }
            LoginVerificationStatus.CANCELLED -> {
                val reason = data.readUtf(256)
                logger.warn("User cancelled: $reason")
                fail(Component.translatable("disconnect.beaconauth.cancelled", reason))
            }
            LoginVerificationStatus.ERROR -> {
                val error = data.readUtf(256)
                logger.error("Client error: $error")
                fail(Component.translatable("disconnect.beaconauth.failure", error))
            }
        }
    }

    private fun startBeaconFlow() {
        negotiation.phase = ServerLoginNegotiation.Phase.INIT
        sendQuery(LoginQueryType.INIT) { }
        negotiation.resetTick()
    }

    private fun finish() {
        negotiation.markFinished()
        logger.info("Negotiation finished successfully")
        finishCallback()
    }

    private fun fail(reason: Component) {
        logger.warn("Negotiation failed: ${reason.string}")
        disconnectCallback(reason)
    }

    private fun sendQuery(type: LoginQueryType, writer: Consumer<FriendlyByteBuf>) {
        val buf = FriendlyByteBuf(Unpooled.buffer())
        writer.accept(buf)
        val transactionId = ++transactionCounter
        negotiation.registerTransaction(transactionId, type)
        connection.send(ClientboundCustomQueryPacket(transactionId, type.id(), buf))
    }
}
