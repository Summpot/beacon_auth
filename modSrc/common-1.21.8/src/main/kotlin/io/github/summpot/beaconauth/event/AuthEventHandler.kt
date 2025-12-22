package io.github.summpot.beaconauth.event

import dev.architectury.event.events.common.PlayerEvent
import io.github.summpot.beaconauth.server.AuthServer
import net.minecraft.server.level.ServerPlayer
import org.slf4j.LoggerFactory

/**
 * Event handlers for authentication checks
 */
object AuthEventHandler {
    private val logger = LoggerFactory.getLogger("BeaconAuth/Events")

    fun register() {
        PlayerEvent.PLAYER_QUIT.register { player ->
            if (player is ServerPlayer) {
                handlePlayerQuit(player)
            }
        }
    }

    private fun handlePlayerQuit(player: ServerPlayer) {
        logger.info("Player ${player.gameProfile.name} left the server")
        AuthServer.removeAuthenticatedPlayer(player.uuid)
    }
}
