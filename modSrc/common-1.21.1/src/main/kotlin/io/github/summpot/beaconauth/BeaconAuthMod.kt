package io.github.summpot.beaconauth

import dev.architectury.event.events.common.CommandRegistrationEvent
import io.github.summpot.beaconauth.command.AuthCommand
import io.github.summpot.beaconauth.event.AuthEventHandler
import org.slf4j.LoggerFactory

object BeaconAuthMod {
    const val MOD_ID = "beaconauth"
    private val logger = LoggerFactory.getLogger("BeaconAuth")

    /**
     * Common initialization
     * Registers network packets and events
     */
    fun init() {
        logger.info("Initializing BeaconAuth mod...")
        
        // Register event handlers
        AuthEventHandler.register()
        
        logger.info("BeaconAuth mod initialized")
    }

    /**
     * Client-side initialization
     * Starts local Ktor HTTP server and registers client commands
     */
    fun initClient() {
        logger.info("Initializing BeaconAuth client-side...")
        io.github.summpot.beaconauth.client.AuthClient.init()
        
        // Register client-side commands
        CommandRegistrationEvent.EVENT.register { dispatcher, _, _ ->
            AuthCommand.registerClient(dispatcher)
        }
    }

    /**
     * Server-side initialization
     * Sets up JWT validation and registers server commands
     */
    fun initServer() {
        logger.info("Initializing BeaconAuth server-side...")
        io.github.summpot.beaconauth.server.AuthServer.init()
        
        // Register server-side commands
        CommandRegistrationEvent.EVENT.register { dispatcher, _, _ ->
            AuthCommand.registerServer(dispatcher)
        }
    }
}
