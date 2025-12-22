package io.github.summpot.beaconauth.command

import com.mojang.brigadier.CommandDispatcher
import com.mojang.brigadier.context.CommandContext
import io.github.summpot.beaconauth.util.TranslationHelper
import net.minecraft.commands.CommandSourceStack
import net.minecraft.commands.Commands

/**
 * BeaconAuth commands for both client and server
 */
object AuthCommand {
    /**
     * Register client-side command
     * This runs on the logical client and triggers the local Ktor server
     */
    fun registerClient(dispatcher: CommandDispatcher<CommandSourceStack>) {
        dispatcher.register(
            Commands.literal("beaconauth")
                .then(
                    Commands.literal("login")
                        .executes { context -> executeClientLogin(context) }
                )
        )
    }

    /**
     * Register server-side command
     * This runs on the logical server and sends the RequestClientLogin packet
     */
    fun registerServer(dispatcher: CommandDispatcher<CommandSourceStack>) {
        dispatcher.register(
            Commands.literal("beaconauth")
                .then(
                    Commands.literal("login")
                        .executes { context -> executeServerLogin(context) }
                )
        )
    }

    private fun executeClientLogin(context: CommandContext<CommandSourceStack>): Int {
        context.source.sendSuccess({ TranslationHelper.autoLogin() }, false)
        return 1
    }
    
    private fun executeServerLogin(context: CommandContext<CommandSourceStack>): Int {
        context.source.sendSuccess({ TranslationHelper.autoLogin() }, false)
        return 1
    }
}
