package io.github.summpot.beaconauth.mixin;

import io.github.summpot.beaconauth.server.AuthServer;
import net.minecraft.network.protocol.game.ServerGamePacketListener;
import net.minecraft.network.protocol.game.ServerboundChatSessionUpdatePacket;
import net.minecraft.server.network.ServerGamePacketListenerImpl;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * Server-side: ignore chat-session updates for BeaconAuth-authenticated players.
 *
 * Secure chat sessions are tied to a Mojang-signed profile public key; BeaconAuth players won't
 * have one, so accepting chat-session updates may trigger warnings and/or disable chat.
 */
@Mixin(ServerboundChatSessionUpdatePacket.class)
public class ServerboundChatSessionUpdatePacketMixin {

	@Inject(method = "handle", at = @At("HEAD"), cancellable = true)
	private void beaconAuth$maybeIgnoreChatSessionUpdate(ServerGamePacketListener listener, CallbackInfo ci) {
		if (!(listener instanceof ServerGamePacketListenerImpl impl)) {
			return;
		}

		try {
			var player = impl.getPlayer();
			if (player != null && AuthServer.INSTANCE.isPlayerAuthenticated(player.getUUID())) {
				ci.cancel();
			}
		} catch (Throwable ignored) {
			// Be conservative on mapping differences.
		}
	}
}
