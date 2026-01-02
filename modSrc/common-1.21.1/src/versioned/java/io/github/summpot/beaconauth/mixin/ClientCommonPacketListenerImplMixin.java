package io.github.summpot.beaconauth.mixin;

import io.github.summpot.beaconauth.client.BeaconAuthClientSession;
import net.minecraft.client.multiplayer.ClientCommonPacketListenerImpl;
import net.minecraft.network.protocol.Packet;
import net.minecraft.network.protocol.game.ServerboundChatSessionUpdatePacket;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

@Mixin(ClientCommonPacketListenerImpl.class)
public abstract class ClientCommonPacketListenerImplMixin {

	@Inject(method = "send(Lnet/minecraft/network/protocol/Packet;)V", at = @At("HEAD"), cancellable = true)
	private void beaconAuth$dropChatSessionUpdate(Packet<?> packet, CallbackInfo ci) {
		if (!BeaconAuthClientSession.isBeaconAuthAuthenticatedConnection()) {
			return;
		}

		if (packet instanceof ServerboundChatSessionUpdatePacket) {
			ci.cancel();
		}
	}
}
