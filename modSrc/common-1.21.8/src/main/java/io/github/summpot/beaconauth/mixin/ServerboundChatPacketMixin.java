package io.github.summpot.beaconauth.mixin;

import io.github.summpot.beaconauth.client.BeaconAuthClientSession;
import net.minecraft.network.chat.MessageSignature;
import net.minecraft.network.protocol.game.ServerboundChatPacket;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

/**
 * Client-side: if this connection completed BeaconAuth authentication, downgrade outgoing chat
 * to unsigned by stripping message signatures.
 */
@Mixin(ServerboundChatPacket.class)
public class ServerboundChatPacketMixin {

	@Inject(method = "signature", at = @At("RETURN"), cancellable = true)
	private void beaconAuth$stripSignature(CallbackInfoReturnable<MessageSignature> cir) {
		if (BeaconAuthClientSession.isBeaconAuthAuthenticatedConnection()) {
			cir.setReturnValue(null);
		}
	}
}
