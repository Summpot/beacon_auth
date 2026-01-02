package io.github.summpot.beaconauth.mixin;

import io.github.summpot.beaconauth.client.BeaconAuthClientSession;
import net.minecraft.commands.arguments.ArgumentSignatures;
import net.minecraft.network.protocol.game.ServerboundChatCommandSignedPacket;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

@Mixin(ServerboundChatCommandSignedPacket.class)
public class ServerboundChatCommandSignedPacketMixin {

	@Inject(method = "argumentSignatures", at = @At("RETURN"), cancellable = true)
	private void beaconAuth$stripArgumentSignatures(CallbackInfoReturnable<ArgumentSignatures> cir) {
		if (BeaconAuthClientSession.isBeaconAuthAuthenticatedConnection()) {
			cir.setReturnValue(ArgumentSignatures.EMPTY);
		}
	}
}
