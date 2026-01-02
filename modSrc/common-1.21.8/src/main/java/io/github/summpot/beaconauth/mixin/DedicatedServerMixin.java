package io.github.summpot.beaconauth.mixin;

import net.minecraft.server.dedicated.DedicatedServer;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

/**
 * Server-side: BeaconAuth users do not have Mojang-signed profile public keys.
 *
 * When enforce-secure-profile is enabled, vanilla clients without a profile key will have chat
 * disabled (and may be unable to join / interact as expected). BeaconAuth intentionally supports
 * alternative authentication, so we disable the secure-profile enforcement on dedicated servers.
 */
@Mixin(DedicatedServer.class)
public class DedicatedServerMixin {

	@Inject(method = "enforceSecureProfile", at = @At("RETURN"), cancellable = true)
	private void beaconAuth$disableSecureProfileEnforcement(CallbackInfoReturnable<Boolean> cir) {
		if (cir.getReturnValueZ()) {
			cir.setReturnValue(false);
		}
	}
}
