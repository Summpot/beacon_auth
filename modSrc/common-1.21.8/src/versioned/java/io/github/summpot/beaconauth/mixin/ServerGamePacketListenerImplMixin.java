package io.github.summpot.beaconauth.mixin;

import io.github.summpot.beaconauth.server.AuthServer;
import net.minecraft.network.chat.MessageSignature;
import net.minecraft.network.chat.PlayerChatMessage;
import net.minecraft.network.chat.SignedMessageBody;
import net.minecraft.network.chat.SignedMessageChain;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.network.ServerGamePacketListenerImpl;
import org.jetbrains.annotations.Nullable;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Redirect;

/**
 * Server-side: allow BeaconAuth sessions to keep chat usable.
 *
 * Vanilla will throw {@link net.minecraft.network.chat.SignedMessageChain.DecodeException} with
 * "chat.disabled.missingProfileKey" if a chat/command signature is missing while a signed chat
 * decoder is active.
 *
 * For BeaconAuth players (who intentionally do not have Mojang-signed profile keys), and for any
 * server that does not enforce secure profiles, we treat missing signatures as unsigned messages.
 */
@Mixin(ServerGamePacketListenerImpl.class)
public abstract class ServerGamePacketListenerImplMixin {
	@Shadow @Final private MinecraftServer server;
	@Shadow public ServerPlayer player;

	@Redirect(
		method = "getSignedMessage",
		at = @At(
			value = "INVOKE",
			target = "Lnet/minecraft/network/chat/SignedMessageChain$Decoder;unpack(Lnet/minecraft/network/chat/MessageSignature;Lnet/minecraft/network/chat/SignedMessageBody;)Lnet/minecraft/network/chat/PlayerChatMessage;"
		)
	)
	private PlayerChatMessage beaconAuth$allowUnsignedChatWhenAllowed(
		SignedMessageChain.Decoder decoder,
		@Nullable MessageSignature signature,
		SignedMessageBody body
	) throws SignedMessageChain.DecodeException {
		if (signature == null && beaconAuth$shouldAllowUnsigned()) {
			return PlayerChatMessage.unsigned(this.player.getUUID(), body.content());
		}
		return decoder.unpack(signature, body);
	}

	@Redirect(
		method = "collectUnsignedArguments",
		at = @At(
			value = "INVOKE",
			target = "Lnet/minecraft/network/chat/SignedMessageChain$Decoder;unpack(Lnet/minecraft/network/chat/MessageSignature;Lnet/minecraft/network/chat/SignedMessageBody;)Lnet/minecraft/network/chat/PlayerChatMessage;"
		),
		require = 0
	)
	private PlayerChatMessage beaconAuth$allowUnsignedCommandArgsWhenAllowed(
		SignedMessageChain.Decoder decoder,
		@Nullable MessageSignature signature,
		SignedMessageBody body
	) throws SignedMessageChain.DecodeException {
		if (signature == null && beaconAuth$shouldAllowUnsigned()) {
			return PlayerChatMessage.unsigned(this.player.getUUID(), body.content());
		}
		return decoder.unpack(signature, body);
	}

	private boolean beaconAuth$shouldAllowUnsigned() {
		try {
			if (!this.server.enforceSecureProfile()) {
				return true;
			}
			return AuthServer.INSTANCE.isPlayerAuthenticated(this.player.getUUID());
		} catch (Throwable ignored) {
			return false;
		}
	}
}
