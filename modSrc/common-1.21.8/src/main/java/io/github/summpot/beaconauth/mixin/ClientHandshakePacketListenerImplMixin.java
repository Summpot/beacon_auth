package io.github.summpot.beaconauth.mixin;

import io.github.summpot.beaconauth.client.ClientLoginHandler;
import net.minecraft.client.multiplayer.ClientHandshakePacketListenerImpl;
import net.minecraft.network.Connection;
import net.minecraft.network.protocol.cookie.ClientboundCookieRequestPacket;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * Mixin entry point for BeaconAuth login-phase custom queries on client.
 * All logic delegated to ClientLoginHandler (Kotlin).
 */
@Mixin(ClientHandshakePacketListenerImpl.class)
public abstract class ClientHandshakePacketListenerImplMixin {
    @Shadow @Final private Connection connection;

    @Inject(method = "handleRequestCookie", at = @At("HEAD"), cancellable = true)
    private void beaconAuth$handleRequestCookie(ClientboundCookieRequestPacket packet, CallbackInfo ci) {
        boolean handled = ClientLoginHandler.handleCookieRequest(connection, packet.key());
        if (handled) {
            ci.cancel();
        }
    }
}
