package io.github.summpot.beaconauth.mixin;

import io.github.summpot.beaconauth.client.ClientLoginHandler;
import io.github.summpot.beaconauth.login.LoginQueryType;
import net.minecraft.client.multiplayer.ClientHandshakePacketListenerImpl;
import net.minecraft.network.Connection;
import net.minecraft.resources.ResourceLocation;
import net.minecraft.network.protocol.login.ClientboundCustomQueryPacket;
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

    @Inject(method = "handleCustomQuery", at = @At("HEAD"), cancellable = true)
    private void beaconAuth$handleCustomQuery(ClientboundCustomQueryPacket packet, CallbackInfo ci) {
        ResourceLocation id = packet.getIdentifier();
        if (id.equals(LoginQueryType.PROBE.id())) {
            ClientLoginHandler.respondProbe(connection, packet.getTransactionId());
            ci.cancel();
        } else if (id.equals(LoginQueryType.INIT.id())) {
            ClientLoginHandler.respondInit(connection, packet.getTransactionId());
            ci.cancel();
        } else if (id.equals(LoginQueryType.LOGIN_URL.id())) {
            ClientLoginHandler.handleLoginUrl(connection, packet.getTransactionId(), packet.getData());
            ci.cancel();
        } else if (id.equals(LoginQueryType.VERIFY.id())) {
            ClientLoginHandler.handleVerifyRequest(connection, packet.getTransactionId());
            ci.cancel();
        }
    }
}
