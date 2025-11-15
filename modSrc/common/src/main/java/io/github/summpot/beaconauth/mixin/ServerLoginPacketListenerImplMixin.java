package io.github.summpot.beaconauth.mixin;

import com.mojang.authlib.GameProfile;
import io.github.summpot.beaconauth.server.ServerLoginHandler;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.minecraft.network.protocol.login.ServerboundCustomQueryPacket;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import org.jetbrains.annotations.Nullable;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.Redirect;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * Mixin entry point for BeaconAuth login-phase negotiation on server.
 * All logic delegated to ServerLoginHandler (Kotlin).
 * 
 * This Mixin works on both Fabric and Forge:
 * - On Forge: Intercepts NetworkHooks.tickNegotiation() via @Redirect to prevent NPE
 * - On Fabric & Forge: Uses @Inject to handle BeaconAuth flow at READY_TO_ACCEPT state
 */
@Mixin(value = ServerLoginPacketListenerImpl.class, priority = 1100)
public abstract class ServerLoginPacketListenerImplMixin {
    @Shadow @Final private MinecraftServer server;
    @Shadow @Final Connection connection;
    @Shadow private int tick;
    @Shadow @Nullable GameProfile gameProfile;
    @Shadow @Nullable private ServerPlayer delayedAcceptPlayer;

    @Shadow protected abstract void disconnect(Component reason);

    @Unique private ServerLoginHandler beaconAuth$handler;
    @Unique private boolean beaconAuth$negotiationStarted = false;

    /**
     * Redirect Forge's NetworkHooks.tickNegotiation() call to prevent NPE.
     * When we're handling BeaconAuth, we return false to keep vanilla in NEGOTIATING state.
     * Otherwise, we call the original Forge method.
     */
    @Redirect(
        method = "tick",
        at = @At(
            value = "INVOKE",
            target = "Lnet/minecraftforge/network/NetworkHooks;tickNegotiation(Lnet/minecraft/server/network/ServerLoginPacketListenerImpl;Lnet/minecraft/network/Connection;Lnet/minecraft/server/level/ServerPlayer;)Z",
            remap = false
        ),
        require = 0
    )
    private boolean beaconAuth$redirectForgeNegotiation(
        ServerLoginPacketListenerImpl listener,
        Connection connection,
        ServerPlayer delayedPlayer
    ) {
        // If we're handling BeaconAuth, prevent Forge from proceeding
        if (beaconAuth$handler != null) {
            return false; // Keep vanilla in NEGOTIATING state
        }

        // Otherwise, let Forge handle it normally
        try {
            Class<?> networkHooks = Class.forName("net.minecraftforge.network.NetworkHooks");
            java.lang.reflect.Method method = networkHooks.getMethod(
                "tickNegotiation",
                ServerLoginPacketListenerImpl.class,
                Connection.class,
                ServerPlayer.class
            );
            return (boolean) method.invoke(null, listener, connection, delayedPlayer);
        } catch (Exception e) {
            return true; // Fallback: assume negotiation is complete
        }
    }

    /**
     * Main injection point that works on both Fabric and Forge.
     * Checks if we should start BeaconAuth negotiation when state becomes READY_TO_ACCEPT.
     */
    @Inject(method = "tick", at = @At("HEAD"))
    private void beaconAuth$onTick(CallbackInfo ci) {
        // If we've already started or finished, handle ongoing negotiation
        if (beaconAuth$handler != null) {
            tick = 0; // prevent vanilla slow-login disconnect
            beaconAuth$handler.tick();
            return;
        }

        // Check if we should start negotiation
        if (!beaconAuth$negotiationStarted && beaconAuth$isReadyToAccept()) {
            beaconAuth$startNegotiation();
        }
    }

    @Inject(method = "handleCustomQueryPacket", at = @At("HEAD"), cancellable = true)
    private void beaconAuth$handleCustomQuery(ServerboundCustomQueryPacket packet, CallbackInfo ci) {
        if (beaconAuth$handler == null) {
            return;
        }
        boolean handled = beaconAuth$handler.handleCustomQuery(packet.getTransactionId(), packet.getData());
        if (handled) {
            ci.cancel();
        }
    }

    @Unique
    private boolean beaconAuth$isReadyToAccept() {
        try {
            java.lang.reflect.Field stateField = ServerLoginPacketListenerImpl.class.getDeclaredField("state");
            stateField.setAccessible(true);
            Object stateValue = stateField.get(this);
            return stateValue.toString().equals("READY_TO_ACCEPT") && gameProfile != null;
        } catch (Exception e) {
            return false;
        }
    }

    @Unique
    private void beaconAuth$startNegotiation() {
        if (gameProfile == null) {
            return;
        }
        
        beaconAuth$negotiationStarted = true;
        beaconAuth$handler = new ServerLoginHandler(
            server,
            connection,
            gameProfile,
            (Component reason) -> {
                disconnect(reason);
                beaconAuth$handler = null;
                beaconAuth$setState("ACCEPTED");
                return kotlin.Unit.INSTANCE;
            },
            () -> {
                beaconAuth$handler = null;
                beaconAuth$setState("READY_TO_ACCEPT");
                return kotlin.Unit.INSTANCE;
            }
        );
        beaconAuth$setState("NEGOTIATING");
        beaconAuth$handler.start();
    }

    @Unique
    private void beaconAuth$setState(String stateName) {
        try {
            java.lang.reflect.Field stateField = ServerLoginPacketListenerImpl.class.getDeclaredField("state");
            stateField.setAccessible(true);
            Class<?> stateClass = Class.forName("net.minecraft.server.network.ServerLoginPacketListenerImpl$State");
            Object stateValue = java.util.Arrays.stream(stateClass.getEnumConstants())
                .filter(e -> e.toString().equals(stateName))
                .findFirst()
                .orElse(null);
            if (stateValue != null) {
                stateField.set(this, stateValue);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
