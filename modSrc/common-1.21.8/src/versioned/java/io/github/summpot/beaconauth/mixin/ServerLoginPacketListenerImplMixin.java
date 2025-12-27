package io.github.summpot.beaconauth.mixin;

import com.mojang.authlib.GameProfile;
import io.github.summpot.beaconauth.server.ServerLoginHandler;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.minecraft.network.protocol.cookie.ServerboundCookieResponsePacket;
import net.minecraft.network.protocol.login.ServerboundHelloPacket;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import org.jetbrains.annotations.Nullable;
import org.slf4j.LoggerFactory;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.Redirect;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

import java.util.UUID;

/**
 * Mixin entry point for BeaconAuth login-phase negotiation on server.
 * All logic delegated to ServerLoginHandler (Kotlin).
 * 
 * This Mixin works on both Fabric and Forge:
 * - Intercepts handleHello to skip Mojang auth when BeaconAuth should be used
 * - On Forge: Intercepts NetworkHooks.tickNegotiation() via @Redirect to prevent NPE
 * - On Fabric & Forge: Uses @Inject to handle BeaconAuth flow at READY_TO_ACCEPT state
 */
@Mixin(value = ServerLoginPacketListenerImpl.class, priority = 1100)
public abstract class ServerLoginPacketListenerImplMixin {
    @Unique private static final org.slf4j.Logger BEACON_LOGGER = LoggerFactory.getLogger("BeaconAuth/Mixin");
    
    @Shadow @Final private MinecraftServer server;
    @Shadow @Final Connection connection;
    @Shadow private int tick;
    @Shadow @Nullable GameProfile gameProfile;
    @Shadow @Nullable private ServerPlayer delayedAcceptPlayer;

    @Shadow protected abstract void disconnect(Component reason);

    @Unique private ServerLoginHandler beaconAuth$handler;
    @Unique private boolean beaconAuth$negotiationStarted = false;
    @Unique private boolean beaconAuth$shouldUseBeaconAuth = false;

    /**
     * Intercept handleHello to decide whether to use BeaconAuth or Mojang authentication.
     * 
     * BeaconAuth is designed to work on online-mode=true servers, allowing offline-mode
     * players (without Mojang accounts) to authenticate via the custom BeaconAuth system.
     * 
     * This intercept skips Mojang authentication and goes directly to NEGOTIATING state,
     * where BeaconAuth will probe the client and decide whether to:
     * - Use BeaconAuth authentication (for modded clients without valid Mojang sessions)
     * - Bypass authentication (for clients that already passed Mojang auth)
     * - Reject the connection (for vanilla clients when configured to require the mod)
     */
    @Inject(method = "handleHello", at = @At("HEAD"), cancellable = true)
    private void beaconAuth$onHandleHello(ServerboundHelloPacket packet, CallbackInfo ci) {
        // Only intercept if we're in the expected HELLO state
        if (!beaconAuth$isInState("HELLO")) {
            BEACON_LOGGER.debug("Not in HELLO state, skipping interception");
            return;
        }

        // Get singleplayer profile if exists
        GameProfile singleplayerProfile = server.getSingleplayerProfile();
        if (singleplayerProfile != null && packet.name().equalsIgnoreCase(singleplayerProfile.getName())) {
            BEACON_LOGGER.debug("Singleplayer profile detected, allowing vanilla flow");
            return;
        }

        // Check if server is in online-mode
        boolean serverOnlineMode = server.usesAuthentication();
        boolean isMemoryConnection = connection.isMemoryConnection();

        BEACON_LOGGER.info("Player {} attempting to connect: online-mode={}, memory={}", 
            packet.name(), serverOnlineMode, isMemoryConnection);

        // If server is NOT in online-mode or it's a memory connection, let vanilla handle it
        if (!serverOnlineMode || isMemoryConnection) {
            BEACON_LOGGER.info("Allowing vanilla authentication flow");
            return;
        }

        // Server is in online-mode. BeaconAuth is designed for this scenario.
        // Skip Mojang authentication and let BeaconAuth handle authentication instead.
        BEACON_LOGGER.info("Intercepting handleHello for {} - starting BeaconAuth flow", packet.name());
        
        beaconAuth$shouldUseBeaconAuth = true;
        
        // Set up the game profile with no UUID (will be generated later if needed)
        this.gameProfile = new GameProfile((UUID)null, packet.name());
        
        // Transition directly to NEGOTIATING state, bypassing Mojang authentication
        beaconAuth$setState("NEGOTIATING");
        
        // CRITICAL: Start BeaconAuth negotiation immediately
        // We can't wait for READY_TO_ACCEPT since we skipped Mojang auth
        beaconAuth$startNegotiationNow();
        
        // Cancel the original handleHello execution
        ci.cancel();
    }

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

        // Check if we should start negotiation (for cases where we didn't intercept handleHello)
        if (!beaconAuth$negotiationStarted && !beaconAuth$shouldUseBeaconAuth && beaconAuth$isReadyToAccept()) {
            BEACON_LOGGER.info("Starting BeaconAuth negotiation at READY_TO_ACCEPT state");
            beaconAuth$startNegotiation();
        }
    }

    @Inject(method = "handleCookieResponse", at = @At("HEAD"), cancellable = true)
    private void beaconAuth$handleCookieResponse(ServerboundCookieResponsePacket packet, CallbackInfo ci) {
        if (beaconAuth$handler == null) {
            return;
        }
        boolean handled = beaconAuth$handler.handleCookieResponse(packet.key(), packet.payload());
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
    private boolean beaconAuth$isInState(String expectedState) {
        try {
            java.lang.reflect.Field stateField = ServerLoginPacketListenerImpl.class.getDeclaredField("state");
            stateField.setAccessible(true);
            Object stateValue = stateField.get(this);
            return stateValue.toString().equals(expectedState);
        } catch (Exception e) {
            return false;
        }
    }

    @Unique
    private void beaconAuth$startNegotiation() {
        if (gameProfile == null) {
            BEACON_LOGGER.warn("Cannot start negotiation: gameProfile is null");
            return;
        }
        
        BEACON_LOGGER.info("Starting BeaconAuth negotiation for {}", gameProfile.getName());
        beaconAuth$negotiationStarted = true;
        beaconAuth$handler = new ServerLoginHandler(
            server,
            connection,
            gameProfile,
            (Component reason) -> {
                BEACON_LOGGER.info("BeaconAuth negotiation failed for {}: {}", gameProfile.getName(), reason.getString());
                disconnect(reason);
                beaconAuth$handler = null;
                beaconAuth$setState("ACCEPTED");
                return kotlin.Unit.INSTANCE;
            },
            () -> {
                BEACON_LOGGER.info("BeaconAuth negotiation finished successfully for {}", gameProfile.getName());

                // IMPORTANT: ServerLoginHandler may update the GameProfile UUID after BeaconAuth verification.
                // Copy it back so the server uses a stable per-account UUID (not username-derived).
                if (beaconAuth$handler != null) {
                    GameProfile updated = beaconAuth$handler.getCurrentGameProfile();
                    if (updated != null) {
                        this.gameProfile = updated;
                    }
                }

                beaconAuth$handler = null;
                beaconAuth$setState("READY_TO_ACCEPT");
                return kotlin.Unit.INSTANCE;
            }
        );
        beaconAuth$setState("NEGOTIATING");
        beaconAuth$handler.start();
    }

    @Unique
    private void beaconAuth$startNegotiationNow() {
        if (gameProfile == null) {
            BEACON_LOGGER.error("CRITICAL: Cannot start negotiation immediately - gameProfile is null!");
            return;
        }
        
        if (beaconAuth$negotiationStarted) {
            BEACON_LOGGER.warn("Negotiation already started, skipping duplicate start");
            return;
        }
        
        BEACON_LOGGER.info("Starting immediate BeaconAuth negotiation for {}", gameProfile.getName());
        beaconAuth$startNegotiation();
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
