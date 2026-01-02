package io.github.summpot.beaconauth.mixin;

import com.mojang.authlib.GameProfile;
import io.github.summpot.beaconauth.server.ServerLoginHandler;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.minecraft.network.protocol.cookie.ServerboundCookieResponsePacket;
import net.minecraft.network.protocol.login.ServerboundHelloPacket;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import org.jetbrains.annotations.Nullable;
import org.slf4j.LoggerFactory;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

import java.nio.charset.StandardCharsets;
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

    @Shadow public abstract void disconnect(Component reason);

    @Unique private ServerLoginHandler beaconAuth$handler;
    @Unique private boolean beaconAuth$negotiationStarted = false;
    @Unique private boolean beaconAuth$interceptedHello = false;
    @Unique @Nullable private GameProfile beaconAuth$loginProfile;

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

        // If server is NOT in online-mode or it's a memory connection, let vanilla handle it.
        // (For offline-mode servers, we'll start negotiation later during VERIFYING in tick().)
        if (!serverOnlineMode || isMemoryConnection) {
            BEACON_LOGGER.info("Allowing vanilla authentication flow");
            return;
        }

        // Server is in online-mode. BeaconAuth is designed for this scenario.
        // Skip Mojang authentication and let BeaconAuth handle authentication instead.
        BEACON_LOGGER.info("Intercepting handleHello for {} - starting BeaconAuth flow", packet.name());

        beaconAuth$interceptedHello = true;

        // Mirror vanilla bookkeeping so log messages include the username.
        beaconAuth$setStringFieldIfPresent("requestedUsername", packet.name());

        // IMPORTANT: Some vanilla/loader codepaths require a non-null profile ID.
        // Use the standard offline UUID as a placeholder until BeaconAuth verification
        // installs the stable per-account UUID.
        // We still record that Mojang auth was skipped via beaconAuth$interceptedHello.
        GameProfile loginProfile = new GameProfile(beaconAuth$offlineUuid(packet.name()), packet.name());
        beaconAuth$loginProfile = loginProfile;

        // Enter NEGOTIATING and start BeaconAuth cookie negotiation.
        beaconAuth$setState("NEGOTIATING");
        beaconAuth$startNegotiation(loginProfile);

        // Cancel the original handleHello execution.
        ci.cancel();
    }

    @Unique
    private static UUID beaconAuth$offlineUuid(String username) {
        // Matches vanilla offline-mode UUID computation.
        return UUID.nameUUIDFromBytes(("OfflinePlayer:" + username).getBytes(StandardCharsets.UTF_8));
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

        // Start negotiation for flows where we did NOT intercept handleHello:
        // - offline-mode servers (game profile already assigned)
        // - online-mode players already verified by Mojang (UUID present)
        if (!beaconAuth$negotiationStarted && beaconAuth$isInState("VERIFYING")) {
            GameProfile profile = beaconAuth$getAuthenticatedProfile();
            if (profile != null) {
                BEACON_LOGGER.info("Starting BeaconAuth negotiation at VERIFYING state");
                beaconAuth$loginProfile = profile;
                beaconAuth$setState("NEGOTIATING");
                beaconAuth$startNegotiation(profile);
            }
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
    private void beaconAuth$startNegotiation(GameProfile profile) {
        if (beaconAuth$negotiationStarted) {
            return;
        }

        beaconAuth$negotiationStarted = true;
        BEACON_LOGGER.info("Starting BeaconAuth negotiation for {}", profile.getName());

        beaconAuth$handler = new ServerLoginHandler(
            server,
            connection,
            profile,
            (Component reason) -> {
                BEACON_LOGGER.info("BeaconAuth negotiation failed for {}: {}", profile.getName(), reason.getString());
                disconnect(reason);
                beaconAuth$handler = null;
                // Mark terminal state to avoid additional processing after disconnect.
                beaconAuth$setState("ACCEPTED");
                return kotlin.Unit.INSTANCE;
            },
            () -> {
                BEACON_LOGGER.info("BeaconAuth negotiation finished successfully for {}", profile.getName());

                GameProfile updated = null;
                if (beaconAuth$handler != null) {
                    updated = beaconAuth$handler.getCurrentGameProfile();
                }
                if (updated != null) {
                    beaconAuth$loginProfile = updated;
                }
                if (beaconAuth$loginProfile != null) {
                    beaconAuth$setAuthenticatedProfile(beaconAuth$loginProfile);
                }

                beaconAuth$handler = null;
                // Continue vanilla flow: tick() will verify and finish login.
                beaconAuth$setState("VERIFYING");
                return kotlin.Unit.INSTANCE;
            },
            beaconAuth$interceptedHello
        );
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

    @Unique
    @Nullable
    private GameProfile beaconAuth$getAuthenticatedProfile() {
        // Vanilla 1.21.x uses "authenticatedProfile".
        // Some loaders may patch in "gameProfile".
        GameProfile profile = (GameProfile) beaconAuth$getFieldIfPresent("authenticatedProfile");
        if (profile != null) {
            return profile;
        }
        return (GameProfile) beaconAuth$getFieldIfPresent("gameProfile");
    }

    @Unique
    private void beaconAuth$setAuthenticatedProfile(@Nullable GameProfile profile) {
        if (profile == null) {
            return;
        }
        if (beaconAuth$setFieldIfPresent("authenticatedProfile", profile)) {
            return;
        }
        beaconAuth$setFieldIfPresent("gameProfile", profile);
    }

    @Unique
    private void beaconAuth$setStringFieldIfPresent(String fieldName, String value) {
        beaconAuth$setFieldIfPresent(fieldName, value);
    }

    @Unique
    @Nullable
    private Object beaconAuth$getFieldIfPresent(String fieldName) {
        try {
            java.lang.reflect.Field f = ServerLoginPacketListenerImpl.class.getDeclaredField(fieldName);
            f.setAccessible(true);
            return f.get(this);
        } catch (Throwable ignored) {
            return null;
        }
    }

    @Unique
    private boolean beaconAuth$setFieldIfPresent(String fieldName, Object value) {
        try {
            java.lang.reflect.Field f = ServerLoginPacketListenerImpl.class.getDeclaredField(fieldName);
            f.setAccessible(true);
            f.set(this, value);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }
}
