package io.github.summpot.beaconauth.login;

import net.minecraft.resources.ResourceLocation;
import io.github.summpot.beaconauth.BeaconAuthMod;

/**
 * Identifiers for BeaconAuth login-phase custom query packets.
 */
public enum LoginQueryType {
    PROBE("probe"),
    INIT("init"),
    LOGIN_URL("login_url"),
    VERIFY("verify");

    private final ResourceLocation id;

    LoginQueryType(String path) {
        this.id = new ResourceLocation(BeaconAuthMod.MOD_ID, path);
    }

    public ResourceLocation id() {
        return id;
    }
}
