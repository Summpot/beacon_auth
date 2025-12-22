package io.github.summpot.beaconauth.login;

import java.util.HashMap;
import java.util.Map;

/**
 * Tracks BeaconAuth negotiation state for a single Login listener instance.
 */
public final class ServerLoginNegotiation {
    public enum Phase {
        PROBE,
        INIT,
        LOGIN_URL,
        VERIFY,
        COMPLETE
    }

    private final Map<Integer, LoginQueryType> transactions = new HashMap<>();
    private Phase phase = Phase.PROBE;
    private boolean modded;
    private boolean requiresBeaconAuth;
    private String pendingChallenge;
    private int pendingPort;
    private int ticks;
    private boolean finished;

    public int registerTransaction(int transactionId, LoginQueryType type) {
        transactions.put(transactionId, type);
        return transactionId;
    }

    public LoginQueryType consume(int transactionId) {
        return transactions.remove(transactionId);
    }

    public void markModded(boolean modded) {
        this.modded = modded;
    }

    public boolean isModded() {
        return modded;
    }

    public void requireBeaconAuth(boolean requires) {
        this.requiresBeaconAuth = requires;
    }

    public boolean requiresBeaconAuth() {
        return requiresBeaconAuth;
    }

    public void setChallenge(String challenge, int port) {
        this.pendingChallenge = challenge;
        this.pendingPort = port;
    }

    public String getPendingChallenge() {
        return pendingChallenge;
    }

    public int getPendingPort() {
        return pendingPort;
    }

    public void setPhase(Phase phase) {
        this.phase = phase;
    }

    public Phase getPhase() {
        return phase;
    }

    public void incrementTick() {
        ticks++;
    }

    public int getTicks() {
        return ticks;
    }

    public void resetTick() {
        ticks = 0;
    }

    public void markFinished() {
        finished = true;
    }

    public boolean isFinished() {
        return finished;
    }
}
