package io.github.summpot.beaconauth.login

/**
 * Login verification result sent from client to server during BeaconAuth negotiation.
 *
 * IMPORTANT: This is shared across all supported Minecraft versions.
 */
enum class LoginVerificationStatus {
    SUCCESS,
    CANCELLED,
    ERROR
}
