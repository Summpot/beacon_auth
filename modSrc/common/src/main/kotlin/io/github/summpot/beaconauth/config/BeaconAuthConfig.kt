package io.github.summpot.beaconauth.config

// Intentionally empty.
//
// This folder (`modSrc/common/src/main/**`) is compiled into every Minecraft-versioned
// `common-*` module via Gradle sourceSets. Configuration APIs differ between 1.20.1 and
// 1.21.x targets, so `BeaconAuthConfig` must remain version-specific.
//
// The real `io.github.summpot.beaconauth.config.BeaconAuthConfig` is defined in:
// - modSrc/common-1.20.1/src/...
// - modSrc/common-1.21.1/src/...
// - modSrc/common-1.21.8/src/...
