use argon2::{Algorithm, Argon2, Params, Version};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

/// BeaconAuth password hashing.
///
/// We use Argon2id (RFC 9106 recommended variant) and encode hashes using the PHC string format.
///
/// ## Worker-friendly defaults
///
/// Cloudflare Workers are CPU and memory constrained compared to typical servers.
/// The parameters below are intentionally chosen to be "reasonable" within those constraints
/// while still being a modern, memory-hard password hash.
///
/// Params are expressed as:
/// - m_cost: memory cost in KiB
/// - t_cost: iterations
/// - p_cost: parallelism
///
/// Current default: 19 MiB memory, 2 iterations, parallelism 1.
const DEFAULT_M_COST_KIB: u32 = 19_456;
const DEFAULT_T_COST: u32 = 2;
const DEFAULT_P_COST: u32 = 1;

fn default_params() -> anyhow::Result<Params> {
    Params::new(
        DEFAULT_M_COST_KIB,
        DEFAULT_T_COST,
        DEFAULT_P_COST,
        None,
    )
    .map_err(|e| anyhow::anyhow!("Invalid Argon2 parameters: {e}"))
}

fn argon2() -> anyhow::Result<Argon2<'static>> {
    Ok(Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        default_params()?,
    ))
}

/// Hash a plaintext password and return a PHC-encoded Argon2id hash string.
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let argon2 = argon2()?;

    // Salt must be generated from a CSPRNG.
    // On wasm32 (Workers), this relies on `getrandom`'s JS bindings.
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Failed to hash password: {e}"))?
        .to_string();

    Ok(hash)
}

/// Verify a plaintext password against a PHC-encoded Argon2 hash.
///
/// Returns:
/// - Ok(true)  if password matches
/// - Ok(false) if password does not match
/// - Err(_)    if the stored hash is malformed or an unexpected error occurs
pub fn verify_password(password: &str, password_hash: &str) -> anyhow::Result<bool> {
    let parsed = PasswordHash::new(password_hash)
        .map_err(|e| anyhow::anyhow!("Invalid password hash format: {e}"))?;
    let argon2 = argon2()?;

    match argon2.verify_password(password.as_bytes(), &parsed) {
        Ok(_) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(anyhow::anyhow!("Failed to verify password: {e}")),
    }
}
