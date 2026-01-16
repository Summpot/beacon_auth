use std::sync::OnceLock;

use url::Url;
use worker::{Env, Error, Result};

use super::{db::{d1, db_get_or_create_jwks}, env::env_string};

#[derive(Clone)]
pub struct JwtState {
    pub issuer: String,
    /// JWKS URL to advertise in the JWT header `jku`.
    pub jwks_url: String,
    /// Allowed host patterns for trusting token header `jku` (SSRF protection).
    ///
    /// Patterns are comma/space-separated. Supported:
    /// - `example.com`
    /// - `*.example.com` (matches both `example.com` and any subdomain)
    pub jku_allowed_host_patterns: Vec<String>,
    pub kid: String,
    pub encoding_key: jsonwebtoken::EncodingKey,
    pub decoding_key: jsonwebtoken::DecodingKey,
    pub jwks_json: String,

    pub access_token_expiration: i64,
    pub refresh_token_expiration: i64,
    pub jwt_expiration: i64,
}

static JWT_STATE: OnceLock<JwtState> = OnceLock::new();

static PASSKEY_RP: OnceLock<beacon_passkey::RpConfig> = OnceLock::new();

async fn init_jwt_state(env: &Env) -> Result<JwtState> {
    let issuer = env_string(env, "BASE_URL").unwrap_or_else(|| "https://beaconauth.pages.dev".to_string());
    let kid = env_string(env, "JWT_KID").unwrap_or_else(|| "beacon-auth-key-1".to_string());

    // BeaconAuth is JWKS-first: this worker serves its public key at `/.well-known/jwks.json` and
    // advertises that URL via the JWT header `jku`.
    //
    // Use libsql to persist the ES256 keypair so all worker instances share the same JWKS.
    let db = d1(env).await?;
    let (encoding_key, decoding_key, jwks_json) = db_get_or_create_jwks(&db, &kid).await?;

    let jwks_url = env_string(env, "JWKS_URL").unwrap_or_else(|| {
        format!(
            "{}/.well-known/jwks.json",
            issuer.trim_end_matches('/')
        )
    });

    let jku_allowed_host_patterns = env_string(env, "JKU_ALLOWED_HOST_PATTERNS")
        .map(|raw| {
            raw.split(|c: char| c == ',' || c.is_whitespace())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| {
            // Default to trusting only our own configured JWKS host.
            // This keeps JKU enabled for same-origin tokens while mitigating SSRF.
            let host = Url::parse(&jwks_url)
                .ok()
                .and_then(|u| u.host_str().map(|h| h.to_string()));
            host.into_iter().collect()
        });

    let access_token_expiration = env_string(env, "ACCESS_TOKEN_EXPIRATION")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(900);

    let refresh_token_expiration = env_string(env, "REFRESH_TOKEN_EXPIRATION")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(2_592_000);

    let jwt_expiration = env_string(env, "JWT_EXPIRATION")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(3600);

    Ok(JwtState {
        issuer,
        jwks_url,
        jku_allowed_host_patterns,
        kid,
        encoding_key,
        decoding_key,
        jwks_json,
        access_token_expiration,
        refresh_token_expiration,
        jwt_expiration,
    })
}

pub async fn get_jwt_state(env: &Env) -> Result<&'static JwtState> {
    if let Some(state) = JWT_STATE.get() {
        return Ok(state);
    }

    // `OnceLock::get_or_try_init` is still unstable on some toolchains/targets.
    // Keep initialization race-safe: if another request initialized it first,
    // we just read the already-set value.
    let state = init_jwt_state(env).await?;
    let _ = JWT_STATE.set(state);
    Ok(JWT_STATE
        .get()
        .expect("JWT_STATE must be initialized after set()"))
}

fn init_passkey_rp(env: &Env) -> Result<beacon_passkey::RpConfig> {
    let base_url = env_string(env, "BASE_URL").unwrap_or_else(|| "https://beaconauth.pages.dev".to_string());
    let rp_origin = Url::parse(&base_url)
        .map_err(|e| Error::RustError(format!("Invalid BASE_URL '{base_url}': {e}")))?;

    let rp_id = rp_origin
        .host_str()
        .ok_or_else(|| Error::RustError("BASE_URL must include a host".to_string()))?
        .to_string();

    Ok(beacon_passkey::RpConfig::new(rp_id, rp_origin, "BeaconAuth"))
}

pub fn get_passkey_rp(env: &Env) -> Result<&'static beacon_passkey::RpConfig> {
    if let Some(rp) = PASSKEY_RP.get() {
        return Ok(rp);
    }

    let rp = init_passkey_rp(env)?;
    let _ = PASSKEY_RP.set(rp);
    Ok(PASSKEY_RP
        .get()
        .expect("PASSKEY_RP must be initialized after set()"))
}
