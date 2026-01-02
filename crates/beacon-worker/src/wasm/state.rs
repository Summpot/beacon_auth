use std::sync::OnceLock;

use beacon_core::crypto;
use url::Url;
use worker::{Env, Error, Result};

use super::env::env_string;

#[derive(Clone)]
pub struct JwtState {
    pub issuer: String,
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

fn init_jwt_state(env: &Env) -> Result<JwtState> {
    let issuer = env_string(env, "BASE_URL").unwrap_or_else(|| "https://beaconauth.pages.dev".to_string());
    let kid = env_string(env, "JWT_KID").unwrap_or_else(|| "beacon-auth-key-1".to_string());

    let jwt_private_key_der_b64 = env_string(env, "JWT_PRIVATE_KEY_DER_B64");
    let (encoding_key, decoding_key, jwks_json) = if let Some(b64) = jwt_private_key_der_b64 {
        let der = crypto::decode_pkcs8_der_b64(&b64).map_err(|e| Error::RustError(e.to_string()))?;
        crypto::ecdsa_keypair_from_pkcs8_der(&der, &kid).map_err(|e| Error::RustError(e.to_string()))?
    } else {
        crypto::generate_ecdsa_keypair(&kid).map_err(|e| Error::RustError(e.to_string()))?
    };

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
        kid,
        encoding_key,
        decoding_key,
        jwks_json,
        access_token_expiration,
        refresh_token_expiration,
        jwt_expiration,
    })
}

pub fn get_jwt_state(env: &Env) -> Result<&'static JwtState> {
    if let Some(state) = JWT_STATE.get() {
        return Ok(state);
    }

    // `OnceLock::get_or_try_init` is still unstable on some toolchains/targets.
    // Keep initialization race-safe: if another request initialized it first,
    // we just read the already-set value.
    let state = init_jwt_state(env)?;
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
