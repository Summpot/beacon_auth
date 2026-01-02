use std::sync::OnceLock;

use beacon_core::crypto;
use base64::{engine::general_purpose::STANDARD, Engine};
use url::Url;
use worker::{Env, Error, Result};

use super::env::env_string;
use super::kv::{kv, kv_get_string, kv_put_string};

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

const JWT_PKCS8_DER_B64_KV_KEY_PREFIX: &str = "jwt:pkcs8_der_b64:";

async fn load_or_init_jwt_pkcs8_der_b64(env: &Env, kid: &str) -> Result<String> {
    let kv = kv(env)?;
    let key = format!("{JWT_PKCS8_DER_B64_KV_KEY_PREFIX}{kid}");

    if let Some(existing) = kv_get_string(&kv, &key).await? {
        return Ok(existing);
    }

    // No key persisted yet. Generate a new PKCS#8 private key, persist it, and then read back.
    // Reading back avoids using a locally-generated key in case multiple instances race during
    // initial deployment.
    let der = crypto::generate_ecdsa_pkcs8_der().map_err(|e| Error::RustError(e.to_string()))?;
    let generated_b64 = STANDARD.encode(der);
    kv_put_string(&kv, &key, &generated_b64).await?;

    Ok(kv_get_string(&kv, &key).await?.unwrap_or(generated_b64))
}

async fn init_jwt_state(env: &Env) -> Result<JwtState> {
    let issuer = env_string(env, "BASE_URL").unwrap_or_else(|| "https://beaconauth.pages.dev".to_string());
    let kid = env_string(env, "JWT_KID").unwrap_or_else(|| "beacon-auth-key-1".to_string());

    // BeaconAuth is JWKS-first: the worker MUST serve a stable JWKS, otherwise signatures will be
    // invalid when requests hit different isolates.
    //
    // We persist the ES256 PKCS#8 private key in Workers KV so all instances share the same key.
    let key_b64 = load_or_init_jwt_pkcs8_der_b64(env, &kid).await?;
    let der = crypto::decode_pkcs8_der_b64(&key_b64).map_err(|e| Error::RustError(e.to_string()))?;
    let (encoding_key, decoding_key, jwks_json) =
        crypto::ecdsa_keypair_from_pkcs8_der(&der, &kid).map_err(|e| Error::RustError(e.to_string()))?;

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
