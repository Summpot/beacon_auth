use std::sync::OnceLock;

use beacon_core::{crypto, models, oauth};
use beacon_passkey::{
    extract_challenge_from_client_data_b64url, AuthenticationState, AuthResult,
    CreationChallengeResponse, PublicKeyCredential as PasskeyPublicKeyCredential,
    RegisterPublicKeyCredential, RegistrationState, RequestChallengeResponse, RpConfig,
    StoredPasskey,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use chrono::TimeZone;
use jsonwebtoken::{encode, Header};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;
use wasm_bindgen::JsValue;
use worker::*;

#[derive(Clone)]
struct JwtState {
    issuer: String,
    kid: String,
    encoding_key: jsonwebtoken::EncodingKey,
    decoding_key: jsonwebtoken::DecodingKey,
    jwks_json: String,

    access_token_expiration: i64,
    refresh_token_expiration: i64,
    jwt_expiration: i64,
}

static JWT_STATE: OnceLock<JwtState> = OnceLock::new();

static PASSKEY_RP: OnceLock<RpConfig> = OnceLock::new();

fn env_string(env: &Env, key: &str) -> Option<String> {
    env.var(key).ok().map(|v| v.to_string()).filter(|s| !s.is_empty())
}

fn init_jwt_state(env: &Env) -> Result<JwtState> {
    let issuer = env_string(env, "BASE_URL").unwrap_or_else(|| "http://localhost:8080".to_string());
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

fn get_jwt_state(env: &Env) -> Result<&'static JwtState> {
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

fn init_passkey_rp(env: &Env) -> Result<RpConfig> {
    let base_url = env_string(env, "BASE_URL").unwrap_or_else(|| "http://localhost:8080".to_string());
    let rp_origin = Url::parse(&base_url)
        .map_err(|e| Error::RustError(format!("Invalid BASE_URL '{base_url}': {e}")))?;

    let rp_id = rp_origin
        .host_str()
        .ok_or_else(|| Error::RustError("BASE_URL must include a host".to_string()))?
        .to_string();

    Ok(RpConfig::new(rp_id, rp_origin, "BeaconAuth"))
}

fn get_passkey_rp(env: &Env) -> Result<&'static RpConfig> {
    if let Some(rp) = PASSKEY_RP.get() {
        return Ok(rp);
    }

    let rp = init_passkey_rp(env)?;
    let _ = PASSKEY_RP.set(rp);
    Ok(PASSKEY_RP
        .get()
        .expect("PASSKEY_RP must be initialized after set()"))
}

fn json_with_cors(req: &Request, mut resp: Response) -> Result<Response> {
    let origin = req.headers().get("Origin")?.unwrap_or_else(|| "*".to_string());

    resp.headers_mut().set("Access-Control-Allow-Origin", &origin)?;
    resp.headers_mut().set("Access-Control-Allow-Credentials", "true")?;
    resp.headers_mut().set("Access-Control-Allow-Headers", "Content-Type, Authorization")?;
    resp.headers_mut().set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")?;
    Ok(resp)
}

fn get_cookie(req: &Request, name: &str) -> Result<Option<String>> {
    let Some(header) = req.headers().get("Cookie")? else {
        return Ok(None);
    };

    for part in header.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == name {
                return Ok(Some(v.trim().to_string()));
            }
        }
    }

    Ok(None)
}

fn append_set_cookie(headers: &mut Headers, value: &str) -> Result<()> {
    headers.append("Set-Cookie", value)
}

fn cookie_kv(name: &str, value: &str, max_age_seconds: i64) -> String {
    // Keep settings aligned with the Actix server: HttpOnly + SameSite=Strict + Path=/.
    // (We intentionally do not force Secure here because some dev flows use http.)
    format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age_seconds}"
    )
}

fn clear_cookie(name: &str) -> String {
    format!("{name}=; Path=/; Max-Age=0")
}

fn sign_jwt<T: Serialize>(state: &JwtState, claims: &T) -> Result<String> {
    let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(state.kid.clone());
    encode(&header, claims, &state.encoding_key).map_err(|e| Error::RustError(e.to_string()))
}

fn error_response(req: &Request, status: u16, error: &str, message: impl Into<String>) -> Result<Response> {
    let resp = Response::from_json(&models::ErrorResponse {
        error: error.to_string(),
        message: message.into(),
    })?
    .with_status(status);
    json_with_cors(req, resp)
}

fn internal_error_response(req: &Request, context: &str, err: &dyn std::fmt::Display) -> Result<Response> {
    // Log detailed server-side context for diagnostics.
    // Client receives a stable, non-sensitive message.
    console_log!("{context}: {err}");
    error_response(req, 500, "internal_error", context)
}

fn verify_access_token(state: &JwtState, token: &str) -> std::result::Result<i32, String> {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_issuer(&[&state.issuer]);
    validation.set_audience(&["beaconauth-web"]);
    validation.validate_exp = true;

    let token_data = jsonwebtoken::decode::<models::SessionClaims>(
        token,
        &state.decoding_key,
        &validation,
    )
    .map_err(|e| format!("Invalid access token: {e:?}"))?;

    if token_data.claims.token_type != "access" {
        return Err("Invalid token type".to_string());
    }

    token_data
        .claims
        .sub
        .parse::<i32>()
        .map_err(|_| "Invalid user ID in token".to_string())
}

fn now_ts() -> i64 {
    Utc::now().timestamp()
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    format!("{:x}", hasher.finalize())
}

fn new_refresh_token() -> String {
    let token_bytes = rand::random::<[u8; 32]>();
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, token_bytes)
}

fn new_family_id() -> String {
    // Token family IDs only need to be unique and unguessable.
    let token_bytes = rand::random::<[u8; 16]>();
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, token_bytes)
}

const PASSKEY_STATE_TTL_SECS: u64 = 5 * 60;

fn passkey_reg_state_key(user_id: i64) -> String {
    format!("passkey:reg:{user_id}")
}

fn passkey_auth_state_key(challenge_b64: &str) -> String {
    format!("passkey:auth:{challenge_b64}")
}

fn ts_to_rfc3339(ts: i64) -> String {
    Utc.timestamp_opt(ts, 0)
        .single()
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| ts.to_string())
}

fn d1_number(value: i64) -> JsValue {
    // D1 currently rejects JavaScript BigInt parameters, so always pass numeric values.
    // The `worker` D1 binding expects `JsValue` parameters.
    JsValue::from_f64(value as f64)
}

fn kv(env: &Env) -> Result<KvStore> {
    env.kv("KV")
}

async fn kv_put_json<T: Serialize>(kv: &KvStore, key: &str, value: &T, ttl_secs: u64) -> Result<()> {
    let json = serde_json::to_string(value).map_err(|e| Error::RustError(e.to_string()))?;
    kv.put(key, json)
        .map_err(|e| Error::RustError(e.to_string()))?
        .expiration_ttl(ttl_secs)
        .execute()
        .await
        .map_err(|e| Error::RustError(e.to_string()))?;
    Ok(())
}

async fn kv_get_json<T: DeserializeOwned>(kv: &KvStore, key: &str) -> Result<Option<T>> {
    let value = kv
        .get(key)
        .text()
        .await
        .map_err(|e| Error::RustError(e.to_string()))?;

    let Some(value) = value else {
        return Ok(None);
    };

    let parsed = serde_json::from_str(&value).map_err(|e| Error::RustError(e.to_string()))?;
    Ok(Some(parsed))
}

async fn kv_delete(kv: &KvStore, key: &str) -> Result<()> {
    kv.delete(key)
        .await
        .map_err(|e| Error::RustError(e.to_string()))?;
    Ok(())
}

#[derive(Deserialize)]
struct UserRow {
    id: i64,
    username: String,
    password_hash: String,
}

#[derive(Deserialize)]
struct RefreshTokenRow {
    id: i64,
    user_id: i64,
    family_id: String,
    expires_at: i64,
    revoked: i64,
}

#[derive(Deserialize, Clone)]
struct PasskeyDbRow {
    id: i64,
    user_id: i64,
    credential_id: String,
    credential_data: String,
    name: String,
    last_used_at: Option<i64>,
    created_at: i64,
}

#[derive(Deserialize)]
struct PasskeyRegisterStartRequest {
    name: String,
}

#[derive(Serialize)]
struct PasskeyRegisterStartResponse {
    creation_options: CreationChallengeResponse,
}

#[derive(Deserialize)]
struct PasskeyRegisterFinishRequest {
    credential: RegisterPublicKeyCredential,
    name: Option<String>,
}

#[derive(Serialize)]
struct PasskeyAuthStartResponse {
    request_options: RequestChallengeResponse,
}

#[derive(Deserialize)]
struct PasskeyAuthFinishRequest {
    credential: PasskeyPublicKeyCredential,
}

#[derive(Serialize)]
struct PasskeyInfo {
    id: i64,
    name: String,
    created_at: String,
    last_used_at: Option<String>,
}

#[derive(Serialize)]
struct PasskeyList {
    passkeys: Vec<PasskeyInfo>,
}

#[derive(Deserialize)]
struct PasskeyDeleteRequest {
    id: i64,
}

async fn d1(env: &Env) -> Result<D1Database> {
    env.d1("DB")
}

async fn d1_user_by_username(db: &D1Database, username: &str) -> Result<Option<UserRow>> {
    db.prepare("SELECT id, username, password_hash FROM users WHERE username = ?1")
        .bind(&[username.into()])?
        .first::<UserRow>(None)
        .await
}

async fn d1_user_by_id(db: &D1Database, id: i64) -> Result<Option<UserRow>> {
    db.prepare("SELECT id, username, password_hash FROM users WHERE id = ?1")
    .bind(&[d1_number(id)])?
        .first::<UserRow>(None)
        .await
}

async fn d1_passkeys_by_user_id(db: &D1Database, user_id: i64) -> Result<Vec<PasskeyDbRow>> {
    let result = db.prepare(
        "SELECT id, user_id, credential_id, credential_data, name, last_used_at, created_at FROM passkeys WHERE user_id = ?1 ORDER BY created_at DESC",
    )
    .bind(&[d1_number(user_id)])?
    .all()
    .await?;

    result.results::<PasskeyDbRow>()
}

async fn d1_passkeys_all(db: &D1Database) -> Result<Vec<PasskeyDbRow>> {
    let result = db.prepare(
        "SELECT id, user_id, credential_id, credential_data, name, last_used_at, created_at FROM passkeys ORDER BY created_at DESC",
    )
    .all()
    .await?;

    result.results::<PasskeyDbRow>()
}

async fn d1_passkey_by_id(db: &D1Database, id: i64) -> Result<Option<PasskeyDbRow>> {
    db.prepare(
        "SELECT id, user_id, credential_id, credential_data, name, last_used_at, created_at FROM passkeys WHERE id = ?1",
    )
    .bind(&[d1_number(id)])?
    .first::<PasskeyDbRow>(None)
    .await
}

async fn d1_passkey_by_credential_id(db: &D1Database, credential_id: &str) -> Result<Option<PasskeyDbRow>> {
    db.prepare(
        "SELECT id, user_id, credential_id, credential_data, name, last_used_at, created_at FROM passkeys WHERE credential_id = ?1",
    )
    .bind(&[credential_id.into()])?
    .first::<PasskeyDbRow>(None)
    .await
}

async fn d1_insert_passkey(
    db: &D1Database,
    user_id: i64,
    credential_id: &str,
    credential_data: &str,
    name: &str,
) -> Result<i64> {
    let ts = now_ts();
    db.prepare(
        "INSERT INTO passkeys (user_id, credential_id, credential_data, name, last_used_at, created_at) VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
    )
    .bind(&[
        d1_number(user_id),
        credential_id.into(),
        credential_data.into(),
        name.into(),
        d1_number(ts),
    ])?
    .run()
    .await?;

    let Some(row) = d1_passkey_by_credential_id(db, credential_id).await? else {
        return Err(Error::RustError("Inserted passkey could not be reloaded".to_string()));
    };

    Ok(row.id)
}

async fn d1_update_passkey_usage(db: &D1Database, id: i64, credential_data: &str, last_used_at: i64) -> Result<()> {
    db.prepare("UPDATE passkeys SET credential_data = ?1, last_used_at = ?2 WHERE id = ?3")
        .bind(&[
            credential_data.into(),
            d1_number(last_used_at),
            d1_number(id),
        ])?
        .run()
        .await?;
    Ok(())
}

async fn d1_delete_passkey_by_id(db: &D1Database, id: i64) -> Result<()> {
    db.prepare("DELETE FROM passkeys WHERE id = ?1")
        .bind(&[d1_number(id)])?
        .run()
        .await?;
    Ok(())
}

async fn d1_insert_user(db: &D1Database, username: &str, password_hash: &str) -> Result<i64> {
    let ts = now_ts();
    // NOTE: D1's `last_row_id` metadata is not always available/reliable across environments.
    // Insert and then fetch the created row by unique username.
    db
        .prepare(
            "INSERT INTO users (username, password_hash, created_at, updated_at) VALUES (?1, ?2, ?3, ?3)",
        )
        .bind(&[
            username.into(),
            password_hash.into(),
            d1_number(ts),
        ])?
        .run()
        .await?;

    let Some(user) = d1_user_by_username(db, username).await? else {
        return Err(Error::RustError("Inserted user could not be reloaded".to_string()));
    };

    Ok(user.id)
}

async fn d1_update_user_password(db: &D1Database, user_id: i64, new_hash: &str) -> Result<()> {
    let ts = now_ts();
    db.prepare("UPDATE users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(&[
            new_hash.into(),
            d1_number(ts),
            d1_number(user_id),
        ])?
        .run()
        .await?;
    Ok(())
}

async fn d1_insert_refresh_token(
    db: &D1Database,
    user_id: i64,
    token_hash: &str,
    family_id: &str,
    expires_at: i64,
) -> Result<()> {
    let ts = now_ts();
    db.prepare(
        "INSERT INTO refresh_tokens (user_id, token_hash, family_id, expires_at, revoked, created_at) VALUES (?1, ?2, ?3, ?4, 0, ?5)",
    )
    .bind(&[
        d1_number(user_id),
        token_hash.into(),
        family_id.into(),
        d1_number(expires_at),
        d1_number(ts),
    ])?
    .run()
    .await?;
    Ok(())
}

async fn d1_refresh_token_by_hash(db: &D1Database, token_hash: &str) -> Result<Option<RefreshTokenRow>> {
    db.prepare(
        "SELECT id, user_id, family_id, expires_at, revoked FROM refresh_tokens WHERE token_hash = ?1",
    )
    .bind(&[token_hash.into()])?
    .first::<RefreshTokenRow>(None)
    .await
}

async fn d1_revoke_refresh_token_by_id(db: &D1Database, id: i64) -> Result<()> {
    db.prepare("UPDATE refresh_tokens SET revoked = 1 WHERE id = ?1")
        .bind(&[d1_number(id)])?
        .run()
        .await?;
    Ok(())
}

async fn d1_revoke_all_refresh_tokens_for_user(db: &D1Database, user_id: i64) -> Result<()> {
    db.prepare("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?1")
        .bind(&[d1_number(user_id)])?
        .run()
        .await?;
    Ok(())
}

async fn handle_get_config(req: &Request, env: &Env) -> Result<Response> {
    // We can infer OAuth config from env variables, even if Workers OAuth routes are not enabled yet.
    let github_ok = env_string(env, "GITHUB_CLIENT_ID").is_some() && env_string(env, "GITHUB_CLIENT_SECRET").is_some();
    let google_ok = env_string(env, "GOOGLE_CLIENT_ID").is_some() && env_string(env, "GOOGLE_CLIENT_SECRET").is_some();

    let body = models::ConfigResponse {
        database_auth: true,
        github_oauth: github_ok,
        google_oauth: google_ok,
    };

    let resp = Response::from_json(&body)?;
    json_with_cors(req, resp)
}

async fn handle_get_jwks(req: &Request, env: &Env) -> Result<Response> {
    let jwt = get_jwt_state(env)?;
    let mut resp = Response::ok(jwt.jwks_json.clone())?;
    resp.headers_mut().set("Content-Type", "application/json")?;
    json_with_cors(req, resp)
}

fn query_param(url: &Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find_map(|(k, v)| if k == key { Some(v.to_string()) } else { None })
}

fn truncate_for_log(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }

    // `str` slicing must happen on UTF-8 boundaries.
    let mut end = max_len.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }

    let mut out = s[..end].to_string();
    out.push_str("…(truncated)");
    out
}

fn redact_oauth_token_body_for_log(body: &str) -> String {
    // Best-effort redaction. We generally only log token bodies on error paths,
    // but never risk leaking an access token.
    if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(body) {
        let mut redacted = false;
        if v.get("access_token").is_some() {
            v["access_token"] = json!("[REDACTED]");
            redacted = true;
        }
        if v.get("refresh_token").is_some() {
            v["refresh_token"] = json!("[REDACTED]");
            redacted = true;
        }
        let rendered = v.to_string();
        return truncate_for_log(&rendered, if redacted { 2048 } else { 4096 });
    }

    // GitHub may return urlencoded bodies in some circumstances.
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    if !pairs.is_empty() {
        let mut ser = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in pairs {
            if k == "access_token" || k == "refresh_token" {
                ser.append_pair(&k, "[REDACTED]");
            } else {
                ser.append_pair(&k, &v);
            }
        }
        return truncate_for_log(&ser.finish(), 4096);
    }

    if body.contains("access_token") || body.contains("refresh_token") {
        return "<redacted token response>".to_string();
    }

    truncate_for_log(body, 4096)
}

async fn exchange_github_code(
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<(String, String)> {
    let form_body = format!(
        "client_id={}&client_secret={}&code={}&redirect_uri={}",
        urlencoding::encode(client_id),
        urlencoding::encode(client_secret),
        urlencoding::encode(code),
        urlencoding::encode(redirect_uri)
    );

    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(form_body.into()));
    let headers = Headers::new();
    headers.set("Accept", "application/json")?;
    headers.set("Content-Type", "application/x-www-form-urlencoded")?;
    init.with_headers(headers);

    let token_req = Request::new_with_init("https://github.com/login/oauth/access_token", &init)?;
    let mut token_resp = Fetch::Request(token_req).send().await?;

    let status = token_resp.status_code();
    let token_body = token_resp.text().await?;

    if status >= 400 {
        let safe = redact_oauth_token_body_for_log(&token_body);
        return Err(Error::RustError(format!(
            "GitHub token exchange failed ({status}): {safe}"
        )));
    }

    // GitHub sometimes returns HTTP 200 with an error payload.
    // We must inspect the body, not just the status code.
    let access_token = match oauth::parse_access_token_from_token_exchange_body(&token_body) {
        Ok(tok) => tok,
        Err(oauth::OAuthTokenParseError::ProviderError(e)) => {
            return Err(Error::RustError(format!(
                "GitHub token exchange returned error '{}': {}{} (check GITHUB_CLIENT_ID/GITHUB_CLIENT_SECRET and callback URL: {redirect_uri})",
                e.error,
                e.error_description.unwrap_or_default(),
                e.error_uri.map(|u| format!(" ({u})")).unwrap_or_default(),
            )));
        }
        Err(other) => {
            let safe = redact_oauth_token_body_for_log(&token_body);
            return Err(Error::RustError(format!(
                "GitHub token exchange failed (status {status}): {other}. Response: {safe} (check callback URL: {redirect_uri})"
            )));
        }
    };

    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    let headers = Headers::new();
    headers.set("Accept", "application/json")?;
    headers.set("Authorization", &format!("Bearer {access_token}"))?;
    headers.set("User-Agent", "BeaconAuth")?;
    init.with_headers(headers);

    let user_req = Request::new_with_init("https://api.github.com/user", &init)?;
    let mut user_resp = Fetch::Request(user_req).send().await?;

    if user_resp.status_code() >= 400 {
        let status = user_resp.status_code();
        let body = user_resp.text().await?;
        return Err(Error::RustError(format!(
            "GitHub user fetch failed ({status}): {body}"
        )));
    }

    let user_json: serde_json::Value = user_resp.json().await?;
    let user_id = user_json
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| Error::RustError("No user id in GitHub response".to_string()))?
        .to_string();

    let username_raw = user_json
        .get("login")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::RustError("No login in GitHub response".to_string()))?;

    Ok((user_id, format!("gh_{username_raw}")))
}

async fn exchange_google_code(
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<(String, String)> {
    let form_body = format!(
        "client_id={}&client_secret={}&code={}&grant_type=authorization_code&redirect_uri={}",
        urlencoding::encode(client_id),
        urlencoding::encode(client_secret),
        urlencoding::encode(code),
        urlencoding::encode(redirect_uri)
    );

    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(form_body.into()));
    let headers = Headers::new();
    headers.set("Accept", "application/json")?;
    headers.set("Content-Type", "application/x-www-form-urlencoded")?;
    init.with_headers(headers);

    let token_req = Request::new_with_init("https://oauth2.googleapis.com/token", &init)?;
    let mut token_resp = Fetch::Request(token_req).send().await?;

    if token_resp.status_code() >= 400 {
        let status = token_resp.status_code();
        let body = token_resp.text().await?;
        return Err(Error::RustError(format!(
            "Google token exchange failed ({status}): {body}"
        )));
    }

    let token_json: serde_json::Value = token_resp.json().await?;
    let access_token = token_json
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::RustError("No access_token in Google response".to_string()))?;

    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    let headers = Headers::new();
    headers.set("Accept", "application/json")?;
    headers.set("Authorization", &format!("Bearer {access_token}"))?;
    init.with_headers(headers);

    let user_req = Request::new_with_init("https://www.googleapis.com/oauth2/v2/userinfo", &init)?;
    let mut user_resp = Fetch::Request(user_req).send().await?;

    if user_resp.status_code() >= 400 {
        let status = user_resp.status_code();
        let body = user_resp.text().await?;
        return Err(Error::RustError(format!(
            "Google user fetch failed ({status}): {body}"
        )));
    }

    let user_json: serde_json::Value = user_resp.json().await?;
    let user_id = user_json
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::RustError("No user id in Google response".to_string()))?
        .to_string();

    let email = user_json
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::RustError("No email in Google response".to_string()))?;

    let username_raw = email.split('@').next().unwrap_or(email);
    Ok((user_id, format!("gg_{username_raw}")))
}

async fn handle_oauth_start(mut req: Request, env: &Env) -> Result<Response> {
    let payload: models::OAuthStartPayload = match req.json().await {
        Ok(p) => p,
        Err(e) => {
            console_log!("Invalid JSON in /v1/oauth/start: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };

    let jwt = get_jwt_state(env)?;

    // Stateless OAuth state: encode as a signed JWT so callbacks work across instances.
    let now = Utc::now();
    let exp = now + chrono::Duration::minutes(10);
    let state_id = Uuid::new_v4().to_string();

    let claims = models::OAuthStateClaims {
        iss: jwt.issuer.clone(),
        sub: state_id,
        aud: "beaconauth-oauth".to_string(),
        exp: exp.timestamp(),
        iat: now.timestamp(),
        token_type: "oauth_state".to_string(),
        provider: payload.provider.clone(),
        challenge: if payload.challenge.is_empty() {
            None
        } else {
            Some(payload.challenge.clone())
        },
        redirect_port: if payload.redirect_port == 0 {
            None
        } else {
            Some(payload.redirect_port)
        },
    };

    let state_token = match sign_jwt(jwt, &claims) {
        Ok(t) => t,
        Err(e) => return internal_error_response(&req, "Failed to encode OAuth state JWT", &e),
    };

    let redirect_base = jwt.issuer.trim_end_matches('/');
    let callback_url = format!("{redirect_base}/api/v1/oauth/callback");

    let authorization_url = match payload.provider.as_str() {
        "github" => {
            let github_ok = env_string(env, "GITHUB_CLIENT_ID").is_some() && env_string(env, "GITHUB_CLIENT_SECRET").is_some();
            if !github_ok {
                return error_response(&req, 503, "oauth_not_configured", "GitHub OAuth is not configured");
            }
            let client_id = env_string(env, "GITHUB_CLIENT_ID").expect("checked above");
            format!(
                "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=read:user%20user:email&state={}",
                urlencoding::encode(&client_id),
                urlencoding::encode(&callback_url),
                urlencoding::encode(&state_token)
            )
        }
        "google" => {
            let google_ok = env_string(env, "GOOGLE_CLIENT_ID").is_some() && env_string(env, "GOOGLE_CLIENT_SECRET").is_some();
            if !google_ok {
                return error_response(&req, 503, "oauth_not_configured", "Google OAuth is not configured");
            }
            let client_id = env_string(env, "GOOGLE_CLIENT_ID").expect("checked above");
            format!(
                "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}",
                urlencoding::encode(&client_id),
                urlencoding::encode(&callback_url),
                urlencoding::encode(&state_token)
            )
        }
        _ => {
            return error_response(&req, 400, "invalid_provider", "Unsupported OAuth provider");
        }
    };

    let resp = Response::from_json(&models::OAuthStartResponse { authorization_url })?;
    json_with_cors(&req, resp)
}

async fn handle_oauth_callback(req: &Request, env: &Env) -> Result<Response> {
    let url = req.url()?;
    let Some(code) = query_param(&url, "code") else {
        return error_response(req, 400, "missing_code", "Missing OAuth code");
    };
    let Some(state_token) = query_param(&url, "state") else {
        return error_response(req, 400, "missing_state", "Missing OAuth state");
    };

    let jwt = get_jwt_state(env)?;

    // Validate and decode stateless OAuth state
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_issuer(&[&jwt.issuer]);
    validation.set_audience(&["beaconauth-oauth"]);
    validation.validate_exp = true;

    let oauth_state = match jsonwebtoken::decode::<models::OAuthStateClaims>(
        &state_token,
        &jwt.decoding_key,
        &validation,
    ) {
        Ok(data) => data.claims,
        Err(e) => {
            console_log!("Invalid OAuth state token: {e:?}");
            return error_response(req, 400, "invalid_oauth_state", "Invalid or expired OAuth state");
        }
    };

    if oauth_state.token_type != "oauth_state" {
        return error_response(req, 400, "invalid_oauth_state", "Invalid OAuth state");
    }

    let (provider_user_id, username) = match oauth_state.provider.as_str() {
        "github" => {
            let Some(client_id) = env_string(env, "GITHUB_CLIENT_ID") else {
                return error_response(req, 503, "oauth_not_configured", "GitHub OAuth is not configured");
            };
            let Some(client_secret) = env_string(env, "GITHUB_CLIENT_SECRET") else {
                return error_response(req, 503, "oauth_not_configured", "GitHub OAuth is not configured");
            };
            let redirect_base = jwt.issuer.trim_end_matches('/');
            let callback_url = format!("{redirect_base}/api/v1/oauth/callback");
            match exchange_github_code(&client_id, &client_secret, &code, &callback_url).await {
                Ok(v) => v,
                Err(e) => return internal_error_response(req, "GitHub authentication failed", &e),
            }
        }
        "google" => {
            let Some(client_id) = env_string(env, "GOOGLE_CLIENT_ID") else {
                return error_response(req, 503, "oauth_not_configured", "Google OAuth is not configured");
            };
            let Some(client_secret) = env_string(env, "GOOGLE_CLIENT_SECRET") else {
                return error_response(req, 503, "oauth_not_configured", "Google OAuth is not configured");
            };

            let redirect_base = jwt.issuer.trim_end_matches('/');
            let callback_url = format!("{redirect_base}/api/v1/oauth/callback");
            match exchange_google_code(&client_id, &client_secret, &code, &callback_url).await {
                Ok(v) => v,
                Err(e) => return internal_error_response(req, "Google authentication failed", &e),
            }
        }
        _ => return error_response(req, 400, "invalid_provider", "Invalid provider"),
    };

    let db = match d1(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(req, "Failed to open database binding", &e),
    };

    let user = match d1_user_by_username(&db, &username).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            let password_hash = format!("oauth_{}_{}", oauth_state.provider, provider_user_id);
            match d1_insert_user(&db, &username, &password_hash).await {
                Ok(id) => match d1_user_by_id(&db, id).await {
                    Ok(Some(user)) => user,
                    Ok(None) => {
                        return internal_error_response(req, "Failed to create user", &"Inserted user could not be reloaded");
                    }
                    Err(e) => return internal_error_response(req, "Failed to reload user", &e),
                },
                Err(e) => {
                    // Handle a potential race on username creation (unique constraint) gracefully.
                    let msg = e.to_string();
                    if msg.to_ascii_lowercase().contains("unique") {
                        match d1_user_by_username(&db, &username).await {
                            Ok(Some(user)) => user,
                            Ok(None) => return internal_error_response(req, "Failed to create user", &e),
                            Err(e2) => return internal_error_response(req, "Failed to reload user", &e2),
                        }
                    } else {
                        return internal_error_response(req, "Failed to create user", &e);
                    }
                }
            }
        }
        Err(e) => return internal_error_response(req, "Failed to query user", &e),
    };

    // Issue session cookies
    let now = Utc::now();
    let access_exp = now + chrono::Duration::seconds(jwt.access_token_expiration);
    let access_claims = models::SessionClaims {
        iss: jwt.issuer.clone(),
        sub: (user.id as i32).to_string(),
        aud: "beaconauth-web".to_string(),
        exp: access_exp.timestamp(),
        token_type: "access".to_string(),
    };

    let access_token = match sign_jwt(jwt, &access_claims) {
        Ok(t) => t,
        Err(e) => return internal_error_response(req, "Failed to sign access token", &e),
    };

    let refresh_token = new_refresh_token();
    let token_hash = sha256_hex(&refresh_token);
    let family_id = new_family_id();
    let refresh_exp = now.timestamp() + jwt.refresh_token_expiration;

    if let Err(e) = d1_insert_refresh_token(&db, user.id, &token_hash, &family_id, refresh_exp).await {
        return internal_error_response(req, "Failed to persist refresh token", &e);
    }

    let mut resp = Response::empty()?.with_status(302);
    let headers = resp.headers_mut();
    headers.set("Location", "/oauth-complete")?;
    append_set_cookie(headers, &cookie_kv("access_token", &access_token, jwt.access_token_expiration))?;
    append_set_cookie(headers, &cookie_kv("refresh_token", &refresh_token, jwt.refresh_token_expiration))?;

    json_with_cors(req, resp)
}

async fn handle_register(mut req: Request, env: &Env) -> Result<Response> {
    let db = match d1(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open database binding", &e),
    };

    let payload: models::RegisterPayload = match req.json().await {
        Ok(p) => p,
        Err(e) => {
            console_log!("Invalid JSON in /v1/register: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };

    if payload.username.is_empty() || payload.username.len() > 50 {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "invalid_username".to_string(),
            message: "Username must be between 1 and 50 characters".to_string(),
        })?
        .with_status(400);
        return json_with_cors(&req, resp);
    }

    if payload.password.len() < 6 {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "invalid_password".to_string(),
            message: "Password must be at least 6 characters".to_string(),
        })?
        .with_status(400);
        return json_with_cors(&req, resp);
    }

    match d1_user_by_username(&db, &payload.username).await {
        Ok(Some(_)) => {
            return error_response(&req, 409, "username_taken", "Username already exists");
        }
        Ok(None) => {}
        Err(e) => return internal_error_response(&req, "Failed to check existing username", &e),
    };

    let password_hash = match bcrypt::hash(&payload.password, bcrypt::DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => return internal_error_response(&req, "Failed to hash password", &e),
    };

    let user_id = match d1_insert_user(&db, &payload.username, &password_hash).await {
        Ok(id) => id,
        Err(e) => {
            // Handle a potential race on username creation (unique constraint) gracefully.
            let msg = e.to_string();
            if msg.to_ascii_lowercase().contains("unique") {
                return error_response(&req, 409, "username_taken", "Username already exists");
            }
            return internal_error_response(&req, "Failed to create user", &e);
        }
    };

    if user_id <= 0 {
        return internal_error_response(
            &req,
            "Failed to create user (invalid inserted id)",
            &"insert returned non-positive id",
        );
    }

    let jwt = match get_jwt_state(env) {
        Ok(jwt) => jwt,
        Err(e) => return internal_error_response(&req, "Failed to initialize JWT state", &e),
    };
    let now = Utc::now();

    let access_exp = now + chrono::Duration::seconds(jwt.access_token_expiration);
    let access_claims = models::SessionClaims {
        iss: jwt.issuer.clone(),
        sub: (user_id as i32).to_string(),
        aud: "beaconauth-web".to_string(),
        exp: access_exp.timestamp(),
        token_type: "access".to_string(),
    };

    let access_token = match sign_jwt(jwt, &access_claims) {
        Ok(t) => t,
        Err(e) => return internal_error_response(&req, "Failed to sign access token", &e),
    };

    let refresh_token = new_refresh_token();
    let token_hash = sha256_hex(&refresh_token);
    let family_id = new_family_id();
    let refresh_exp = now.timestamp() + jwt.refresh_token_expiration;

    if let Err(e) = d1_insert_refresh_token(&db, user_id, &token_hash, &family_id, refresh_exp).await {
        return internal_error_response(&req, "Failed to persist refresh token", &e);
    }

    let mut resp = Response::from_json(&json!({ "success": true }))?;
    let headers = resp.headers_mut();
    append_set_cookie(headers, &cookie_kv("access_token", &access_token, jwt.access_token_expiration))?;
    append_set_cookie(headers, &cookie_kv("refresh_token", &refresh_token, jwt.refresh_token_expiration))?;

    json_with_cors(&req, resp)
}

async fn handle_login(mut req: Request, env: &Env) -> Result<Response> {
    let db = d1(env).await?;

    let payload: models::LoginPayload = req.json().await?;

    let Some(user) = d1_user_by_username(&db, &payload.username).await? else {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "unauthorized".to_string(),
            message: "Invalid username or password".to_string(),
        })?
        .with_status(401);
        return json_with_cors(&req, resp);
    };

    let password_valid = bcrypt::verify(&payload.password, &user.password_hash).unwrap_or(false);
    if !password_valid {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "unauthorized".to_string(),
            message: "Invalid username or password".to_string(),
        })?
        .with_status(401);
        return json_with_cors(&req, resp);
    }

    let jwt = get_jwt_state(env)?;
    let now = Utc::now();

    let access_exp = now + chrono::Duration::seconds(jwt.access_token_expiration);
    let access_claims = models::SessionClaims {
        iss: jwt.issuer.clone(),
        sub: (user.id as i32).to_string(),
        aud: "beaconauth-web".to_string(),
        exp: access_exp.timestamp(),
        token_type: "access".to_string(),
    };

    let access_token = sign_jwt(jwt, &access_claims)?;

    let refresh_token = new_refresh_token();
    let token_hash = sha256_hex(&refresh_token);
    let family_id = new_family_id();
    let refresh_exp = now.timestamp() + jwt.refresh_token_expiration;

    d1_insert_refresh_token(&db, user.id, &token_hash, &family_id, refresh_exp).await?;

    // The web UI only requires cookies to be set; the body is ignored.
    let mut resp = Response::from_json(&json!({ "success": true }))?;
    let headers = resp.headers_mut();
    append_set_cookie(headers, &cookie_kv("access_token", &access_token, jwt.access_token_expiration))?;
    append_set_cookie(headers, &cookie_kv("refresh_token", &refresh_token, jwt.refresh_token_expiration))?;

    json_with_cors(&req, resp)
}

async fn handle_refresh(req: &Request, env: &Env) -> Result<Response> {
    let db = d1(env).await?;
    let jwt = get_jwt_state(env)?;

    let Some(refresh_token) = get_cookie(req, "refresh_token")? else {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "missing_token".to_string(),
            message: "No refresh token provided".to_string(),
        })?
        .with_status(401);
        return json_with_cors(req, resp);
    };

    let token_hash = sha256_hex(&refresh_token);
    let Some(record) = d1_refresh_token_by_hash(&db, &token_hash).await? else {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "invalid_token".to_string(),
            message: "Invalid refresh token".to_string(),
        })?
        .with_status(401);
        return json_with_cors(req, resp);
    };

    if record.revoked != 0 {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "revoked_token".to_string(),
            message: "Refresh token has been revoked".to_string(),
        })?
        .with_status(401);
        return json_with_cors(req, resp);
    }

    if record.expires_at < now_ts() {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "expired_token".to_string(),
            message: "Refresh token has expired".to_string(),
        })?
        .with_status(401);
        return json_with_cors(req, resp);
    }

    // Revoke old refresh token (rotation)
    d1_revoke_refresh_token_by_id(&db, record.id).await?;

    // Issue new token pair with same family_id
    let now = Utc::now();
    let access_exp = now + chrono::Duration::seconds(jwt.access_token_expiration);
    let access_claims = models::SessionClaims {
        iss: jwt.issuer.clone(),
        sub: (record.user_id as i32).to_string(),
        aud: "beaconauth-web".to_string(),
        exp: access_exp.timestamp(),
        token_type: "access".to_string(),
    };

    let access_token = sign_jwt(jwt, &access_claims)?;

    let new_refresh_token = new_refresh_token();
    let new_hash = sha256_hex(&new_refresh_token);
    let refresh_exp = now.timestamp() + jwt.refresh_token_expiration;

    d1_insert_refresh_token(&db, record.user_id, &new_hash, &record.family_id, refresh_exp).await?;

    let mut resp = Response::from_json(&json!({ "success": true }))?;
    let headers = resp.headers_mut();
    append_set_cookie(headers, &cookie_kv("access_token", &access_token, jwt.access_token_expiration))?;
    append_set_cookie(headers, &cookie_kv("refresh_token", &new_refresh_token, jwt.refresh_token_expiration))?;

    json_with_cors(req, resp)
}

async fn handle_user_me(req: &Request, env: &Env) -> Result<Response> {
    let db = d1(env).await?;
    let jwt = get_jwt_state(env)?;

    let Some(access_token) = get_cookie(req, "access_token")? else {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "unauthorized".to_string(),
            message: "Not authenticated".to_string(),
        })?
        .with_status(401);
        return json_with_cors(req, resp);
    };

    let user_id = match verify_access_token(jwt, &access_token) {
        Ok(id) => id as i64,
        Err(e) => {
            let resp = Response::from_json(&models::ErrorResponse {
                error: "invalid_token".to_string(),
                message: e,
            })?
            .with_status(401);
            return json_with_cors(req, resp);
        }
    };

    let Some(user) = d1_user_by_id(&db, user_id).await? else {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "user_not_found".to_string(),
            message: "User not found".to_string(),
        })?
        .with_status(404);
        return json_with_cors(req, resp);
    };

    let resp = Response::from_json(&json!({ "id": user.id, "username": user.username }))?;
    json_with_cors(req, resp)
}

async fn handle_change_password(mut req: Request, env: &Env) -> Result<Response> {
    let db = d1(env).await?;
    let jwt = get_jwt_state(env)?;

    let Some(access_token) = get_cookie(&req, "access_token")? else {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "unauthorized".to_string(),
            message: "Not authenticated".to_string(),
        })?
        .with_status(401);
        return json_with_cors(&req, resp);
    };

    let user_id = match verify_access_token(jwt, &access_token) {
        Ok(id) => id as i64,
        Err(e) => {
            let resp = Response::from_json(&models::ErrorResponse {
                error: "invalid_token".to_string(),
                message: e,
            })?
            .with_status(401);
            return json_with_cors(&req, resp);
        }
    };

    let payload: models::ChangePasswordRequest = req.json().await?;

    if payload.new_password.len() < 6 {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "invalid_password".to_string(),
            message: "New password must be at least 6 characters".to_string(),
        })?
        .with_status(400);
        return json_with_cors(&req, resp);
    }

    let Some(user) = d1_user_by_id(&db, user_id).await? else {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "user_not_found".to_string(),
            message: "User not found".to_string(),
        })?
        .with_status(404);
        return json_with_cors(&req, resp);
    };

    let password_valid = bcrypt::verify(&payload.current_password, &user.password_hash).unwrap_or(false);
    if !password_valid {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "invalid_password".to_string(),
            message: "Current password is incorrect".to_string(),
        })?
        .with_status(401);
        return json_with_cors(&req, resp);
    }

    let new_hash = bcrypt::hash(&payload.new_password, bcrypt::DEFAULT_COST)
        .map_err(|e| Error::RustError(e.to_string()))?;

    d1_update_user_password(&db, user_id, &new_hash).await?;

    let resp = Response::from_json(&json!({ "success": true }))?;
    json_with_cors(&req, resp)
}

async fn handle_logout(req: &Request, env: &Env) -> Result<Response> {
    let db = d1(env).await?;
    let jwt = get_jwt_state(env)?;

    let Some(access_token) = get_cookie(req, "access_token")? else {
        let resp = Response::from_json(&json!({ "success": true }))?;
        return json_with_cors(req, resp);
    };

    let user_id = match verify_access_token(jwt, &access_token) {
        Ok(id) => id as i64,
        Err(_) => {
            let resp = Response::from_json(&json!({ "success": true }))?;
            return json_with_cors(req, resp);
        }
    };

    // Revoke all refresh tokens for the user.
    let _ = d1_revoke_all_refresh_tokens_for_user(&db, user_id).await;

    let mut resp = Response::from_json(&json!({ "success": true }))?;
    let headers = resp.headers_mut();
    append_set_cookie(headers, &clear_cookie("access_token"))?;
    append_set_cookie(headers, &clear_cookie("refresh_token"))?;

    json_with_cors(req, resp)
}

async fn handle_passkey_register_start(mut req: Request, env: &Env) -> Result<Response> {
    let db = d1(env).await?;
    let jwt = get_jwt_state(env)?;
    let rp = get_passkey_rp(env)?;
    let kv = match kv(env) {
        Ok(kv) => kv,
        Err(_) => {
            return error_response(
                &req,
                501,
                "not_configured",
                "KV binding is required for passkey endpoints",
            );
        }
    };

    let _body: PasskeyRegisterStartRequest = match req.json().await {
        Ok(b) => b,
        Err(e) => {
            console_log!("Invalid JSON in /v1/passkey/register/start: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };

    let Some(access_token) = get_cookie(&req, "access_token")? else {
        return error_response(&req, 401, "unauthorized", "Not authenticated");
    };

    let user_id = match verify_access_token(jwt, &access_token) {
        Ok(id) => id as i64,
        Err(e) => return error_response(&req, 401, "invalid_token", e),
    };

    let Some(user) = d1_user_by_id(&db, user_id).await? else {
        return error_response(&req, 404, "user_not_found", "User not found");
    };

    let existing_passkeys = d1_passkeys_by_user_id(&db, user_id).await?;
    let exclude_credentials: Vec<Vec<u8>> = existing_passkeys
        .iter()
        .filter_map(|pk| BASE64.decode(&pk.credential_id).ok())
        .collect();

    let user_uuid = Uuid::from_u128(user.id as u128);
    let (ccr, reg_state) = beacon_passkey::start_passkey_registration(
        rp,
        user_uuid.as_bytes(),
        &user.username,
        &user.username,
        if exclude_credentials.is_empty() {
            None
        } else {
            Some(exclude_credentials)
        },
    );

    kv_put_json(
        &kv,
        &passkey_reg_state_key(user_id),
        &reg_state,
        PASSKEY_STATE_TTL_SECS,
    )
    .await?;

    let resp = Response::from_json(&PasskeyRegisterStartResponse {
        creation_options: ccr,
    })?;
    json_with_cors(&req, resp)
}

async fn handle_passkey_register_finish(mut req: Request, env: &Env) -> Result<Response> {
    let db = d1(env).await?;
    let jwt = get_jwt_state(env)?;
    let rp = get_passkey_rp(env)?;
    let kv = match kv(env) {
        Ok(kv) => kv,
        Err(_) => {
            return error_response(
                &req,
                501,
                "not_configured",
                "KV binding is required for passkey endpoints",
            );
        }
    };

    let body: PasskeyRegisterFinishRequest = match req.json().await {
        Ok(b) => b,
        Err(e) => {
            console_log!("Invalid JSON in /v1/passkey/register/finish: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };

    let Some(access_token) = get_cookie(&req, "access_token")? else {
        return error_response(&req, 401, "unauthorized", "Not authenticated");
    };

    let user_id = match verify_access_token(jwt, &access_token) {
        Ok(id) => id as i64,
        Err(e) => return error_response(&req, 401, "invalid_token", e),
    };

    let state_key = passkey_reg_state_key(user_id);
    let reg_state: RegistrationState = match kv_get_json(&kv, &state_key).await? {
        Some(s) => s,
        None => return error_response(&req, 400, "no_registration", "No registration in progress"),
    };
    // Remove after retrieval to prevent replays.
    let _ = kv_delete(&kv, &state_key).await;

    let stored = beacon_passkey::finish_passkey_registration(rp, &body.credential, &reg_state)
        .map_err(|e| Error::RustError(format!("Passkey registration failed: {} ({})", e.message, e.code)))?;

    let credential_data = serde_json::to_string(&stored).map_err(|e| Error::RustError(e.to_string()))?;

    // Store credential_id in the DB as standard base64 (to match the rest of the codebase).
    let raw_id_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&body.credential.raw_id)
        .map_err(|_| Error::RustError("Invalid credential rawId".to_string()))?;
    let credential_id_b64 = BASE64.encode(&raw_id_bytes);
    let name = body.name.unwrap_or_else(|| "Passkey".to_string());

    let passkey_id = match d1_insert_passkey(&db, user_id, &credential_id_b64, &credential_data, &name).await {
        Ok(id) => id,
        Err(e) => {
            let msg = e.to_string();
            if msg.to_ascii_lowercase().contains("unique") {
                return error_response(&req, 409, "passkey_exists", "Passkey already exists");
            }
            return internal_error_response(&req, "Failed to persist passkey", &e);
        }
    };

    let resp = Response::from_json(&json!({
        "success": true,
        "passkey_id": passkey_id,
    }))?
    .with_status(201);
    json_with_cors(&req, resp)
}

async fn handle_passkey_auth_start(mut req: Request, env: &Env) -> Result<Response> {
    let db = d1(env).await?;
    let rp = get_passkey_rp(env)?;
    let kv = match kv(env) {
        Ok(kv) => kv,
        Err(_) => {
            return error_response(
                &req,
                501,
                "not_configured",
                "KV binding is required for passkey endpoints",
            );
        }
    };

    // Body is optional in the web UI; treat missing/invalid JSON as empty.
    let body: serde_json::Value = req.json().await.unwrap_or_else(|_| json!({}));
    let username = body.get("username").and_then(|v| v.as_str()).map(|s| s.to_string());

    let (allow_credential_ids, has_any_passkeys) = if let Some(username) = username {
        let Some(user) = d1_user_by_username(&db, &username).await? else {
            return error_response(&req, 404, "user_not_found", "User not found");
        };
        let passkeys = d1_passkeys_by_user_id(&db, user.id).await?;
        if passkeys.is_empty() {
            return error_response(&req, 404, "no_passkeys", "No passkeys found");
        }
        let ids = passkeys
            .into_iter()
            .filter_map(|pk| BASE64.decode(pk.credential_id).ok())
            .collect::<Vec<_>>();
        (Some(ids), true)
    } else {
        // Discoverable credentials: do not send allowCredentials.
        let passkeys = d1_passkeys_all(&db).await?;
        (None, !passkeys.is_empty())
    };

    if !has_any_passkeys {
        return error_response(&req, 404, "no_passkeys", "No passkeys found");
    }

    let (rcr, auth_state) = beacon_passkey::start_passkey_authentication(rp, allow_credential_ids);

    let challenge_str = rcr.public_key.challenge.clone();
    kv_put_json(
        &kv,
        &passkey_auth_state_key(&challenge_str),
        &auth_state,
        PASSKEY_STATE_TTL_SECS,
    )
    .await?;

    let resp = Response::from_json(&PasskeyAuthStartResponse { request_options: rcr })?;
    json_with_cors(&req, resp)
}

async fn handle_passkey_auth_finish(mut req: Request, env: &Env) -> Result<Response> {
    let db = d1(env).await?;
    let jwt = get_jwt_state(env)?;
    let rp = get_passkey_rp(env)?;
    let kv = match kv(env) {
        Ok(kv) => kv,
        Err(_) => {
            return error_response(
                &req,
                501,
                "not_configured",
                "KV binding is required for passkey endpoints",
            );
        }
    };

    let body: PasskeyAuthFinishRequest = match req.json().await {
        Ok(b) => b,
        Err(e) => {
            console_log!("Invalid JSON in /v1/passkey/auth/finish: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };

    let challenge_b64 = extract_challenge_from_client_data_b64url(&body.credential.response.client_data_json)
        .map_err(|e| Error::RustError(format!("Invalid clientDataJSON: {} ({})", e.message, e.code)))?;

    let state_key = passkey_auth_state_key(&challenge_b64);
    let auth_state: AuthenticationState = match kv_get_json(&kv, &state_key).await? {
        Some(s) => s,
        None => return error_response(&req, 400, "no_auth", "No authentication in progress"),
    };
    // Remove after retrieval to prevent replays.
    let _ = kv_delete(&kv, &state_key).await;

    // Determine credential ID and load stored passkey.
    let raw_id_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&body.credential.raw_id)
        .map_err(|_| Error::RustError("Invalid credential rawId".to_string()))?;
    let credential_id_b64 = BASE64.encode(&raw_id_bytes);
    let Some(passkey_row) = d1_passkey_by_credential_id(&db, &credential_id_b64).await? else {
        return error_response(&req, 404, "passkey_not_found", "Passkey not found");
    };

    let mut stored_passkey: StoredPasskey = serde_json::from_str(&passkey_row.credential_data)
        .map_err(|e| Error::RustError(format!("Invalid stored passkey data: {e}")))?;

    let AuthResult { new_sign_count } = beacon_passkey::finish_passkey_authentication(
        rp,
        &body.credential,
        &auth_state,
        &stored_passkey,
    )
    .map_err(|e| Error::RustError(format!("Passkey authentication failed: {} ({})", e.message, e.code)))?;

    stored_passkey.sign_count = new_sign_count;
    let updated_data = serde_json::to_string(&stored_passkey)
        .map_err(|e| Error::RustError(e.to_string()))?;

    let used_ts = now_ts();
    d1_update_passkey_usage(&db, passkey_row.id, &updated_data, used_ts).await?;

    let Some(user) = d1_user_by_id(&db, passkey_row.user_id).await? else {
        return error_response(&req, 404, "user_not_found", "User not found");
    };

    // Create a new session (same behavior as password login).
    let now = Utc::now();
    let access_exp = now + chrono::Duration::seconds(jwt.access_token_expiration);
    let access_claims = models::SessionClaims {
        iss: jwt.issuer.clone(),
        sub: (user.id as i32).to_string(),
        aud: "beaconauth-web".to_string(),
        exp: access_exp.timestamp(),
        token_type: "access".to_string(),
    };
    let access_token = sign_jwt(jwt, &access_claims)?;

    let refresh_token = new_refresh_token();
    let token_hash = sha256_hex(&refresh_token);
    let family_id = new_family_id();
    let refresh_exp = now.timestamp() + jwt.refresh_token_expiration;
    d1_insert_refresh_token(&db, user.id, &token_hash, &family_id, refresh_exp).await?;

    let mut resp = Response::from_json(&json!({ "success": true, "username": user.username }))?;
    let headers = resp.headers_mut();
    append_set_cookie(headers, &cookie_kv("access_token", &access_token, jwt.access_token_expiration))?;
    append_set_cookie(headers, &cookie_kv("refresh_token", &refresh_token, jwt.refresh_token_expiration))?;
    json_with_cors(&req, resp)
}

async fn handle_passkey_list(req: &Request, env: &Env) -> Result<Response> {
    let db = d1(env).await?;
    let jwt = get_jwt_state(env)?;

    let Some(access_token) = get_cookie(req, "access_token")? else {
        return error_response(req, 401, "unauthorized", "Not authenticated");
    };

    let user_id = match verify_access_token(jwt, &access_token) {
        Ok(id) => id as i64,
        Err(e) => return error_response(req, 401, "invalid_token", e),
    };

    let passkeys = d1_passkeys_by_user_id(&db, user_id).await?;
    let list = PasskeyList {
        passkeys: passkeys
            .into_iter()
            .map(|pk| PasskeyInfo {
                id: pk.id,
                name: pk.name,
                created_at: ts_to_rfc3339(pk.created_at),
                last_used_at: pk.last_used_at.map(ts_to_rfc3339),
            })
            .collect(),
    };

    let resp = Response::from_json(&list)?;
    json_with_cors(req, resp)
}

async fn handle_passkey_delete_by_id(req: &Request, env: &Env, id: i64) -> Result<Response> {
    let db = d1(env).await?;
    let jwt = get_jwt_state(env)?;

    let Some(access_token) = get_cookie(req, "access_token")? else {
        return error_response(req, 401, "unauthorized", "Not authenticated");
    };

    let user_id = match verify_access_token(jwt, &access_token) {
        Ok(id) => id as i64,
        Err(e) => return error_response(req, 401, "invalid_token", e),
    };

    let Some(passkey) = d1_passkey_by_id(&db, id).await? else {
        return error_response(req, 404, "passkey_not_found", "Passkey not found");
    };

    if passkey.user_id != user_id {
        return error_response(req, 403, "forbidden", "Not your passkey");
    }

    d1_delete_passkey_by_id(&db, id).await?;
    let resp = Response::from_json(&json!({ "success": true }))?;
    json_with_cors(req, resp)
}

async fn handle_passkey_delete(mut req: Request, env: &Env) -> Result<Response> {
    let body: PasskeyDeleteRequest = match req.json().await {
        Ok(b) => b,
        Err(e) => {
            console_log!("Invalid JSON in /v1/passkey/delete: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };
    handle_passkey_delete_by_id(&req, env, body.id).await
}

async fn handle_minecraft_jwt(mut req: Request, env: &Env) -> Result<Response> {
    let jwt = get_jwt_state(env)?;

    let payload: models::MinecraftJwtRequest = req.json().await?;

    let Some(access_token) = get_cookie(&req, "access_token")? else {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "unauthorized".to_string(),
            message: "Not authenticated. Please log in again.".to_string(),
        })?
        .with_status(401);
        return json_with_cors(&req, resp);
    };

    let user_id = match verify_access_token(jwt, &access_token) {
        Ok(id) => id,
        Err(e) => {
            let resp = Response::from_json(&models::ErrorResponse {
                error: "unauthorized".to_string(),
                message: format!("Not authenticated. Please log in again. ({e})"),
            })?
            .with_status(401);
            return json_with_cors(&req, resp);
        }
    };

    let now = Utc::now();
    let exp = now + chrono::Duration::seconds(jwt.jwt_expiration);

    let claims = models::Claims {
        iss: jwt.issuer.clone(),
        sub: user_id.to_string(),
        aud: "minecraft-client".to_string(),
        exp: exp.timestamp(),
        challenge: payload.challenge.clone(),
    };

    let token = sign_jwt(jwt, &claims)?;

    let redirect_url = format!(
        "http://localhost:{}/auth-callback?jwt={}&profile_url={}",
        payload.redirect_port,
        token,
        urlencoding::encode(&payload.profile_url)
    );

    let resp = Response::from_json(&models::MinecraftJwtResponse { redirect_url })?;
    json_with_cors(&req, resp)
}

fn not_found(req: &Request) -> Result<Response> {
    let resp = Response::from_json(&models::ErrorResponse {
        error: "not_found".to_string(),
        message: "Route not found".to_string(),
    })?
    .with_status(404);
    json_with_cors(req, resp)
}

fn method_not_allowed(req: &Request) -> Result<Response> {
    let resp = Response::from_json(&models::ErrorResponse {
        error: "method_not_allowed".to_string(),
        message: "Method not allowed".to_string(),
    })?
    .with_status(405);
    json_with_cors(req, resp)
}

fn is_api_path(raw_path: &str) -> bool {
    // In the single-worker deployment, the UI lives at `/` and the API uses `/api/v1/*`.
    // Additionally, we support route-mounted deployments like `example.com/api/*` where
    // requests arrive as `/api/v1/...` (normalized later).
    raw_path == "/api"
        || raw_path.starts_with("/api/")
        || raw_path == "/v1"
        || raw_path.starts_with("/v1/")
        || raw_path.starts_with("/.well-known/")
}

async fn serve_assets(req: Request, env: &Env) -> Result<Response> {
    // Wrangler [assets] bindings are exposed as a Fetcher.
    // https://docs.rs/worker/latest/src/worker/env.rs.html
    let assets = env.assets("ASSETS")?;
    assets.fetch_request(req).await
}

#[event(fetch)]
pub async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    let url = req.url()?;
    let raw_path = url.path().to_string();
    let api = is_api_path(&raw_path);

    if req.method() == Method::Options {
        // Preflight handling is only relevant for API endpoints.
        // For static assets, just delegate to the assets fetcher.
        if api {
            let resp = Response::empty()?.with_status(204);
            return json_with_cors(&req, resp);
        }
        return serve_assets(req, &env).await;
    }

    // When `assets.run_worker_first = true`, we must explicitly serve the UI from the ASSETS
    // binding for all non-API requests.
    if !api {
        return serve_assets(req, &env).await;
    }

    let method = req.method();
    // Support deployments where the backend is mounted at a context path, e.g. `/api/*`.
    // For example, when a Worker route is configured as `example.com/api/*`, requests will
    // arrive with paths like `/api/v1/login`. We normalize to `/v1/login` for routing.
    let path = raw_path.strip_prefix("/api").unwrap_or(raw_path.as_str());
    let path = if path.is_empty() { "/" } else { path };

    // Endpoints that read request bodies must take ownership of the request.
    if method == Method::Post && path == "/v1/login" {
        return handle_login(req, &env).await;
    }
    if method == Method::Post && path == "/v1/register" {
        return handle_register(req, &env).await;
    }
    if method == Method::Post && path == "/v1/passkey/register/start" {
        return handle_passkey_register_start(req, &env).await;
    }
    if method == Method::Post && path == "/v1/passkey/register/finish" {
        return handle_passkey_register_finish(req, &env).await;
    }
    if method == Method::Post && path == "/v1/passkey/auth/start" {
        return handle_passkey_auth_start(req, &env).await;
    }
    if method == Method::Post && path == "/v1/passkey/auth/finish" {
        return handle_passkey_auth_finish(req, &env).await;
    }
    if method == Method::Post && path == "/v1/passkey/delete" {
        return handle_passkey_delete(req, &env).await;
    }
    if method == Method::Post && path == "/v1/user/change-password" {
        return handle_change_password(req, &env).await;
    }
    if method == Method::Post && path == "/v1/minecraft-jwt" {
        return handle_minecraft_jwt(req, &env).await;
    }
    if method == Method::Post && path == "/v1/oauth/start" {
        return handle_oauth_start(req, &env).await;
    }

    match (method, path) {
        (Method::Get, "/v1/config") => handle_get_config(&req, &env).await,
        (Method::Post, "/v1/refresh") => handle_refresh(&req, &env).await,
        (Method::Post, "/v1/logout") => handle_logout(&req, &env).await,
        (Method::Get, "/v1/user/me") => handle_user_me(&req, &env).await,
        (Method::Get, "/v1/oauth/callback") => handle_oauth_callback(&req, &env).await,
        (Method::Get, "/.well-known/jwks.json") => handle_get_jwks(&req, &env).await,

        (Method::Get, "/v1/passkey/list") => handle_passkey_list(&req, &env).await,
        (Method::Delete, p) if p.starts_with("/v1/passkey/") => {
            let Some(id_str) = p.strip_prefix("/v1/passkey/") else {
                return not_found(&req);
            };

            let id = match id_str.parse::<i64>() {
                Ok(id) => id,
                Err(_) => return error_response(&req, 400, "invalid_passkey_id", "Invalid passkey id"),
            };

            handle_passkey_delete_by_id(&req, &env, id).await
        }

        (Method::Get, _) | (Method::Post, _) | (Method::Delete, _) => not_found(&req),
        _ => method_not_allowed(&req),
    }
}
