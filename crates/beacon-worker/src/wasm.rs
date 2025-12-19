use std::sync::OnceLock;

use beacon_core::{crypto, models};
use chrono::Utc;
use jsonwebtoken::{encode, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
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

fn json_with_cors(req: &Request, mut resp: Response) -> Result<Response> {
    let origin = req.headers().get("Origin")?.unwrap_or_else(|| "*".to_string());

    resp.headers_mut().set("Access-Control-Allow-Origin", &origin)?;
    resp.headers_mut().set("Access-Control-Allow-Credentials", "true")?;
    resp.headers_mut().set("Access-Control-Allow-Headers", "Content-Type, Authorization")?;
    resp.headers_mut().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")?;
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
        .bind(&[id.into()])?
        .first::<UserRow>(None)
        .await
}

async fn d1_insert_user(db: &D1Database, username: &str, password_hash: &str) -> Result<i64> {
    let ts = now_ts();
    let result = db
        .prepare(
            "INSERT INTO users (username, password_hash, created_at, updated_at) VALUES (?1, ?2, ?3, ?3)",
        )
        .bind(&[username.into(), password_hash.into(), ts.into()])?
        .run()
        .await?;

    Ok(result
        .meta()?
        .and_then(|m| m.last_row_id)
        .unwrap_or(0))
}

async fn d1_update_user_password(db: &D1Database, user_id: i64, new_hash: &str) -> Result<()> {
    let ts = now_ts();
    db.prepare("UPDATE users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(&[new_hash.into(), ts.into(), user_id.into()])?
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
        user_id.into(),
        token_hash.into(),
        family_id.into(),
        expires_at.into(),
        ts.into(),
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
        .bind(&[id.into()])?
        .run()
        .await?;
    Ok(())
}

async fn d1_revoke_all_refresh_tokens_for_user(db: &D1Database, user_id: i64) -> Result<()> {
    db.prepare("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?1")
        .bind(&[user_id.into()])?
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

async fn handle_register(mut req: Request, env: &Env) -> Result<Response> {
    let db = d1(env).await?;

    let payload: models::RegisterPayload = req.json().await?;

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

    if d1_user_by_username(&db, &payload.username).await?.is_some() {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "username_taken".to_string(),
            message: "Username already exists".to_string(),
        })?
        .with_status(409);
        return json_with_cors(&req, resp);
    }

    let password_hash = bcrypt::hash(&payload.password, bcrypt::DEFAULT_COST)
        .map_err(|e| Error::RustError(e.to_string()))?;

    let user_id = d1_insert_user(&db, &payload.username, &password_hash).await?;

    let jwt = get_jwt_state(env)?;
    let now = Utc::now();

    let access_exp = now + chrono::Duration::seconds(jwt.access_token_expiration);
    let access_claims = models::SessionClaims {
        iss: jwt.issuer.clone(),
        sub: (user_id as i32).to_string(),
        aud: "beaconauth-web".to_string(),
        exp: access_exp.timestamp(),
        token_type: "access".to_string(),
    };

    let access_token = sign_jwt(jwt, &access_claims)?;

    let refresh_token = new_refresh_token();
    let token_hash = sha256_hex(&refresh_token);
    let family_id = new_family_id();
    let refresh_exp = now.timestamp() + jwt.refresh_token_expiration;

    d1_insert_refresh_token(&db, user_id, &token_hash, &family_id, refresh_exp).await?;

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
    if method == Method::Post && path == "/v1/user/change-password" {
        return handle_change_password(req, &env).await;
    }
    if method == Method::Post && path == "/v1/minecraft-jwt" {
        return handle_minecraft_jwt(req, &env).await;
    }

    match (method, path) {
        (Method::Get, "/v1/config") => handle_get_config(&req, &env).await,
        (Method::Post, "/v1/refresh") => handle_refresh(&req, &env).await,
        (Method::Post, "/v1/logout") => handle_logout(&req, &env).await,
        (Method::Get, "/v1/user/me") => handle_user_me(&req, &env).await,
        (Method::Get, "/.well-known/jwks.json") => handle_get_jwks(&req, &env).await,

        // Present-but-not-implemented endpoints in Workers.
        (Method::Post, p) if p.starts_with("/v1/passkey/") => {
            let resp = Response::from_json(&models::ErrorResponse {
                error: "not_supported".to_string(),
                message: "Passkey (WebAuthn) endpoints are not enabled in the Workers build yet".to_string(),
            })?
            .with_status(501);
            json_with_cors(&req, resp)
        }
        (Method::Get, p) if p.starts_with("/v1/passkey/") => {
            let resp = Response::from_json(&models::ErrorResponse {
                error: "not_supported".to_string(),
                message: "Passkey (WebAuthn) endpoints are not enabled in the Workers build yet".to_string(),
            })?
            .with_status(501);
            json_with_cors(&req, resp)
        }

        (Method::Post, p) if p.starts_with("/v1/oauth/") => {
            let resp = Response::from_json(&models::ErrorResponse {
                error: "not_supported".to_string(),
                message: "OAuth endpoints are not enabled in the Workers build yet".to_string(),
            })?
            .with_status(501);
            json_with_cors(&req, resp)
        }
        (Method::Get, p) if p.starts_with("/v1/oauth/") => {
            let resp = Response::from_json(&models::ErrorResponse {
                error: "not_supported".to_string(),
                message: "OAuth endpoints are not enabled in the Workers build yet".to_string(),
            })?
            .with_status(501);
            json_with_cors(&req, resp)
        }

        (Method::Get, _) | (Method::Post, _) => not_found(&req),
        _ => method_not_allowed(&req),
    }
}
