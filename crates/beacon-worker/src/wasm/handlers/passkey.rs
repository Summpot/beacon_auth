use beacon_passkey::{
    extract_challenge_from_client_data_b64url, AuthenticationState, AuthResult,
    CreationChallengeResponse, PublicKeyCredential as PasskeyPublicKeyCredential,
    RegisterPublicKeyCredential, RegistrationState, RequestChallengeResponse, StoredPasskey,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use worker::{Env, Error, Request, Response, Result};

use crate::wasm::{
    cookies::{append_set_cookie, cookie_kv, get_cookie},
    db::{
        d1, db_put_passkey_state, db_take_passkey_state, d1_delete_passkey_by_id,
        d1_insert_passkey, d1_passkey_by_credential_id, d1_insert_refresh_token,
        d1_passkey_by_id, d1_passkeys_all, d1_passkeys_by_user_id, d1_update_passkey_usage,
        d1_user_by_id, passkey_auth_state_key, passkey_reg_state_key, PASSKEY_STATE_TTL_SECS,
    },
    http::{error_response, internal_error_response, json_with_cors},
    jwt::{sign_jwt, verify_access_token},
    state::{get_jwt_state, get_passkey_rp},
    util::{new_family_id, new_refresh_token, now_ts, sha256_hex, ts_to_rfc3339},
};

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
    id: String,
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
    id: String,
}

pub async fn handle_passkey_register_start(mut req: Request, env: &Env) -> Result<Response> {
    let db = d1(env).await?;
    let jwt = get_jwt_state(env).await?;
    let rp = get_passkey_rp(env)?;

    let _body: PasskeyRegisterStartRequest = match req.json().await {
        Ok(b) => b,
        Err(e) => {
            worker::console_log!("Invalid JSON in /v1/passkey/register/start: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };
        // The request includes a suggested display name; we don't need it for challenge creation,
        // but reading it keeps the field from being flagged as unused.
        let _ = _body.name;

    let Some(access_token) = get_cookie(&req, "access_token")? else {
        return error_response(&req, 401, "unauthorized", "Not authenticated");
    };

    let user_id = match verify_access_token(jwt, &access_token).await {
        Ok(id) => id,
        Err(e) => return error_response(&req, 401, "invalid_token", e),
    };

    let Some(user) = d1_user_by_id(&db, &user_id).await? else {
        return error_response(&req, 404, "user_not_found", "User not found");
    };

    let existing_passkeys = d1_passkeys_by_user_id(&db, &user_id).await?;
    let exclude_credentials: Vec<Vec<u8>> = existing_passkeys
        .iter()
        .filter_map(|pk| BASE64.decode(&pk.credential_id).ok())
        .collect();

    let user_uuid = Uuid::parse_str(&user.id)
        .map_err(|_| Error::RustError("Invalid user id".to_string()))?;
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

    db_put_passkey_state(
        &db,
        &passkey_reg_state_key(&user_id),
        &reg_state,
        PASSKEY_STATE_TTL_SECS,
    )
    .await?;

    let resp = Response::from_json(&PasskeyRegisterStartResponse {
        creation_options: ccr,
    })?;
    json_with_cors(&req, resp)
}

pub async fn handle_passkey_register_finish(mut req: Request, env: &Env) -> Result<Response> {
    let db = d1(env).await?;
    let jwt = get_jwt_state(env).await?;
    let rp = get_passkey_rp(env)?;

    let body: PasskeyRegisterFinishRequest = match req.json().await {
        Ok(b) => b,
        Err(e) => {
            worker::console_log!("Invalid JSON in /v1/passkey/register/finish: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };

    let Some(access_token) = get_cookie(&req, "access_token")? else {
        return error_response(&req, 401, "unauthorized", "Not authenticated");
    };

    let user_id = match verify_access_token(jwt, &access_token).await {
        Ok(id) => id,
        Err(e) => return error_response(&req, 401, "invalid_token", e),
    };

    let state_key = passkey_reg_state_key(&user_id);
    let reg_state: RegistrationState = match db_take_passkey_state(&db, &state_key).await? {
        Some(s) => s,
        None => return error_response(&req, 400, "no_registration", "No registration in progress"),
    };

    let stored = beacon_passkey::finish_passkey_registration(rp, &body.credential, &reg_state)
        .map_err(|e| Error::RustError(format!("Passkey registration failed: {} ({})", e.message, e.code)))?;

    let credential_data = serde_json::to_string(&stored).map_err(|e| Error::RustError(e.to_string()))?;

    // Store credential_id in the DB as standard base64 (to match the rest of the codebase).
    let raw_id_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&body.credential.raw_id)
        .map_err(|_| Error::RustError("Invalid credential rawId".to_string()))?;
    let credential_id_b64 = BASE64.encode(&raw_id_bytes);
    let name = body.name.unwrap_or_else(|| "Passkey".to_string());

    let passkey_id = match d1_insert_passkey(&db, &user_id, &credential_id_b64, &credential_data, &name).await {
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

pub async fn handle_passkey_auth_start(mut req: Request, env: &Env) -> Result<Response> {
    let db = d1(env).await?;
    let rp = get_passkey_rp(env)?;

    // Body is optional in the web UI; treat missing/invalid JSON as empty.
    let body: serde_json::Value = req.json().await.unwrap_or_else(|_| json!({}));
    let username = body
        .get("username")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let (allow_credential_ids, has_any_passkeys) = if let Some(username) = username {
        let Some(user) = crate::wasm::db::d1_user_by_username(&db, &username).await? else {
            return error_response(&req, 404, "user_not_found", "User not found");
        };
        let passkeys = d1_passkeys_by_user_id(&db, &user.id).await?;
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
    db_put_passkey_state(
        &db,
        &passkey_auth_state_key(&challenge_str),
        &auth_state,
        PASSKEY_STATE_TTL_SECS,
    )
    .await?;

    let resp = Response::from_json(&PasskeyAuthStartResponse { request_options: rcr })?;
    json_with_cors(&req, resp)
}

pub async fn handle_passkey_auth_finish(mut req: Request, env: &Env) -> Result<Response> {
    let db = d1(env).await?;
    let jwt = get_jwt_state(env).await?;
    let rp = get_passkey_rp(env)?;

    let body: PasskeyAuthFinishRequest = match req.json().await {
        Ok(b) => b,
        Err(e) => {
            worker::console_log!("Invalid JSON in /v1/passkey/auth/finish: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };

    let challenge_b64 = extract_challenge_from_client_data_b64url(&body.credential.response.client_data_json)
        .map_err(|e| Error::RustError(format!("Invalid clientDataJSON: {} ({})", e.message, e.code)))?;

    let state_key = passkey_auth_state_key(&challenge_b64);
    let auth_state: AuthenticationState = match db_take_passkey_state(&db, &state_key).await? {
        Some(s) => s,
        None => return error_response(&req, 400, "no_auth", "No authentication in progress"),
    };

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
    d1_update_passkey_usage(&db, &passkey_row.id, &updated_data, used_ts).await?;

    let Some(user) = d1_user_by_id(&db, &passkey_row.user_id).await? else {
        return error_response(&req, 404, "user_not_found", "User not found");
    };

    // Create a new session (same behavior as password login).
    let now = Utc::now();
    let access_exp = now + chrono::Duration::seconds(jwt.access_token_expiration);
    let access_claims = beacon_core::models::SessionClaims {
        iss: jwt.issuer.clone(),
        sub: user.id.clone(),
        aud: "beaconauth-web".to_string(),
        exp: access_exp.timestamp(),
        token_type: "access".to_string(),
    };
    let access_token = sign_jwt(jwt, &access_claims)?;

    let refresh_token = new_refresh_token();
    let token_hash = sha256_hex(&refresh_token);
    let family_id = new_family_id();
    let refresh_exp = now.timestamp() + jwt.refresh_token_expiration;
    d1_insert_refresh_token(&db, &user.id, &token_hash, &family_id, refresh_exp).await?;

    let mut resp = Response::from_json(&json!({ "success": true, "username": user.username }))?;
    let headers = resp.headers_mut();
    append_set_cookie(headers, &cookie_kv("access_token", &access_token, jwt.access_token_expiration))?;
    append_set_cookie(headers, &cookie_kv("refresh_token", &refresh_token, jwt.refresh_token_expiration))?;
    json_with_cors(&req, resp)
}

pub async fn handle_passkey_list(req: &Request, env: &Env) -> Result<Response> {
    let db = d1(env).await?;
    let jwt = get_jwt_state(env).await?;

    let Some(access_token) = get_cookie(req, "access_token")? else {
        return error_response(req, 401, "unauthorized", "Not authenticated");
    };

    let user_id = match verify_access_token(jwt, &access_token).await {
        Ok(id) => id,
        Err(e) => return error_response(req, 401, "invalid_token", e),
    };

    let passkeys = d1_passkeys_by_user_id(&db, &user_id).await?;
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

pub async fn handle_passkey_delete_by_id(req: &Request, env: &Env, id: String) -> Result<Response> {
    let db = d1(env).await?;
    let jwt = get_jwt_state(env).await?;

    let Some(access_token) = get_cookie(req, "access_token")? else {
        return error_response(req, 401, "unauthorized", "Not authenticated");
    };

    let user_id = match verify_access_token(jwt, &access_token).await {
        Ok(id) => id,
        Err(e) => return error_response(req, 401, "invalid_token", e),
    };

    let Some(passkey) = d1_passkey_by_id(&db, &id).await? else {
        return error_response(req, 404, "passkey_not_found", "Passkey not found");
    };

    if passkey.user_id != user_id {
        return error_response(req, 403, "forbidden", "Not your passkey");
    }

    d1_delete_passkey_by_id(&db, &id).await?;
    let resp = Response::from_json(&json!({ "success": true }))?;
    json_with_cors(req, resp)
}

pub async fn handle_passkey_delete(mut req: Request, env: &Env) -> Result<Response> {
    let body: PasskeyDeleteRequest = match req.json().await {
        Ok(b) => b,
        Err(e) => {
            worker::console_log!("Invalid JSON in /v1/passkey/delete: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };
    handle_passkey_delete_by_id(&req, env, body.id).await
}
