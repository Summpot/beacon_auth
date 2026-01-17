use beacon_core::models;
use beacon_core::password;
use beacon_core::username;
use chrono::Utc;
use serde_json::json;
use worker::{Env, Error, Request, Response, Result};

use crate::wasm::{
    cookies::{append_set_cookie, clear_cookie, cookie_kv, get_cookie},
    db::{
        d1, d1_insert_identity, d1_insert_refresh_token, d1_insert_user, d1_password_identity_by_identifier,
        d1_password_identity_by_user_id, d1_refresh_token_by_hash, d1_revoke_all_refresh_tokens_for_user,
        d1_revoke_refresh_token_by_id, d1_update_password_identity_hash, d1_user_by_id, d1_user_by_username,
    },
    http::{error_response, internal_error_response, json_with_cors},
    jwt::{sign_jwt, verify_access_token},
    state::get_jwt_state,
    util::{new_family_id, new_refresh_token, now_ts, sha256_hex},
};

pub async fn handle_register(mut req: Request, env: &Env) -> Result<Response> {
    let db = match d1(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open database binding", &e),
    };

    let payload: models::RegisterPayload = match req.json().await {
        Ok(p) => p,
        Err(e) => {
            worker::console_log!("Invalid JSON in /v1/register: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };

    let requested_username = payload.username.trim().to_string();
    if let Err(msg) = username::validate_minecraft_username(&requested_username) {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "invalid_username".to_string(),
            message: msg.to_string(),
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

    match d1_user_by_username(&db, &requested_username).await {
        Ok(Some(_)) => {
            return error_response(&req, 409, "username_taken", "Username already exists");
        }
        Ok(None) => {}
        Err(e) => return internal_error_response(&req, "Failed to check existing username", &e),
    };

    let password_hash = match password::hash_password(&payload.password) {
        Ok(h) => h,
        Err(e) => return internal_error_response(&req, "Failed to hash password", &e),
    };

    let user_id = match d1_insert_user(&db, &requested_username).await {
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

    // Create the password identity for this user.
    let identifier = username::normalize_username(&requested_username);
    if let Err(e) = d1_insert_identity(&db, &user_id, "password", &identifier, Some(&password_hash)).await {
        let msg = e.to_string();
        if msg.to_ascii_lowercase().contains("unique") {
            return error_response(&req, 409, "username_taken", "Username already exists");
        }
        return internal_error_response(&req, "Failed to create password identity", &e);
    }

    let jwt = match get_jwt_state(env).await {
        Ok(jwt) => jwt,
        Err(e) => return internal_error_response(&req, "Failed to initialize JWT state", &e),
    };
    let now = Utc::now();

    let access_exp = now + chrono::Duration::seconds(jwt.access_token_expiration);
    let access_claims = models::SessionClaims {
        iss: jwt.issuer.clone(),
        sub: user_id.clone(),
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

    if let Err(e) = d1_insert_refresh_token(&db, &user_id, &token_hash, &family_id, refresh_exp).await {
        return internal_error_response(&req, "Failed to persist refresh token", &e);
    }

    let mut resp = Response::from_json(&json!({ "success": true }))?;
    let headers = resp.headers_mut();
    append_set_cookie(headers, &cookie_kv("access_token", &access_token, jwt.access_token_expiration))?;
    append_set_cookie(headers, &cookie_kv("refresh_token", &refresh_token, jwt.refresh_token_expiration))?;

    json_with_cors(&req, resp)
}

pub async fn handle_login(mut req: Request, env: &Env) -> Result<Response> {
    let db = d1(env).await?;

    let payload: models::LoginPayload = req.json().await?;

    let Some(identity) = d1_password_identity_by_identifier(&db, &payload.username).await? else {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "unauthorized".to_string(),
            message: "Invalid username or password".to_string(),
        })?
        .with_status(401);
        return json_with_cors(&req, resp);
    };

    let Some(password_hash) = identity.password_hash.as_deref() else {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "unauthorized".to_string(),
            message: "Invalid username or password".to_string(),
        })?
        .with_status(401);
        return json_with_cors(&req, resp);
    };

    let Some(user) = d1_user_by_id(&db, &identity.user_id).await? else {
        return internal_error_response(&req, "Identity references missing user", &"user missing");
    };

    let password_valid = match password::verify_password(&payload.password, password_hash) {
        Ok(v) => v,
        Err(e) => {
            return internal_error_response(&req, "Failed to verify password", &e);
        }
    };
    if !password_valid {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "unauthorized".to_string(),
            message: "Invalid username or password".to_string(),
        })?
        .with_status(401);
        return json_with_cors(&req, resp);
    }

    let jwt = get_jwt_state(env).await?;
    let now = Utc::now();

    let access_exp = now + chrono::Duration::seconds(jwt.access_token_expiration);
    let access_claims = models::SessionClaims {
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

    // The web UI only requires cookies to be set; the body is ignored.
    let mut resp = Response::from_json(&json!({ "success": true }))?;
    let headers = resp.headers_mut();
    append_set_cookie(headers, &cookie_kv("access_token", &access_token, jwt.access_token_expiration))?;
    append_set_cookie(headers, &cookie_kv("refresh_token", &refresh_token, jwt.refresh_token_expiration))?;

    json_with_cors(&req, resp)
}

pub async fn handle_refresh(req: &Request, env: &Env) -> Result<Response> {
    let db = d1(env).await?;
    let jwt = get_jwt_state(env).await?;

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
    d1_revoke_refresh_token_by_id(&db, &record.id).await?;

    // Issue new token pair with same family_id
    let now = Utc::now();
    let access_exp = now + chrono::Duration::seconds(jwt.access_token_expiration);
    let access_claims = models::SessionClaims {
        iss: jwt.issuer.clone(),
        sub: record.user_id.clone(),
        aud: "beaconauth-web".to_string(),
        exp: access_exp.timestamp(),
        token_type: "access".to_string(),
    };

    let access_token = sign_jwt(jwt, &access_claims)?;

    let new_refresh_token = new_refresh_token();
    let new_hash = sha256_hex(&new_refresh_token);
    let refresh_exp = now.timestamp() + jwt.refresh_token_expiration;

    d1_insert_refresh_token(&db, &record.user_id, &new_hash, &record.family_id, refresh_exp).await?;

    let mut resp = Response::from_json(&json!({ "success": true }))?;
    let headers = resp.headers_mut();
    append_set_cookie(headers, &cookie_kv("access_token", &access_token, jwt.access_token_expiration))?;
    append_set_cookie(headers, &cookie_kv("refresh_token", &new_refresh_token, jwt.refresh_token_expiration))?;

    json_with_cors(req, resp)
}

pub async fn handle_user_me(req: &Request, env: &Env) -> Result<Response> {
    let db = d1(env).await?;
    let jwt = get_jwt_state(env).await?;

    let Some(access_token) = get_cookie(req, "access_token")? else {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "unauthorized".to_string(),
            message: "Not authenticated".to_string(),
        })?
        .with_status(401);
        return json_with_cors(req, resp);
    };

        let user_id = match verify_access_token(jwt, &access_token).await {
        Ok(id) => id,
        Err(e) => {
            let resp = Response::from_json(&models::ErrorResponse {
                error: "invalid_token".to_string(),
                message: e,
            })?
            .with_status(401);
            return json_with_cors(req, resp);
        }
    };

    let Some(user) = d1_user_by_id(&db, &user_id).await? else {
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

pub async fn handle_change_password(mut req: Request, env: &Env) -> Result<Response> {
    let db = d1(env).await?;
    let jwt = get_jwt_state(env).await?;

    let Some(access_token) = get_cookie(&req, "access_token")? else {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "unauthorized".to_string(),
            message: "Not authenticated".to_string(),
        })?
        .with_status(401);
        return json_with_cors(&req, resp);
    };

        let user_id = match verify_access_token(jwt, &access_token).await {
        Ok(id) => id,
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

    let Some(user) = d1_user_by_id(&db, &user_id).await? else {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "user_not_found".to_string(),
            message: "User not found".to_string(),
        })?
        .with_status(404);
        return json_with_cors(&req, resp);
    };

    let existing = d1_password_identity_by_user_id(&db, &user_id).await?;
    if let Some(identity) = existing.as_ref() {
        let Some(existing_hash) = identity.password_hash.as_deref() else {
            return internal_error_response(&req, "Password identity is missing password_hash", &"invalid row");
        };

        let password_valid = match password::verify_password(&payload.current_password, existing_hash) {
            Ok(v) => v,
            Err(e) => {
                return internal_error_response(&req, "Failed to verify password", &e);
            }
        };
        if !password_valid {
            let resp = Response::from_json(&models::ErrorResponse {
                error: "invalid_password".to_string(),
                message: "Current password is incorrect".to_string(),
            })?
            .with_status(401);
            return json_with_cors(&req, resp);
        }
    }

    let new_hash = password::hash_password(&payload.new_password)
        .map_err(|e| Error::RustError(e.to_string()))?;

    if existing.is_some() {
        d1_update_password_identity_hash(&db, &user_id, &new_hash).await?;
    } else {
        d1_insert_identity(
            &db,
            &user_id,
            "password",
            &user.username_lower,
            Some(&new_hash),
        )
        .await?;
    }

    let resp = Response::from_json(&json!({ "success": true }))?;
    json_with_cors(&req, resp)
}

pub async fn handle_change_username(mut req: Request, env: &Env) -> Result<Response> {
    let db = d1(env).await?;
    let jwt = get_jwt_state(env).await?;

    let Some(access_token) = get_cookie(&req, "access_token")? else {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "unauthorized".to_string(),
            message: "Not authenticated".to_string(),
        })?
        .with_status(401);
        return json_with_cors(&req, resp);
    };

        let user_id = match verify_access_token(jwt, &access_token).await {
        Ok(id) => id,
        Err(e) => {
            let resp = Response::from_json(&models::ErrorResponse {
                error: "invalid_token".to_string(),
                message: e,
            })?
            .with_status(401);
            return json_with_cors(&req, resp);
        }
    };

    let payload: models::ChangeUsernameRequest = req.json().await?;
    let requested_username = payload.username.trim().to_string();

    if let Err(msg) = username::validate_minecraft_username(&requested_username) {
        return error_response(&req, 400, "invalid_username", msg);
    }

    let requested_lower = username::normalize_username(&requested_username);

    if let Some(existing) = d1_user_by_username(&db, &requested_lower).await? {
        if existing.id != user_id {
            return error_response(&req, 409, "username_taken", "Username already exists");
        }
    }

    crate::wasm::db::d1_update_user_username(&db, &user_id, &requested_username, &requested_lower)
        .await?;

    // Keep the password identity's identifier aligned with the normalized username.
    let _ = crate::wasm::db::d1_update_password_identity_identifier(&db, &user_id, &requested_lower).await;

    let resp = Response::from_json(&models::ChangeUsernameResponse {
        success: true,
        username: requested_username,
    })?;
    json_with_cors(&req, resp)
}

pub async fn handle_logout(req: &Request, env: &Env) -> Result<Response> {
    let db = d1(env).await?;
    let jwt = get_jwt_state(env).await?;

    let Some(access_token) = get_cookie(req, "access_token")? else {
        let resp = Response::from_json(&json!({ "success": true }))?;
        return json_with_cors(req, resp);
    };

        let user_id = match verify_access_token(jwt, &access_token).await {
        Ok(id) => id,
        Err(_) => {
            let resp = Response::from_json(&json!({ "success": true }))?;
            return json_with_cors(req, resp);
        }
    };

    // Revoke all refresh tokens for the user.
    let _ = d1_revoke_all_refresh_tokens_for_user(&db, &user_id).await;

    let mut resp = Response::from_json(&json!({ "success": true }))?;
    let headers = resp.headers_mut();
    append_set_cookie(headers, &clear_cookie("access_token"))?;
    append_set_cookie(headers, &clear_cookie("refresh_token"))?;

    json_with_cors(req, resp)
}
