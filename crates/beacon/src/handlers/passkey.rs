use actix_web::{web, HttpRequest, HttpResponse};
use base64::{engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64URL}, Engine};
use chrono::{TimeZone, Utc};
use redis::AsyncCommands;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::de::DeserializeOwned;
use serde::Serialize;
use webauthn_rs::prelude::*;
use uuid::Uuid;

use beacon_core::username;

use crate::app_state::AppState;
use crate::handlers::extract_session_user;
use crate::models::{
    PasskeyAuthFinishRequest, PasskeyAuthStartResponse, PasskeyDeleteRequest, PasskeyInfo, PasskeyList,
    PasskeyRegisterFinishRequest, PasskeyRegisterStartRequest, PasskeyRegisterStartResponse,
};
use entity::{passkey, user};

const PASSKEY_STATE_TTL_SECS: u64 = 5 * 60;

fn redis_reg_key(user_id: &str) -> String {
    format!("beaconauth:passkey:reg:{user_id}")
}

fn redis_auth_key(challenge_b64: &str) -> String {
    format!("beaconauth:passkey:auth:{challenge_b64}")
}

async fn redis_set_json<T: Serialize>(
    redis: &redis::aio::ConnectionManager,
    key: &str,
    value: &T,
) -> actix_web::Result<()> {
    let json = serde_json::to_string(value).map_err(actix_web::error::ErrorInternalServerError)?;
    let mut conn = redis.clone();
    let _: () = conn
        .set_ex(key, json, PASSKEY_STATE_TTL_SECS)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(())
}

async fn redis_get_json<T: DeserializeOwned>(
    redis: &redis::aio::ConnectionManager,
    key: &str,
) -> actix_web::Result<Option<T>> {
    let mut conn = redis.clone();
    let value: Option<String> = conn
        .get(key)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let Some(value) = value else {
        return Ok(None);
    };

    let parsed = serde_json::from_str(&value).map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(Some(parsed))
}

async fn redis_del(
    redis: &redis::aio::ConnectionManager,
    key: &str,
) -> actix_web::Result<()> {
    let mut conn = redis.clone();
    let _: () = conn
        .del(key)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(())
}

/// POST /api/v1/passkey/register/start
pub async fn register_start(
    req: HttpRequest,
    app_state: web::Data<AppState>,
    _body: web::Json<PasskeyRegisterStartRequest>,
) -> actix_web::Result<HttpResponse> {
    let user_id = extract_session_user(&req, &app_state)?;

    // Find user in database
    let user_model = user::Entity::find_by_id(user_id.clone())
        .one(&app_state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("User not found"))?;

    // Get existing passkeys for this user
    let existing_passkeys = passkey::Entity::find()
        .filter(passkey::Column::UserId.eq(user_id.clone()))
        .all(&app_state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    // Parse existing credentials
    let exclude_credentials: Vec<CredentialID> = existing_passkeys
        .iter()
        .filter_map(|pk| BASE64.decode(&pk.credential_id).ok())
        .map(CredentialID::from)
        .collect();

    // Start registration
    let user_uuid = Uuid::parse_str(&user_model.id)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Invalid user id"))?;
    let (ccr, passkey_registration) = app_state
        .webauthn
        .start_passkey_registration(
            user_uuid.into(),
            &user_model.username,
            &user_model.username,
            Some(exclude_credentials),
        )
        .map_err(|e| {
            log::error!("Failed to start passkey registration: {:?}", e);
            actix_web::error::ErrorInternalServerError("Failed to start registration")
        })?;

    // Store registration state (5-minute TTL)
    if let Some(redis) = &app_state.passkey_redis {
        redis_set_json(redis, &redis_reg_key(&user_id), &passkey_registration).await?;
    } else {
        app_state
            .passkey_reg_states
            .insert(user_id.clone(), passkey_registration);
    }

    Ok(HttpResponse::Ok().json(PasskeyRegisterStartResponse {
        creation_options: ccr,
    }))
}

/// POST /api/v1/passkey/register/finish
pub async fn register_finish(
    req: HttpRequest,
    app_state: web::Data<AppState>,
    body: web::Json<PasskeyRegisterFinishRequest>,
) -> actix_web::Result<HttpResponse> {
    let user_id = extract_session_user(&req, &app_state)?;

    // Retrieve registration state
    let passkey_registration = if let Some(redis) = &app_state.passkey_redis {
        let key = redis_reg_key(&user_id);
        let state: Option<PasskeyRegistration> = redis_get_json(redis, &key).await?;
        // Remove after retrieval to prevent replays.
        let _ = redis_del(redis, &key).await;
        state.ok_or_else(|| actix_web::error::ErrorBadRequest("No registration in progress"))?
    } else {
        let state = app_state
            .passkey_reg_states
            .get(&user_id)
            .ok_or_else(|| actix_web::error::ErrorBadRequest("No registration in progress"))?;
        app_state.passkey_reg_states.invalidate(&user_id);
        state
    };

    // Finish registration
    let passkey = app_state
        .webauthn
        .finish_passkey_registration(&body.credential, &passkey_registration)
        .map_err(|e| {
            log::error!("Failed to finish passkey registration: {:?}", e);
            actix_web::error::ErrorBadRequest("Failed to complete registration")
        })?;

    // Serialize passkey credential
    let credential_data =
        serde_json::to_string(&passkey).map_err(actix_web::error::ErrorInternalServerError)?;

    // Save to database
    let now_ts = Utc::now().timestamp();
    let passkey_id = Uuid::now_v7().to_string();
    let passkey_model = passkey::ActiveModel {
        id: Set(passkey_id),
        user_id: Set(user_id.clone()),
        credential_id: Set(BASE64.encode(passkey.cred_id())),
        credential_data: Set(credential_data),
        name: Set(body.name.clone().unwrap_or_else(|| "Passkey".to_string())),
        created_at: Set(now_ts),
        last_used_at: Set(None),
        ..Default::default()
    };

    let saved_passkey = passkey_model
        .insert(&app_state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    log::info!(
        "User {} registered passkey: {}",
        user_id,
        saved_passkey.name
    );

    Ok(HttpResponse::Created().json(serde_json::json!({
        "success": true,
        "passkey_id": saved_passkey.id,
    })))
}

/// POST /api/v1/passkey/auth/start
pub async fn auth_start(
    app_state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> actix_web::Result<HttpResponse> {
    // Optional: Get username from body for user verification
    let username = body
        .get("username")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Get all passkeys (or filter by username if provided)
    let passkeys = if let Some(ref username) = username {
        let username_lower = username::normalize_username(username);
        let user_model = user::Entity::find()
            .filter(user::Column::UsernameLower.eq(username_lower))
            .one(&app_state.db)
            .await
            .map_err(actix_web::error::ErrorInternalServerError)?
            .ok_or_else(|| actix_web::error::ErrorNotFound("User not found"))?;

        passkey::Entity::find()
            .filter(passkey::Column::UserId.eq(user_model.id))
            .all(&app_state.db)
            .await
            .map_err(actix_web::error::ErrorInternalServerError)?
    } else {
        // Allow any passkey (discoverable credentials)
        passkey::Entity::find()
            .all(&app_state.db)
            .await
            .map_err(actix_web::error::ErrorInternalServerError)?
    };

    // Parse stored passkeys
    let credentials: Vec<Passkey> = passkeys
        .iter()
        .filter_map(|pk| serde_json::from_str(&pk.credential_data).ok())
        .collect();

    if credentials.is_empty() {
        return Err(actix_web::error::ErrorNotFound("No passkeys found"));
    }

    // Start authentication
    let (rcr, passkey_authentication) = app_state
        .webauthn
        .start_passkey_authentication(&credentials)
        .map_err(|e| {
            log::error!("Failed to start passkey authentication: {:?}", e);
            actix_web::error::ErrorInternalServerError("Failed to start authentication")
        })?;

    // Store authentication state in cache using challenge as key (5-minute TTL)
    // Use base64url encoding (no padding) to match WebAuthn client_data_json format
    let challenge_str = BASE64URL.encode(rcr.public_key.challenge.as_ref());
    if let Some(redis) = &app_state.passkey_redis {
        redis_set_json(redis, &redis_auth_key(&challenge_str), &passkey_authentication).await?;
    } else {
        app_state
            .passkey_auth_states
            .insert(challenge_str.clone(), passkey_authentication);
    }

    Ok(HttpResponse::Ok().json(PasskeyAuthStartResponse {
        request_options: rcr,
    }))
}

/// POST /api/v1/passkey/auth/finish
pub async fn auth_finish(
    app_state: web::Data<AppState>,
    body: web::Json<PasskeyAuthFinishRequest>,
) -> actix_web::Result<HttpResponse> {
    // Parse client_data_json to extract challenge
    let client_data_json = std::str::from_utf8(&body.credential.response.client_data_json)
        .map_err(|e| {
            log::error!("Invalid UTF-8 in client_data_json: {:?}", e);
            actix_web::error::ErrorBadRequest("Invalid client data")
        })?;
    
    let client_data: serde_json::Value = serde_json::from_str(client_data_json)
        .map_err(|e| {
            log::error!("Failed to parse client_data_json: {:?}", e);
            actix_web::error::ErrorBadRequest("Invalid client data JSON")
        })?;
    
    let challenge_b64 = client_data
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| actix_web::error::ErrorBadRequest("Challenge not found in client data"))?;

    // Retrieve authentication state using the challenge
    let passkey_authentication = if let Some(redis) = &app_state.passkey_redis {
        let key = redis_auth_key(challenge_b64);
        let state: Option<PasskeyAuthentication> = redis_get_json(redis, &key).await?;
        // Remove after retrieval to prevent replays.
        let _ = redis_del(redis, &key).await;
        state.ok_or_else(|| {
            log::error!("No authentication state found for challenge: {}", challenge_b64);
            actix_web::error::ErrorBadRequest("No authentication in progress")
        })?
    } else {
        let state = app_state
            .passkey_auth_states
            .get(challenge_b64)
            .ok_or_else(|| {
                log::error!("No authentication state found for challenge: {}", challenge_b64);
                actix_web::error::ErrorBadRequest("No authentication in progress")
            })?;
        app_state.passkey_auth_states.invalidate(challenge_b64);
        state
    };

    // Finish authentication
    let auth_result = app_state
        .webauthn
        .finish_passkey_authentication(&body.credential, &passkey_authentication)
        .map_err(|e| {
            log::error!("Failed to finish passkey authentication: {:?}", e);
            actix_web::error::ErrorBadRequest("Failed to complete authentication")
        })?;

    // Find passkey in database
    let credential_id_b64 = BASE64.encode(auth_result.cred_id());
    let passkey_model = passkey::Entity::find()
        .filter(passkey::Column::CredentialId.eq(&credential_id_b64))
        .one(&app_state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?
        .ok_or_else(|| actix_web::error::ErrorNotFound("Passkey not found"))?;

    // Update last_used_at
    let mut passkey_update: passkey::ActiveModel = passkey_model.clone().into();
    passkey_update.last_used_at = Set(Some(Utc::now().timestamp()));
    passkey_update
        .update(&app_state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    // Update stored credential with counter
    let mut updated_passkey: Passkey =
        serde_json::from_str(&passkey_model.credential_data)
            .map_err(actix_web::error::ErrorInternalServerError)?;
    updated_passkey.update_credential(&auth_result);
    
    let updated_data = serde_json::to_string(&updated_passkey)
        .map_err(actix_web::error::ErrorInternalServerError)?;
    
    let mut passkey_update: passkey::ActiveModel = passkey_model.clone().into();
    passkey_update.credential_data = Set(updated_data);
    passkey_update
        .update(&app_state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    // Create session for this user
    let user_id = passkey_model.user_id.clone();
    let user_model = user::Entity::find_by_id(user_id.clone())
        .one(&app_state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?
        .ok_or_else(|| actix_web::error::ErrorNotFound("User not found"))?;

    // Generate tokens
    let (access_token, refresh_token) = crate::handlers::auth::create_session_for_user(
        &app_state,
        &user_id,
    )
    .await
    .map_err(actix_web::error::ErrorInternalServerError)?;

    log::info!("User {} authenticated with passkey", user_model.username);

    // Set cookies using proper cookie builder (same as login flow)
    Ok(HttpResponse::Ok()
        .cookie(
            actix_web::cookie::Cookie::build("access_token", access_token)
                .path("/")
                .http_only(true)
                .same_site(actix_web::cookie::SameSite::Strict)
                .max_age(actix_web::cookie::time::Duration::seconds(
                    app_state.access_token_expiration,
                ))
                .finish(),
        )
        .cookie(
            actix_web::cookie::Cookie::build("refresh_token", refresh_token)
                .path("/")
                .http_only(true)
                .same_site(actix_web::cookie::SameSite::Strict)
                .max_age(actix_web::cookie::time::Duration::seconds(
                    app_state.refresh_token_expiration,
                ))
                .finish(),
        )
        .json(serde_json::json!({
            "success": true,
            "username": user_model.username,
        })))
}

/// GET /api/v1/passkey/list
pub async fn list_passkeys(
    req: HttpRequest,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let user_id = extract_session_user(&req, &app_state)?;

    let passkeys = passkey::Entity::find()
        .filter(passkey::Column::UserId.eq(user_id.clone()))
        .all(&app_state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let passkey_list: Vec<PasskeyInfo> = passkeys
        .into_iter()
        .map(|pk| PasskeyInfo {
            id: pk.id,
            name: pk.name,
            created_at: Utc
                .timestamp_opt(pk.created_at, 0)
                .single()
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| pk.created_at.to_string()),
            last_used_at: pk.last_used_at.map(|ts| {
                Utc.timestamp_opt(ts, 0)
                    .single()
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_else(|| ts.to_string())
            }),
        })
        .collect();

    Ok(HttpResponse::Ok().json(PasskeyList {
        passkeys: passkey_list,
    }))
}

/// POST /api/v1/passkey/delete
pub async fn delete_passkey(
    req: HttpRequest,
    app_state: web::Data<AppState>,
    body: web::Json<PasskeyDeleteRequest>,
) -> actix_web::Result<HttpResponse> {
    let user_id = extract_session_user(&req, &app_state)?;
    let passkey_id = body.id.clone();

    // Find passkey and verify ownership
    let passkey_model = passkey::Entity::find_by_id(passkey_id.clone())
        .one(&app_state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?
        .ok_or_else(|| actix_web::error::ErrorNotFound("Passkey not found"))?;

    if passkey_model.user_id != user_id {
        return Err(actix_web::error::ErrorForbidden("Not your passkey"));
    }

    // Delete passkey
    passkey::Entity::delete_by_id(passkey_id.clone())
        .exec(&app_state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    log::info!("User {} deleted passkey {}", user_id, passkey_id);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
    })))
}

/// DELETE /api/v1/passkey/{id}
///
/// Route alias for the web UI (matches the frontend's DELETE call).
pub async fn delete_passkey_by_id(
    req: HttpRequest,
    app_state: web::Data<AppState>,
    id: web::Path<String>,
) -> actix_web::Result<HttpResponse> {
    let user_id = extract_session_user(&req, &app_state)?;
    let passkey_id = match Uuid::parse_str(&id.into_inner()) {
        Ok(u) => u.to_string(),
        Err(_) => return Err(actix_web::error::ErrorBadRequest("Invalid passkey id")),
    };

    // Find passkey and verify ownership
    let passkey_model = passkey::Entity::find_by_id(passkey_id.clone())
        .one(&app_state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?
        .ok_or_else(|| actix_web::error::ErrorNotFound("Passkey not found"))?;

    if passkey_model.user_id != user_id {
        return Err(actix_web::error::ErrorForbidden("Not your passkey"));
    }

    // Delete passkey
    passkey::Entity::delete_by_id(passkey_id.clone())
        .exec(&app_state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    log::info!("User {} deleted passkey {}", user_id, passkey_id);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
    })))
}
