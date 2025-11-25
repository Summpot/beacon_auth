use actix_web::{web, HttpRequest, HttpResponse};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use webauthn_rs::prelude::*;

use crate::app_state::AppState;
use crate::handlers::extract_session_user;
use crate::models::{
    PasskeyAuthFinishRequest, PasskeyAuthStartResponse, PasskeyDeleteRequest, PasskeyInfo, PasskeyList,
    PasskeyRegisterFinishRequest, PasskeyRegisterStartRequest, PasskeyRegisterStartResponse,
};
use entity::{passkey, user};

/// POST /api/v1/passkey/register/start
pub async fn register_start(
    req: HttpRequest,
    app_state: web::Data<AppState>,
    _body: web::Json<PasskeyRegisterStartRequest>,
) -> actix_web::Result<HttpResponse> {
    let user_id = extract_session_user(&req, &app_state)?;

    // Find user in database
    let user_model = user::Entity::find_by_id(user_id)
        .one(&app_state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("User not found"))?;

    // Get existing passkeys for this user
    let existing_passkeys = passkey::Entity::find()
        .filter(passkey::Column::UserId.eq(user_id))
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
    let user_uuid = uuid::Uuid::from_u128(user_model.id as u128);
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

    // Store registration state in cache (5-minute TTL)
    app_state
        .passkey_reg_states
        .insert(user_id, passkey_registration);

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

    // Retrieve registration state from cache
    let passkey_registration = app_state
        .passkey_reg_states
        .get(&user_id)
        .ok_or_else(|| actix_web::error::ErrorBadRequest("No registration in progress"))?;
    
    // Remove from cache after retrieval
    app_state.passkey_reg_states.invalidate(&user_id);

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
    let passkey_model = passkey::ActiveModel {
        user_id: Set(user_id),
        credential_id: Set(BASE64.encode(passkey.cred_id())),
        credential_data: Set(credential_data),
        name: Set(body.name.clone().unwrap_or_else(|| "Passkey".to_string())),
        created_at: Set(chrono::Utc::now()),
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
        let user_model = user::Entity::find()
            .filter(user::Column::Username.eq(username))
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
    let challenge_str = BASE64.encode(rcr.public_key.challenge.as_ref());
    app_state
        .passkey_auth_states
        .insert(challenge_str.clone(), passkey_authentication);

    Ok(HttpResponse::Ok().json(PasskeyAuthStartResponse {
        request_options: rcr,
    }))
}

/// POST /api/v1/passkey/auth/finish
pub async fn auth_finish(
    app_state: web::Data<AppState>,
    body: web::Json<PasskeyAuthFinishRequest>,
) -> actix_web::Result<HttpResponse> {
    // Extract challenge from credential response
    let challenge_str = BASE64.encode(&body.credential.response.client_data_json);

    // Retrieve authentication state from cache
    let passkey_authentication = app_state
        .passkey_auth_states
        .get(&challenge_str)
        .ok_or_else(|| actix_web::error::ErrorBadRequest("No authentication in progress"))?;
    
    // Remove from cache after retrieval
    app_state.passkey_auth_states.invalidate(&challenge_str);

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
    passkey_update.last_used_at = Set(Some(chrono::Utc::now()));
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
    let user_id = passkey_model.user_id;
    let user_model = user::Entity::find_by_id(user_id)
        .one(&app_state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?
        .ok_or_else(|| actix_web::error::ErrorNotFound("User not found"))?;

    // Generate tokens
    let (access_cookie_str, refresh_cookie_str) = crate::handlers::auth::create_session_for_user(
        &app_state,
        user_id,
    )
    .await
    .map_err(actix_web::error::ErrorInternalServerError)?;

    log::info!("User {} authenticated with passkey", user_model.username);

    Ok(HttpResponse::Ok()
        .insert_header(("Set-Cookie", access_cookie_str))
        .insert_header(("Set-Cookie", refresh_cookie_str))
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
        .filter(passkey::Column::UserId.eq(user_id))
        .all(&app_state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let passkey_list: Vec<PasskeyInfo> = passkeys
        .into_iter()
        .map(|pk| PasskeyInfo {
            id: pk.id,
            name: pk.name,
            created_at: pk.created_at.to_rfc3339(),
            last_used_at: pk.last_used_at.map(|dt| dt.to_rfc3339()),
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
    let passkey_id = body.id;

    // Find passkey and verify ownership
    let passkey_model = passkey::Entity::find_by_id(passkey_id)
        .one(&app_state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?
        .ok_or_else(|| actix_web::error::ErrorNotFound("Passkey not found"))?;

    if passkey_model.user_id != user_id {
        return Err(actix_web::error::ErrorForbidden("Not your passkey"));
    }

    // Delete passkey
    passkey::Entity::delete_by_id(passkey_id)
        .exec(&app_state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    log::info!("User {} deleted passkey {}", user_id, passkey_id);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
    })))
}
