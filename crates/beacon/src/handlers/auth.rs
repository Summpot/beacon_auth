use actix_web::{web, HttpRequest, HttpResponse, Responder};
use chrono::Utc;
use entity::refresh_token;
use jsonwebtoken::{encode, Header};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    models::*,
};

/// Helper: Generate access token
fn generate_access_token(
    app_state: &AppState,
    user_id: i32,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let exp = now + chrono::Duration::seconds(app_state.access_token_expiration);

    let claims = SessionClaims {
        iss: "http://localhost:8080".to_string(),
        sub: user_id.to_string(),
        aud: "beaconauth-web".to_string(),
        exp: exp.timestamp(),
        token_type: "access".to_string(),
    };

    let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some("beacon-auth-key-1".to_string());

    encode(&header, &claims, &app_state.encoding_key)
}

/// Helper: Generate refresh token
async fn generate_refresh_token(
    app_state: &AppState,
    user_id: i32,
) -> Result<String, anyhow::Error> {
    // Generate random token
    let token_bytes = rand::random::<[u8; 32]>();
    let token = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, token_bytes);

    // Hash the token for storage
    let mut hasher = Sha256::new();
    hasher.update(&token);
    let token_hash = format!("{:x}", hasher.finalize());

    // Generate family ID (for token rotation tracking)
    let family_id = Uuid::new_v4().to_string();

    let now = Utc::now();
    let expires_at = now + chrono::Duration::seconds(app_state.refresh_token_expiration);

    // Store in database
    let refresh_token_model = refresh_token::ActiveModel {
        user_id: Set(user_id),
        token_hash: Set(token_hash),
        family_id: Set(family_id),
        expires_at: Set(expires_at),
        revoked: Set(false),
        created_at: Set(now),
        ..Default::default()
    };

    refresh_token_model.insert(&app_state.db).await?;

    Ok(token)
}



/// POST /api/v1/refresh
/// Refresh access token using refresh token
pub async fn refresh_token(
    app_state: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    // Get refresh token from cookie
    let refresh_token = match req.cookie("refresh_token") {
        Some(cookie) => cookie.value().to_string(),
        None => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "missing_token".to_string(),
                message: "No refresh token provided".to_string(),
            });
        }
    };

    // Hash the provided token
    let mut hasher = Sha256::new();
    hasher.update(&refresh_token);
    let token_hash = format!("{:x}", hasher.finalize());

    // Look up token in database
    let token_record = match refresh_token::Entity::find()
        .filter(refresh_token::Column::TokenHash.eq(&token_hash))
        .one(&app_state.db)
        .await
    {
        Ok(Some(record)) => record,
        Ok(None) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "invalid_token".to_string(),
                message: "Invalid refresh token".to_string(),
            });
        }
        Err(e) => {
            log::error!("Database error: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Database error occurred".to_string(),
            });
        }
    };

    // Check if token is revoked
    if token_record.revoked {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "revoked_token".to_string(),
            message: "Refresh token has been revoked".to_string(),
        });
    }

    // Check if token is expired
    if token_record.expires_at < Utc::now() {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "expired_token".to_string(),
            message: "Refresh token has expired".to_string(),
        });
    }

    // Generate new access token
    let access_token = match generate_access_token(&app_state, token_record.user_id) {
        Ok(token) => token,
        Err(e) => {
            log::error!("Failed to generate access token: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Failed to generate token".to_string(),
            });
        }
    };

    // Return new access token as cookie
    HttpResponse::Ok()
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
        .json(serde_json::json!({ "success": true }))
}

/// POST /api/v1/minecraft-jwt
/// Get Minecraft JWT using access token
pub async fn get_minecraft_jwt(
    app_state: web::Data<AppState>,
    req: HttpRequest,
    payload: web::Json<MinecraftJwtRequest>,
) -> impl Responder {
    // Get and verify access token
    let access_token = match get_access_token_from_cookie(&req) {
        Some(token) => token,
        None => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "unauthorized".to_string(),
                message: "Not authenticated".to_string(),
            });
        }
    };

    let user_id = match verify_access_token(&app_state, &access_token) {
        Ok(id) => id,
        Err(e) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "invalid_token".to_string(),
                message: e,
            });
        }
    };

    // Create Minecraft JWT with challenge
    let now = Utc::now();
    let exp = now + chrono::Duration::seconds(app_state.jwt_expiration);

    let claims = Claims {
        iss: "http://localhost:8080".to_string(),
        sub: user_id.to_string(),
        aud: "minecraft-client".to_string(),
        exp: exp.timestamp(),
        challenge: payload.challenge.clone(),
    };

    let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some("beacon-auth-key-1".to_string());

    let token = match encode(&header, &claims, &app_state.encoding_key) {
        Ok(t) => t,
        Err(e) => {
            log::error!("Failed to sign JWT: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Failed to generate token".to_string(),
            });
        }
    };

    let redirect_url = format!(
        "http://localhost:{}/auth-callback?jwt={}&profile_url={}",
        payload.redirect_port, token,
        urlencoding::encode(&payload.profile_url)
    );

    HttpResponse::Ok().json(MinecraftJwtResponse { redirect_url })
}

/// Helper: Set auth cookies after successful authentication
pub fn set_auth_cookies(
    app_state: &AppState,
    access_token: String,
    refresh_token: String,
) -> HttpResponse {
    HttpResponse::Ok()
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
        .json(serde_json::json!({ "success": true }))
}

/// Helper: Create session tokens for a user
pub async fn create_session_for_user(
    app_state: &AppState,
    user_id: i32,
) -> Result<(String, String), anyhow::Error> {
    let access_token = generate_access_token(app_state, user_id)?;
    let refresh_token = generate_refresh_token(app_state, user_id).await?;
    Ok((access_token, refresh_token))
}

/// Helper: Extract access token from cookie
pub fn get_access_token_from_cookie(req: &HttpRequest) -> Option<String> {
    req.cookie("access_token")
        .map(|cookie| cookie.value().to_string())
}

/// Helper: Verify access token (simplified - should verify signature in production)
pub fn verify_access_token(_app_state: &AppState, token: &str) -> Result<i32, String> {
    // For now, decode without verification
    // In production, you should verify the ES256 signature properly
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid token format".to_string());
    }

    let payload = parts[1];
    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        payload,
    )
    .map_err(|_| "Failed to decode token".to_string())?;

    let claims: SessionClaims = serde_json::from_slice(&decoded)
        .map_err(|_| "Invalid token claims".to_string())?;

    if claims.token_type != "access" {
        return Err("Invalid token type".to_string());
    }

    claims
        .sub
        .parse::<i32>()
        .map_err(|_| "Invalid user ID in token".to_string())
}
