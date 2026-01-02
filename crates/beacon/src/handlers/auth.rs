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

/// Token pair returned from token generation
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub family_id: String,
}

/// Helper: Generate a raw JWT token with given claims
/// This is the core JWT generation logic used by all token types
fn generate_jwt<T: serde::Serialize>(
    app_state: &AppState,
    claims: &T,
) -> Result<String, jsonwebtoken::errors::Error> {
    let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(app_state.jwt_kid.clone());
    encode(&header, claims, &app_state.encoding_key)
}

/// Helper: Generate a pair of access and refresh tokens atomically
/// This ensures tokens are always created together with proper family_id tracking
async fn create_token_pair(
    app_state: &AppState,
    user_id: &str,
    family_id: Option<String>,
) -> Result<TokenPair, anyhow::Error> {
    let now = Utc::now();
    let now_ts = now.timestamp();

    // Generate access token using the unified JWT generator
    let access_exp = now + chrono::Duration::seconds(app_state.access_token_expiration);
    let access_claims = SessionClaims {
        iss: app_state.oauth_config.redirect_base.clone(),
        sub: user_id.to_string(),
        aud: "beaconauth-web".to_string(),
        exp: access_exp.timestamp(),
        token_type: "access".to_string(),
    };

    let access_token = generate_jwt(app_state, &access_claims)?;

    // Generate refresh token
    let token_bytes = rand::random::<[u8; 32]>();
    let refresh_token = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, token_bytes);

    // Hash the refresh token for storage
    let mut hasher = Sha256::new();
    hasher.update(&refresh_token);
    let token_hash = format!("{:x}", hasher.finalize());

    // Use existing family_id or create new one
    let token_family_id = family_id.unwrap_or_else(|| Uuid::new_v4().to_string());

    let refresh_exp = now_ts + app_state.refresh_token_expiration;

    let refresh_token_id = Uuid::now_v7().to_string();

    // Store refresh token in database
    let refresh_token_model = refresh_token::ActiveModel {
        id: Set(refresh_token_id),
        user_id: Set(user_id.to_string()),
        token_hash: Set(token_hash),
        family_id: Set(token_family_id.clone()),
        expires_at: Set(refresh_exp),
        revoked: Set(0_i64),
        created_at: Set(now_ts),
        ..Default::default()
    };

    refresh_token_model.insert(&app_state.db).await?;

    Ok(TokenPair {
        access_token,
        refresh_token,
        family_id: token_family_id,
    })
}



/// POST /api/v1/refresh
/// Refresh access token using refresh token with token rotation
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
    if token_record.revoked != 0 {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "revoked_token".to_string(),
            message: "Refresh token has been revoked".to_string(),
        });
    }

    // Check if token is expired
    if token_record.expires_at < Utc::now().timestamp() {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "expired_token".to_string(),
            message: "Refresh token has expired".to_string(),
        });
    }

    // Save user_id and family_id for token rotation
    let user_id = token_record.user_id.clone();
    let family_id = token_record.family_id.clone();

    // Revoke old refresh token (for rotation security)
    let mut token_to_revoke: refresh_token::ActiveModel = token_record.into();
    token_to_revoke.revoked = Set(1_i64);
    if let Err(e) = token_to_revoke.update(&app_state.db).await {
        log::error!("Failed to revoke old refresh token: {}", e);
    }

    // Generate new token pair with same family_id (token rotation)
    let token_pair = match create_token_pair(&app_state, &user_id, Some(family_id)).await {
        Ok(pair) => pair,
        Err(e) => {
            log::error!("Failed to generate token pair: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Failed to generate tokens".to_string(),
            });
        }
    };

    // Return new tokens as cookies
    HttpResponse::Ok()
        .cookie(
            actix_web::cookie::Cookie::build("access_token", token_pair.access_token)
                .path("/")
                .http_only(true)
                .same_site(actix_web::cookie::SameSite::Strict)
                .max_age(actix_web::cookie::time::Duration::seconds(
                    app_state.access_token_expiration,
                ))
                .finish(),
        )
        .cookie(
            actix_web::cookie::Cookie::build("refresh_token", token_pair.refresh_token)
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

/// POST /api/v1/minecraft-jwt
/// Get Minecraft JWT using access token
/// This endpoint ONLY generates the Minecraft-specific JWT for client-server communication.
/// It does NOT refresh or modify session tokens - that should only happen during login or explicit refresh.
pub async fn get_minecraft_jwt(
    app_state: web::Data<AppState>,
    req: HttpRequest,
    payload: web::Json<MinecraftJwtRequest>,
) -> impl Responder {
    // Get user_id from access token (no automatic refresh)
    let user_id = match get_access_token_from_cookie(&req) {
        Some(access_token) => {
            match verify_access_token(&app_state, &access_token) {
                Ok(id) => id,
                Err(e) => {
                    log::warn!("Invalid access token for minecraft-jwt: {}", e);
                    return HttpResponse::Unauthorized().json(ErrorResponse {
                        error: "unauthorized".to_string(),
                        message: "Not authenticated. Please log in again.".to_string(),
                    });
                }
            }
        }
        None => {
            log::warn!("No access token provided for minecraft-jwt");
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "unauthorized".to_string(),
                message: "Not authenticated. Please log in again.".to_string(),
            });
        }
    };

    // Create Minecraft JWT with challenge using the unified JWT generator
    let now = Utc::now();
    let exp = now + chrono::Duration::seconds(app_state.jwt_expiration);

    let claims = Claims {
        iss: app_state.oauth_config.redirect_base.clone(),
        sub: user_id.to_string(),
        aud: "minecraft-client".to_string(),
        exp: exp.timestamp(),
        challenge: payload.challenge.clone(),
    };

    let token = match generate_jwt(&app_state, &claims) {
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
/// Returns a tuple of (access_token, refresh_token) for backward compatibility
pub async fn create_session_for_user(
    app_state: &AppState,
    user_id: &str,
) -> Result<(String, String), anyhow::Error> {
    let token_pair = create_token_pair(app_state, user_id, None).await?;
    Ok((token_pair.access_token, token_pair.refresh_token))
}

/// Helper: Extract access token from cookie
pub fn get_access_token_from_cookie(req: &HttpRequest) -> Option<String> {
    req.cookie("access_token")
        .map(|cookie| cookie.value().to_string())
}

/// Helper: Verify access token with proper ES256 signature verification
pub fn verify_access_token(app_state: &AppState, token: &str) -> Result<String, String> {
    // Create validation for ES256 tokens
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_issuer(&[&app_state.oauth_config.redirect_base]);
    validation.set_audience(&["beaconauth-web"]);
    validation.validate_exp = true;

    // Decode and validate JWT with signature verification
    let token_data = jsonwebtoken::decode::<SessionClaims>(
        token,
        &app_state.decoding_key,
        &validation,
    )
    .map_err(|e| {
        log::debug!("Failed to decode access token: {:?}", e);
        format!("Invalid access token: {:?}", e)
    })?;

    // Verify token type
    if token_data.claims.token_type != "access" {
        return Err("Invalid token type".to_string());
    }

    // Parse and normalize user ID from subject claim.
    // We store user ids as UUIDv7 strings.
    let user_id = Uuid::parse_str(&token_data.claims.sub)
        .map_err(|_| "Invalid user ID in token".to_string())?
        .to_string();

    Ok(user_id)
}


