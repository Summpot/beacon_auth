use actix_web::{web, HttpRequest, HttpResponse, Responder};
use entity::{identity, user};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, TransactionTrait};
use chrono::Utc;

use beacon_core::username;

use crate::{
    app_state::AppState,
    handlers::auth::get_access_token_from_cookie,
    models::*,
};

/// GET /api/v1/user/me
/// Get current user information
pub async fn get_user_info(
    app_state: web::Data<AppState>,
    req: HttpRequest,
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

    let user_id = match crate::handlers::auth::verify_access_token(&app_state, &access_token) {
        Ok(id) => id,
        Err(e) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "invalid_token".to_string(),
                message: e,
            });
        }
    };

    // Query user from database
    let user_result = user::Entity::find_by_id(user_id)
        .one(&app_state.db)
        .await;

    let user = match user_result {
        Ok(Some(user)) => user,
        Ok(None) => {
            return HttpResponse::NotFound().json(ErrorResponse {
                error: "user_not_found".to_string(),
                message: "User not found".to_string(),
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

    HttpResponse::Ok().json(serde_json::json!({
        "id": user.id,
        "username": user.username,
    }))
}

/// POST /api/v1/user/change-username
/// Change the user's username (Minecraft rules + case-insensitive uniqueness)
pub async fn change_username(
    app_state: web::Data<AppState>,
    req: HttpRequest,
    payload: web::Json<ChangeUsernameRequest>,
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

    let user_id = match crate::handlers::auth::verify_access_token(&app_state, &access_token) {
        Ok(id) => id,
        Err(e) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "invalid_token".to_string(),
                message: e,
            });
        }
    };

    let requested_username = payload.username.trim().to_string();
    if let Err(msg) = username::validate_minecraft_username(&requested_username) {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "invalid_username".to_string(),
            message: msg.to_string(),
        });
    }
    let requested_lower = username::normalize_username(&requested_username);

    // Load current user
    let user_model = match user::Entity::find_by_id(user_id).one(&app_state.db).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return HttpResponse::NotFound().json(ErrorResponse {
                error: "user_not_found".to_string(),
                message: "User not found".to_string(),
            });
        }
        Err(e) => {
            log::error!("Database error (user lookup): {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Database error occurred".to_string(),
            });
        }
    };

    // Check uniqueness (case-insensitive) against other users.
    let existing = match user::Entity::find()
        .filter(user::Column::UsernameLower.eq(&requested_lower))
        .one(&app_state.db)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            log::error!("Database error (username check): {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Database error occurred".to_string(),
            });
        }
    };

    if let Some(other) = existing {
        if other.id != user_model.id {
            return HttpResponse::Conflict().json(ErrorResponse {
                error: "username_taken".to_string(),
                message: "Username already exists".to_string(),
            });
        }
    }

    let now = Utc::now();
    let txn = match app_state.db.begin().await {
        Ok(t) => t,
        Err(e) => {
            log::error!("Failed to begin transaction: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Database error occurred".to_string(),
            });
        }
    };

    // Update user
    let mut user_active: user::ActiveModel = user_model.into();
    user_active.username = Set(requested_username.clone());
    user_active.username_lower = Set(requested_lower.clone());
    user_active.updated_at = Set(now);

    if let Err(e) = user_active.update(&txn).await {
        let _ = txn.rollback().await;
        log::error!("Failed to update user username: {}", e);
        return HttpResponse::InternalServerError().json(ErrorResponse {
            error: "internal_error".to_string(),
            message: "Failed to update username".to_string(),
        });
    }

    // Keep the password identity identifier aligned with the normalized username.
    let password_identity = match identity::Entity::find()
        .filter(identity::Column::UserId.eq(user_id))
        .filter(identity::Column::Provider.eq("password"))
        .one(&txn)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            let _ = txn.rollback().await;
            log::error!("Database error (password identity lookup): {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Database error occurred".to_string(),
            });
        }
    };

    if let Some(identity_model) = password_identity {
        let mut active: identity::ActiveModel = identity_model.into();
        active.provider_user_id = Set(requested_lower.clone());
        active.updated_at = Set(now);
        if let Err(e) = active.update(&txn).await {
            let _ = txn.rollback().await;
            log::error!("Failed to update password identity identifier: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Failed to update username".to_string(),
            });
        }
    }

    if let Err(e) = txn.commit().await {
        log::error!("Failed to commit transaction: {}", e);
        return HttpResponse::InternalServerError().json(ErrorResponse {
            error: "internal_error".to_string(),
            message: "Database error occurred".to_string(),
        });
    }

    HttpResponse::Ok().json(ChangeUsernameResponse {
        success: true,
        username: requested_username,
    })
}

/// POST /api/v1/user/change-password
/// Change user password
pub async fn change_password(
    app_state: web::Data<AppState>,
    req: HttpRequest,
    payload: web::Json<ChangePasswordRequest>,
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

    let user_id = match crate::handlers::auth::verify_access_token(&app_state, &access_token) {
        Ok(id) => id,
        Err(e) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "invalid_token".to_string(),
                message: e,
            });
        }
    };

    // Query user from database
    let user_result = user::Entity::find_by_id(user_id)
        .one(&app_state.db)
        .await;

    let user = match user_result {
        Ok(Some(user)) => user,
        Ok(None) => {
            return HttpResponse::NotFound().json(ErrorResponse {
                error: "user_not_found".to_string(),
                message: "User not found".to_string(),
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

    // Load existing password identity if present.
    let existing_password_identity = match identity::Entity::find()
        .filter(identity::Column::UserId.eq(user_id))
        .filter(identity::Column::Provider.eq("password"))
        .one(&app_state.db)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            log::error!("Database error (password identity lookup): {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Database error occurred".to_string(),
            });
        }
    };

    if let Some(ref identity_model) = existing_password_identity {
        let Some(existing_hash) = identity_model.password_hash.as_deref() else {
            log::error!("Password identity missing password_hash (id={})", identity_model.id);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Invalid password identity".to_string(),
            });
        };

        // Verify current password.
        let password_valid =
            bcrypt::verify(&payload.current_password, existing_hash).unwrap_or(false);

        if !password_valid {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "invalid_password".to_string(),
                message: "Current password is incorrect".to_string(),
            });
        }
    }

    // Validate new password
    if payload.new_password.len() < 6 {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "invalid_password".to_string(),
            message: "New password must be at least 6 characters".to_string(),
        });
    }

    // Hash new password
    let new_password_hash = match bcrypt::hash(&payload.new_password, bcrypt::DEFAULT_COST) {
        Ok(hash) => hash,
        Err(e) => {
            log::error!("Failed to hash password: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Failed to process password".to_string(),
            });
        }
    };

    // Upsert password identity.
    let now = Utc::now();
    if let Some(identity_model) = existing_password_identity {
        let mut active: identity::ActiveModel = identity_model.into();
        active.password_hash = Set(Some(new_password_hash));
        active.updated_at = Set(now);

        match active.update(&app_state.db).await {
            Ok(_) => {
                log::info!("Password changed successfully for user ID: {}", user_id);
                HttpResponse::Ok().json(serde_json::json!({ "success": true }))
            }
            Err(e) => {
                log::error!("Failed to update password identity: {}", e);
                HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "internal_error".to_string(),
                    message: "Failed to update password".to_string(),
                })
            }
        }
    } else {
        let new_identity = identity::ActiveModel {
            user_id: Set(user_id),
            provider: Set("password".to_string()),
            provider_user_id: Set(user.username_lower.clone()),
            password_hash: Set(Some(new_password_hash)),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        };

        match new_identity.insert(&app_state.db).await {
            Ok(_) => {
                log::info!("Password set successfully for user ID: {}", user_id);
                HttpResponse::Ok().json(serde_json::json!({ "success": true }))
            }
            Err(e) => {
                log::error!("Failed to insert password identity: {}", e);
                HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "internal_error".to_string(),
                    message: "Failed to update password".to_string(),
                })
            }
        }
    }
}

/// POST /api/v1/logout
/// Logout user by revoking all their refresh tokens
pub async fn logout(
    app_state: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    // Get and verify access token
    let access_token = match get_access_token_from_cookie(&req) {
        Some(token) => token,
        None => {
            // Already logged out
            return HttpResponse::Ok().json(serde_json::json!({ "success": true }));
        }
    };

    let user_id = match crate::handlers::auth::verify_access_token(&app_state, &access_token) {
        Ok(id) => id,
        Err(_) => {
            // Invalid token, consider already logged out
            return HttpResponse::Ok().json(serde_json::json!({ "success": true }));
        }
    };

    // Revoke all refresh tokens for this user
    use entity::refresh_token;
    match refresh_token::Entity::update_many()
        .filter(refresh_token::Column::UserId.eq(user_id))
        .col_expr(refresh_token::Column::Revoked, sea_orm::sea_query::Expr::value(true))
        .exec(&app_state.db)
        .await
    {
        Ok(_) => {
            log::info!("User logged out successfully: {}", user_id);
        }
        Err(e) => {
            log::error!("Failed to revoke tokens: {}", e);
        }
    }

    // Clear cookies
    HttpResponse::Ok()
        .cookie(
            actix_web::cookie::Cookie::build("access_token", "")
                .path("/")
                .max_age(actix_web::cookie::time::Duration::seconds(0))
                .finish(),
        )
        .cookie(
            actix_web::cookie::Cookie::build("refresh_token", "")
                .path("/")
                .max_age(actix_web::cookie::time::Duration::seconds(0))
                .finish(),
        )
        .json(serde_json::json!({ "success": true }))
}
