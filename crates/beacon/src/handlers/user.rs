use actix_web::{web, HttpRequest, HttpResponse, Responder};
use entity::user;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use chrono::Utc;

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

    // Verify current password
    let password_valid = bcrypt::verify(&payload.current_password, &user.password_hash).unwrap_or(false);

    if !password_valid {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "invalid_password".to_string(),
            message: "Current password is incorrect".to_string(),
        });
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

    // Update password in database
    let mut user_active: user::ActiveModel = user.into();
    user_active.password_hash = Set(new_password_hash);
    user_active.updated_at = Set(Utc::now());

    match user_active.update(&app_state.db).await {
        Ok(_) => {
            log::info!("Password changed successfully for user ID: {}", user_id);
            HttpResponse::Ok().json(serde_json::json!({ "success": true }))
        }
        Err(e) => {
            log::error!("Failed to update password: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Failed to update password".to_string(),
            })
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
