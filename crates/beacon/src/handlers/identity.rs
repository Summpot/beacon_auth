use actix_web::{web, HttpRequest, HttpResponse};
use entity::{identity, passkey};
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, TransactionTrait};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    handlers::extract_session_user,
    models::{ErrorResponse, IdentitiesResponse, IdentityInfo},
};

/// GET /api/v1/identities
pub async fn list_identities(
    req: HttpRequest,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let user_id = extract_session_user(&req, &app_state)?;

    let identities = identity::Entity::find()
        .filter(identity::Column::UserId.eq(user_id.clone()))
        .order_by_desc(identity::Column::CreatedAt)
        .all(&app_state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let passkey_count = passkey::Entity::find()
        .filter(passkey::Column::UserId.eq(user_id.clone()))
        .count(&app_state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)? as i64;

    let has_password = identities
        .iter()
        .any(|i| i.provider == "password" && i.password_hash.as_deref().is_some());

    let resp = IdentitiesResponse {
        identities: identities
            .into_iter()
            .map(|i| IdentityInfo {
                id: i.id,
                provider: i.provider,
                provider_user_id: i.provider_user_id,
            })
            .collect(),
        has_password,
        passkey_count,
    };

    Ok(HttpResponse::Ok().json(resp))
}

/// DELETE /api/v1/identities/{id}
pub async fn delete_identity_by_id(
    req: HttpRequest,
    app_state: web::Data<AppState>,
    id: web::Path<String>,
) -> actix_web::Result<HttpResponse> {
    let user_id = extract_session_user(&req, &app_state)?;
    let identity_id = match Uuid::parse_str(&id.into_inner()) {
        Ok(u) => u.to_string(),
        Err(_) => {
            return Ok(HttpResponse::BadRequest().json(ErrorResponse {
                error: "invalid_identity_id".to_string(),
                message: "Invalid identity id".to_string(),
            }));
        }
    };

    let txn = app_state
        .db
        .begin()
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let identity_model = match identity::Entity::find_by_id(identity_id.clone())
        .one(&txn)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?
    {
        Some(i) => i,
        None => {
            let _ = txn.rollback().await;
            return Ok(HttpResponse::NotFound().json(ErrorResponse {
                error: "identity_not_found".to_string(),
                message: "Identity not found".to_string(),
            }));
        }
    };

    if identity_model.user_id != user_id {
        let _ = txn.rollback().await;
        return Ok(HttpResponse::Forbidden().json(ErrorResponse {
            error: "forbidden".to_string(),
            message: "Identity does not belong to the current user".to_string(),
        }));
    }

    let identities_count = identity::Entity::find()
        .filter(identity::Column::UserId.eq(&user_id))
        .count(&txn)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)? as i64;

    let passkey_count = passkey::Entity::find()
        .filter(passkey::Column::UserId.eq(&user_id))
        .count(&txn)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)? as i64;

    let remaining_identities = (identities_count - 1).max(0);
    let remaining_methods = remaining_identities
        + if passkey_count > 0 { 1 } else { 0 };

    if remaining_methods <= 0 {
        let _ = txn.rollback().await;
        return Ok(HttpResponse::Conflict().json(ErrorResponse {
            error: "cannot_unlink_last_method".to_string(),
            message: "Cannot unlink the last remaining login method".to_string(),
        }));
    }

    identity::Entity::delete_by_id(identity_id)
        .exec(&txn)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    txn.commit()
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "success": true })))
}
