use beacon_core::models;
use worker::{Env, Request, Response, Result};

use crate::wasm::{
    cookies::get_cookie,
    db::{
        d1, d1_count_identities_by_user_id, d1_count_passkeys_by_user_id, d1_delete_identity_by_id,
        d1_identities_by_user_id, d1_identity_by_id, d1_user_by_id,
    },
    http::{error_response, internal_error_response, json_with_cors},
    jwt::verify_access_token,
    state::get_jwt_state,
};

pub async fn handle_identities_list(req: &Request, env: &Env) -> Result<Response> {
    let db = match d1(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(req, "Failed to open database binding", &e),
    };
    let jwt = match get_jwt_state(env) {
        Ok(jwt) => jwt,
        Err(e) => return internal_error_response(req, "Failed to initialize JWT state", &e),
    };

    let Some(access_token) = get_cookie(req, "access_token")? else {
        return error_response(req, 401, "unauthorized", "Not authenticated");
    };

    let user_id = match verify_access_token(jwt, &access_token) {
        Ok(id) => id,
        Err(e) => return error_response(req, 401, "invalid_token", e),
    };

    let Some(_user) = d1_user_by_id(&db, &user_id).await? else {
        return error_response(req, 404, "user_not_found", "User not found");
    };

    let identities = d1_identities_by_user_id(&db, &user_id).await?;
    let passkey_count = d1_count_passkeys_by_user_id(&db, &user_id).await?;
    let has_password = identities
        .iter()
        .any(|i| i.provider == "password" && i.password_hash.as_deref().is_some());

    let resp = Response::from_json(&models::IdentitiesResponse {
        identities: identities
            .into_iter()
            .map(|i| models::IdentityInfo {
                id: i.id,
                provider: i.provider,
                provider_user_id: i.provider_user_id,
            })
            .collect(),
        has_password,
        passkey_count,
    })?;

    json_with_cors(req, resp)
}

pub async fn handle_identity_delete_by_id(req: &Request, env: &Env, identity_id: String) -> Result<Response> {
    let db = match d1(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(req, "Failed to open database binding", &e),
    };
    let jwt = match get_jwt_state(env) {
        Ok(jwt) => jwt,
        Err(e) => return internal_error_response(req, "Failed to initialize JWT state", &e),
    };

    let Some(access_token) = get_cookie(req, "access_token")? else {
        return error_response(req, 401, "unauthorized", "Not authenticated");
    };

    let user_id = match verify_access_token(jwt, &access_token) {
        Ok(id) => id,
        Err(e) => return error_response(req, 401, "invalid_token", e),
    };

    let Some(_user) = d1_user_by_id(&db, &user_id).await? else {
        return error_response(req, 404, "user_not_found", "User not found");
    };

    let Some(identity) = d1_identity_by_id(&db, &identity_id).await? else {
        return error_response(req, 404, "identity_not_found", "Identity not found");
    };

    if identity.user_id != user_id {
        return error_response(req, 403, "forbidden", "Identity does not belong to the current user");
    }

    // Enforce: the user must keep at least one login method.
    let identities_count = d1_count_identities_by_user_id(&db, &user_id).await?;
    let passkey_count = d1_count_passkeys_by_user_id(&db, &user_id).await?;
    let remaining_identities = (identities_count - 1).max(0);
    let remaining_methods = remaining_identities
        + if passkey_count > 0 { 1 } else { 0 };

    if remaining_methods <= 0 {
        return error_response(
            req,
            409,
            "cannot_unlink_last_method",
            "Cannot unlink the last remaining login method",
        );
    }

    if let Err(e) = d1_delete_identity_by_id(&db, &identity_id).await {
        return internal_error_response(req, "Failed to delete identity", &e);
    }

    let resp = Response::from_json(&serde_json::json!({ "success": true }))?;
    json_with_cors(req, resp)
}
