use beacon_core::models;
use chrono::Utc;
use worker::{Env, Request, Response, Result};

use crate::wasm::{
    cookies::{get_cookie},
    db::{d1, d1_user_by_id},
    http::{json_with_cors},
    jwt::{sign_jwt, verify_access_token},
    state::get_jwt_state,
};

pub async fn handle_minecraft_jwt(mut req: Request, env: &Env) -> Result<Response> {
    let jwt = get_jwt_state(env).await?;

    let payload: models::MinecraftJwtRequest = req.json().await?;

    let Some(access_token) = get_cookie(&req, "access_token")? else {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "unauthorized".to_string(),
            message: "Not authenticated. Please log in again.".to_string(),
        })?
        .with_status(401);
        return json_with_cors(&req, resp);
    };

    let user_id = match verify_access_token(jwt, &access_token) {
        Ok(id) => id,
        Err(e) => {
            let resp = Response::from_json(&models::ErrorResponse {
                error: "unauthorized".to_string(),
                message: format!("Not authenticated. Please log in again. ({e})"),
            })?
            .with_status(401);
            return json_with_cors(&req, resp);
        }
    };

    let db = d1(env).await?;
    let Some(user) = d1_user_by_id(&db, &user_id).await? else {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "unauthorized".to_string(),
            message: "Not authenticated. Please log in again.".to_string(),
        })?
        .with_status(401);
        return json_with_cors(&req, resp);
    };

    let now = Utc::now();
    let exp = now + chrono::Duration::seconds(jwt.jwt_expiration);

    let claims = models::Claims {
        iss: jwt.issuer.clone(),
        sub: user_id.to_string(),
        aud: "minecraft-client".to_string(),
        username: user.username,
        exp: exp.timestamp(),
        challenge: payload.challenge.clone(),
    };

    let token = sign_jwt(jwt, &claims)?;

    let redirect_url = format!(
        "http://localhost:{}/auth-callback?jwt={}&profile_url={}",
        payload.redirect_port,
        token,
        urlencoding::encode(&payload.profile_url)
    );

    let resp = Response::from_json(&models::MinecraftJwtResponse { redirect_url })?;
    json_with_cors(&req, resp)
}
