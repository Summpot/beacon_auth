use beacon_core::models;
use worker::{Env, Request, Response, Result};

use crate::wasm::{env::env_string, http::json_with_cors, state::get_jwt_state};

pub async fn handle_get_config(req: &Request, env: &Env) -> Result<Response> {
    // We can infer OAuth config from env variables, even if Workers OAuth routes are not enabled yet.
    let github_ok = env_string(env, "GITHUB_CLIENT_ID").is_some()
        && env_string(env, "GITHUB_CLIENT_SECRET").is_some();
    let google_ok = env_string(env, "GOOGLE_CLIENT_ID").is_some()
        && env_string(env, "GOOGLE_CLIENT_SECRET").is_some();
    let microsoft_ok = env_string(env, "MICROSOFT_CLIENT_ID").is_some()
        && env_string(env, "MICROSOFT_CLIENT_SECRET").is_some();

    let body = models::ConfigResponse {
        database_auth: true,
        github_oauth: github_ok,
        google_oauth: google_ok,
        microsoft_oauth: microsoft_ok,
    };

    let resp = Response::from_json(&body)?;
    json_with_cors(req, resp)
}

pub async fn handle_get_jwks(req: &Request, env: &Env) -> Result<Response> {
    let jwt = get_jwt_state(env).await?;
    let mut resp = Response::ok(jwt.jwks_json.clone())?;
    resp.headers_mut().set("Content-Type", "application/json")?;
    json_with_cors(req, resp)
}
