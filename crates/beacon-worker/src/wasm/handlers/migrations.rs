use serde::Deserialize;
use serde_json::json;
use worker::{Fetch, Headers, Method, Request, RequestInit, Response, Result};

use migration::MigratorTrait;

use crate::wasm::{
    db::d1,
    http::{error_response, internal_error_response, json_with_cors},
};

#[derive(Debug, Deserialize)]
struct CloudflareApiMessage {
    #[allow(dead_code)]
    code: Option<i64>,
    #[allow(dead_code)]
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CloudflareVerifyResult {
    id: String,
    status: String,
    #[allow(dead_code)]
    expires_on: Option<String>,
    #[allow(dead_code)]
    not_before: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CloudflareEnvelope<T> {
    success: bool,
    #[allow(dead_code)]
    errors: Vec<CloudflareApiMessage>,
    #[allow(dead_code)]
    messages: Vec<CloudflareApiMessage>,
    result: Option<T>,
}

fn extract_bearer_token(req: &Request) -> Result<Option<String>> {
    let Some(raw) = req.headers().get("Authorization")? else {
        return Ok(None);
    };

    // Allow some tolerance for casing/whitespace.
    let raw = raw.trim();
    let Some(rest) = raw.strip_prefix("Bearer ") else {
        return Ok(None);
    };

    let token = rest.trim();
    if token.is_empty() {
        return Ok(None);
    }

    Ok(Some(token.to_string()))
}

async fn verify_cloudflare_api_token(token: &str) -> Result<CloudflareVerifyResult> {
    let headers = Headers::new();
    headers.set("Authorization", &format!("Bearer {token}"))?;

    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    init.with_headers(headers);

    let cf_req = Request::new_with_init(
        "https://api.cloudflare.com/client/v4/user/tokens/verify",
        &init,
    )?;

    let mut resp = Fetch::Request(cf_req).send().await?;
    let parsed: CloudflareEnvelope<CloudflareVerifyResult> = resp.json().await?;

    if !parsed.success {
        return Err(worker::Error::RustError(
            "Cloudflare API token verification failed".to_string(),
        ));
    }

    parsed
        .result
        .ok_or_else(|| worker::Error::RustError("Cloudflare verify response missing result".to_string()))
}

pub async fn handle_migrations_up(req: &Request, env: &worker::Env) -> Result<Response> {
    let Some(token) = extract_bearer_token(req)? else {
        return error_response(req, 401, "missing_token", "Missing Authorization Bearer token");
    };

    let verify = match verify_cloudflare_api_token(&token).await {
        Ok(v) => v,
        Err(_e) => {
            // Do not leak token or Cloudflare details to clients.
            return error_response(req, 401, "unauthorized", "Invalid Cloudflare API token");
        }
    };

    let db = match d1(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(req, "Failed to open database binding", &e),
    };

    if let Err(e) = migration::Migrator::up(&db, None).await {
        return internal_error_response(req, "Failed to apply migrations", &e);
    }

    let resp = Response::from_json(&json!({
        "success": true,
        "token": {
            "id": verify.id,
            "status": verify.status,
        },
        "migrations": {
            "applied": true
        }
    }))?;

    json_with_cors(req, resp)
}
