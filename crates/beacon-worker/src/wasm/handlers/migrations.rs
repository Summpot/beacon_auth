use serde::Deserialize;
use serde_json::json;
use worker::{Env, Fetch, Headers, Method, Request, RequestInit, Response, Result};

use migration::MigratorTrait;

use crate::wasm::{
    db::d1,
    env::env_string,
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
    let Some((scheme, rest)) = raw.split_once(' ') else {
        return Ok(None);
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Ok(None);
    }

    let token = rest.trim();
    if token.is_empty() {
        return Ok(None);
    }

    Ok(Some(token.to_string()))
}

async fn verify_cloudflare_api_token_against_url(token: &str, url: &str) -> Result<CloudflareVerifyResult> {
    let headers = Headers::new();
    headers.set("Authorization", &format!("Bearer {token}"))?;
    headers.set("Accept", "application/json")?;
    // Cloudflare API endpoints sometimes behave better with an explicit UA.
    headers.set("User-Agent", "BeaconAuth/1.0 (Cloudflare Worker)")?;

    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    init.with_headers(headers);

    let cf_req = Request::new_with_init(url, &init)?;

    let mut resp = Fetch::Request(cf_req).send().await?;
    let status = resp.status_code();
    let body = resp.text().await.unwrap_or_default();

    let parsed: CloudflareEnvelope<CloudflareVerifyResult> = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            let snippet = body.chars().take(512).collect::<String>();
            return Err(worker::Error::RustError(format!(
                "Cloudflare verify returned non-JSON body (status={status}): {e}; body_snippet={snippet:?}"
            )));
        }
    };

    if !parsed.success {
        let mut details = String::new();
        if !parsed.errors.is_empty() {
            details.push_str(" errors=");
            details.push_str(
                &parsed
                    .errors
                    .iter()
                    .map(|m| {
                        let code = m.code.map(|c| c.to_string()).unwrap_or_else(|| "?".to_string());
                        let msg = m.message.clone().unwrap_or_else(|| "".to_string());
                        format!("[{code}:{msg}]")
                    })
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        return Err(worker::Error::RustError(format!(
            "Cloudflare API token verification failed (status={status}, url={url}).{details}"
        )));
    }

    parsed.result.ok_or_else(|| {
        worker::Error::RustError(format!(
            "Cloudflare verify response missing result (status={status}, url={url})"
        ))
    })
}

async fn verify_cloudflare_api_token(env: &Env, token: &str) -> Result<CloudflareVerifyResult> {
    // There are two token “families”:
    // - User API tokens: verified via `/user/tokens/verify`
    // - Account API tokens: verified via `/accounts/{account_id}/tokens/verify`
    // See: https://api.cloudflare.com/client/v4/user/tokens/verify
    // See: https://api.cloudflare.com/client/v4/accounts/{account_id}/tokens/verify

    let user_url = "https://api.cloudflare.com/client/v4/user/tokens/verify";
    match verify_cloudflare_api_token_against_url(token, user_url).await {
        Ok(v) => return Ok(v),
        Err(user_err) => {
            if let Some(account_id) = env_string(env, "CLOUDFLARE_ACCOUNT_ID") {
                let account_url = format!(
                    "https://api.cloudflare.com/client/v4/accounts/{account_id}/tokens/verify"
                );
                match verify_cloudflare_api_token_against_url(token, &account_url).await {
                    Ok(v) => return Ok(v),
                    Err(account_err) => {
                        return Err(worker::Error::RustError(format!(
                            "Cloudflare token verification failed. user_verify={user_err}; account_verify={account_err}"
                        )));
                    }
                }
            }

            Err(worker::Error::RustError(format!(
                "Cloudflare token verification failed using user token endpoint, and CLOUDFLARE_ACCOUNT_ID is not configured for account-token verification: {user_err}"
            )))
        }
    }
}

pub async fn handle_migrations_up(req: &Request, env: &worker::Env) -> Result<Response> {
    let Some(token) = extract_bearer_token(req)? else {
        return error_response(req, 401, "missing_token", "Missing Authorization Bearer token");
    };

    let verify = match verify_cloudflare_api_token(env, &token).await {
        Ok(v) => v,
        Err(e) => {
            // Log details server-side (no token included) to diagnose CI issues like IP restrictions.
            worker::console_log!("/v1/admin/migrations/up token verification failed: {e}");
            // Do not leak Cloudflare details to clients.
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
