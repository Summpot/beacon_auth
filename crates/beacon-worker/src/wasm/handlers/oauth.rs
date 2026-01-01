use beacon_core::{models, oauth};
use chrono::Utc;
use worker::{Env, Fetch, Headers, Method, Request, RequestInit, Response, Result};

use crate::wasm::{
    cookies::{append_set_cookie, cookie_kv, get_cookie},
    db::{
        d1, d1_identity_by_provider_user_id, d1_insert_identity, d1_insert_refresh_token,
        d1_insert_user, d1_user_by_id, d1_user_by_username,
    },
    env::env_string,
    http::{error_response, internal_error_response, json_with_cors},
    jwt::{sign_jwt, verify_access_token},
    state::get_jwt_state,
    util::{new_family_id, new_refresh_token, query_param, redact_oauth_token_body_for_log, sha256_hex},
};

async fn exchange_github_code(
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<(String, String)> {
    let client_id_hint = {
        // Client ID is not secret, but keep logging conservative.
        let prefix = client_id.chars().take(6).collect::<String>();
        format!("len={}, prefix='{}'", client_id.len(), prefix)
    };

    let form_body = format!(
        "client_id={}&client_secret={}&code={}&redirect_uri={}",
        urlencoding::encode(client_id),
        urlencoding::encode(client_secret),
        urlencoding::encode(code),
        urlencoding::encode(redirect_uri)
    );

    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(form_body.into()));
    let headers = Headers::new();
    headers.set("Accept", "application/json")?;
    headers.set("Content-Type", "application/x-www-form-urlencoded")?;
    init.with_headers(headers);

    let token_req = Request::new_with_init("https://github.com/login/oauth/access_token", &init)?;
    let mut token_resp = Fetch::Request(token_req).send().await?;

    let status = token_resp.status_code();
    let token_body = token_resp.text().await?;

    if status >= 400 {
        let safe = redact_oauth_token_body_for_log(&token_body);
        return Err(worker::Error::RustError(format!(
            "GitHub token exchange failed ({status}): {safe}"
        )));
    }

    // GitHub sometimes returns HTTP 200 with an error payload.
    // We must inspect the body, not just the status code.
    let access_token = match oauth::parse_access_token_from_token_exchange_body(&token_body) {
        Ok(tok) => tok,
        Err(oauth::OAuthTokenParseError::ProviderError(e)) => {
            return Err(worker::Error::RustError(format!(
                "GitHub token exchange returned error '{}': {}{} (check GITHUB_CLIENT_ID/GITHUB_CLIENT_SECRET; client_id {client_id_hint}; callback URL: {redirect_uri})",
                e.error,
                e.error_description.unwrap_or_default(),
                e.error_uri.map(|u| format!(" ({u})")).unwrap_or_default(),
            )));
        }
        Err(other) => {
            let safe = redact_oauth_token_body_for_log(&token_body);
            return Err(worker::Error::RustError(format!(
                "GitHub token exchange failed (status {status}): {other}. Response: {safe} (client_id {client_id_hint}; callback URL: {redirect_uri})"
            )));
        }
    };

    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    let headers = Headers::new();
    headers.set("Accept", "application/json")?;
    headers.set("Authorization", &format!("Bearer {access_token}"))?;
    headers.set("User-Agent", "BeaconAuth")?;
    init.with_headers(headers);

    let user_req = Request::new_with_init("https://api.github.com/user", &init)?;
    let mut user_resp = Fetch::Request(user_req).send().await?;

    if user_resp.status_code() >= 400 {
        let status = user_resp.status_code();
        let body = user_resp.text().await?;
        return Err(worker::Error::RustError(format!(
            "GitHub user fetch failed ({status}): {body}"
        )));
    }

    let user_json: serde_json::Value = user_resp.json().await?;
    let user_id = user_json
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| worker::Error::RustError("No user id in GitHub response".to_string()))?
        .to_string();

    let username_raw = user_json
        .get("login")
        .and_then(|v| v.as_str())
        .ok_or_else(|| worker::Error::RustError("No login in GitHub response".to_string()))?;

    Ok((user_id, username_raw.to_string()))
}

async fn exchange_google_code(
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<(String, String)> {
    let form_body = format!(
        "client_id={}&client_secret={}&code={}&grant_type=authorization_code&redirect_uri={}",
        urlencoding::encode(client_id),
        urlencoding::encode(client_secret),
        urlencoding::encode(code),
        urlencoding::encode(redirect_uri)
    );

    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(form_body.into()));
    let headers = Headers::new();
    headers.set("Accept", "application/json")?;
    headers.set("Content-Type", "application/x-www-form-urlencoded")?;
    init.with_headers(headers);

    let token_req = Request::new_with_init("https://oauth2.googleapis.com/token", &init)?;
    let mut token_resp = Fetch::Request(token_req).send().await?;

    if token_resp.status_code() >= 400 {
        let status = token_resp.status_code();
        let body = token_resp.text().await?;
        return Err(worker::Error::RustError(format!(
            "Google token exchange failed ({status}): {body}"
        )));
    }

    let token_json: serde_json::Value = token_resp.json().await?;
    let access_token = token_json
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| worker::Error::RustError("No access_token in Google response".to_string()))?;

    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    let headers = Headers::new();
    headers.set("Accept", "application/json")?;
    headers.set("Authorization", &format!("Bearer {access_token}"))?;
    init.with_headers(headers);

    let user_req = Request::new_with_init("https://www.googleapis.com/oauth2/v2/userinfo", &init)?;
    let mut user_resp = Fetch::Request(user_req).send().await?;

    if user_resp.status_code() >= 400 {
        let status = user_resp.status_code();
        let body = user_resp.text().await?;
        return Err(worker::Error::RustError(format!(
            "Google user fetch failed ({status}): {body}"
        )));
    }

    let user_json: serde_json::Value = user_resp.json().await?;
    let user_id = user_json
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| worker::Error::RustError("No user id in Google response".to_string()))?
        .to_string();

    let email = user_json
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or_else(|| worker::Error::RustError("No email in Google response".to_string()))?;

    let username_raw = email.split('@').next().unwrap_or(email);
    Ok((user_id, username_raw.to_string()))
}

pub async fn handle_oauth_start(mut req: Request, env: &Env) -> Result<Response> {
    let payload: models::OAuthStartPayload = match req.json().await {
        Ok(p) => p,
        Err(e) => {
            worker::console_log!("Invalid JSON in /v1/oauth/start: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };

    let jwt = get_jwt_state(env)?;

    // Stateless OAuth state: encode as a signed JWT so callbacks work across instances.
    let now = Utc::now();
    let exp = now + chrono::Duration::minutes(10);
    let state_id = uuid::Uuid::new_v4().to_string();

    let claims = models::OAuthStateClaims {
        iss: jwt.issuer.clone(),
        sub: state_id,
        aud: "beaconauth-oauth".to_string(),
        exp: exp.timestamp(),
        iat: now.timestamp(),
        token_type: "oauth_state".to_string(),
        provider: payload.provider.clone(),
        challenge: if payload.challenge.is_empty() {
            None
        } else {
            Some(payload.challenge.clone())
        },
        redirect_port: if payload.redirect_port == 0 {
            None
        } else {
            Some(payload.redirect_port)
        },
        link_user_id: None,
    };

    let state_token = match sign_jwt(jwt, &claims) {
        Ok(t) => t,
        Err(e) => return internal_error_response(&req, "Failed to encode OAuth state JWT", &e),
    };

    let redirect_base = jwt.issuer.trim_end_matches('/');
    let callback_url = format!("{redirect_base}/api/v1/oauth/callback");

    let authorization_url = match payload.provider.as_str() {
        "github" => {
            let github_ok = env_string(env, "GITHUB_CLIENT_ID").is_some()
                && env_string(env, "GITHUB_CLIENT_SECRET").is_some();
            if !github_ok {
                return error_response(&req, 503, "oauth_not_configured", "GitHub OAuth is not configured");
            }
            let client_id = env_string(env, "GITHUB_CLIENT_ID").expect("checked above");
            format!(
                "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=read:user%20user:email&state={}",
                urlencoding::encode(&client_id),
                urlencoding::encode(&callback_url),
                urlencoding::encode(&state_token)
            )
        }
        "google" => {
            let google_ok = env_string(env, "GOOGLE_CLIENT_ID").is_some()
                && env_string(env, "GOOGLE_CLIENT_SECRET").is_some();
            if !google_ok {
                return error_response(&req, 503, "oauth_not_configured", "Google OAuth is not configured");
            }
            let client_id = env_string(env, "GOOGLE_CLIENT_ID").expect("checked above");
            format!(
                "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}",
                urlencoding::encode(&client_id),
                urlencoding::encode(&callback_url),
                urlencoding::encode(&state_token)
            )
        }
        _ => {
            return error_response(&req, 400, "invalid_provider", "Unsupported OAuth provider");
        }
    };

    let resp = Response::from_json(&models::OAuthStartResponse { authorization_url })?;
    json_with_cors(&req, resp)
}

/// POST /api/v1/oauth/link/start
///
/// Starts an OAuth flow that links the provider identity to the currently-authenticated user.
///
/// NOTE: because our session cookies are SameSite=Strict, the browser will typically NOT send
/// cookies on the cross-site redirect back from the OAuth provider. Therefore the user id must
/// be encoded in the signed `state` JWT.
pub async fn handle_oauth_link_start(mut req: Request, env: &Env) -> Result<Response> {
    let payload: models::OAuthStartPayload = match req.json().await {
        Ok(p) => p,
        Err(e) => {
            worker::console_log!("Invalid JSON in /v1/oauth/link/start: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };

    let jwt = get_jwt_state(env)?;
    let Some(access_token) = get_cookie(&req, "access_token")? else {
        return error_response(&req, 401, "unauthorized", "Not authenticated");
    };

    let link_user_id = match verify_access_token(jwt, &access_token) {
        Ok(id) => id as i64,
        Err(e) => return error_response(&req, 401, "invalid_token", e),
    };

    // Stateless OAuth state: encode as a signed JWT so callbacks work across instances.
    let now = Utc::now();
    let exp = now + chrono::Duration::minutes(10);
    let state_id = uuid::Uuid::new_v4().to_string();

    let claims = models::OAuthStateClaims {
        iss: jwt.issuer.clone(),
        sub: state_id,
        aud: "beaconauth-oauth".to_string(),
        exp: exp.timestamp(),
        iat: now.timestamp(),
        token_type: "oauth_state".to_string(),
        provider: payload.provider.clone(),
        challenge: if payload.challenge.is_empty() {
            None
        } else {
            Some(payload.challenge.clone())
        },
        redirect_port: if payload.redirect_port == 0 {
            None
        } else {
            Some(payload.redirect_port)
        },
        link_user_id: Some(link_user_id),
    };

    let state_token = match sign_jwt(jwt, &claims) {
        Ok(t) => t,
        Err(e) => return internal_error_response(&req, "Failed to encode OAuth state JWT", &e),
    };

    let redirect_base = jwt.issuer.trim_end_matches('/');
    let callback_url = format!("{redirect_base}/api/v1/oauth/callback");

    let authorization_url = match payload.provider.as_str() {
        "github" => {
            let github_ok = env_string(env, "GITHUB_CLIENT_ID").is_some()
                && env_string(env, "GITHUB_CLIENT_SECRET").is_some();
            if !github_ok {
                return error_response(
                    &req,
                    503,
                    "oauth_not_configured",
                    "GitHub OAuth is not configured",
                );
            }
            let client_id = env_string(env, "GITHUB_CLIENT_ID").expect("checked above");
            format!(
                "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=read:user%20user:email&state={}",
                urlencoding::encode(&client_id),
                urlencoding::encode(&callback_url),
                urlencoding::encode(&state_token)
            )
        }
        "google" => {
            let google_ok = env_string(env, "GOOGLE_CLIENT_ID").is_some()
                && env_string(env, "GOOGLE_CLIENT_SECRET").is_some();
            if !google_ok {
                return error_response(
                    &req,
                    503,
                    "oauth_not_configured",
                    "Google OAuth is not configured",
                );
            }
            let client_id = env_string(env, "GOOGLE_CLIENT_ID").expect("checked above");
            format!(
                "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}",
                urlencoding::encode(&client_id),
                urlencoding::encode(&callback_url),
                urlencoding::encode(&state_token)
            )
        }
        _ => {
            return error_response(&req, 400, "invalid_provider", "Unsupported OAuth provider");
        }
    };

    let resp = Response::from_json(&models::OAuthStartResponse { authorization_url })?;
    json_with_cors(&req, resp)
}

pub async fn handle_oauth_callback(req: &Request, env: &Env) -> Result<Response> {
    let url = req.url()?;
    let Some(code) = query_param(&url, "code") else {
        return error_response(req, 400, "missing_code", "Missing OAuth code");
    };
    let Some(state_token) = query_param(&url, "state") else {
        return error_response(req, 400, "missing_state", "Missing OAuth state");
    };

    let jwt = get_jwt_state(env)?;

    // Validate and decode stateless OAuth state
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_issuer(&[&jwt.issuer]);
    validation.set_audience(&["beaconauth-oauth"]);
    validation.validate_exp = true;

    let oauth_state = match jsonwebtoken::decode::<models::OAuthStateClaims>(
        &state_token,
        &jwt.decoding_key,
        &validation,
    ) {
        Ok(data) => data.claims,
        Err(e) => {
            worker::console_log!("Invalid OAuth state token: {e:?}");
            return error_response(req, 400, "invalid_oauth_state", "Invalid or expired OAuth state");
        }
    };

    if oauth_state.token_type != "oauth_state" {
        return error_response(req, 400, "invalid_oauth_state", "Invalid OAuth state");
    }

    let (provider_user_id, username) = match oauth_state.provider.as_str() {
        "github" => {
            let Some(client_id) = env_string(env, "GITHUB_CLIENT_ID") else {
                return error_response(req, 503, "oauth_not_configured", "GitHub OAuth is not configured");
            };
            let Some(client_secret) = env_string(env, "GITHUB_CLIENT_SECRET") else {
                return error_response(req, 503, "oauth_not_configured", "GitHub OAuth is not configured");
            };
            let redirect_base = jwt.issuer.trim_end_matches('/');
            let callback_url = format!("{redirect_base}/api/v1/oauth/callback");
            match exchange_github_code(&client_id, &client_secret, &code, &callback_url).await {
                Ok(v) => v,
                Err(e) => return internal_error_response(req, "GitHub authentication failed", &e),
            }
        }
        "google" => {
            let Some(client_id) = env_string(env, "GOOGLE_CLIENT_ID") else {
                return error_response(req, 503, "oauth_not_configured", "Google OAuth is not configured");
            };
            let Some(client_secret) = env_string(env, "GOOGLE_CLIENT_SECRET") else {
                return error_response(req, 503, "oauth_not_configured", "Google OAuth is not configured");
            };

            let redirect_base = jwt.issuer.trim_end_matches('/');
            let callback_url = format!("{redirect_base}/api/v1/oauth/callback");
            match exchange_google_code(&client_id, &client_secret, &code, &callback_url).await {
                Ok(v) => v,
                Err(e) => return internal_error_response(req, "Google authentication failed", &e),
            }
        }
        _ => return error_response(req, 400, "invalid_provider", "Invalid provider"),
    };

    let db = match d1(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(req, "Failed to open database binding", &e),
    };

    // Identity-first resolution: provider+provider_user_id is the stable key.
    // This allows a single canonical user to link multiple identities.
    let existing_identity = match d1_identity_by_provider_user_id(&db, &oauth_state.provider, &provider_user_id).await {
        Ok(v) => v,
        Err(e) => return internal_error_response(req, "Failed to query identity", &e),
    };

    let user = if let Some(identity) = existing_identity {
        // Existing linked identity -> canonical user
        match d1_user_by_id(&db, identity.user_id).await {
            Ok(Some(u)) => {
                if let Some(link_user_id) = oauth_state.link_user_id {
                    // Link flow: ensure the identity is linked to the intended user.
                    if identity.user_id != link_user_id as i64 {
                        return error_response(
                            req,
                            409,
                            "identity_already_linked",
                            "This OAuth account is already linked to a different user",
                        );
                    }
                }
                u
            }
            Ok(None) => {
                return internal_error_response(req, "Linked user not found", &"user missing");
            }
            Err(e) => return internal_error_response(req, "Failed to load linked user", &e),
        }
    } else if let Some(link_user_id) = oauth_state.link_user_id {
        // Link flow: attach this identity to the intended user.
        let target_user = match d1_user_by_id(&db, link_user_id as i64).await {
            Ok(Some(u)) => u,
            Ok(None) => return error_response(req, 404, "user_not_found", "User not found"),
            Err(e) => return internal_error_response(req, "Failed to load link target user", &e),
        };

        match d1_insert_identity(&db, target_user.id, &oauth_state.provider, &provider_user_id, None).await {
            Ok(_) => {}
            Err(e) => {
                let msg = e.to_string();
                if msg.to_ascii_lowercase().contains("unique") {
                    return error_response(
                        req,
                        409,
                        "identity_already_linked",
                        "This OAuth account is already linked",
                    );
                }
                return internal_error_response(req, "Failed to link identity", &e);
            }
        }

        target_user
    } else {
        // Login/register flow: no legacy compatibility. If this OAuth identity is new, create a
        // brand-new user (never implicitly link by username).
        let prefix = match oauth_state.provider.as_str() {
            "github" => "gh_",
            "google" => "gg_",
            _ => "id_",
        };

        let mut candidate = String::new();
        for attempt in 0u32..=100u32 {
            let c = beacon_core::username::make_minecraft_username_with_prefix(prefix, &username, attempt);
            if d1_user_by_username(&db, &c).await?.is_none() {
                candidate = c;
                break;
            }
        }

        if candidate.is_empty() {
            return internal_error_response(req, "Failed to allocate unique username", &"too many collisions");
        }

        let user_id = match d1_insert_user(&db, &candidate).await {
            Ok(id) => id,
            Err(e) => return internal_error_response(req, "Failed to create user", &e),
        };
        let Some(new_user) = d1_user_by_id(&db, user_id).await? else {
            return internal_error_response(req, "Failed to reload new user", &"user missing");
        };

        let canonical_user = match d1_insert_identity(
            &db,
            new_user.id,
            &oauth_state.provider,
            &provider_user_id,
            None,
        )
        .await
        {
            Ok(_) => new_user,
            Err(e) => {
                let msg = e.to_string();
                if msg.to_ascii_lowercase().contains("unique") {
                    // Race: identity now exists; resolve it.
                    let Some(identity) = d1_identity_by_provider_user_id(
                        &db,
                        &oauth_state.provider,
                        &provider_user_id,
                    )
                    .await?
                    else {
                        return internal_error_response(req, "Failed to reload identity after race", &e);
                    };
                    let Some(u) = d1_user_by_id(&db, identity.user_id).await? else {
                        return internal_error_response(req, "Linked user not found", &"user missing");
                    };
                    u
                } else {
                    return internal_error_response(req, "Failed to create identity", &e);
                }
            }
        };

        canonical_user
    };

    // Issue session cookies
    let now = Utc::now();
    let access_exp = now + chrono::Duration::seconds(jwt.access_token_expiration);
    let access_claims = models::SessionClaims {
        iss: jwt.issuer.clone(),
        sub: (user.id as i32).to_string(),
        aud: "beaconauth-web".to_string(),
        exp: access_exp.timestamp(),
        token_type: "access".to_string(),
    };

    let access_token = match sign_jwt(jwt, &access_claims) {
        Ok(t) => t,
        Err(e) => return internal_error_response(req, "Failed to sign access token", &e),
    };

    let refresh_token = new_refresh_token();
    let token_hash = sha256_hex(&refresh_token);
    let family_id = new_family_id();
    let refresh_exp = now.timestamp() + jwt.refresh_token_expiration;

    if let Err(e) = d1_insert_refresh_token(&db, user.id, &token_hash, &family_id, refresh_exp).await {
        return internal_error_response(req, "Failed to persist refresh token", &e);
    }

    let mut resp = Response::empty()?.with_status(302);
    let headers = resp.headers_mut();
    headers.set("Location", "/oauth-complete")?;
    append_set_cookie(headers, &cookie_kv("access_token", &access_token, jwt.access_token_expiration))?;
    append_set_cookie(headers, &cookie_kv("refresh_token", &refresh_token, jwt.refresh_token_expiration))?;

    json_with_cors(req, resp)
}
