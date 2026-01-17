use worker::*;
use uuid::Uuid;

mod cookies;
#[path = "wasm/db/mod.rs"]
mod db;
mod env;
mod handlers;
mod http;
mod jwt;
mod state;
mod util;

use http::{error_response, json_with_cors, method_not_allowed, not_found};

fn is_api_path(raw_path: &str) -> bool {
    // In the single-worker deployment, the UI lives at `/` and the API uses `/api/v1/*`.
    // Additionally, we support route-mounted deployments like `example.com/api/*` where
    // requests arrive as `/api/v1/...` (normalized later).
    raw_path == "/api"
        || raw_path.starts_with("/api/")
        || raw_path == "/v1"
        || raw_path.starts_with("/v1/")
        || raw_path.starts_with("/.well-known/")
}

async fn serve_assets(req: Request, env: &Env) -> Result<Response> {
    // Wrangler [assets] bindings are exposed as a Fetcher.
    // https://docs.rs/worker/latest/src/worker/env.rs.html
    let assets = env.assets("ASSETS")?;
    assets.fetch_request(req).await
}

#[event(fetch)]
pub async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    let url = req.url()?;
    let raw_path = url.path().to_string();
    let api = is_api_path(&raw_path);

    if req.method() == Method::Options {
        // Preflight handling is only relevant for API endpoints.
        // For static assets, just delegate to the assets fetcher.
        if api {
            let resp = Response::empty()?.with_status(204);
            return json_with_cors(&req, resp);
        }
        return serve_assets(req, &env).await;
    }

    // When `assets.run_worker_first = true`, we must explicitly serve the UI from the ASSETS
    // binding for all non-API requests.
    if !api {
        return serve_assets(req, &env).await;
    }

    let method = req.method();
    // Support deployments where the backend is mounted at a context path, e.g. `/api/*`.
    // For example, when a Worker route is configured as `example.com/api/*`, requests will
    // arrive with paths like `/api/v1/login`. We normalize to `/v1/login` for routing.
    let path = raw_path.strip_prefix("/api").unwrap_or(raw_path.as_str());
    let path = if path.is_empty() { "/" } else { path };

    // Endpoints that read request bodies must take ownership of the request.
    if method == Method::Post && path == "/v1/login" {
        return handlers::session::handle_login(req, &env).await;
    }
    if method == Method::Post && path == "/v1/register" {
        return handlers::session::handle_register(req, &env).await;
    }
    if method == Method::Post && path == "/v1/passkey/register/start" {
        return handlers::passkey::handle_passkey_register_start(req, &env).await;
    }
    if method == Method::Post && path == "/v1/passkey/register/finish" {
        return handlers::passkey::handle_passkey_register_finish(req, &env).await;
    }
    if method == Method::Post && path == "/v1/passkey/auth/start" {
        return handlers::passkey::handle_passkey_auth_start(req, &env).await;
    }
    if method == Method::Post && path == "/v1/passkey/auth/finish" {
        return handlers::passkey::handle_passkey_auth_finish(req, &env).await;
    }
    if method == Method::Post && path == "/v1/passkey/delete" {
        return handlers::passkey::handle_passkey_delete(req, &env).await;
    }
    if method == Method::Post && path == "/v1/user/change-password" {
        return handlers::session::handle_change_password(req, &env).await;
    }
    if method == Method::Post && path == "/v1/user/change-username" {
        return handlers::session::handle_change_username(req, &env).await;
    }
    if method == Method::Post && path == "/v1/minecraft-jwt" {
        return handlers::minecraft::handle_minecraft_jwt(req, &env).await;
    }
    if method == Method::Post && path == "/v1/oauth/start" {
        return handlers::oauth::handle_oauth_start(req, &env).await;
    }
    if method == Method::Post && path == "/v1/oauth/link/start" {
        return handlers::oauth::handle_oauth_link_start(req, &env).await;
    }

    let result = match (method, path) {
        (Method::Get, "/v1/config") => handlers::config::handle_get_config(&req, &env).await,
        (Method::Post, "/v1/admin/migrations/up") => {
            handlers::migrations::handle_migrations_up(&req, &env).await
        }
        (Method::Post, "/v1/refresh") => handlers::session::handle_refresh(&req, &env).await,
        (Method::Post, "/v1/logout") => handlers::session::handle_logout(&req, &env).await,
        (Method::Get, "/v1/user/me") => handlers::session::handle_user_me(&req, &env).await,
        (Method::Get, "/v1/identities") => handlers::identity::handle_identities_list(&req, &env).await,
        (Method::Get, "/v1/oauth/callback") => handlers::oauth::handle_oauth_callback(&req, &env).await,
        (Method::Get, "/.well-known/jwks.json") => handlers::config::handle_get_jwks(&req, &env).await,

        (Method::Get, "/v1/passkey/list") => handlers::passkey::handle_passkey_list(&req, &env).await,
        (Method::Delete, p) if p.starts_with("/v1/passkey/") => {
            let Some(id_str) = p.strip_prefix("/v1/passkey/") else {
                return not_found(&req);
            };

            if Uuid::parse_str(id_str).is_err() {
                return error_response(&req, 400, "invalid_passkey_id", "Invalid passkey id");
            }

            handlers::passkey::handle_passkey_delete_by_id(&req, &env, id_str.to_string()).await
        }

        (Method::Delete, p) if p.starts_with("/v1/identities/") => {
            let Some(id_str) = p.strip_prefix("/v1/identities/") else {
                return not_found(&req);
            };

            if Uuid::parse_str(id_str).is_err() {
                return error_response(&req, 400, "invalid_identity_id", "Invalid identity id");
            }

            handlers::identity::handle_identity_delete_by_id(&req, &env, id_str.to_string()).await
        }

        (Method::Get, _) | (Method::Post, _) | (Method::Delete, _) => not_found(&req),
        _ => method_not_allowed(&req),
    };

    // Never let a handler error bubble up to the runtime unhandled.
    // In production this can manifest as "script will never generate a response".
    match result {
        Ok(resp) => Ok(resp),
        Err(e) => http::internal_error_response(&req, "Unhandled worker error", &e),
    }
}
