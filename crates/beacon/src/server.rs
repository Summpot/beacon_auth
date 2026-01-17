use crate::{
    app_state::{AppState, OAuthConfig},
    config::ServeConfig,
    crypto, handlers,
};
use actix_cors::Cors;
use actix_web::{middleware, web, App, HttpServer};
use migration::MigratorTrait;
use sea_orm::Database;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use moka::sync::Cache;
use redis::aio::ConnectionManager;


#[cfg(unix)]
use tokio::net::UnixListener;

#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

pub fn build_api_routes() -> actix_web::Scope {
    web::scope("/v1")
        .route("/config", web::get().to(handlers::get_config))
        .route("/login", web::post().to(handlers::login))
        .route("/register", web::post().to(handlers::register))
        .route("/logout", web::post().to(handlers::user::logout))
        .route("/oauth/start", web::post().to(handlers::oauth_start))
        .route("/oauth/link/start", web::post().to(handlers::oauth_link_start))
        .route("/oauth/callback", web::get().to(handlers::oauth_callback))
        .route("/refresh", web::post().to(handlers::refresh_token))
        .route("/minecraft-jwt", web::post().to(handlers::get_minecraft_jwt))
        .route("/user/me", web::get().to(handlers::user::get_user_info))
        .route("/identities", web::get().to(handlers::identity::list_identities))
        .route(
            "/identities/{id}",
            web::delete().to(handlers::identity::delete_identity_by_id),
        )
        .route(
            "/user/change-password",
            web::post().to(handlers::user::change_password),
        )
        .route(
            "/user/change-username",
            web::post().to(handlers::user::change_username),
        )
        .route(
            "/passkey/register/start",
            web::post().to(handlers::passkey::register_start),
        )
        .route(
            "/passkey/register/finish",
            web::post().to(handlers::passkey::register_finish),
        )
        .route("/passkey/auth/start", web::post().to(handlers::passkey::auth_start))
        .route(
            "/passkey/auth/finish",
            web::post().to(handlers::passkey::auth_finish),
        )
        .route("/passkey/list", web::get().to(handlers::passkey::list_passkeys))
        .route(
            "/passkey/{id}",
            web::delete().to(handlers::passkey::delete_passkey_by_id),
        )
        .route(
            "/passkey/delete",
            web::post().to(handlers::passkey::delete_passkey),
        )
}

/// All backend routes under the `/api` context path.
///
/// This enables same-origin deployment where the frontend is served at `/` and the backend lives
/// at `/api/*` (e.g. Cloudflare Pages + Workers route on `/api/*`).
pub fn build_api_context_routes() -> actix_web::Scope {
    web::scope("/api")
        .service(build_api_routes())
        .service(build_jwks_routes())
}

pub fn build_jwks_routes() -> actix_web::Scope {
    web::scope("/.well-known").route("/jwks.json", web::get().to(handlers::get_jwks))
}

fn build_cors(cors_origins: &[String]) -> Cors {
    let mut cors = Cors::default()
        .allowed_methods(vec!["GET", "POST", "DELETE", "OPTIONS"])
        .allowed_headers(vec![
            actix_web::http::header::AUTHORIZATION,
            actix_web::http::header::ACCEPT,
            actix_web::http::header::CONTENT_TYPE,
        ])
        .max_age(3600);

    for origin in cors_origins {
        cors = cors.allowed_origin(origin);
    }

    cors
}

async fn init_jwt_material(
    config: &ServeConfig,
) -> anyhow::Result<(jsonwebtoken::EncodingKey, jsonwebtoken::DecodingKey, String, String)> {
    // This server is JWKS-first: it always serves its public key via `/.well-known/jwks.json`.
    //
    // Unlike the Cloudflare Worker deployment, the standalone server does not require shared
    // storage for JWT keys. Each instance can advertise its own JWKS URL via the `jku` header.
    // This enables multi-instance deployments without a shared signing key, as long as clients
    // enforce a strict allow-list for acceptable JKU domains.
    let der = crypto::generate_ecdsa_pkcs8_der()?;
    let (encoding_key, decoding_key, jwks_json) =
        crypto::ecdsa_keypair_from_pkcs8_der(&der, &config.jwt_kid)?;

    let advertised_jwks_url = config.jwks_url.clone().unwrap_or_else(|| {
        format!(
            "{}/.well-known/jwks.json",
            config.base_url.trim_end_matches('/')
        )
    });

    Ok((encoding_key, decoding_key, jwks_json, advertised_jwks_url))
}

/// Build shared application state (DB, migrations, JWT keys, WebAuthn, caches).
///
/// This is intentionally split out so alternative entrypoints (e.g., serverless) can reuse it.
pub async fn build_app_state(config: &ServeConfig) -> anyhow::Result<web::Data<AppState>> {
    log::info!("Starting BeaconAuth API Server initialization...");

    // 1. Connect to database
    log::info!("Connecting to database: {}", config.database_url);
    let db = Database::connect(&config.database_url).await?;

    // Run migrations
    log::info!("Running database migrations...");
    migration::Migrator::up(&db, None).await?;
    log::info!("Database migrations completed");

    // 2. JWT key material / JWKS
    log::info!("Initializing ES256 key material...");
    let (encoding_key, decoding_key, jwks_json, jwks_url) = init_jwt_material(config).await?;
    log::info!("JWT/JWKS initialized successfully");

    // 3. Create OAuth configuration
    let oauth_config = OAuthConfig {
        github_client_id: config.github_client_id.clone(),
        github_client_secret: config.github_client_secret.clone(),
        google_client_id: config.google_client_id.clone(),
        google_client_secret: config.google_client_secret.clone(),
        microsoft_client_id: config.microsoft_client_id.clone(),
        microsoft_client_secret: config.microsoft_client_secret.clone(),
        microsoft_tenant: config.microsoft_tenant.clone(),
        redirect_base: config.base_url.clone(),
    };

    // 4. Initialize WebAuthn
    log::info!("Initializing WebAuthn...");
    let rp_origin = url::Url::parse(&config.base_url)?;
    let rp_id = rp_origin
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid redirect base URL"))?;

    let webauthn = Arc::new(
        webauthn_rs::WebauthnBuilder::new(rp_id, &rp_origin)?
            .rp_name("BeaconAuth")
            .build()?,
    );

    log::info!("WebAuthn initialized for RP: {}", rp_id);

    // 5. Optional Redis-backed ceremony state store (5-minute TTL)
    let passkey_redis: Option<ConnectionManager> = if let Some(url) = config
        .redis_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        log::info!("Initializing Redis passkey state store...");
        let client = redis::Client::open(url)?;
        let manager = ConnectionManager::new(client).await?;
        log::info!("Redis passkey state store initialized");
        Some(manager)
    } else {
        None
    };

    // 6. Initialize moka caches for passkey state (5-minute TTL)
    let passkey_reg_cache = Cache::builder()
        .max_capacity(10_000)
        .time_to_live(Duration::from_secs(5 * 60))
        .build();

    let passkey_auth_cache = Cache::builder()
        .max_capacity(10_000)
        .time_to_live(Duration::from_secs(5 * 60))
        .build();

    log::info!("Passkey state caches initialized with 5-minute TTL");

    Ok(web::Data::new(AppState {
        db: db.clone(),
        encoding_key,
        decoding_key,
        jwks_json,
        jwks_url,
        jwt_kid: config.jwt_kid.clone(),
        jwt_expiration: config.jwt_expiration,
        access_token_expiration: 900, // 15 minutes
        refresh_token_expiration: 2_592_000, // 30 days
        oauth_config,
        webauthn,
        passkey_redis,
        passkey_reg_states: passkey_reg_cache,
        passkey_auth_states: passkey_auth_cache,
    }))
}

pub async fn run_server(config: ServeConfig) -> anyhow::Result<()> {
    log::info!("Starting BeaconAuth API Server...");

    let app_state = build_app_state(&config).await?;

    // 5. Start control listener (Unix Domain Socket on Unix, Named Pipe on Windows)
    let control_socket = config.control_socket.clone();
    let control_db = app_state.db.clone();

    tokio::spawn(async move {
        if let Err(e) = run_control_listener(control_socket, control_db).await {
            log::error!("Control listener error: {}", e);
        }
    });

    // 6. Start HTTP server
    let bind_address = config.bind_address.clone();

    let cors_origins = config.cors_origin_list();

    HttpServer::new(move || {
        let cors = build_cors(&cors_origins);
        let api_routes = build_api_context_routes();
        let legacy_jwks_route = build_jwks_routes();
        App::new()
            .app_data(app_state.clone())
            .wrap(middleware::Logger::default())
            .wrap(cors)
            .service(api_routes)
            // Back-compat for deployments that still expose JWKS at `/.well-known/jwks.json`.
            .service(legacy_jwks_route)
    })
    .bind(&bind_address)?
    .run()
    .await?;

    Ok(())
}

// Unix version: using Unix Domain Socket
#[cfg(unix)]
async fn run_control_listener(
    socket_path: std::path::PathBuf,
    db: sea_orm::DatabaseConnection,
) -> anyhow::Result<()> {
    // Remove old socket if exists
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    let listener = UnixListener::bind(&socket_path)?;
    log::info!("Control socket listening at {:?}", socket_path);

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let db = db.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_control_connection_unix(stream, db).await {
                        log::error!("Control connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                log::error!("Failed to accept control connection: {}", e);
            }
        }
    }
}

// Windows version: using Named Pipe
#[cfg(windows)]
async fn run_control_listener(
    pipe_name: std::path::PathBuf,
    db: sea_orm::DatabaseConnection,
) -> anyhow::Result<()> {
    // Convert path to named pipe name
    // Example: if configured as "beacon-auth", use \\.\pipe\beacon-auth
    let pipe_name_str = pipe_name.to_string_lossy();
    let pipe_path = if pipe_name_str.starts_with(r"\\.\pipe\") {
        pipe_name_str.to_string()
    } else {
        // Extract file name part as pipe name
        let name = pipe_name
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("beacon-auth");
        format!(r"\\.\pipe\{}", name)
    };

    log::info!("Control named pipe listening at {}", pipe_path);

    loop {
        // Create a new named pipe instance for each connection
        let server = ServerOptions::new()
            .first_pipe_instance(false)
            .create(&pipe_path)?;

        let db = db.clone();
        let pipe_path_clone = pipe_path.clone();

        tokio::spawn(async move {
            // Wait for client connection
            match server.connect().await {
                Ok(_) => {
                    log::info!("Client connected to control pipe");
                    if let Err(e) = handle_control_connection_windows(server, db).await {
                        log::error!("Control connection error: {}", e);
                    }
                }
                Err(e) => {
                    log::error!("Failed to connect to client on {}: {}", pipe_path_clone, e);
                }
            }
        });

        // Small delay to avoid tight loop
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
}

#[cfg(unix)]
async fn handle_control_connection_unix(
    stream: tokio::net::UnixStream,
    _db: sea_orm::DatabaseConnection,
) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // Simple command protocol: one line commands
    while reader.read_line(&mut line).await? > 0 {
        let command = line.trim();
        log::info!("Received control command: {}", command);

        let response = match command {
            "status" => "OK: Server is running\n",
            "ping" => "PONG\n",
            _ => "ERROR: Unknown command\n",
        };

        writer.write_all(response.as_bytes()).await?;
        line.clear();
    }

    Ok(())
}

#[cfg(windows)]
async fn handle_control_connection_windows(
    pipe: NamedPipeServer,
    _db: sea_orm::DatabaseConnection,
) -> anyhow::Result<()> {
    let (reader, mut writer) = tokio::io::split(pipe);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // Simple command protocol: one line commands
    while reader.read_line(&mut line).await? > 0 {
        let command = line.trim();
        log::info!("Received control command: {}", command);

        let response = match command {
            "status" => "OK: Server is running\n",
            "ping" => "PONG\n",
            _ => "ERROR: Unknown command\n",
        };

        writer.write_all(response.as_bytes()).await?;
        line.clear();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cors_origin_parsing() {
        let config = ServeConfig {
            database_url: "sqlite::memory:".to_string(),
            bind_address: "127.0.0.1:8080".to_string(),
            control_socket: "/tmp/test.sock".into(),
            cors_origins: "http://localhost:3000, http://example.com".to_string(),
            jwt_expiration: 3600,
            log_level: "info".to_string(),
            github_client_id: None,
            github_client_secret: None,
            google_client_id: None,
            google_client_secret: None,
            microsoft_client_id: None,
            microsoft_client_secret: None,
            microsoft_tenant: "common".to_string(),
            redis_url: None,
            base_url: "https://beaconauth.pages.dev".to_string(),
            jwks_url: None,
            jwt_kid: "beacon-auth-key-1".to_string(),
        };

        let origins = config.cors_origin_list();
        assert_eq!(origins.len(), 2);
        assert_eq!(origins[0], "http://localhost:3000");
        assert_eq!(origins[1], "http://example.com");
    }
}
