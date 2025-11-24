use crate::{
    app_state::{AppState, OAuthConfig},
    config::ServeConfig,
    crypto, handlers,
};
use actix_cors::Cors;
use actix_web::{middleware, web, App, HttpServer};
use migration::MigratorTrait;
use sea_orm::Database;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use moka::sync::Cache;


#[cfg(unix)]
use tokio::net::UnixListener;

#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

// For embedding static files (Release mode)
#[cfg(not(debug_assertions))]
use rust_embed::RustEmbed;

#[cfg(not(debug_assertions))]
#[derive(RustEmbed)]
#[folder = "../../dist/"] // Path relative to crates/auth_server/Cargo.toml
struct Assets;

pub async fn run_server(config: ServeConfig) -> anyhow::Result<()> {
    log::info!("Starting BeaconAuth API Server...");

    // 1. Generate ES256 (ECDSA P-256) keypair
    log::info!("Generating ECDSA P-256 keypair...");
    let (encoding_key, decoding_key, jwks_json) = crypto::generate_ecdsa_keypair()?;
    log::info!("JWKS generated successfully");

    // 2. Connect to database
    log::info!("Connecting to database: {}", config.database_url);
    let db = Database::connect(&config.database_url).await?;

    // Run migrations
    log::info!("Running database migrations...");
    migration::Migrator::up(&db, None).await?;
    log::info!("Database migrations completed");

    // 3. Create OAuth configuration
    let oauth_config = OAuthConfig {
        github_client_id: config.github_client_id.clone(),
        github_client_secret: config.github_client_secret.clone(),
        google_client_id: config.google_client_id.clone(),
        google_client_secret: config.google_client_secret.clone(),
        redirect_base: config.oauth_redirect_base.clone(),
    };

    // 4. Initialize WebAuthn
    log::info!("Initializing WebAuthn...");
    let rp_origin = url::Url::parse(&config.oauth_redirect_base)?;
    let rp_id = rp_origin
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid redirect base URL"))?;

    let webauthn = Arc::new(
        webauthn_rs::WebauthnBuilder::new(rp_id, &rp_origin)?
            .rp_name("BeaconAuth")
            .build()?,
    );

    log::info!("WebAuthn initialized for RP: {}", rp_id);

    // 5. Initialize moka caches for passkey state (5-minute TTL)
    let passkey_reg_cache = Cache::builder()
        .max_capacity(10_000)
        .time_to_live(Duration::from_secs(5 * 60))
        .build();
    
    let passkey_auth_cache = Cache::builder()
        .max_capacity(10_000)
        .time_to_live(Duration::from_secs(5 * 60))
        .build();
    
    log::info!("Passkey state caches initialized with 5-minute TTL");

    // 6. Create AppState
    let app_state = web::Data::new(AppState {
        db: db.clone(),
        encoding_key,
        decoding_key,
        jwks_json,
        jwt_expiration: config.jwt_expiration,
        access_token_expiration: 900,  // 15 minutes
        refresh_token_expiration: 2592000, // 30 days
        oauth_config,
        oauth_states: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        webauthn,
        passkey_reg_states: passkey_reg_cache,
        passkey_auth_states: passkey_auth_cache,
    });

    // 5. Start control listener (Unix Domain Socket on Unix, Named Pipe on Windows)
    let control_socket = config.control_socket.clone();
    let control_db = db.clone();

    tokio::spawn(async move {
        if let Err(e) = run_control_listener(control_socket, control_db).await {
            log::error!("Control listener error: {}", e);
        }
    });

    // 6. Start HTTP server
    let bind_address = config.bind_address.clone();

    #[cfg(debug_assertions)]
    log::info!(
        "Starting server in DEBUG mode on {} (serving from filesystem)",
        bind_address
    );

    #[cfg(not(debug_assertions))]
    log::info!(
        "Starting server in RELEASE mode on {} (serving from embedded assets)",
        bind_address
    );

    let cors_origins = config.cors_origin_list();

    HttpServer::new(move || {
        // Configure CORS
        let mut cors = Cors::default()
            .allowed_methods(vec!["GET", "POST", "OPTIONS"])
            .allowed_headers(vec![
                actix_web::http::header::AUTHORIZATION,
                actix_web::http::header::ACCEPT,
                actix_web::http::header::CONTENT_TYPE,
            ])
            .max_age(3600);

        // Add all configured origins
        for origin in &cors_origins {
            cors = cors.allowed_origin(origin);
        }

        // Define API routes
        let api_routes = web::scope("/api/v1")
            .route("/config", web::get().to(handlers::get_config))
            .route("/login", web::post().to(handlers::login))
            .route("/register", web::post().to(handlers::register))
            .route("/logout", web::post().to(handlers::user::logout))
            .route("/oauth/start", web::post().to(handlers::oauth_start))
            .route("/oauth/callback", web::get().to(handlers::oauth_callback))
            .route("/refresh", web::post().to(handlers::refresh_token))
            .route("/minecraft-jwt", web::post().to(handlers::get_minecraft_jwt))
            .route("/user/me", web::get().to(handlers::user::get_user_info))
            .route("/user/change-password", web::post().to(handlers::user::change_password))
            .route("/passkeys/register/start", web::post().to(handlers::passkey::register_start))
            .route("/passkeys/register/finish", web::post().to(handlers::passkey::register_finish))
            .route("/passkeys/auth/start", web::post().to(handlers::passkey::auth_start))
            .route("/passkeys/auth/finish", web::post().to(handlers::passkey::auth_finish))
            .route("/passkeys", web::get().to(handlers::passkey::list_passkeys))
            .route("/passkeys/delete", web::post().to(handlers::passkey::delete_passkey));

        let jwks_route =
            web::scope("/.well-known").route("/jwks.json", web::get().to(handlers::get_jwks));

        #[cfg(debug_assertions)]
        {
            // ***** DEBUG MODE *****
            // Serve from filesystem, allows hot-reloading

            // SPA fallback function
            async fn serve_index_html() -> std::io::Result<actix_files::NamedFile> {
                actix_files::NamedFile::open_async("./dist/index.html").await
            }

            App::new()
                .app_data(app_state.clone())
                .wrap(middleware::Logger::default())
                .wrap(cors)
                .service(api_routes)
                .service(jwks_route)
                // Serve static assets from build output
                .service(actix_files::Files::new("/static", "./dist/static"))
                // favicon
                .service(actix_files::Files::new(
                    "/favicon.png",
                    "./dist/favicon.png",
                ))
                // Fallback all other GET requests to index.html (SPA)
                .default_service(web::get().to(serve_index_html))
        }

        #[cfg(not(debug_assertions))]
        {
            // ***** RELEASE MODE *****
            // Serve from embedded memory
            use actix_web::{HttpRequest, HttpResponse};

            // Handle static files and SPA fallback
            async fn serve_embedded_assets(req: HttpRequest) -> HttpResponse {
                let path = req.path().trim_start_matches('/');
                let path = if path.is_empty() { "index.html" } else { path };

                // Try to get the requested file
                if let Some(content) = Assets::get(path) {
                    let mime_type = mime_guess::from_path(path).first_or_octet_stream();
                    HttpResponse::Ok()
                        .content_type(mime_type.as_ref())
                        .body(content.data.into_owned())
                } else {
                    // Fallback to index.html (for SPA routing)
                    if let Some(content) = Assets::get("index.html") {
                        HttpResponse::Ok()
                            .content_type("text/html")
                            .body(content.data.into_owned())
                    } else {
                        HttpResponse::NotFound().body("404 Not Found")
                    }
                }
            }

            App::new()
                .app_data(app_state.clone())
                .wrap(middleware::Logger::default())
                .wrap(cors)
                .service(api_routes)
                .service(jwks_route)
                // All other requests handled by embedded assets with SPA fallback
                .default_service(web::to(serve_embedded_assets))
        }
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
            oauth_redirect_base: "http://localhost:8080".to_string(),
        };

        let origins = config.cors_origin_list();
        assert_eq!(origins.len(), 2);
        assert_eq!(origins[0], "http://localhost:3000");
        assert_eq!(origins[1], "http://example.com");
    }
}
