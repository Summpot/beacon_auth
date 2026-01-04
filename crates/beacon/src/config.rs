use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Clone, Parser)]
#[command(name = "beacon")]
#[command(about = "BeaconAuth Authentication Server", long_about = None)]
pub struct Config {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, clap::Subcommand)]
pub enum Command {
    /// Start the authentication server
    Serve(ServeConfig),

    /// Run database migrations
    Migrate {
        /// Database connection URL
        #[arg(
            long,
            env = "DATABASE_URL",
            default_value = "sqlite://./beacon_auth.db?mode=rwc"
        )]
        database_url: String,
    },

    /// Create a new user
    CreateUser {
        /// Username
        #[arg(short, long)]
        username: String,

        /// Password
        #[arg(short, long)]
        password: String,
    },

    /// List all users
    ListUsers,

    /// Delete a user
    DeleteUser {
        /// Username to delete
        #[arg(short, long)]
        username: String,
    },
}

#[derive(Debug, Clone, Parser)]
pub struct ServeConfig {
    /// Database connection URL
    #[arg(
        long,
        env = "DATABASE_URL",
        default_value = "sqlite://./beacon_auth.db?mode=rwc"
    )]
    pub database_url: String,

    /// Server bind address
    #[arg(long, env = "BIND_ADDRESS", default_value = "127.0.0.1:8080")]
    pub bind_address: String,

    /// Control socket path (Unix) or named pipe name (Windows)
    /// Unix: path like /tmp/beacon-auth.sock
    /// Windows: pipe name like beacon-auth (will become \\.\pipe\beacon-auth)
    #[cfg(unix)]
    #[arg(long, env = "CONTROL_SOCKET", default_value = "/tmp/beacon-auth.sock")]
    pub control_socket: PathBuf,

    #[cfg(windows)]
    #[arg(long, env = "CONTROL_SOCKET", default_value = "beacon-auth")]
    pub control_socket: PathBuf,

    /// Allowed CORS origins (comma-separated)
    #[arg(
        long,
        env = "CORS_ORIGINS",
        default_value = "http://localhost:3000,http://localhost:5173"
    )]
    pub cors_origins: String,

    /// JWT expiration time in seconds
    #[arg(long, env = "JWT_EXPIRATION", default_value = "3600")]
    pub jwt_expiration: i64,

    /// Log level
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    pub log_level: String,

    /// GitHub OAuth Client ID
    #[arg(long, env = "GITHUB_CLIENT_ID")]
    pub github_client_id: Option<String>,

    /// GitHub OAuth Client Secret
    #[arg(long, env = "GITHUB_CLIENT_SECRET")]
    pub github_client_secret: Option<String>,

    /// Google OAuth Client ID
    #[arg(long, env = "GOOGLE_CLIENT_ID")]
    pub google_client_id: Option<String>,

    /// Google OAuth Client Secret
    #[arg(long, env = "GOOGLE_CLIENT_SECRET")]
    pub google_client_secret: Option<String>,

    /// Microsoft OAuth Client ID (Microsoft Entra ID / Azure AD)
    #[arg(long, env = "MICROSOFT_CLIENT_ID")]
    pub microsoft_client_id: Option<String>,

    /// Microsoft OAuth Client Secret (Microsoft Entra ID / Azure AD)
    #[arg(long, env = "MICROSOFT_CLIENT_SECRET")]
    pub microsoft_client_secret: Option<String>,

    /// Microsoft OAuth tenant (common, organizations, consumers, or a tenant GUID)
    #[arg(long, env = "MICROSOFT_TENANT", default_value = "common")]
    pub microsoft_tenant: String,

    /// Base URL for the server (e.g., https://beaconauth.pages.dev)
    /// Used for OAuth redirects, JWT issuer claim, and WebAuthn RP origin
    #[arg(
        long,
        env = "BASE_URL",
        default_value = "https://beaconauth.pages.dev"
    )]
    pub base_url: String,

    /// Optional Redis connection URL.
    ///
    /// When set, BeaconAuth stores temporary WebAuthn ceremony state (registration/authentication)
    /// in Redis with a short TTL to support multi-instance deployments.
    /// When unset, BeaconAuth falls back to in-memory moka caches.
    #[arg(long, env = "REDIS_URL")]
    pub redis_url: Option<String>,

    /// Optional JWKS URL to advertise in the JWT header `jku`.
    ///
    /// When unset, BeaconAuth advertises `${BASE_URL}/.well-known/jwks.json`.
    ///
    /// This is useful for deployments where the externally-reachable JWKS URL differs from
    /// `BASE_URL` (reverse proxies, per-instance subdomains, etc.).
    #[arg(long, env = "JWKS_URL")]
    pub jwks_url: Option<String>,

    /// JWT Key ID (kid) used in JWT headers and for selecting a key in remote JWKS.
    #[arg(long, env = "JWT_KID", default_value = "beacon-auth-key-1")]
    pub jwt_kid: String,
}

impl ServeConfig {
    pub fn cors_origin_list(&self) -> Vec<String> {
        self.cors_origins
            .split(',')
            .map(|s| s.trim().to_string())
            .collect()
    }
}
