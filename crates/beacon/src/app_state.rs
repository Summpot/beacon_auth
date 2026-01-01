use jsonwebtoken::{DecodingKey, EncodingKey};
use sea_orm::DatabaseConnection;
use std::sync::Arc;
use webauthn_rs::Webauthn;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration};
use moka::sync::Cache;
use redis::aio::ConnectionManager;

/// Shared application state
pub struct AppState {
    /// Sea-ORM database connection pool
    pub db: DatabaseConnection,

    /// ECDSA private key for signing JWTs (ES256)
    pub encoding_key: EncodingKey,

    /// ECDSA public key for verifying JWTs (ES256)
    pub decoding_key: DecodingKey,

    /// Pre-generated JWKS JSON string containing the public key (EC P-256)
    pub jwks_json: String,

    /// JWT Key ID (kid) used in JWT headers and JWKS selection
    pub jwt_kid: String,

    /// JWT expiration time in seconds (for Minecraft JWT)
    pub jwt_expiration: i64,

    /// Access token expiration time in seconds
    pub access_token_expiration: i64,

    /// Refresh token expiration time in seconds
    pub refresh_token_expiration: i64,

    /// OAuth configuration
    pub oauth_config: OAuthConfig,

    /// WebAuthn instance for passkey operations
    pub webauthn: Arc<Webauthn>,

    /// Optional Redis connection manager for distributed passkey ceremony state.
    ///
    /// When present, handlers will store/retrieve `PasskeyRegistration` and `PasskeyAuthentication`
    /// states in Redis with a short TTL.
    pub passkey_redis: Option<ConnectionManager>,

    /// Temporary passkey registration state storage (user_id -> PasskeyRegistration)
    /// Uses moka cache with 5-minute TTL to avoid state serialization
    pub passkey_reg_states: Cache<i64, PasskeyRegistration>,

    /// Temporary passkey authentication state storage (session_id -> PasskeyAuthentication)
    /// Uses moka cache with 5-minute TTL to avoid state serialization
    pub passkey_auth_states: Cache<String, PasskeyAuthentication>,
}

#[derive(Debug, Clone)]
pub struct OAuthConfig {
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
    pub redirect_base: String,
}
