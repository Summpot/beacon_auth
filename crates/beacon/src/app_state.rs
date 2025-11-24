use jsonwebtoken::{DecodingKey, EncodingKey};
use sea_orm::DatabaseConnection;
use std::collections::HashMap;
use std::sync::Arc;
use webauthn_rs::Webauthn;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration};
use moka::sync::Cache;

use crate::models::OAuthState;

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

    /// JWT expiration time in seconds (for Minecraft JWT)
    pub jwt_expiration: i64,

    /// Access token expiration time in seconds
    pub access_token_expiration: i64,

    /// Refresh token expiration time in seconds
    pub refresh_token_expiration: i64,

    /// OAuth configuration
    pub oauth_config: OAuthConfig,

    /// Temporary OAuth state storage (state_token -> OAuthState)
    pub oauth_states: Arc<tokio::sync::RwLock<HashMap<String, OAuthState>>>,

    /// WebAuthn instance for passkey operations
    pub webauthn: Arc<Webauthn>,

    /// Temporary passkey registration state storage (user_id -> PasskeyRegistration)
    /// Uses moka cache with 5-minute TTL to avoid state serialization
    pub passkey_reg_states: Cache<i32, PasskeyRegistration>,

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
