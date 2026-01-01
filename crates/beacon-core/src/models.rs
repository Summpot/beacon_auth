use serde::{Deserialize, Serialize};

#[cfg(feature = "passkey")]
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

/// Request payload for POST /api/v1/register
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterPayload {
    pub username: String,
    pub password: String,
}

/// Request payload for POST /api/v1/login
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginPayload {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub challenge: String,
    #[serde(default)]
    pub redirect_port: u16,
}

/// Response for successful login
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    #[serde(rename = "redirectUrl")]
    pub redirect_url: String,
}

/// Error response
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

/// Request payload for POST /api/v1/oauth/start
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthStartPayload {
    pub provider: String,
    #[serde(default)]
    pub challenge: String,
    #[serde(default)]
    pub redirect_port: u16,
}

/// Response for OAuth start
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthStartResponse {
    #[serde(rename = "authorizationUrl")]
    pub authorization_url: String,
}

/// Request payload for GET /api/v1/oauth/callback
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: String,
    pub state: String,
}

/// OAuth state encoded into the `state` parameter as a signed JWT.
///
/// This avoids server-side in-memory storage so OAuth works behind load balancers
/// and in multi-instance deployments.
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthStateClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub token_type: String,

    pub provider: String,
    pub challenge: Option<String>,
    pub redirect_port: Option<u16>,

    /// When present, the OAuth flow is being used to link this provider identity
    /// to an already-authenticated user.
    pub link_user_id: Option<i64>,
}

/// JWT Claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Issuer
    pub iss: String,

    /// Subject (user ID)
    pub sub: String,

    /// Audience
    pub aud: String,

    /// Expiration time (Unix timestamp)
    pub exp: i64,

    /// PKCE challenge (critical for BeaconAuth)
    pub challenge: String,
}

/// Response for GET /api/v1/config
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigResponse {
    /// Whether database authentication is enabled (always true if database is configured)
    pub database_auth: bool,
    /// Whether GitHub OAuth is configured
    pub github_oauth: bool,
    /// Whether Google OAuth is configured
    pub google_oauth: bool,
}

/// Session token claims (for access token and refresh token)
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    /// Issuer
    pub iss: String,
    /// Subject (user ID)
    pub sub: String,
    /// Audience
    pub aud: String,
    /// Expiration time
    pub exp: i64,
    /// Token type: "access" or "refresh"
    pub token_type: String,
}

/// Request payload for POST /api/v1/minecraft-jwt
#[derive(Debug, Serialize, Deserialize)]
pub struct MinecraftJwtRequest {
    pub challenge: String,
    pub redirect_port: u16,
    pub profile_url: String,
}

/// Response for POST /api/v1/minecraft-jwt
#[derive(Debug, Serialize, Deserialize)]
pub struct MinecraftJwtResponse {
    #[serde(rename = "redirectUrl")]
    pub redirect_url: String,
}

/// Linked identity info (e.g. an OAuth provider account linked to the canonical user).
#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityInfo {
    pub id: i64,
    pub provider: String,
    pub provider_user_id: String,
}

/// Response for GET /api/v1/identities
#[derive(Debug, Serialize, Deserialize)]
pub struct IdentitiesResponse {
    pub identities: Vec<IdentityInfo>,
    pub has_password: bool,
    pub passkey_count: i64,
}

// -------------------- Passkey models (optional feature) --------------------

/// Passkey registration challenge request
#[cfg(feature = "passkey")]
#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyRegisterStartRequest {
    pub name: String,
}

/// Passkey registration challenge response
#[cfg(feature = "passkey")]
#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyRegisterStartResponse {
    pub creation_options: CreationChallengeResponse,
}

/// Passkey registration verification request
#[cfg(feature = "passkey")]
#[derive(Debug, Deserialize, Serialize)]
pub struct PasskeyRegisterFinishRequest {
    pub credential: RegisterPublicKeyCredential,
    pub name: Option<String>,
}

/// Passkey authentication challenge request
#[cfg(feature = "passkey")]
#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyAuthStartRequest {
    pub challenge: String,
    pub redirect_port: u16,
}

/// Passkey authentication challenge response
#[cfg(feature = "passkey")]
#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyAuthStartResponse {
    pub request_options: RequestChallengeResponse,
}

/// Passkey authentication verification request
#[cfg(feature = "passkey")]
#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyAuthFinishRequest {
    pub credential: PublicKeyCredential,
}

/// List passkeys response
#[cfg(feature = "passkey")]
#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyList {
    pub passkeys: Vec<PasskeyInfo>,
}

#[cfg(feature = "passkey")]
#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyInfo {
    pub id: i64,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

/// Delete passkey request
#[cfg(feature = "passkey")]
#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyDeleteRequest {
    pub id: i64,
}

/// Change password request
#[derive(Debug, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// Change username request
#[derive(Debug, Serialize, Deserialize)]
pub struct ChangeUsernameRequest {
    pub username: String,
}

/// Change username response
#[derive(Debug, Serialize, Deserialize)]
pub struct ChangeUsernameResponse {
    pub success: bool,
    pub username: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_payload_deserialization() {
        let json = r#"{
            "username": "testuser",
            "password": "testpass",
            "challenge": "abc123",
            "redirect_port": 25585
        }"#;

        let payload: LoginPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.username, "testuser");
        assert_eq!(payload.password, "testpass");
        assert_eq!(payload.challenge, "abc123");
        assert_eq!(payload.redirect_port, 25585);
    }

    #[test]
    fn test_login_response_serialization() {
        let response = LoginResponse {
            redirect_url: "http://localhost:25585/callback?jwt=token".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("redirectUrl"));
        assert!(json.contains("http://localhost:25585"));
    }

    #[test]
    fn test_error_response_serialization() {
        let error = ErrorResponse {
            error: "unauthorized".to_string(),
            message: "Invalid credentials".to_string(),
        };

        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("unauthorized"));
        assert!(json.contains("Invalid credentials"));
    }

    #[test]
    fn test_claims_serialization() {
        let claims = Claims {
            iss: "test-issuer".to_string(),
            sub: "user123".to_string(),
            aud: "test-audience".to_string(),
            exp: 1234567890,
            challenge: "challenge123".to_string(),
        };

        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("test-issuer"));
        assert!(json.contains("user123"));
        assert!(json.contains("challenge123"));

        // Test deserialization
        let decoded: Claims = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.iss, claims.iss);
        assert_eq!(decoded.challenge, claims.challenge);
    }
}
