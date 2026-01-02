use beacon_core::models;
use jsonwebtoken::{encode, Header};
use uuid::Uuid;
use worker::{Error, Result};

use super::state::JwtState;

pub fn sign_jwt<T: serde::Serialize>(state: &JwtState, claims: &T) -> Result<String> {
    let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(state.kid.clone());
    header.jku = Some(format!(
        "{}/.well-known/jwks.json",
        state.issuer.trim_end_matches('/')
    ));
    encode(&header, claims, &state.encoding_key).map_err(|e| Error::RustError(e.to_string()))
}

pub fn verify_access_token(state: &JwtState, token: &str) -> std::result::Result<String, String> {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_issuer(&[&state.issuer]);
    validation.set_audience(&["beaconauth-web"]);
    validation.validate_exp = true;

    let token_data = jsonwebtoken::decode::<models::SessionClaims>(
        token,
        &state.decoding_key,
        &validation,
    )
    .map_err(|e| format!("Invalid access token: {e:?}"))?;

    if token_data.claims.token_type != "access" {
        return Err("Invalid token type".to_string());
    }

    // We store user ids as UUIDv7 strings.
    let user_id = Uuid::parse_str(&token_data.claims.sub)
        .map_err(|_| "Invalid user ID in token".to_string())?
        .to_string();

    Ok(user_id)
}
