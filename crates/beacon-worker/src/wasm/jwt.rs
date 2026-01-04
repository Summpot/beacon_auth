use beacon_core::{crypto, models};
use jsonwebtoken::{decode, decode_header, encode, Header};
use uuid::Uuid;
use worker::{Error, Fetch, Headers, Method, Request, RequestInit, Result};

use url::Url;

use super::state::JwtState;

pub fn sign_jwt<T: serde::Serialize>(state: &JwtState, claims: &T) -> Result<String> {
    let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(state.kid.clone());
    header.jku = Some(state.jwks_url.clone());
    encode(&header, claims, &state.encoding_key).map_err(|e| Error::RustError(e.to_string()))
}

fn host_matches_pattern(host: &str, pattern: &str) -> bool {
    let p = pattern.trim();
    if p.is_empty() {
        return false;
    }

    if let Some(base) = p.strip_prefix("*.") {
        host == base || host.ends_with(&format!(".{base}"))
    } else {
        host == p
    }
}

fn is_allowed_jku(state: &JwtState, jku: &Url) -> bool {
    if state.jku_allowed_host_patterns.is_empty() {
        return false;
    }

    // When enabled, require HTTPS to reduce SSRF risk.
    if jku.scheme() != "https" {
        return false;
    }

    let Some(host) = jku.host_str() else {
        return false;
    };

    state
        .jku_allowed_host_patterns
        .iter()
        .any(|p| host_matches_pattern(host, p))
}

async fn fetch_jwks_json(jku: &Url) -> std::result::Result<String, String> {
    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    let headers = Headers::new();
    headers
        .set("Accept", "application/json")
        .map_err(|e| format!("Failed to build JWKS request headers: {e}"))?;
    init.with_headers(headers);

    let req = Request::new_with_init(jku.as_str(), &init)
        .map_err(|e| format!("Invalid jku URL '{}': {e}", jku.as_str()))?;

    let mut resp = Fetch::Request(req)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch JWKS from '{}': {e}", jku.as_str()))?;

    let status = resp.status_code();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("Failed to read JWKS response body: {e}"))?;

    if status >= 400 {
        return Err(format!(
            "JWKS fetch failed from '{}' (HTTP {status})",
            jku.as_str()
        ));
    }

    Ok(body)
}

async fn decode_with_dynamic_jwks<T: serde::de::DeserializeOwned>(
    state: &JwtState,
    token: &str,
    validation: &jsonwebtoken::Validation,
) -> std::result::Result<jsonwebtoken::TokenData<T>, String> {
    let header = decode_header(token).map_err(|e| format!("Invalid JWT header: {e}"))?;
    let preferred_kid = header.kid.as_deref();

    let mut remote_key: Option<jsonwebtoken::DecodingKey> = None;
    let key_ref: &jsonwebtoken::DecodingKey = if let Some(jku_raw) = header.jku.as_deref() {
        // Fast-path: if the token points at our own advertised JWKS URL, we can verify locally.
        if jku_raw == state.jwks_url {
            &state.decoding_key
        } else {
        let jku = Url::parse(jku_raw).map_err(|e| format!("Invalid token jku URL '{jku_raw}': {e}"))?;
        if is_allowed_jku(state, &jku) {
            let jwks_json = fetch_jwks_json(&jku).await?;
            let (decoding_key, _selected_kid, _x, _y) =
                crypto::decoding_key_from_jwks_json(&jwks_json, preferred_kid)
                    .map_err(|e| format!("Failed to parse remote JWKS: {e}"))?;
            remote_key = Some(decoding_key);
            remote_key.as_ref().expect("set above")
        } else {
            &state.decoding_key
        }
        }
    } else {
        &state.decoding_key
    };

    decode::<T>(token, key_ref, validation)
        .map_err(|e| format!("Invalid token: {e:?}"))
}

pub async fn verify_access_token(
    state: &JwtState,
    token: &str,
) -> std::result::Result<String, String> {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_issuer(&[&state.issuer]);
    validation.set_audience(&["beaconauth-web"]);
    validation.validate_exp = true;

    let token_data = decode_with_dynamic_jwks::<models::SessionClaims>(state, token, &validation).await?;

    if token_data.claims.token_type != "access" {
        return Err("Invalid token type".to_string());
    }

    // We store user ids as UUIDv7 strings.
    let user_id = Uuid::parse_str(&token_data.claims.sub)
        .map_err(|_| "Invalid user ID in token".to_string())?
        .to_string();

    Ok(user_id)
}

pub async fn verify_oauth_state_token(
    state: &JwtState,
    token: &str,
) -> std::result::Result<models::OAuthStateClaims, String> {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_issuer(&[&state.issuer]);
    validation.set_audience(&["beaconauth-oauth"]);
    validation.validate_exp = true;

    let token_data = decode_with_dynamic_jwks::<models::OAuthStateClaims>(state, token, &validation).await?;

    if token_data.claims.token_type != "oauth_state" {
        return Err("Invalid OAuth state".to_string());
    }

    Ok(token_data.claims)
}
