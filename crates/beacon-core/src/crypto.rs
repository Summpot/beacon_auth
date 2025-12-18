use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{DecodingKey, EncodingKey};
use p256::{
    ecdsa::SigningKey,
    elliptic_curve::rand_core::OsRng,
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Clone, Deserialize)]
struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    pub kty: String,
    pub crv: Option<String>,
    #[allow(dead_code)]
    pub alg: Option<String>,

    #[serde(rename = "use")]
    #[allow(dead_code)]
    pub use_: Option<String>,

    pub kid: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
}

/// Generate an ES256 (ECDSA P-256) keypair and return the EncodingKey, DecodingKey, and JWKS JSON string.
///
/// Note: This key is ephemeral (generated at startup). For stable keys across instances,
/// load a fixed PKCS#8 key instead.
pub fn generate_ecdsa_keypair(kid: &str) -> anyhow::Result<(EncodingKey, DecodingKey, String)> {
    // Generate ECDSA P-256 keypair using OsRng
    let signing_key = SigningKey::random(&mut OsRng);

    // Convert private key to PKCS#8 DER format for EncodingKey
    let pkcs8_der = signing_key.to_pkcs8_der()?;
    ecdsa_keypair_from_pkcs8_der(pkcs8_der.as_bytes(), kid)
}

/// Load an ES256 (P-256) keypair from PKCS#8 DER bytes and return (EncodingKey, DecodingKey, JWKS JSON).
pub fn ecdsa_keypair_from_pkcs8_der(
    pkcs8_der: &[u8],
    kid: &str,
) -> anyhow::Result<(EncodingKey, DecodingKey, String)> {
    let signing_key = SigningKey::from_pkcs8_der(pkcs8_der)
        .map_err(|e| anyhow::anyhow!("Failed to parse PKCS#8 private key: {e}"))?;
    let verifying_key = signing_key.verifying_key();

    let encoding_key = EncodingKey::from_ec_der(pkcs8_der);

    // Extract x and y coordinates from public key for JWKS and DecodingKey
    let encoded_point = verifying_key.to_encoded_point(false); // uncompressed format

    let x_bytes = encoded_point
        .x()
        .ok_or_else(|| anyhow::anyhow!("Failed to get x coordinate"))?;
    let y_bytes = encoded_point
        .y()
        .ok_or_else(|| anyhow::anyhow!("Failed to get y coordinate"))?;

    let x_b64 = URL_SAFE_NO_PAD.encode(x_bytes);
    let y_b64 = URL_SAFE_NO_PAD.encode(y_bytes);

    let decoding_key = DecodingKey::from_ec_components(&x_b64, &y_b64)
        .map_err(|e| anyhow::anyhow!("Failed to create DecodingKey: {e}"))?;

    let jwks_json = jwks_json_from_ec_components(kid, &x_b64, &y_b64)?;

    Ok((encoding_key, decoding_key, jwks_json))
}

/// Decode a PKCS#8 DER private key provided as base64 (standard or base64url, with or without padding).
pub fn decode_pkcs8_der_b64(input: &str) -> anyhow::Result<Vec<u8>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        anyhow::bail!("JWT_PRIVATE_KEY_DER_B64 is empty");
    }

    // Try base64url (no padding) first, then standard base64.
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed) {
        return Ok(bytes);
    }
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(trimmed) {
        return Ok(bytes);
    }
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE.decode(trimmed) {
        return Ok(bytes);
    }

    anyhow::bail!("Failed to decode base64 key material (expected base64/base64url)");
}

/// Parse JWKS JSON and build a DecodingKey for an ES256 (P-256) key.
/// Returns (DecodingKey, selected_kid, x, y).
pub fn decoding_key_from_jwks_json(
    jwks_json: &str,
    preferred_kid: Option<&str>,
) -> anyhow::Result<(DecodingKey, String, String, String)> {
    let jwks: Jwks = serde_json::from_str(jwks_json)
        .map_err(|e| anyhow::anyhow!("Invalid JWKS JSON: {e}"))?;

    let mut candidates = jwks.keys.iter().filter(|k| {
        k.kty == "EC"
            && k.crv.as_deref() == Some("P-256")
            && k.x.is_some()
            && k.y.is_some()
    });

    let selected = if let Some(kid) = preferred_kid {
        candidates
            .find(|k| k.kid.as_deref() == Some(kid))
            .ok_or_else(|| anyhow::anyhow!("No matching EC P-256 key found in JWKS for kid='{kid}'"))?
    } else {
        candidates
            .next()
            .ok_or_else(|| anyhow::anyhow!("No usable EC P-256 key found in JWKS"))?
    };

    let x = selected
        .x
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Selected JWK is missing 'x'"))?;
    let y = selected
        .y
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Selected JWK is missing 'y'"))?;

    let selected_kid = selected
        .kid
        .clone()
        .unwrap_or_else(|| preferred_kid.unwrap_or("<unknown>").to_string());

    let decoding_key = DecodingKey::from_ec_components(&x, &y)
        .map_err(|e| anyhow::anyhow!("Failed to create DecodingKey from JWKS components: {e}"))?;

    Ok((decoding_key, selected_kid, x, y))
}

pub fn ec_components_from_jwks_json(
    jwks_json: &str,
    preferred_kid: Option<&str>,
) -> anyhow::Result<(String, String)> {
    let (_decoding, _kid, x, y) = decoding_key_from_jwks_json(jwks_json, preferred_kid)?;
    Ok((x, y))
}

fn jwks_json_from_ec_components(kid: &str, x_b64: &str, y_b64: &str) -> anyhow::Result<String> {
    let jwks = json!({
        "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "use": "sig",
            "alg": "ES256",
            "kid": kid,
            "x": x_b64,
            "y": y_b64
        }]
    });

    Ok(serde_json::to_string(&jwks)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ecdsa_keypair() {
        let result = generate_ecdsa_keypair("beacon-auth-key-1");
        assert!(result.is_ok());

        let (_encoding_key, _decoding_key, jwks_json) = result.unwrap();

        // Verify JWKS JSON is valid
        let jwks: serde_json::Value = serde_json::from_str(&jwks_json).unwrap();
        assert!(jwks["keys"].is_array());
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);

        let key = &jwks["keys"][0];
        assert_eq!(key["kty"], "EC");
        assert_eq!(key["crv"], "P-256");
        assert_eq!(key["alg"], "ES256");
        assert!(key["x"].is_string());
        assert!(key["y"].is_string());
    }
}
