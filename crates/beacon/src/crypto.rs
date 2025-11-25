use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{DecodingKey, EncodingKey};
use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng, pkcs8::EncodePrivateKey};
use serde_json::json;

/// Generate an ES256 (ECDSA P-256) keypair and return the EncodingKey, DecodingKey, and JWKS JSON string
pub fn generate_ecdsa_keypair() -> anyhow::Result<(EncodingKey, DecodingKey, String)> {
    // Generate ECDSA P-256 keypair using OsRng
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Convert private key to PKCS#8 DER format for EncodingKey
    let pkcs8_der = signing_key.to_pkcs8_der()?;
    let encoding_key = EncodingKey::from_ec_der(pkcs8_der.as_bytes());

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

    // Create DecodingKey from EC components (x, y coordinates)
    // This is the correct way to create a DecodingKey for ES256 verification
    let decoding_key = DecodingKey::from_ec_components(&x_b64, &y_b64)
        .map_err(|e| anyhow::anyhow!("Failed to create DecodingKey: {}", e))?;

    // Build JWKS JSON for ES256 (ECDSA with P-256 curve)
    let jwks = json!({
        "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "use": "sig",
            "alg": "ES256",
            "kid": "beacon-auth-key-1",
            "x": x_b64,
            "y": y_b64
        }]
    });

    let jwks_json = serde_json::to_string(&jwks)?;

    Ok((encoding_key, decoding_key, jwks_json))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ecdsa_keypair() {
        let result = generate_ecdsa_keypair();
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
