use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthErrorFields {
    pub error: String,
    pub error_description: Option<String>,
    pub error_uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthTokenParseError {
    /// The provider returned an explicit error payload (often with HTTP 200).
    ProviderError(OAuthErrorFields),

    /// The body was parseable but did not contain an access token or a provider error.
    MissingAccessToken,

    /// The body could not be parsed as JSON or x-www-form-urlencoded.
    InvalidFormat,
}

impl std::fmt::Display for OAuthTokenParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OAuthTokenParseError::ProviderError(err) => {
                write!(f, "OAuth token exchange returned error '{}'", err.error)?;
                if let Some(desc) = &err.error_description {
                    if !desc.is_empty() {
                        write!(f, ": {desc}")?;
                    }
                }
                if let Some(uri) = &err.error_uri {
                    if !uri.is_empty() {
                        write!(f, " ({uri})")?;
                    }
                }
                Ok(())
            }
            OAuthTokenParseError::MissingAccessToken => {
                write!(f, "OAuth token exchange response missing access_token")
            }
            OAuthTokenParseError::InvalidFormat => {
                write!(f, "OAuth token exchange response had an unrecognized format")
            }
        }
    }
}

impl std::error::Error for OAuthTokenParseError {}

/// Parse an OAuth token exchange response body and extract `access_token`.
///
/// Supports JSON (preferred) and `application/x-www-form-urlencoded` bodies.
///
/// This intentionally does **not** return the full raw body on error to avoid
/// accidentally leaking access tokens into logs.
pub fn parse_access_token_from_token_exchange_body(body: &str) -> Result<String, OAuthTokenParseError> {
    // 1) JSON
    if let Ok(v) = serde_json::from_str::<Value>(body) {
        if let Some(tok) = v.get("access_token").and_then(|v| v.as_str()) {
            return Ok(tok.to_string());
        }

        if let Some(err) = v.get("error").and_then(|v| v.as_str()) {
            let desc = v
                .get("error_description")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let uri = v
                .get("error_uri")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            return Err(OAuthTokenParseError::ProviderError(OAuthErrorFields {
                error: err.to_string(),
                error_description: desc,
                error_uri: uri,
            }));
        }

        return Err(OAuthTokenParseError::MissingAccessToken);
    }

    // 2) x-www-form-urlencoded
    let pairs = parse_form_urlencoded(body);
    if !pairs.is_empty() {
        let mut access_token: Option<String> = None;
        let mut err: Option<String> = None;
        let mut desc: Option<String> = None;
        let mut uri: Option<String> = None;

        for (k, v) in pairs {
            match k.as_str() {
                "access_token" => access_token = Some(v),
                "error" => err = Some(v),
                "error_description" => desc = Some(v),
                "error_uri" => uri = Some(v),
                _ => {}
            }
        }

        if let Some(tok) = access_token {
            return Ok(tok);
        }

        if let Some(err) = err {
            return Err(OAuthTokenParseError::ProviderError(OAuthErrorFields {
                error: err,
                error_description: desc,
                error_uri: uri,
            }));
        }

        return Err(OAuthTokenParseError::MissingAccessToken);
    }

    Err(OAuthTokenParseError::InvalidFormat)
}

fn parse_form_urlencoded(body: &str) -> Vec<(String, String)> {
    // Very small parser: split by '&', then split each pair on the first '='.
    // Decode using `urlencoding`, which is designed for application/x-www-form-urlencoded.
    let mut out = Vec::new();

    // Fast check to avoid treating arbitrary strings as form bodies.
    if !body.contains('=') {
        return out;
    }

    for part in body.split('&') {
        if part.is_empty() {
            continue;
        }
        let (k, v) = match part.split_once('=') {
            Some((k, v)) => (k, v),
            None => (part, ""),
        };

        let k = urlencoding::decode(k)
            .map(|c| c.into_owned())
            .unwrap_or_else(|_| k.to_string());
        let v = urlencoding::decode(v)
            .map(|c| c.into_owned())
            .unwrap_or_else(|_| v.to_string());

        out.push((k, v));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_json_success() {
        let body = r#"{"access_token":"abc","token_type":"bearer"}"#;
        let tok = parse_access_token_from_token_exchange_body(body).unwrap();
        assert_eq!(tok, "abc");
    }

    #[test]
    fn parse_json_error_on_200() {
        let body = r#"{"error":"bad_verification_code","error_description":"The code passed is incorrect or expired.","error_uri":"https://docs.github.com/"}"#;
        let err = parse_access_token_from_token_exchange_body(body).unwrap_err();
        match err {
            OAuthTokenParseError::ProviderError(fields) => {
                assert_eq!(fields.error, "bad_verification_code");
                assert!(fields.error_description.unwrap().contains("expired"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_form_success() {
        let body = "access_token=abc&token_type=bearer&scope=read%3Auser";
        let tok = parse_access_token_from_token_exchange_body(body).unwrap();
        assert_eq!(tok, "abc");
    }

    #[test]
    fn parse_form_error() {
        let body = "error=bad_verification_code&error_description=The+code+passed+is+incorrect+or+expired.";
        let err = parse_access_token_from_token_exchange_body(body).unwrap_err();
        match err {
            OAuthTokenParseError::ProviderError(fields) => {
                assert_eq!(fields.error, "bad_verification_code");
                assert!(fields.error_description.unwrap().contains("expired"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
