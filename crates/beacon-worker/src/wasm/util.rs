use chrono::{TimeZone, Utc};
use serde_json::json;
use sha2::{Digest, Sha256};
use url::Url;

pub fn now_ts() -> i64 {
    Utc::now().timestamp()
}

pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    format!("{:x}", hasher.finalize())
}

pub fn new_refresh_token() -> String {
    let token_bytes = rand::random::<[u8; 32]>();
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, token_bytes)
}

pub fn new_family_id() -> String {
    // Token family IDs only need to be unique and unguessable.
    let token_bytes = rand::random::<[u8; 16]>();
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, token_bytes)
}

pub fn ts_to_rfc3339(ts: i64) -> String {
    Utc.timestamp_opt(ts, 0)
        .single()
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| ts.to_string())
}

pub fn query_param(url: &Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find_map(|(k, v)| if k == key { Some(v.to_string()) } else { None })
}

pub fn truncate_for_log(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }

    // `str` slicing must happen on UTF-8 boundaries.
    let mut end = max_len.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }

    let mut out = s[..end].to_string();
    out.push_str("…(truncated)");
    out
}

pub fn redact_oauth_token_body_for_log(body: &str) -> String {
    // Best-effort redaction. We generally only log token bodies on error paths,
    // but never risk leaking an access token.
    if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(body) {
        let mut redacted = false;
        if v.get("access_token").is_some() {
            v["access_token"] = json!("[REDACTED]");
            redacted = true;
        }
        if v.get("refresh_token").is_some() {
            v["refresh_token"] = json!("[REDACTED]");
            redacted = true;
        }
        let rendered = v.to_string();
        return truncate_for_log(&rendered, if redacted { 2048 } else { 4096 });
    }

    // GitHub may return urlencoded bodies in some circumstances.
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    if !pairs.is_empty() {
        let mut ser = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in pairs {
            if k == "access_token" || k == "refresh_token" {
                ser.append_pair(&k, "[REDACTED]");
            } else {
                ser.append_pair(&k, &v);
            }
        }
        return truncate_for_log(&ser.finish(), 4096);
    }

    if body.contains("access_token") || body.contains("refresh_token") {
        return "<redacted token response>".to_string();
    }

    truncate_for_log(body, 4096)
}
