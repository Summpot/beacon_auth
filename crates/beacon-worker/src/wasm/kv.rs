use serde::de::DeserializeOwned;
use serde::Serialize;
use worker::{Env, Error, KvStore, Result};

pub const PASSKEY_STATE_TTL_SECS: u64 = 5 * 60;

pub fn kv(env: &Env) -> Result<KvStore> {
    env.kv("KV")
}

pub async fn kv_put_json<T: Serialize>(kv: &KvStore, key: &str, value: &T, ttl_secs: u64) -> Result<()> {
    let json = serde_json::to_string(value).map_err(|e| Error::RustError(e.to_string()))?;
    kv.put(key, json)
        .map_err(|e| Error::RustError(e.to_string()))?
        .expiration_ttl(ttl_secs)
        .execute()
        .await
        .map_err(|e| Error::RustError(e.to_string()))?;
    Ok(())
}

pub async fn kv_get_json<T: DeserializeOwned>(kv: &KvStore, key: &str) -> Result<Option<T>> {
    let value = kv
        .get(key)
        .text()
        .await
        .map_err(|e| Error::RustError(e.to_string()))?;

    let Some(value) = value else {
        return Ok(None);
    };

    let parsed = serde_json::from_str(&value).map_err(|e| Error::RustError(e.to_string()))?;
    Ok(Some(parsed))
}

pub async fn kv_delete(kv: &KvStore, key: &str) -> Result<()> {
    kv.delete(key)
        .await
        .map_err(|e| Error::RustError(e.to_string()))?;
    Ok(())
}

pub async fn kv_put_string(kv: &KvStore, key: &str, value: &str) -> Result<()> {
    kv.put(key, value.to_string())
        .map_err(|e| Error::RustError(e.to_string()))?
        .execute()
        .await
        .map_err(|e| Error::RustError(e.to_string()))?;
    Ok(())
}

pub async fn kv_get_string(kv: &KvStore, key: &str) -> Result<Option<String>> {
    kv.get(key)
        .text()
        .await
        .map_err(|e| Error::RustError(e.to_string()))
}

pub fn passkey_reg_state_key(user_id: &str) -> String {
    format!("passkey:reg:{user_id}")
}

pub fn passkey_auth_state_key(challenge_b64: &str) -> String {
    format!("passkey:auth:{challenge_b64}")
}
