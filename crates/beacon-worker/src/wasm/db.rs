// (deprecated) legacy D1 SQL layer; kept temporarily during refactor.
use serde::Deserialize;
use worker::{wasm_bindgen::JsValue, D1Database, Env, Error, Result};

use super::util::{d1_number, now_ts};

#[derive(Deserialize)]
pub struct UserRow {
    pub id: i64,
    pub username: String,
    pub username_lower: String,
}

#[derive(Deserialize)]
pub struct RefreshTokenRow {
    pub id: i64,
    pub user_id: i64,
    pub family_id: String,
    pub expires_at: i64,
    pub revoked: i64,
}

#[derive(Deserialize, Clone)]
pub struct PasskeyDbRow {
    pub id: i64,
    pub user_id: i64,
    pub credential_id: String,
    pub credential_data: String,
    pub name: String,
    pub last_used_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Deserialize)]
pub struct IdentityRow {
    pub id: i64,
    pub user_id: i64,
    pub provider: String,
    pub provider_user_id: String,
    pub password_hash: Option<String>,
    #[allow(dead_code)]
    pub created_at: i64,
    #[allow(dead_code)]
    pub updated_at: i64,
}

pub async fn d1(env: &Env) -> Result<D1Database> {
    env.d1("DB")
}

pub async fn d1_user_by_username(db: &D1Database, username: &str) -> Result<Option<UserRow>> {
    let username_lower = beacon_core::username::normalize_username(username);
    db.prepare("SELECT id, username, username_lower FROM users WHERE username_lower = ?1")
        .bind(&[username_lower.into()])?
        .first::<UserRow>(None)
        .await
}

pub async fn d1_user_by_id(db: &D1Database, id: i64) -> Result<Option<UserRow>> {
    db.prepare("SELECT id, username, username_lower FROM users WHERE id = ?1")
        .bind(&[d1_number(id)])?
        .first::<UserRow>(None)
        .await
}

pub async fn d1_insert_user(db: &D1Database, username: &str) -> Result<i64> {
    let ts = now_ts();
    let username_lower = beacon_core::username::normalize_username(username);
    // NOTE: D1's `last_row_id` metadata is not always available/reliable across environments.
    // Insert and then fetch the created row by unique username.
    db.prepare(
        "INSERT INTO users (username, username_lower, created_at, updated_at) VALUES (?1, ?2, ?3, ?3)",
    )
    .bind(&[
        username.into(),
        username_lower.clone().into(),
        d1_number(ts),
    ])?
    .run()
    .await?;

    let Some(user) = d1_user_by_username(db, &username_lower).await? else {
        return Err(Error::RustError("Inserted user could not be reloaded".to_string()));
    };

    Ok(user.id)
}

pub async fn d1_update_user_username(
    db: &D1Database,
    user_id: i64,
    username: &str,
    username_lower: &str,
) -> Result<()> {
    let ts = now_ts();
    db.prepare("UPDATE users SET username = ?1, username_lower = ?2, updated_at = ?3 WHERE id = ?4")
        .bind(&[
            username.into(),
            username_lower.into(),
            d1_number(ts),
            d1_number(user_id),
        ])?
        .run()
        .await?;
    Ok(())
}

pub async fn d1_passkeys_by_user_id(db: &D1Database, user_id: i64) -> Result<Vec<PasskeyDbRow>> {
    let result = db
        .prepare(
            "SELECT id, user_id, credential_id, credential_data, name, last_used_at, created_at FROM passkeys WHERE user_id = ?1 ORDER BY created_at DESC",
        )
        .bind(&[d1_number(user_id)])?
        .all()
        .await?;

    result.results::<PasskeyDbRow>()
}

pub async fn d1_passkeys_all(db: &D1Database) -> Result<Vec<PasskeyDbRow>> {
    let result = db
        .prepare(
            "SELECT id, user_id, credential_id, credential_data, name, last_used_at, created_at FROM passkeys ORDER BY created_at DESC",
        )
        .all()
        .await?;

    result.results::<PasskeyDbRow>()
}

pub async fn d1_passkey_by_id(db: &D1Database, id: i64) -> Result<Option<PasskeyDbRow>> {
    db.prepare(
        "SELECT id, user_id, credential_id, credential_data, name, last_used_at, created_at FROM passkeys WHERE id = ?1",
    )
    .bind(&[d1_number(id)])?
    .first::<PasskeyDbRow>(None)
    .await
}

pub async fn d1_passkey_by_credential_id(
    db: &D1Database,
    credential_id: &str,
) -> Result<Option<PasskeyDbRow>> {
    db.prepare(
        "SELECT id, user_id, credential_id, credential_data, name, last_used_at, created_at FROM passkeys WHERE credential_id = ?1",
    )
    .bind(&[credential_id.into()])?
    .first::<PasskeyDbRow>(None)
    .await
}

pub async fn d1_insert_passkey(
    db: &D1Database,
    user_id: i64,
    credential_id: &str,
    credential_data: &str,
    name: &str,
) -> Result<i64> {
    let ts = now_ts();
    db.prepare(
        "INSERT INTO passkeys (user_id, credential_id, credential_data, name, last_used_at, created_at) VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
    )
    .bind(&[
        d1_number(user_id),
        credential_id.into(),
        credential_data.into(),
        name.into(),
        d1_number(ts),
    ])?
    .run()
    .await?;

    let Some(row) = d1_passkey_by_credential_id(db, credential_id).await? else {
        return Err(Error::RustError("Inserted passkey could not be reloaded".to_string()));
    };

    Ok(row.id)
}

pub async fn d1_update_passkey_usage(
    db: &D1Database,
    id: i64,
    credential_data: &str,
    last_used_at: i64,
) -> Result<()> {
    db.prepare("UPDATE passkeys SET credential_data = ?1, last_used_at = ?2 WHERE id = ?3")
        .bind(&[
            credential_data.into(),
            d1_number(last_used_at),
            d1_number(id),
        ])?
        .run()
        .await?;
    Ok(())
}

pub async fn d1_delete_passkey_by_id(db: &D1Database, id: i64) -> Result<()> {
    db.prepare("DELETE FROM passkeys WHERE id = ?1")
        .bind(&[d1_number(id)])?
        .run()
        .await?;
    Ok(())
}

pub async fn d1_insert_refresh_token(
    db: &D1Database,
    user_id: i64,
    token_hash: &str,
    family_id: &str,
    expires_at: i64,
) -> Result<()> {
    let ts = now_ts();
    db.prepare(
        "INSERT INTO refresh_tokens (user_id, token_hash, family_id, expires_at, revoked, created_at) VALUES (?1, ?2, ?3, ?4, 0, ?5)",
    )
    .bind(&[
        d1_number(user_id),
        token_hash.into(),
        family_id.into(),
        d1_number(expires_at),
        d1_number(ts),
    ])?
    .run()
    .await?;
    Ok(())
}

pub async fn d1_refresh_token_by_hash(
    db: &D1Database,
    token_hash: &str,
) -> Result<Option<RefreshTokenRow>> {
    db.prepare(
        "SELECT id, user_id, family_id, expires_at, revoked FROM refresh_tokens WHERE token_hash = ?1",
    )
    .bind(&[token_hash.into()])?
    .first::<RefreshTokenRow>(None)
    .await
}

pub async fn d1_revoke_refresh_token_by_id(db: &D1Database, id: i64) -> Result<()> {
    db.prepare("UPDATE refresh_tokens SET revoked = 1 WHERE id = ?1")
        .bind(&[d1_number(id)])?
        .run()
        .await?;
    Ok(())
}

pub async fn d1_revoke_all_refresh_tokens_for_user(db: &D1Database, user_id: i64) -> Result<()> {
    db.prepare("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?1")
        .bind(&[d1_number(user_id)])?
        .run()
        .await?;
    Ok(())
}

pub async fn d1_identity_by_provider_user_id(
    db: &D1Database,
    provider: &str,
    provider_user_id: &str,
) -> Result<Option<IdentityRow>> {
    db.prepare(
        "SELECT id, user_id, provider, provider_user_id, password_hash, created_at, updated_at FROM identities WHERE provider = ?1 AND provider_user_id = ?2",
    )
    .bind(&[provider.into(), provider_user_id.into()])?
    .first::<IdentityRow>(None)
    .await
}

pub async fn d1_identity_by_id(db: &D1Database, id: i64) -> Result<Option<IdentityRow>> {
    db.prepare(
        "SELECT id, user_id, provider, provider_user_id, password_hash, created_at, updated_at FROM identities WHERE id = ?1",
    )
    .bind(&[d1_number(id)])?
    .first::<IdentityRow>(None)
    .await
}

pub async fn d1_identities_by_user_id(db: &D1Database, user_id: i64) -> Result<Vec<IdentityRow>> {
    let result = db
        .prepare(
            "SELECT id, user_id, provider, provider_user_id, password_hash, created_at, updated_at FROM identities WHERE user_id = ?1 ORDER BY created_at DESC",
        )
        .bind(&[d1_number(user_id)])?
        .all()
        .await?;

    result.results::<IdentityRow>()
}

pub async fn d1_insert_identity(
    db: &D1Database,
    user_id: i64,
    provider: &str,
    provider_user_id: &str,
    password_hash: Option<&str>,
) -> Result<i64> {
    let ts = now_ts();
    let password_js = password_hash
        .map(JsValue::from_str)
        .unwrap_or(JsValue::NULL);
    db.prepare(
        "INSERT INTO identities (user_id, provider, provider_user_id, password_hash, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
    )
    .bind(&[
        d1_number(user_id),
        provider.into(),
        provider_user_id.into(),
        password_js,
        d1_number(ts),
    ])?
    .run()
    .await?;

    // D1's last_row_id metadata isn't reliably surfaced; reload by unique pair.
    let Some(row) = d1_identity_by_provider_user_id(db, provider, provider_user_id).await? else {
        return Err(Error::RustError(
            "Inserted identity could not be reloaded".to_string(),
        ));
    };
    Ok(row.id)
}

pub async fn d1_password_identity_by_user_id(db: &D1Database, user_id: i64) -> Result<Option<IdentityRow>> {
    db.prepare(
        "SELECT id, user_id, provider, provider_user_id, password_hash, created_at, updated_at FROM identities WHERE user_id = ?1 AND provider = 'password' LIMIT 1",
    )
    .bind(&[d1_number(user_id)])?
    .first::<IdentityRow>(None)
    .await
}

pub async fn d1_password_identity_by_identifier(db: &D1Database, identifier: &str) -> Result<Option<IdentityRow>> {
    let identifier_lower = beacon_core::username::normalize_username(identifier);
    db.prepare(
        "SELECT id, user_id, provider, provider_user_id, password_hash, created_at, updated_at FROM identities WHERE provider = 'password' AND provider_user_id = ?1 LIMIT 1",
    )
    .bind(&[identifier_lower.into()])?
    .first::<IdentityRow>(None)
    .await
}

pub async fn d1_update_password_identity_hash(db: &D1Database, user_id: i64, new_hash: &str) -> Result<()> {
    let ts = now_ts();
    db.prepare(
        "UPDATE identities SET password_hash = ?1, updated_at = ?2 WHERE user_id = ?3 AND provider = 'password'",
    )
    .bind(&[new_hash.into(), d1_number(ts), d1_number(user_id)])?
    .run()
    .await?;
    Ok(())
}

pub async fn d1_update_password_identity_identifier(
    db: &D1Database,
    user_id: i64,
    new_identifier: &str,
) -> Result<()> {
    let ts = now_ts();
    db.prepare(
        "UPDATE identities SET provider_user_id = ?1, updated_at = ?2 WHERE user_id = ?3 AND provider = 'password'",
    )
    .bind(&[new_identifier.into(), d1_number(ts), d1_number(user_id)])?
    .run()
    .await?;
    Ok(())
}

pub async fn d1_delete_identity_by_id(db: &D1Database, id: i64) -> Result<()> {
    db.prepare("DELETE FROM identities WHERE id = ?1")
        .bind(&[d1_number(id)])?
        .run()
        .await?;
    Ok(())
}

pub async fn d1_count_identities_by_user_id(db: &D1Database, user_id: i64) -> Result<i64> {
    #[derive(Deserialize)]
    struct Row {
        cnt: i64,
    }

    let row = db
        .prepare("SELECT COUNT(1) as cnt FROM identities WHERE user_id = ?1")
        .bind(&[d1_number(user_id)])?
        .first::<Row>(None)
        .await?;

    Ok(row.map(|r| r.cnt).unwrap_or(0))
}

pub async fn d1_count_passkeys_by_user_id(db: &D1Database, user_id: i64) -> Result<i64> {
    #[derive(Deserialize)]
    struct Row {
        cnt: i64,
    }

    let row = db
        .prepare("SELECT COUNT(1) as cnt FROM passkeys WHERE user_id = ?1")
        .bind(&[d1_number(user_id)])?
        .first::<Row>(None)
        .await?;

    Ok(row.map(|r| r.cnt).unwrap_or(0))
}

