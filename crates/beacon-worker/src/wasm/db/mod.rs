mod d1_entity;

use worker::{Env, Error, Result};

use sea_orm::{
    ColumnTrait, Database, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    Set,
};
use sea_orm::sea_query::Expr;

use super::util::now_ts;

pub type UserRow = d1_entity::user::Model;
pub type RefreshTokenRow = d1_entity::refresh_token::Model;
pub type PasskeyDbRow = d1_entity::passkey::Model;
pub type IdentityRow = d1_entity::identity::Model;

fn map_db_err(e: sea_orm::DbErr) -> Error {
    Error::RustError(e.to_string())
}

pub async fn d1(env: &Env) -> Result<DatabaseConnection> {
    let binding = env.d1("DB")?;
    Database::connect_d1(binding).await.map_err(map_db_err)
}

pub async fn d1_user_by_username(db: &DatabaseConnection, username: &str) -> Result<Option<UserRow>> {
    let username_lower = beacon_core::username::normalize_username(username);
    d1_entity::user::Entity::find()
        .filter(d1_entity::user::Column::UsernameLower.eq(username_lower))
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn d1_user_by_id(db: &DatabaseConnection, id: i64) -> Result<Option<UserRow>> {
    d1_entity::user::Entity::find_by_id(id)
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn d1_insert_user(db: &DatabaseConnection, username: &str) -> Result<i64> {
    let ts = now_ts();
    let username_lower = beacon_core::username::normalize_username(username);

    // NOTE: D1's `last_row_id` metadata is not always available/reliable across environments.
    // Insert and then fetch the created row by unique username.
    let new_user = d1_entity::user::ActiveModel {
        username: Set(username.to_string()),
        username_lower: Set(username_lower.clone()),
        created_at: Set(ts),
        updated_at: Set(ts),
        ..Default::default()
    };

    d1_entity::user::Entity::insert(new_user)
        .exec(db)
        .await
        .map_err(map_db_err)?;

    let Some(user) = d1_user_by_username(db, &username_lower).await? else {
        return Err(Error::RustError("Inserted user could not be reloaded".to_string()));
    };

    Ok(user.id)
}

pub async fn d1_update_user_username(
    db: &DatabaseConnection,
    user_id: i64,
    username: &str,
    username_lower: &str,
) -> Result<()> {
    let ts = now_ts();
    d1_entity::user::Entity::update_many()
        .col_expr(d1_entity::user::Column::Username, Expr::value(username))
        .col_expr(d1_entity::user::Column::UsernameLower, Expr::value(username_lower))
        .col_expr(d1_entity::user::Column::UpdatedAt, Expr::value(ts))
        .filter(d1_entity::user::Column::Id.eq(user_id))
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn d1_passkeys_by_user_id(db: &DatabaseConnection, user_id: i64) -> Result<Vec<PasskeyDbRow>> {
    d1_entity::passkey::Entity::find()
        .filter(d1_entity::passkey::Column::UserId.eq(user_id))
        .order_by_desc(d1_entity::passkey::Column::CreatedAt)
        .all(db)
        .await
        .map_err(map_db_err)
}

pub async fn d1_passkeys_all(db: &DatabaseConnection) -> Result<Vec<PasskeyDbRow>> {
    d1_entity::passkey::Entity::find()
        .order_by_desc(d1_entity::passkey::Column::CreatedAt)
        .all(db)
        .await
        .map_err(map_db_err)
}

pub async fn d1_passkey_by_id(db: &DatabaseConnection, id: i64) -> Result<Option<PasskeyDbRow>> {
    d1_entity::passkey::Entity::find_by_id(id)
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn d1_passkey_by_credential_id(
    db: &DatabaseConnection,
    credential_id: &str,
) -> Result<Option<PasskeyDbRow>> {
    d1_entity::passkey::Entity::find()
        .filter(d1_entity::passkey::Column::CredentialId.eq(credential_id))
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn d1_insert_passkey(
    db: &DatabaseConnection,
    user_id: i64,
    credential_id: &str,
    credential_data: &str,
    name: &str,
) -> Result<i64> {
    let ts = now_ts();

    let new_passkey = d1_entity::passkey::ActiveModel {
        user_id: Set(user_id),
        credential_id: Set(credential_id.to_string()),
        credential_data: Set(credential_data.to_string()),
        name: Set(name.to_string()),
        last_used_at: Set(None),
        created_at: Set(ts),
        ..Default::default()
    };

    d1_entity::passkey::Entity::insert(new_passkey)
        .exec(db)
        .await
        .map_err(map_db_err)?;

    let Some(row) = d1_passkey_by_credential_id(db, credential_id).await? else {
        return Err(Error::RustError("Inserted passkey could not be reloaded".to_string()));
    };

    Ok(row.id)
}

pub async fn d1_update_passkey_usage(
    db: &DatabaseConnection,
    id: i64,
    credential_data: &str,
    last_used_at: i64,
) -> Result<()> {
    d1_entity::passkey::Entity::update_many()
        .col_expr(d1_entity::passkey::Column::CredentialData, Expr::value(credential_data))
        .col_expr(d1_entity::passkey::Column::LastUsedAt, Expr::value(last_used_at))
        .filter(d1_entity::passkey::Column::Id.eq(id))
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn d1_delete_passkey_by_id(db: &DatabaseConnection, id: i64) -> Result<()> {
    d1_entity::passkey::Entity::delete_by_id(id)
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn d1_insert_refresh_token(
    db: &DatabaseConnection,
    user_id: i64,
    token_hash: &str,
    family_id: &str,
    expires_at: i64,
) -> Result<()> {
    let ts = now_ts();

    let model = d1_entity::refresh_token::ActiveModel {
        user_id: Set(user_id),
        token_hash: Set(token_hash.to_string()),
        family_id: Set(family_id.to_string()),
        expires_at: Set(expires_at),
        revoked: Set(0),
        created_at: Set(ts),
        ..Default::default()
    };

    d1_entity::refresh_token::Entity::insert(model)
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn d1_refresh_token_by_hash(
    db: &DatabaseConnection,
    token_hash: &str,
) -> Result<Option<RefreshTokenRow>> {
    d1_entity::refresh_token::Entity::find()
        .filter(d1_entity::refresh_token::Column::TokenHash.eq(token_hash))
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn d1_revoke_refresh_token_by_id(db: &DatabaseConnection, id: i64) -> Result<()> {
    d1_entity::refresh_token::Entity::update_many()
        .col_expr(d1_entity::refresh_token::Column::Revoked, Expr::value(1_i64))
        .filter(d1_entity::refresh_token::Column::Id.eq(id))
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn d1_revoke_all_refresh_tokens_for_user(db: &DatabaseConnection, user_id: i64) -> Result<()> {
    d1_entity::refresh_token::Entity::update_many()
        .col_expr(d1_entity::refresh_token::Column::Revoked, Expr::value(1_i64))
        .filter(d1_entity::refresh_token::Column::UserId.eq(user_id))
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn d1_identity_by_provider_user_id(
    db: &DatabaseConnection,
    provider: &str,
    provider_user_id: &str,
) -> Result<Option<IdentityRow>> {
    d1_entity::identity::Entity::find()
        .filter(d1_entity::identity::Column::Provider.eq(provider))
        .filter(d1_entity::identity::Column::ProviderUserId.eq(provider_user_id))
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn d1_identity_by_id(db: &DatabaseConnection, id: i64) -> Result<Option<IdentityRow>> {
    d1_entity::identity::Entity::find_by_id(id)
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn d1_identities_by_user_id(db: &DatabaseConnection, user_id: i64) -> Result<Vec<IdentityRow>> {
    d1_entity::identity::Entity::find()
        .filter(d1_entity::identity::Column::UserId.eq(user_id))
        .order_by_desc(d1_entity::identity::Column::CreatedAt)
        .all(db)
        .await
        .map_err(map_db_err)
}

pub async fn d1_insert_identity(
    db: &DatabaseConnection,
    user_id: i64,
    provider: &str,
    provider_user_id: &str,
    password_hash: Option<&str>,
) -> Result<i64> {
    let ts = now_ts();

    let model = d1_entity::identity::ActiveModel {
        user_id: Set(user_id),
        provider: Set(provider.to_string()),
        provider_user_id: Set(provider_user_id.to_string()),
        password_hash: Set(password_hash.map(|s| s.to_string())),
        created_at: Set(ts),
        updated_at: Set(ts),
        ..Default::default()
    };

    d1_entity::identity::Entity::insert(model)
        .exec(db)
        .await
        .map_err(map_db_err)?;

    // D1's last_row_id metadata isn't reliably surfaced; reload by unique pair.
    let Some(row) = d1_identity_by_provider_user_id(db, provider, provider_user_id).await? else {
        return Err(Error::RustError("Inserted identity could not be reloaded".to_string()));
    };

    Ok(row.id)
}

pub async fn d1_password_identity_by_user_id(db: &DatabaseConnection, user_id: i64) -> Result<Option<IdentityRow>> {
    d1_entity::identity::Entity::find()
        .filter(d1_entity::identity::Column::UserId.eq(user_id))
        .filter(d1_entity::identity::Column::Provider.eq("password"))
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn d1_password_identity_by_identifier(
    db: &DatabaseConnection,
    identifier: &str,
) -> Result<Option<IdentityRow>> {
    let identifier_lower = beacon_core::username::normalize_username(identifier);

    d1_entity::identity::Entity::find()
        .filter(d1_entity::identity::Column::Provider.eq("password"))
        .filter(d1_entity::identity::Column::ProviderUserId.eq(identifier_lower))
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn d1_update_password_identity_hash(db: &DatabaseConnection, user_id: i64, new_hash: &str) -> Result<()> {
    let ts = now_ts();

    d1_entity::identity::Entity::update_many()
        .col_expr(d1_entity::identity::Column::PasswordHash, Expr::value(new_hash))
        .col_expr(d1_entity::identity::Column::UpdatedAt, Expr::value(ts))
        .filter(d1_entity::identity::Column::UserId.eq(user_id))
        .filter(d1_entity::identity::Column::Provider.eq("password"))
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn d1_update_password_identity_identifier(
    db: &DatabaseConnection,
    user_id: i64,
    new_identifier: &str,
) -> Result<()> {
    let ts = now_ts();

    d1_entity::identity::Entity::update_many()
        .col_expr(d1_entity::identity::Column::ProviderUserId, Expr::value(new_identifier))
        .col_expr(d1_entity::identity::Column::UpdatedAt, Expr::value(ts))
        .filter(d1_entity::identity::Column::UserId.eq(user_id))
        .filter(d1_entity::identity::Column::Provider.eq("password"))
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn d1_delete_identity_by_id(db: &DatabaseConnection, id: i64) -> Result<()> {
    d1_entity::identity::Entity::delete_by_id(id)
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn d1_count_identities_by_user_id(db: &DatabaseConnection, user_id: i64) -> Result<i64> {
    let count = d1_entity::identity::Entity::find()
        .filter(d1_entity::identity::Column::UserId.eq(user_id))
        .count(db)
        .await
        .map_err(map_db_err)?;

    Ok(count as i64)
}

pub async fn d1_count_passkeys_by_user_id(db: &DatabaseConnection, user_id: i64) -> Result<i64> {
    let count = d1_entity::passkey::Entity::find()
        .filter(d1_entity::passkey::Column::UserId.eq(user_id))
        .count(db)
        .await
        .map_err(map_db_err)?;

    Ok(count as i64)
}
