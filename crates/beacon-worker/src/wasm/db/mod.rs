use worker::{Env, Error, Result};

use entity::{identity, passkey, refresh_token, user};
use uuid::Uuid;

use sea_orm::{
    ColumnTrait, Database, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    Set,
};
use sea_orm::sea_query::Expr;

use super::util::now_ts;

pub type UserRow = user::Model;
pub type RefreshTokenRow = refresh_token::Model;
pub type PasskeyDbRow = passkey::Model;
pub type IdentityRow = identity::Model;

fn map_db_err(e: sea_orm::DbErr) -> Error {
    Error::RustError(e.to_string())
}

pub async fn d1(env: &Env) -> Result<DatabaseConnection> {
    let binding = env.d1("DB")?;
    Database::connect_d1(binding).await.map_err(map_db_err)
}

pub async fn d1_user_by_username(db: &DatabaseConnection, username: &str) -> Result<Option<UserRow>> {
    let username_lower = beacon_core::username::normalize_username(username);
    user::Entity::find()
        .filter(user::Column::UsernameLower.eq(username_lower))
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn d1_user_by_id(db: &DatabaseConnection, id: &str) -> Result<Option<UserRow>> {
    user::Entity::find_by_id(id.to_string())
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn d1_insert_user(db: &DatabaseConnection, username: &str) -> Result<String> {
    let ts = now_ts();
    let username_lower = beacon_core::username::normalize_username(username);

    let user_id = Uuid::now_v7().to_string();

    // NOTE: D1's `last_row_id` metadata is not always available/reliable across environments.
    // Insert and then fetch the created row by unique username.
    let new_user = user::ActiveModel {
        id: Set(user_id.clone()),
        username: Set(username.to_string()),
        username_lower: Set(username_lower.clone()),
        created_at: Set(ts),
        updated_at: Set(ts),
        ..Default::default()
    };

    // Cloudflare D1 does not always report rows_affected/last_insert_id reliably.
    // Use exec_without_returning + reload by unique key.
    user::Entity::insert(new_user)
        .exec_without_returning(db)
        .await
        .map_err(map_db_err)?;

    let Some(user) = d1_user_by_id(db, &user_id).await? else {
        return Err(Error::RustError("Inserted user could not be reloaded".to_string()));
    };

    Ok(user.id)
}

pub async fn d1_update_user_username(
    db: &DatabaseConnection,
    user_id: &str,
    username: &str,
    username_lower: &str,
) -> Result<()> {
    let ts = now_ts();
    user::Entity::update_many()
        .col_expr(user::Column::Username, Expr::value(username))
        .col_expr(user::Column::UsernameLower, Expr::value(username_lower))
        .col_expr(user::Column::UpdatedAt, Expr::value(ts))
        .filter(user::Column::Id.eq(user_id.to_string()))
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn d1_passkeys_by_user_id(db: &DatabaseConnection, user_id: &str) -> Result<Vec<PasskeyDbRow>> {
    passkey::Entity::find()
    .filter(passkey::Column::UserId.eq(user_id.to_string()))
        .order_by_desc(passkey::Column::CreatedAt)
        .all(db)
        .await
        .map_err(map_db_err)
}

pub async fn d1_passkeys_all(db: &DatabaseConnection) -> Result<Vec<PasskeyDbRow>> {
    passkey::Entity::find()
        .order_by_desc(passkey::Column::CreatedAt)
        .all(db)
        .await
        .map_err(map_db_err)
}

pub async fn d1_passkey_by_id(db: &DatabaseConnection, id: &str) -> Result<Option<PasskeyDbRow>> {
    passkey::Entity::find_by_id(id.to_string())
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn d1_passkey_by_credential_id(
    db: &DatabaseConnection,
    credential_id: &str,
) -> Result<Option<PasskeyDbRow>> {
    passkey::Entity::find()
        .filter(passkey::Column::CredentialId.eq(credential_id))
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn d1_insert_passkey(
    db: &DatabaseConnection,
    user_id: &str,
    credential_id: &str,
    credential_data: &str,
    name: &str,
) -> Result<String> {
    let ts = now_ts();

    let passkey_id = Uuid::now_v7().to_string();

    let new_passkey = passkey::ActiveModel {
        id: Set(passkey_id.clone()),
        user_id: Set(user_id.to_string()),
        credential_id: Set(credential_id.to_string()),
        credential_data: Set(credential_data.to_string()),
        name: Set(name.to_string()),
        last_used_at: Set(None),
        created_at: Set(ts),
        ..Default::default()
    };

    // See note in d1_insert_user (D1 metadata can be unreliable).
    passkey::Entity::insert(new_passkey)
        .exec_without_returning(db)
        .await
        .map_err(map_db_err)?;

    let Some(row) = d1_passkey_by_credential_id(db, credential_id).await? else {
        return Err(Error::RustError("Inserted passkey could not be reloaded".to_string()));
    };

    Ok(row.id)
}

pub async fn d1_update_passkey_usage(
    db: &DatabaseConnection,
    id: &str,
    credential_data: &str,
    last_used_at: i64,
) -> Result<()> {
    passkey::Entity::update_many()
        .col_expr(passkey::Column::CredentialData, Expr::value(credential_data))
        .col_expr(passkey::Column::LastUsedAt, Expr::value(last_used_at))
        .filter(passkey::Column::Id.eq(id.to_string()))
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn d1_delete_passkey_by_id(db: &DatabaseConnection, id: &str) -> Result<()> {
    passkey::Entity::delete_by_id(id.to_string())
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn d1_insert_refresh_token(
    db: &DatabaseConnection,
    user_id: &str,
    token_hash: &str,
    family_id: &str,
    expires_at: i64,
) -> Result<()> {
    let ts = now_ts();

    let refresh_token_id = Uuid::now_v7().to_string();

    let model = refresh_token::ActiveModel {
        id: Set(refresh_token_id),
        user_id: Set(user_id.to_string()),
        token_hash: Set(token_hash.to_string()),
        family_id: Set(family_id.to_string()),
        expires_at: Set(expires_at),
        revoked: Set(0),
        created_at: Set(ts),
        ..Default::default()
    };

    // Use exec_without_returning to avoid DbErr::RecordNotInserted when D1 reports 0 rows_affected.
    refresh_token::Entity::insert(model)
        .exec_without_returning(db)
        .await
        .map_err(map_db_err)?;

    // Verify that the inserted row exists and matches our expected values.
    // This also helps detect the extremely unlikely case of token hash collision.
    let Some(row) = d1_refresh_token_by_hash(db, token_hash).await? else {
        return Err(Error::RustError(
            "Inserted refresh token could not be reloaded".to_string(),
        ));
    };
    if row.user_id != user_id
        || row.family_id != family_id
        || row.expires_at != expires_at
        || row.created_at != ts
    {
        return Err(Error::RustError(
            "Refresh token insert did not persist expected row (possible hash collision)"
                .to_string(),
        ));
    }

    Ok(())
}

pub async fn d1_refresh_token_by_hash(
    db: &DatabaseConnection,
    token_hash: &str,
) -> Result<Option<RefreshTokenRow>> {
    refresh_token::Entity::find()
        .filter(refresh_token::Column::TokenHash.eq(token_hash))
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn d1_revoke_refresh_token_by_id(db: &DatabaseConnection, id: &str) -> Result<()> {
    refresh_token::Entity::update_many()
        .col_expr(refresh_token::Column::Revoked, Expr::value(1_i64))
        .filter(refresh_token::Column::Id.eq(id.to_string()))
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn d1_revoke_all_refresh_tokens_for_user(db: &DatabaseConnection, user_id: &str) -> Result<()> {
    refresh_token::Entity::update_many()
        .col_expr(refresh_token::Column::Revoked, Expr::value(1_i64))
        .filter(refresh_token::Column::UserId.eq(user_id.to_string()))
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
    identity::Entity::find()
        .filter(identity::Column::Provider.eq(provider))
        .filter(identity::Column::ProviderUserId.eq(provider_user_id))
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn d1_identity_by_id(db: &DatabaseConnection, id: &str) -> Result<Option<IdentityRow>> {
    identity::Entity::find_by_id(id.to_string())
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn d1_identities_by_user_id(db: &DatabaseConnection, user_id: &str) -> Result<Vec<IdentityRow>> {
    identity::Entity::find()
        .filter(identity::Column::UserId.eq(user_id.to_string()))
        .order_by_desc(identity::Column::CreatedAt)
        .all(db)
        .await
        .map_err(map_db_err)
}

pub async fn d1_insert_identity(
    db: &DatabaseConnection,
    user_id: &str,
    provider: &str,
    provider_user_id: &str,
    password_hash: Option<&str>,
) -> Result<String> {
    let ts = now_ts();

    let identity_id = Uuid::now_v7().to_string();

    let model = identity::ActiveModel {
        id: Set(identity_id),
        user_id: Set(user_id.to_string()),
        provider: Set(provider.to_string()),
        provider_user_id: Set(provider_user_id.to_string()),
        password_hash: Set(password_hash.map(|s| s.to_string())),
        created_at: Set(ts),
        updated_at: Set(ts),
        ..Default::default()
    };

    // See note in d1_insert_user (D1 metadata can be unreliable).
    identity::Entity::insert(model)
        .exec_without_returning(db)
        .await
        .map_err(map_db_err)?;

    // D1's last_row_id metadata isn't reliably surfaced; reload by unique pair.
    let Some(row) = d1_identity_by_provider_user_id(db, provider, provider_user_id).await? else {
        return Err(Error::RustError("Inserted identity could not be reloaded".to_string()));
    };

    Ok(row.id)
}

pub async fn d1_password_identity_by_user_id(db: &DatabaseConnection, user_id: &str) -> Result<Option<IdentityRow>> {
    identity::Entity::find()
        .filter(identity::Column::UserId.eq(user_id.to_string()))
        .filter(identity::Column::Provider.eq("password"))
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn d1_password_identity_by_identifier(
    db: &DatabaseConnection,
    identifier: &str,
) -> Result<Option<IdentityRow>> {
    let identifier_lower = beacon_core::username::normalize_username(identifier);

    identity::Entity::find()
        .filter(identity::Column::Provider.eq("password"))
        .filter(identity::Column::ProviderUserId.eq(identifier_lower))
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn d1_update_password_identity_hash(db: &DatabaseConnection, user_id: &str, new_hash: &str) -> Result<()> {
    let ts = now_ts();

    identity::Entity::update_many()
        .col_expr(identity::Column::PasswordHash, Expr::value(new_hash))
        .col_expr(identity::Column::UpdatedAt, Expr::value(ts))
        .filter(identity::Column::UserId.eq(user_id.to_string()))
        .filter(identity::Column::Provider.eq("password"))
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn d1_update_password_identity_identifier(
    db: &DatabaseConnection,
    user_id: &str,
    new_identifier: &str,
) -> Result<()> {
    let ts = now_ts();

    identity::Entity::update_many()
        .col_expr(identity::Column::ProviderUserId, Expr::value(new_identifier))
        .col_expr(identity::Column::UpdatedAt, Expr::value(ts))
        .filter(identity::Column::UserId.eq(user_id.to_string()))
        .filter(identity::Column::Provider.eq("password"))
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn d1_delete_identity_by_id(db: &DatabaseConnection, id: &str) -> Result<()> {
    identity::Entity::delete_by_id(id.to_string())
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn d1_count_identities_by_user_id(db: &DatabaseConnection, user_id: &str) -> Result<i64> {
    let count = identity::Entity::find()
        .filter(identity::Column::UserId.eq(user_id.to_string()))
        .count(db)
        .await
        .map_err(map_db_err)?;

    Ok(count as i64)
}

pub async fn d1_count_passkeys_by_user_id(db: &DatabaseConnection, user_id: &str) -> Result<i64> {
    let count = passkey::Entity::find()
        .filter(passkey::Column::UserId.eq(user_id.to_string()))
        .count(db)
        .await
        .map_err(map_db_err)?;

    Ok(count as i64)
}
