use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "refresh_tokens")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: String,

    /// Foreign key to users table
    pub user_id: String,

    /// SHA-256 hash of the refresh token
    #[sea_orm(unique)]
    pub token_hash: String,

    /// Token family ID for rotation tracking
    pub family_id: String,

    /// Expiration time
    /// Unix timestamp (seconds).
    pub expires_at: i64,

    /// Whether this token has been revoked
    /// D1 schema stores this as INTEGER 0/1.
    pub revoked: i64,

    /// Unix timestamp (seconds).
    pub created_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::user::Entity",
        from = "Column::UserId",
        to = "super::user::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    User,
}

impl Related<super::user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

