use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i64,

    #[sea_orm(unique)]
    pub username: String,

    /// Normalized username for case-insensitive uniqueness and lookups.
    ///
    /// This should always be `username.to_ascii_lowercase()`.
    #[sea_orm(unique)]
    pub username_lower: String,

    /// Unix timestamp (seconds).
    pub created_at: i64,

    /// Unix timestamp (seconds).
    pub updated_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

