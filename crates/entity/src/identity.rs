use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "identities")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i64,

    /// Foreign key to users table
    pub user_id: i64,

    /// Identity provider (e.g. "github", "google")
    pub provider: String,

    /// Provider-scoped stable user identifier (e.g. GitHub numeric id as string)
    pub provider_user_id: String,

    /// When provider == "password", this stores the bcrypt password hash.
    /// For OAuth/passkey providers this is NULL.
    pub password_hash: Option<String>,

    /// Unix timestamp (seconds).
    pub created_at: i64,

    /// Unix timestamp (seconds).
    pub updated_at: i64,
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

