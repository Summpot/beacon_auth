use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "passkeys")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,

    /// Foreign key to users table
    pub user_id: i32,

    /// Base64-encoded credential ID (unique identifier for this passkey)
    #[sea_orm(unique)]
    pub credential_id: String,

    /// Serialized credential data (WebAuthn Credential)
    #[sea_orm(column_type = "Text")]
    pub credential_data: String,

    /// User-friendly name for this passkey (e.g., "iPhone 14", "YubiKey")
    pub name: String,

    /// Last time this passkey was used for authentication
    pub last_used_at: Option<ChronoDateTimeUtc>,

    pub created_at: ChronoDateTimeUtc,
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
