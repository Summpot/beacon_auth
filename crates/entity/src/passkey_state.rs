use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "passkey_states")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub key: String,

    /// JSON-serialized RegistrationState / AuthenticationState.
    #[sea_orm(column_type = "Text")]
    pub state_json: String,

    /// Unix timestamp (seconds).
    pub expires_at: i64,

    /// Unix timestamp (seconds).
    pub created_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
