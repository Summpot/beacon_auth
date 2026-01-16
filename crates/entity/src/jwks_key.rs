use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "jwks_keys")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub kid: String,

    /// Base64-encoded PKCS#8 DER private key.
    #[sea_orm(column_type = "Text")]
    pub pkcs8_der_b64: String,

    /// Cached JWKS JSON for this key.
    #[sea_orm(column_type = "Text")]
    pub jwks_json: String,

    /// Unix timestamp (seconds).
    pub created_at: i64,

    /// Unix timestamp (seconds).
    pub updated_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
