use sea_orm::entity::prelude::*;

pub mod user {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
    #[sea_orm(table_name = "users")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = true)]
        pub id: i64,

        #[sea_orm(unique)]
        pub username: String,

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
}

pub mod passkey {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
    #[sea_orm(table_name = "passkeys")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = true)]
        pub id: i64,

        pub user_id: i64,

        #[sea_orm(unique)]
        pub credential_id: String,

        #[sea_orm(column_type = "Text")]
        pub credential_data: String,

        pub name: String,

        /// Unix timestamp (seconds).
        pub last_used_at: Option<i64>,

        /// Unix timestamp (seconds).
        pub created_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod refresh_token {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
    #[sea_orm(table_name = "refresh_tokens")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = true)]
        pub id: i64,

        pub user_id: i64,

        #[sea_orm(unique)]
        pub token_hash: String,

        pub family_id: String,

        /// Unix timestamp (seconds).
        pub expires_at: i64,

        /// D1 schema stores this as INTEGER 0/1.
        pub revoked: i64,

        /// Unix timestamp (seconds).
        pub created_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod identity {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
    #[sea_orm(table_name = "identities")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = true)]
        pub id: i64,

        pub user_id: i64,

        pub provider: String,

        pub provider_user_id: String,

        pub password_hash: Option<String>,

        /// Unix timestamp (seconds).
        pub created_at: i64,

        /// Unix timestamp (seconds).
        pub updated_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
