use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create users table
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Users::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Users::Username)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(Users::UsernameLower)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(Users::CreatedAt)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Users::UpdatedAt)
                            .big_integer()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Create identities table (OAuth providers + password identity).
        manager
            .create_table(
                Table::create()
                    .table(Identities::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Identities::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Identities::UserId).big_integer().not_null())
                    .col(ColumnDef::new(Identities::Provider).string().not_null())
                    .col(
                        ColumnDef::new(Identities::ProviderUserId)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Identities::PasswordHash).string())
                    .col(
                        ColumnDef::new(Identities::CreatedAt)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Identities::UpdatedAt)
                            .big_integer()
                            .not_null(),
                    )
                    .index(
                        Index::create()
                            .name("uidx_identities_provider_user")
                            .table(Identities::Table)
                            .col(Identities::Provider)
                            .col(Identities::ProviderUserId)
                            .unique(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_identities_user_id")
                            .from(Identities::Table, Identities::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

                // SQLite cannot represent a non-unique index as a table-level CONSTRAINT,
                // so we create these indexes separately.
                manager
                    .create_index(
                    Index::create()
                        .name("idx_identities_user_id")
                        .table(Identities::Table)
                        .col(Identities::UserId)
                        .to_owned(),
                    )
                    .await?;

        // Create passkeys table
        manager
            .create_table(
                Table::create()
                    .table(Passkeys::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Passkeys::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Passkeys::UserId).big_integer().not_null())
                    .col(
                        ColumnDef::new(Passkeys::CredentialId)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(Passkeys::CredentialData).text().not_null())
                    .col(ColumnDef::new(Passkeys::Name).string().not_null())
                    .col(ColumnDef::new(Passkeys::LastUsedAt).big_integer())
                    .col(
                        ColumnDef::new(Passkeys::CreatedAt)
                            .big_integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_passkeys_user_id")
                            .from(Passkeys::Table, Passkeys::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_passkeys_user_id")
                    .table(Passkeys::Table)
                    .col(Passkeys::UserId)
                    .to_owned(),
            )
            .await?;

        // Create refresh_tokens table
        manager
            .create_table(
                Table::create()
                    .table(RefreshTokens::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(RefreshTokens::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(RefreshTokens::UserId).big_integer().not_null())
                    .col(
                        ColumnDef::new(RefreshTokens::TokenHash)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(RefreshTokens::FamilyId).string().not_null())
                    .col(
                        ColumnDef::new(RefreshTokens::ExpiresAt)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RefreshTokens::Revoked)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(RefreshTokens::CreatedAt)
                            .big_integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_refresh_tokens_user_id")
                            .from(RefreshTokens::Table, RefreshTokens::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_refresh_tokens_user_id")
                    .table(RefreshTokens::Table)
                    .col(RefreshTokens::UserId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop tables in reverse order (due to foreign keys)
        manager
            .drop_table(Table::drop().table(RefreshTokens::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(Passkeys::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(Identities::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(Users::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
    Username,
    UsernameLower,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Identities {
    Table,
    Id,
    UserId,
    Provider,
    ProviderUserId,
    PasswordHash,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Passkeys {
    Table,
    Id,
    UserId,
    CredentialId,
    CredentialData,
    Name,
    LastUsedAt,
    CreatedAt,
}

#[derive(DeriveIden)]
enum RefreshTokens {
    Table,
    Id,
    UserId,
    TokenHash,
    FamilyId,
    ExpiresAt,
    Revoked,
    CreatedAt,
}
