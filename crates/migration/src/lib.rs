pub use sea_orm_migration::prelude::*;

mod m20250124_000001_create_all_tables;

pub struct Migrator;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250124_000001_create_all_tables::Migration),
        ]
    }
}
