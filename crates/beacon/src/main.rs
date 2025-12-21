use bcrypt::hash;
use beacon_core::username;
use beacon_lib::{
    config::{Command, Config},
    server::run_server,
};
use chrono::Utc;
use clap::Parser;
use entity::{identity, user};
use migration::MigratorTrait;
use sea_orm::{ActiveModelTrait, ColumnTrait, Database, EntityTrait, QueryFilter, Set};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    // Parse CLI arguments
    let config = Config::parse();

    // Initialize logger based on command
    let log_level = match &config.command {
        Command::Serve(serve_config) => serve_config.log_level.as_str(),
        _ => "info",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    match config.command {
        Command::Serve(serve_config) => {
            run_server(serve_config).await?;
        }
        Command::Migrate { database_url } => {
            run_migrations(&database_url).await?;
        }
        Command::CreateUser { username, password } => {
            create_user(&username, &password).await?;
        }
        Command::ListUsers => {
            list_users().await?;
        }
        Command::DeleteUser { username } => {
            delete_user(&username).await?;
        }
    }

    Ok(())
}

async fn run_migrations(database_url: &str) -> anyhow::Result<()> {
    log::info!("Connecting to database: {}", database_url);
    let db = Database::connect(database_url).await?;

    log::info!("Running database migrations...");
    migration::Migrator::up(&db, None).await?;

    println!("✅ Database migrations completed successfully!");

    Ok(())
}

async fn create_user(username: &str, password: &str) -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://./beacon_auth.db?mode=rwc".to_string());

    log::info!("Connecting to database...");
    let db = Database::connect(&database_url).await?;

    let requested_username = username.trim().to_string();
    if let Err(msg) = username::validate_minecraft_username(&requested_username) {
        anyhow::bail!("Invalid username: {msg}");
    }
    let requested_username_lower = username::normalize_username(&requested_username);

    // Check if user already exists
    let existing = user::Entity::find()
        .filter(user::Column::UsernameLower.eq(&requested_username_lower))
        .one(&db)
        .await?;

    if existing.is_some() {
        anyhow::bail!("User '{}' already exists", username);
    }

    // Hash password
    log::info!("Hashing password...");
    let password_hash = hash(password, bcrypt::DEFAULT_COST)?;

    // Create user
    let now = Utc::now();
    let new_user = user::ActiveModel {
        username: Set(requested_username.clone()),
        username_lower: Set(requested_username_lower.clone()),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };

    let result = user::Entity::insert(new_user).exec(&db).await?;

    let new_identity = identity::ActiveModel {
        user_id: Set(result.last_insert_id),
        provider: Set("password".to_string()),
        provider_user_id: Set(requested_username_lower.clone()),
        password_hash: Set(Some(password_hash)),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };
    new_identity.insert(&db).await?;

    println!("✅ User created successfully!");
    println!("   ID: {}", result.last_insert_id);
    println!("   Username: {}", requested_username);

    Ok(())
}

async fn list_users() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://./beacon_auth.db?mode=rwc".to_string());

    let db = Database::connect(&database_url).await?;

    let users = user::Entity::find().all(&db).await?;

    if users.is_empty() {
        println!("No users found.");
    } else {
        println!("Users:");
        println!("{:<5} {:<20} {:<30}", "ID", "Username", "Created At");
        println!("{}", "-".repeat(60));
        for user in users {
            println!(
                "{:<5} {:<20} {:<30}",
                user.id,
                user.username,
                user.created_at.format("%Y-%m-%d %H:%M:%S")
            );
        }
    }

    Ok(())
}

async fn delete_user(username: &str) -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://./beacon_auth.db?mode=rwc".to_string());

    let db = Database::connect(&database_url).await?;

    let username_lower = username::normalize_username(username);
    let user = user::Entity::find()
        .filter(user::Column::UsernameLower.eq(username_lower))
        .one(&db)
        .await?;

    match user {
        Some(user) => {
            user::Entity::delete_by_id(user.id).exec(&db).await?;
            println!("✅ User '{}' deleted successfully!", username);
        }
        None => {
            anyhow::bail!("User '{}' not found", username);
        }
    }

    Ok(())
}
