-- D1 (SQLite) schema for BeaconAuth.
--
-- This file is generated from the SeaORM migrator (crates/migration).
-- Regenerate with:
--   cargo run -p migration --bin generate_d1_sql

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS "users" ( "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "username" varchar NOT NULL UNIQUE, "username_lower" varchar NOT NULL UNIQUE, "created_at" integer NOT NULL, "updated_at" integer NOT NULL );

CREATE TABLE IF NOT EXISTS "identities" ( "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "user_id" integer NOT NULL, "provider" varchar NOT NULL, "provider_user_id" varchar NOT NULL, "password_hash" varchar, "created_at" integer NOT NULL, "updated_at" integer NOT NULL, CONSTRAINT "uidx_identities_provider_user" UNIQUE ("provider", "provider_user_id"), FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE CASCADE );

CREATE TABLE IF NOT EXISTS "passkeys" ( "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "user_id" integer NOT NULL, "credential_id" varchar NOT NULL UNIQUE, "credential_data" text NOT NULL, "name" varchar NOT NULL, "last_used_at" integer, "created_at" integer NOT NULL, FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE CASCADE );

CREATE TABLE IF NOT EXISTS "refresh_tokens" ( "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "user_id" integer NOT NULL, "token_hash" varchar NOT NULL UNIQUE, "family_id" varchar NOT NULL, "expires_at" integer NOT NULL, "revoked" integer NOT NULL DEFAULT 0, "created_at" integer NOT NULL, FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE CASCADE );

CREATE INDEX IF NOT EXISTS "idx_identities_user_id" ON "identities" ("user_id");

CREATE INDEX IF NOT EXISTS "idx_passkeys_user_id" ON "passkeys" ("user_id");

CREATE INDEX IF NOT EXISTS "idx_refresh_tokens_user_id" ON "refresh_tokens" ("user_id");

