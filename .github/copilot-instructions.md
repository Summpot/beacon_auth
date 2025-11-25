# BeaconAuth Monorepo - AI Guidance

## 1. Our Goal
You are an AI assistant helping to build the **BeaconAuth** monorepo. Your task is to understand and correctly modify the three distinct projects within this repository:
1.  **The Frontend** (React/Rsbuild)
2.  **The Backend** (Rust/Actix-web API)
3.  **The Minecraft Mod** (Kotlin/Architectury/Gradle)

## 2. Core Monorepo Structure (CRITICAL)
This repository contains three projects with two different "root" concepts.

* **Project 1: Root (Frontend & Backend)**
    * The **project root** directory contains the **React Frontend** (`package.json`, `rsbuild.config.ts`, `src/`) and the **Rust Backend** (`Cargo.toml`, `crates/`).
    * This is the "main" project for web development.
    * `cargo` and `pnpm` commands are run from here.

* **Project 2: `modSrc/` (Minecraft Mod)**
    * The `modSrc/` directory is a **separate, self-contained Gradle project**.
    * It contains all Kotlin Mod code (`common/`, `fabric/`, `forge/`) and its own build system (`build.gradle.kts`, `settings.gradle.kts`, `gradlew`).
    * **To work on the Mod in an IDE, you MUST open the `modSrc/` directory as the project root (or open `modSrc/build.gradle.kts`).**

## 3. Global Coding Guidelines
* **[NEW] Language:** 
    * **User Communication:** When responding to users, use the **same language as the user's request** for better understanding.
    * **Code Output:** All code content (comments, documentation, commit messages, console logs) **must** be written in **English** for consistency.
* **[CRITICAL] Git Change Synchronization:**
    * **Before summarizing completed changes**, you **MUST** read git changes using `get_changed_files` tool.
    * **After reviewing git changes**, update this instruction file (`.github/copilot-instructions.md`) to reflect any new patterns, endpoints, architecture changes, or workflows discovered in the changes.
    * This ensures the instruction file stays synchronized with actual implementation.
* **[CRITICAL] Code Verification:** 
    * **After modifying any Rust code**, you **MUST** run `cargo check --workspace` to verify compilation before completing your task.
    * **After modifying any Kotlin/Mod code**, you **SHOULD** run `./gradlew build` (from `modSrc/`) to verify compilation when feasible.
    * Never consider a code modification complete without verification.
* **[CRITICAL] Database Migrations:**
    * **Always assume migrations have been applied successfully** unless the error specifically indicates a migration failure.
    * **Do NOT manually run migrations** (e.g., `cargo run -- migrate`) during development or debugging, unless you are explicitly testing the migration system itself.
    * The application **automatically runs migrations on startup** via `migration::Migrator::up(&db, None)` in the `serve` command.
    * If database errors occur, investigate the **schema definition** (entities and migrations) rather than attempting to re-run migrations.
* **[CRITICAL] Library Usage Research:**
    * **Before using any external library**, you **MUST** use the **DeepWiki MCP server** to query the correct usage patterns, API methods, and best practices.
    * Query format: Use `mcp_cognitionai_d_ask_question` with the repo name (e.g., `"moka-rs/moka"`, `"actix/actix-web"`) and a specific question about usage.
    * This ensures you're using the latest API correctly and avoiding deprecated or incorrect patterns.
* **[CRITICAL] Project Synchronization:**
    * **After making major changes** to the project (new features, architecture changes, API modifications, build system updates), you **MUST** synchronize documentation:
        * Update this **instruction file** (`.github/copilot-instructions.md`) with new patterns, endpoints, or workflows.
        * Update the **README.md** with user-facing changes, setup instructions, or API documentation.
        * Update **GitHub Actions workflows** (`.github/workflows/*.yml`) if build processes, dependencies, or deployment steps change.
    * This ensures consistency across documentation, AI guidance, and automation.
* **Dependency Management:**
    * **Frontend:** Always use `pnpm add <package-name>` from the **root** directory.
    * **Backend:** Always use `cargo add -p <crate-name>` (or `--build -p`) from the **root** directory to add dependencies to the correct workspace crate.
    * **Mod:** Gradle dependencies are managed in `modSrc/build.gradle.kts`.

---

## Project 1: Frontend (Root - `src/`, `package.json`, etc.)
* **Tech Stack:** React (Hooks), Rsbuild, `pnpm`, `tailwind`, `@tanstack/react-router`, `@tanstack/react-query`, `react-hook-form`, `@simplewebauthn/browser`.
* **Data Fetching:** **`@tanstack/react-query`** is used for server state management. The `QueryClient` is configured in `__root.tsx` with appropriate defaults (1-minute stale time, refetchOnWindowFocus disabled).
* **API Utilities:** `src/utils/api.ts` provides:
    * `fetchWithAuth()` - Fetch wrapper for automatic token refresh on 401 responses. **ALL** authenticated API calls **must** use `fetchWithAuth()` instead of plain `fetch()`.
    * `fetchJsonWithAuth()` - Type-safe JSON wrapper that throws `ApiError` for better error handling with TanStack Query.
    * `queryKeys` - Query key factory for consistent cache key management (e.g., `queryKeys.userMe()`, `queryKeys.passkeys()`).
    * `fetchWithAuth()` automatically calls `POST /api/v1/refresh` on 401, retries the original request, and redirects to `/` if refresh fails.
    * This ensures seamless session management across all authenticated endpoints.
* **Routing & State:** **`@tanstack/react-router`** is the *only* tool for routing and URL search parameter management.
    * The login route (`/login`) has **optional** `challenge` and `redirect_port` params (used for Minecraft mode). Non-Minecraft web login works without these params.
    * The component **must** use the `useSearch()` hook to retrieve these values.
    * The index route (`/`) is the **home page** (dashboard), accessible to all users. Shows project info and links to profile.
    * The `/profile` route is the **user profile page** (requires authentication). Shows user info and links to settings.
    * The `/settings` route is the **profile settings page** where users can change password, register passkeys, and manage existing passkeys.
    * The `/oauth-complete` route is a **processing page** that completes OAuth authentication by generating Minecraft JWT and redirecting to the mod (or home page for web-only OAuth).
* **Forms:** **`react-hook-form`** must be used for the login and registration forms.
* **Styling:** **`tailwind`** must be used for all styling.
* **Configuration Fetching:**
    * On component mount, the login page **must** fetch `GET /api/v1/config` to determine which auth providers are available.
    * The response contains: `{ database_auth: boolean, github_oauth: boolean, google_oauth: boolean }`.
* **Conditional UI Rendering:**
    * **Challenge/Port info box**: Only shown if `challenge` and `redirect_port` params are present (Minecraft mode).
    * **Database login form**: Only shown if `config.database_auth === true`.
    * **OAuth buttons**: Only shown if `config.github_oauth === true` or `config.google_oauth === true`.
    * **"Or continue with" divider**: Only shown if both database auth and at least one OAuth provider are enabled.
    * **Register link**: Only shown if `config.database_auth === true`.
* **Login Flow (Standard):**
    * The login form `onSubmit` handler must:
        * Get `username`, `password` (from `react-hook-form`) and `challenge`, `redirect_port` (from `useSearch()`).
        * **Step 1**: `fetch` (NOT `fetchWithAuth`) `POST /api/v1/login` with `{ username, password }` and `credentials: 'include'`. This sets `HttpOnly` session cookies (`access_token`, `refresh_token`).
        * **Step 2**: If `challenge` and `redirect_port` exist (Minecraft mode), call `fetchWithAuth` `POST /api/v1/minecraft-jwt` with `{ challenge, redirect_port, profile_url }`. The `profile_url` is `window.location.origin + '/profile'`. On success, execute `window.location.href = data.redirectUrl;`.
        * **Step 2 Alternative**: If no challenge/redirect_port (web login), simply redirect to `/` home page.
    * **Auto-Login**: On mount, if `challenge` and `redirect_port` exist, check for valid session by calling `fetchWithAuth` `POST /api/v1/minecraft-jwt`. If successful, auto-redirect immediately without showing login UI.
* **Login Flow (OAuth):**
    * The "Login with..." buttons must:
        * Get `challenge` and `redirect_port` from `useSearch()` (may be undefined for web-only OAuth).
        * If challenge/redirect_port exist, save to `sessionStorage` with keys `minecraft_challenge` and `minecraft_redirect_port`. Otherwise, clear these keys.
        * `fetch` (NOT `fetchWithAuth`) `POST /api/v1/oauth/start` with `{ provider, challenge: challenge || '', redirect_port: redirect_port || 0 }`.
        * On 200 OK, parse the `{"authorizationUrl": "..."}` JSON response.
        * **Execute `window.location.href = data.authorizationUrl;`** to redirect to the OAuth provider.
    * **OAuth Callback Flow**:
        * The backend `/api/v1/oauth/callback` endpoint sets session cookies and redirects to `/oauth-complete`.
        * The `/oauth-complete` page retrieves `challenge` and `redirect_port` from `sessionStorage` (keys: `minecraft_challenge`, `minecraft_redirect_port`).
        * **If challenge/redirect_port exist (Minecraft mode)**: Calls `fetchWithAuth` `POST /api/v1/minecraft-jwt`, cleans up sessionStorage, redirects to Minecraft via `redirectUrl`.
        * **If challenge/redirect_port missing (web mode)**: Cleans up sessionStorage, redirects to `/` home page.
* **Registration Flow:**
    * The register form must `fetch` (NOT `fetchWithAuth`) `POST /api/v1/register` with `{ username, password }`.
    * On 201 Created, session cookies are automatically set.
    * Then call `fetchWithAuth` `POST /api/v1/minecraft-jwt` (if challenge/redirect_port exist) and redirect via `redirectUrl`.
* **Passkey Registration:**
    * Use `@simplewebauthn/browser`'s `startRegistration()` function to handle WebAuthn ceremony.
    * **CRITICAL**: Pass `data.creation_options.publicKey` to `startRegistration()`, NOT `data.creation_options`. The response has a nested structure: `{ creation_options: { publicKey: {...} } }`.
    * The `startRegistration()` function automatically handles all base64url ↔ ArrayBuffer conversions.

---

## Project 2: Backend (Root - `crates/`, `Cargo.toml`)
* **Tech Stack:** Rust, Actix-web, Sea-ORM, `jsonwebtoken`, `p256`, `ecdsa`, `clap`, `rust-embed`, `actix-files`, `which`, `reqwest`, `bcrypt`, `webauthn-rs` (for passkey support).
* **Project Structure:** This is a **virtual Cargo workspace** defined in the **root `Cargo.toml`**. All Rust code lives in the `crates/` directory:
    * `crates/beacon/` - Main auth server binary (`beacon`)
    * `crates/entity/` - Sea-ORM entity definitions
    * `crates/migration/` - Database migration definitions
* **Database Schema Conventions:**
    * **Table names MUST use plural form** (e.g., `users`, `passkeys`, `refresh_tokens`).
    * Entity structs use singular names (e.g., `User`, `Passkey`, `RefreshToken`) but map to plural table names.
    * All timestamps should use `chrono::DateTime<Utc>` and be named with `_at` suffix (e.g., `created_at`, `updated_at`).
* **Application:** The `beacon` crate is a **CLI application** using `clap`. The `main` function parses commands (`serve`, `migrate`, `create-user`, `list-users`, `delete-user`).
* **`build.rs` (in `crates/beacon`):**
    * **Must** have a `[build-dependencies]` section that includes `which`.
    * **Must** use `which::which("pnpm")` to find the full path to `pnpm` (or `pnpm.cmd`) to ensure Windows compatibility.
    * **Must** execute `pnpm build` in the **root directory** (`../../`) before the Rust build proceeds.
* **`serve` Command Logic:**
    * **Crypto:** All JWTs **must** be signed using **`ES256`** (Elliptic Curve, P-256).
    * **Keys:** `ES256` keys must be generated on startup using `p256` crate.
    * **DecodingKey Creation:** The `DecodingKey` for JWT verification **MUST** be created using `DecodingKey::from_ec_components(x, y)` with base64url-encoded x and y coordinates. **DO NOT** use `DecodingKey::from_ec_der()` with SPKI format as `jsonwebtoken`'s `rust_crypto` backend expects PKCS#8 format which is incompatible.
    * **JWKS:** The `/.well-known/jwks.json` endpoint **must** serve the `ES256` public key in `kty: "EC"`, `crv: "P-256"` format.
    * **Static Serving (Dual Mode):**
        * **Debug (`cfg(debug_assertions)`)**: Must serve files from the `dist/` directory using `actix-files`, with a SPA fallback to `dist/index.html`.
        * **Release (`cfg(not(debug_assertions)`)**: Must serve files from memory using `rust-embed` and `rust-embed-actix-web`.
* **Configuration:**
    * **`--base-url` / `BASE_URL`**: Single unified URL parameter (default: `http://localhost:8080`) used for:
        * OAuth redirect callbacks
        * JWT issuer (`iss`) claim
        * WebAuthn Relying Party origin
    * This replaces the previous separate `--oauth-redirect-base` and `--issuer-url` parameters.
* **API Endpoints:**
    * **`GET /api/v1/config`**: Returns JSON with available authentication providers: `{ "database_auth": bool, "github_oauth": bool, "google_oauth": bool }`. Used by frontend to conditionally show login options.
    * **`POST /api/v1/login`**: Receives JSON `{ username, password }`. Verifies password (`bcrypt`). On success, creates `access_token` (ES256 JWT, 15 min expiry) and `refresh_token` (random SHA-256 hashed, stored in DB with family_id for rotation tracking, 30 day expiry). Sets `HttpOnly` cookies. Returns `{ "success": true }`.
    * **`POST /api/v1/register`**: Receives JSON `{ username, password }`. Validates input (min 6 chars password), hashes password with bcrypt, creates user in Sea-ORM. Auto-logs in user by creating session tokens and setting cookies. Returns 201 Created with `{ "success": true }`.
    * **`POST /api/v1/refresh`**: Receives `refresh_token` from cookie. Validates refresh token from database by SHA-256 hash lookup, checks expiration and revocation. **Implements token rotation**: revokes old refresh token and generates new token pair with same `family_id`. Returns new tokens as cookies.
    * **`POST /api/v1/minecraft-jwt`**: **[Authenticated]** Receives JSON `{ challenge, redirect_port, profile_url }`. Verifies `access_token` cookie using **proper ES256 signature verification** (issuer, audience, expiration checks). Creates Minecraft-specific `ES256` JWT with `challenge` claim (audience: `minecraft-client`, 1 hour expiry). Returns `{ "redirectUrl": "http://localhost:{port}/auth-callback?jwt={token}&profile_url={encoded_url}" }` where `profile_url` is URL-encoded.
* **Token Verification:**
    * Access tokens are verified using `jsonwebtoken::decode()` with proper ES256 signature verification.
    * Validation checks: issuer (must match `base_url`), audience (`beaconauth-web`), expiration, and token type (`access`).
    * The `verify_access_token()` helper function in `handlers/auth.rs` handles this verification.
    * **`POST /api/v1/oauth/start`**: Receives JSON `{ provider, challenge, redirect_port }`. Generates UUID state token, stores OAuth state in memory (using `Arc<RwLock<HashMap>>`). Returns JSON: `{ "authorizationUrl": "..." }`.
    * **`GET /api/v1/oauth/callback`**: Receives query params `?code=...&state=...`. Validates state token, exchanges code for OAuth user info (GitHub/Google), finds or creates user in database (username format: `gh_{login}` or `gg_{email_prefix}`, password_hash: `oauth_{provider}_{id}`). Creates session tokens (`access_token`, `refresh_token`) and sets cookies. Returns **HTTP 302 Redirect** to `/oauth-complete` page.
    * **`GET /api/v1/user/me`**: **[Authenticated]** Returns current user info: `{ id, username }`. Verifies `access_token` cookie.
    * **`POST /api/v1/user/change-password`**: **[Authenticated]** Receives `{ current_password, new_password }`. Verifies current password, validates new password (min 6 chars), hashes and updates in database. Returns `{ "success": true }`.
    * **`POST /api/v1/logout`**: **[Authenticated]** Revokes all refresh tokens for the authenticated user. Clears `access_token` and `refresh_token` cookies. Returns `{ "success": true }`.
    * **`POST /api/v1/passkey/register/start`**: **[Authenticated]** Receives `{ name }`. Starts WebAuthn passkey registration using `webauthn-rs`. Returns `{ "creation_options": CreationChallengeResponse }`. Stores registration state in moka cache (5-min TTL).
    * **`POST /api/v1/passkey/register/finish`**: **[Authenticated]** Receives `{ credential, name }`. Completes passkey registration, stores credential in database. Returns `{ "success": true, "passkey_id": int }`.
    * **`POST /api/v1/passkey/auth/start`**: Receives optional `{ username }`. Starts passkey authentication. Returns `{ "request_options": RequestChallengeResponse }`. Stores auth state in moka cache (5-min TTL, keyed by challenge).
    * **`POST /api/v1/passkey/auth/finish`**: Receives `{ credential }`. Completes passkey auth, updates credential counter and last_used_at. Creates session tokens and returns them as cookies. Returns `{ "success": true, "username": str }`.
    * **`GET /api/v1/passkey/list`**: **[Authenticated]** Returns `{ "passkeys": [{ id, name, created_at, last_used_at }, ...] }`.
    * **`DELETE /api/v1/passkey/{id}`**: **[Authenticated]** Deletes the specified passkey if owned by authenticated user. Returns `{ "success": true }`.

---

## Project 3: Minecraft Mod (`modSrc/`)
* **Tech Stack:** Kotlin 2.2.21, Architectury, Gradle 8.x, `com.sun.net.httpserver`, `nimbus-jose-jwt:10.6`, Minecraft 1.20.1.
* **Build System:** This is a **self-contained Gradle project** using Architectury Loom 1.11 and Kotlin DSL.
* **Subprojects:**
    * `modSrc/common/` - Common code shared between loaders
    * `modSrc/fabric/` - Fabric-specific implementation
    * `modSrc/forge/` - Forge-specific implementation
* **Dependencies (`modSrc/common/build.gradle.kts`):**
    * **Must** include `com.nimbusds:nimbus-jose-jwt:10.6` for JWT validation.
    * **Must** use `modImplementation` for Architectury dependencies.
    * **Must** include `fuzs.forgeconfigapiport:forgeconfigapiport-common:8.0.2` for cross-loader config API.
* **Config:**
    * A server-side config file (`beaconauth-server.toml`) **must** be used via FuzzyConfig.
    * The config loader **must** auto-generate this file on first run.
    * The **default** URLs in the config **must** point to `http://localhost:8080` (e.g., login URL: `http://localhost:8080/`, JWKS URL: `http://localhost:8080/.well-known/jwks.json`).
* **Internationalization (i18n):**
    * Translation files in `modSrc/common/src/main/resources/assets/beaconauth/lang/`:
        * `en_us.json` - English translations
        * `zh_cn.json` - Simplified Chinese translations
    * All user-facing strings (chat messages, HTML pages, commands) **must** use `TranslationHelper`.
* **`AuthClient.kt` (Client-Side):**
    * **Must** use `com.sun.net.httpserver.HttpServer` (Java built-in, not Ktor).
    * **Must** find a free port in the `38123-38133` range using `NetUtils.findAvailablePort()` and save it.
    * Receives `RequestClientLoginPacket` (S2C), then calls `startLoginProcess()`.
    * `startLoginProcess()`: Generates PKCE challenge/verifier via `PKCEUtils`, sends `RequestLoginUrlPacket` (C2S) with `challenge` and `boundPort`.
    * `HttpHandler` at `/auth-callback`: 
        * Receives callback with `?jwt=...&profile_url=...` query params (both URL-encoded).
        * Parses query parameters to extract `jwt` and `profile_url` using `URLDecoder.decode()`.
        * Attempts to focus the Minecraft window using **safe** GLFW functions (`glfwRestoreWindow()` if minimized, `glfwRequestWindowAttention()` for taskbar flash).
        * Parses JWT, sends `VerifyAuthPacket` (C2S) with JWT and verifier.
        * Returns an **HTTP 302 Redirect** to `{profile_url}?status=success&message=...` (or error with appropriate message).
        * **CRITICAL**: The `profile_url` is provided by the backend, **NOT** read from `ServerConfig`. This ensures proper client-server separation.
    * **Window Focus Behavior**: Window focus attempts are **best-effort only**. Due to OS-level security restrictions (especially on Windows), the window focus request **will fail** when the browser has focus. The most reliable behavior is taskbar icon flashing via `glfwRequestWindowAttention()`. **DO NOT** use `glfwFocusWindow()` or `glfwShowWindow()` as these can cause input capture issues, trapping the user's cursor. This is an OS limitation, not a bug.
* **`AuthServer.kt` (Server-Side):**
    * **State:** Must maintain a `MutableSet<UUID>` of `authenticatedPlayers` (thread-safe).
    * **Auto-Login:** **Must** hook the `PlayerJoinEvent` via `AuthEventHandler`. If player UUID is not in the `authenticatedPlayers` set, send `RequestClientLoginPacket` (S2C) to trigger login flow.
    * **Network Handlers (via `ServerLoginHandler`):**
        * `onReceiveRequestLoginUrl`: (C2S) Receives `challenge` & `boundPort`, uses `ServerConfig` to build full login URL, sends `LoginUrlPacket` (S2C) with the URL.
        * `onReceiveVerifyAuth`: (C2S) Receives `jwt` & `verifier`. Validates JWT and PKCE, then sends `AuthResultPacket` (S2C) with success/failure.
    * **Validation (Nimbus):**
        * The `jwtProcessor` **must** be initialized lazily using `RemoteJWKSet` pointing to `ServerConfig.jwksUrl`.
        * The processor **must** be configured with `JWSAlgorithm.ES256` and require `iss`, `aud`, and `exp` claims.
        * Validation: Call `jwtProcessor.process(jwt, null)` to validate signature and standard claims.
        * Then, perform PKCE check: `PKCEUtils.verifyChallenge(verifier, claims.challenge)`.
        * On success: Add player UUID to `authenticatedPlayers`, send success `AuthResultPacket`, log success message.
        * On failure: Send failure `AuthResultPacket` with error message, kick player.
    * **Events:** Must hook `PlayerQuitEvent` to remove player UUID from `authenticatedPlayers` set.
    * **Command:** A `/beaconauth login` command **must** exist (registered via `AuthCommand`) to manually trigger `RequestClientLoginPacket` (S2C) for the executing player.