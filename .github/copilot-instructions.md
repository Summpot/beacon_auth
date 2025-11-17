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
* **[CRITICAL] Code Verification:** 
    * **After modifying any Rust code**, you **MUST** run `cargo check --workspace` to verify compilation before completing your task.
    * **After modifying any Kotlin/Mod code**, you **SHOULD** run `./gradlew build` (from `modSrc/`) to verify compilation when feasible.
    * Never consider a code modification complete without verification.
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
* **Tech Stack:** React (Hooks), Rsbuild, `pnpm`, `tailwind`, `@tanstack/react-router`, `react-hook-form`.
* **Routing & State:** **`@tanstack/react-router`** is the *only* tool for routing and URL search parameter management.
    * The index route (`/`) **must** use `validateSearch` to parse and require `challenge` (string) and `redirect_port` (number).
    * The component **must** use the `useSearch()` hook to retrieve these values.
* **Forms:** **`react-hook-form`** must be used for the login and registration forms.
* **Styling:** **`tailwind`** must be used for all styling.
* **Configuration Fetching:**
    * On component mount, the login page **must** fetch `GET /api/v1/config` to determine which auth providers are available.
    * The response contains: `{ database_auth: boolean, github_oauth: boolean, google_oauth: boolean }`.
* **Conditional UI Rendering:**
    * **Database login form**: Only shown if `config.database_auth === true`.
    * **OAuth buttons**: Only shown if `config.github_oauth === true` or `config.google_oauth === true`.
    * **"Or continue with" divider**: Only shown if both database auth and at least one OAuth provider are enabled.
    * **Register link**: Only shown if `config.database_auth === true`.
* **Login Flow (Standard):**
    * The login form `onSubmit` handler must:
        * Get `username`, `password` (from `react-hook-form`) and `challenge`, `redirect_port` (from `useSearch()`).
        * `fetch` `POST /api/v1/login` with all 4 values in a JSON body.
        * On 200 OK, parse the `{"redirectUrl": "..."}` JSON response.
        * **Execute `window.location.href = data.redirectUrl;`** to trigger the redirect back to the Mod.
* **Login Flow (OAuth):**
    * The "Login with..." buttons must:
        * Get `challenge` and `redirect_port` from `useSearch()`.
        * `fetch` `POST /api/v1/oauth/start` with `{ provider, challenge, redirect_port }`.
        * On 200 OK, parse the `{"authorizationUrl": "..."}` JSON response.
        * **Execute `window.location.href = data.authorizationUrl;`** to redirect to the OAuth provider.
* **Registration Flow:**
    * The register form must `fetch` `POST /api/v1/register`.
    * On 201 Created, it must use the `router` from `TanStack Router` to navigate back to the login page (`/`).

---

## Project 2: Backend (Root - `crates/`, `Cargo.toml`)
* **Tech Stack:** Rust, Actix-web, Sea-ORM, `jsonwebtoken`, `p256`, `ecdsa`, `clap`, `rust-embed`, `actix-files`, `which`, `reqwest`, `bcrypt`.
* **Project Structure:** This is a **virtual Cargo workspace** defined in the **root `Cargo.toml`**. All Rust code lives in the `crates/` directory:
    * `crates/beacon/` - Main auth server binary (`beacon`)
    * `crates/entity/` - Sea-ORM entity definitions
    * `crates/migration/` - Database migration definitions
* **Application:** The `beacon` crate is a **CLI application** using `clap`. The `main` function parses commands (`serve`, `migrate`, `create-user`, `list-users`, `delete-user`).
* **`build.rs` (in `crates/beacon`):**
    * **Must** have a `[build-dependencies]` section that includes `which`.
    * **Must** use `which::which("pnpm")` to find the full path to `pnpm` (or `pnpm.cmd`) to ensure Windows compatibility.
    * **Must** execute `pnpm build` in the **root directory** (`../../`) before the Rust build proceeds.
* **`serve` Command Logic:**
    * **Crypto:** All JWTs **must** be signed using **`ES256`** (Elliptic Curve, P-256).
    * **Keys:** `ES256` keys must be generated on startup.
    * **JWKS:** The `/.well-known/jwks.json` endpoint **must** serve the `ES256` public key in `kty: "EC"`, `crv: "P-256"` format.
    * **Static Serving (Dual Mode):**
        * **Debug (`cfg(debug_assertions)`)**: Must serve files from the `dist/` directory using `actix-files`, with a SPA fallback to `dist/index.html`.
        * **Release (`cfg(not(debug_assertions)`)**: Must serve files from memory using `rust-embed` and `rust-embed-actix-web`.
* **API Endpoints:**
    * **`GET /api/v1/config`**: Returns JSON with available authentication providers: `{ "database_auth": bool, "github_oauth": bool, "google_oauth": bool }`. Used by frontend to conditionally show login options.
    * **`POST /api/v1/login`**: Receives JSON `{ username, password, challenge, redirect_port }`. Verifies password (`bcrypt`). On success, creates `ES256` JWT (embedding `challenge` claim) and returns JSON: `{ "redirectUrl": "http://localhost:{redirect_port}/auth-callback?jwt=..." }`.
    * **`POST /api/v1/register`**: Receives JSON `{ username, password, challenge, redirect_port }`. Validates input, hashes password with bcrypt, creates user in Sea-ORM. Auto-logs in user by generating JWT. Returns 201 Created with JSON: `{ "redirectUrl": "..." }`.
    * **`POST /api/v1/oauth/start`**: Receives JSON `{ provider, challenge, redirect_port }`. Generates UUID state token, stores OAuth state in memory (using `RwLock<HashMap>`). Returns JSON: `{ "authorizationUrl": "..." }`.
    * **`GET /api/v1/oauth/callback`**: Receives query params `?code=...&state=...`. Validates state token, exchanges code for OAuth user info (GitHub/Google), finds or creates user in database. Creates the final *Minecraft `ES256` JWT*. Returns an **HTTP 302 Redirect** back to the Mod's `localhost` URL: `http://localhost:{port}/auth-callback?jwt=...`.

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
    * `HttpHandler` at `/auth-callback`: Receives callback with `?jwt=...` query param, attempts to focus the Minecraft window using `GLFW.glfwRequestWindowAttention()`, parses JWT, sends `VerifyAuthPacket` (C2S) with JWT and verifier. Returns an **i18n-translated** HTML "Success" page using `TranslationHelper.translate()`.
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