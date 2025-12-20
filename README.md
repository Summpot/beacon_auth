# BeaconAuth

**BeaconAuth** is a modern, secure authentication system for Minecraft servers, featuring a web-based login interface with OAuth support and a companion mod for seamless in-game authentication.

[![Build](https://github.com/Summpot/beacon_auth/actions/workflows/build.yml/badge.svg)](https://github.com/Summpot/beacon_auth/actions/workflows/build.yml)
[![Release](https://github.com/Summpot/beacon_auth/actions/workflows/release.yml/badge.svg)](https://github.com/Summpot/beacon_auth/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Features

### Authentication Server
- 🔐 **ES256 JWT Authentication** - Industry-standard elliptic curve cryptography
- 🌐 **Modern Web Interface** - React-based login and registration pages
- 🍪 **Session Management** - Secure HttpOnly cookies with refresh token rotation
- 🔑 **OAuth Integration** - Support for GitHub and Google authentication
- 🔒 **WebAuthn/Passkey Support** - Passwordless authentication with biometrics
- 🗄️ **SQLite Database** - Simple, file-based user storage
- 🐳 **Docker Ready** - Multi-architecture container images (amd64/arm64)
- ⚡ **High Performance** - Built with Rust and Actix-web

### Minecraft Mod
- 🎮 **Automatic Login Flow** - Seamless in-game authentication
- 🔒 **PKCE Security** - Proof Key for Code Exchange protection
- 🌍 **Multi-Loader Support** - Works with both Fabric and Forge
- 🌐 **Internationalization** - English and Chinese translations
- ⚙️ **Configurable** - Server-side TOML configuration
- 🔗 **JWT Validation** - Secure verification using JWKS

## Table of Contents

- [Quick Start](#quick-start)
  - [Using Docker (Recommended)](#using-docker-recommended)
  - [Using Pre-built Binaries](#using-pre-built-binaries)
  - [Building from Source](#building-from-source)
- [Cloudflare Deployment (Workers + Pages)](#cloudflare-deployment-workers--pages)
  - [One-time Cloudflare setup](#one-time-cloudflare-setup)
  - [GitHub Actions deployment](#github-actions-deployment)
  - [Routing (same-origin API)](#routing-same-origin-api)
- [Auth Server Deployment](#auth-server-deployment)
  - [Configuration](#configuration)
  - [Database Setup](#database-setup)
  - [OAuth Setup](#oauth-setup)
  - [Production Deployment](#production-deployment)
- [Mod Installation](#mod-installation)
  - [Server Installation](#server-installation)
  - [Client Installation](#client-installation)
  - [Mod Configuration](#mod-configuration)
- [Development Guide](#development-guide)
  - [Project Structure](#project-structure)
  - [Development Setup](#development-setup)
  - [Building Components](#building-components)
  - [Testing](#testing)
- [API Documentation](#api-documentation)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Quick Start

### Using Docker (Recommended)

The easiest way to deploy BeaconAuth is using Docker:

```bash
# Pull the latest image
docker pull ghcr.io/summpot/beacon_auth:latest

# Run the server
docker run -d --name beaconauth \
  -p 8080:8080 \
  -v $(pwd)/data:/app/data \
  -e DATABASE_URL=sqlite:///app/data/beacon_auth.db \
  ghcr.io/summpot/beacon_auth:latest
```

The server will be available at `http://localhost:8080`.

### Using Pre-built Binaries

Download the latest release for your platform from the [Releases](https://github.com/Summpot/beacon_auth/releases) page:

**Linux (amd64)**:
```bash
wget https://github.com/Summpot/beacon_auth/releases/latest/download/beaconauth-linux-amd64-musl-v1.0.0.tar.gz
tar -xzf beaconauth-linux-amd64-musl-v1.0.0.tar.gz
chmod +x beacon
./beacon serve
```

**Windows (amd64)**:
```powershell
# Download and extract the zip file
# Run in PowerShell:
.\beacon.exe serve
```

**macOS (Apple Silicon)**:
```bash
wget https://github.com/Summpot/beacon_auth/releases/latest/download/beaconauth-macos-arm64-v1.0.0.tar.gz
tar -xzf beaconauth-macos-arm64-v1.0.0.tar.gz
chmod +x beacon
./beacon serve
```

### Building from Source

#### Prerequisites
- [Rust](https://www.rust-lang.org/) 1.70 or later
- [Node.js](https://nodejs.org/) 20 or later
- [pnpm](https://pnpm.io/) 9 or later

#### Build Steps

```bash
# Clone the repository
git clone https://github.com/Summpot/beacon_auth.git
cd beacon_auth

# Install frontend dependencies
pnpm install

# Build the project
cargo build --workspace --release

# The binary will be at target/release/beacon
```

## Cloudflare Deployment (Worker + Pages)

This repository ships a Cloudflare deployment that keeps the browser on a **single origin** while still separating concerns:

- **API Worker**: `crates/beacon-worker` (Rust/WASM) using **D1** + **Workers KV**.
- **Frontend** (React): deployed to **Cloudflare Pages**.

To avoid cross-origin headaches, the Pages deployment includes a small `dist/_worker.js` that proxies these paths to the API Worker:

- `/api/*`
- `/v1/*`
- `/.well-known/*`

Everything else (SPA routes like `/login`) is served as static content from Pages.

### Wrangler config

The primary Wrangler config is `wrangler.jsonc` at repo root.

This repo is configured for **Automatic provisioning**:

- D1 binding: `DB` (configured with `database_name`, no hard-coded `database_id`)
- KV binding: `PASSKEY_KV` (no hard-coded namespace id)

### GitHub Actions deployment

Workflow:

- `.github/workflows/deploy-cloudflare.yml`

Required **GitHub Actions secrets**:

| Secret | Required | Used for |
|---|---:|---|
| `CLOUDFLARE_API_TOKEN` | Yes | Wrangler authentication (deploy + D1 operations + secrets) |
| `CLOUDFLARE_ACCOUNT_ID` | Yes | Pin the Cloudflare Account ID in CI so Wrangler does not need to infer it via `/memberships` |

Recommended / optional secrets:

| Secret | Required | Used for |
|---|---:|---|
| `CLOUDFLARE_WORKER_BASE_URL` | Recommended | Sets `BASE_URL` for issuer + OAuth redirects + WebAuthn RP origin. If omitted, CI defaults to `https://<workerName>.pages.dev`. |
| `CLOUDFLARE_WORKER_JWT_PRIVATE_KEY_DER_B64` | Strongly recommended | Stable ES256 signing key (base64-encoded PKCS#8 DER P-256 private key) |
| `CLOUDFLARE_WORKER_GITHUB_CLIENT_ID` | Optional | GitHub OAuth |
| `CLOUDFLARE_WORKER_GITHUB_CLIENT_SECRET` | Optional | GitHub OAuth |
| `CLOUDFLARE_WORKER_GOOGLE_CLIENT_ID` | Optional | Google OAuth |
| `CLOUDFLARE_WORKER_GOOGLE_CLIENT_SECRET` | Optional | Google OAuth |

The workflow will:

- build the frontend (React)
- deploy the API Worker (Automatic provisioning will create/link D1 + KV if needed)
- apply the schema `crates/beacon-worker/migrations/0001_init.sql` (idempotent)
- sync Worker secrets (when provided)
- deploy Pages from `dist/` and generate `dist/_worker.js` as the proxy layer

The workflow runs on pushes to `main` and can also be triggered manually.

## Auth Server Deployment

### Configuration

BeaconAuth can be configured using environment variables or command-line arguments. All configuration options can be viewed with:

```bash
beacon serve --help
```

#### Key Configuration Options

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| `--bind-address` | `BIND_ADDRESS` | `127.0.0.1:8080` | Server bind address |
| `--database-url` | `DATABASE_URL` | `sqlite://./beacon_auth.db?mode=rwc` | Database connection URL |
| `--jwt-expiration` | `JWT_EXPIRATION` | `3600` | JWT expiration time in seconds |
| `--cors-origins` | `CORS_ORIGINS` | `http://localhost:3000,http://localhost:5173` | Allowed CORS origins |
| `--github-client-id` | `GITHUB_CLIENT_ID` | - | GitHub OAuth client ID |
| `--github-client-secret` | `GITHUB_CLIENT_SECRET` | - | GitHub OAuth client secret |
| `--google-client-id` | `GOOGLE_CLIENT_ID` | - | Google OAuth client ID |
| `--google-client-secret` | `GOOGLE_CLIENT_SECRET` | - | Google OAuth client secret |
| `--oauth-redirect-base` | `OAUTH_REDIRECT_BASE` | `http://localhost:8080` | OAuth redirect base URL |

#### Example Configuration

Create a `.env` file in your working directory:

```env
DATABASE_URL=sqlite:///app/data/beacon_auth.db
BIND_ADDRESS=0.0.0.0:8080
JWT_EXPIRATION=7200
CORS_ORIGINS=http://localhost:3000

# Optional: OAuth providers
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
OAUTH_REDIRECT_BASE=https://auth.example.com
```

### Database Setup

BeaconAuth uses SQLite by default. Initialize the database with:

```bash
# Run migrations
beacon migrate --database-url sqlite://./beacon_auth.db

# Create an initial admin user
beacon create-user --username admin --password your_secure_password

# List all users
beacon list-users

# Delete a user
beacon delete-user --username username
```

### OAuth Setup

#### GitHub OAuth

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in the details:
   - **Application name**: BeaconAuth
   - **Homepage URL**: `http://localhost:8080` (or your domain)
   - **Authorization callback URL**: `http://localhost:8080/api/v1/oauth/callback`
4. Copy the Client ID and Client Secret
5. Set environment variables:
   ```bash
   export GITHUB_CLIENT_ID=your_client_id
   export GITHUB_CLIENT_SECRET=your_client_secret
   ```

#### Google OAuth

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API
4. Go to **Credentials** → **Create Credentials** → **OAuth Client ID**
5. Configure the OAuth consent screen
6. Create credentials:
   - **Application type**: Web application
   - **Authorized redirect URIs**: `http://localhost:8080/api/v1/oauth/callback`
7. Copy the Client ID and Client Secret
8. Set environment variables:
   ```bash
   export GOOGLE_CLIENT_ID=your_client_id
   export GOOGLE_CLIENT_SECRET=your_client_secret
   ```

### Production Deployment

#### Using Docker Compose

Create a `docker-compose.yml`:

```yaml
version: '3.8'

services:
  beaconauth:
    image: ghcr.io/summpot/beacon_auth:latest
    ports:
      - "8080:8080"
    volumes:
      - ./data:/app/data
    environment:
      DATABASE_URL: sqlite:///app/data/beacon_auth.db
      BIND_ADDRESS: 0.0.0.0:8080
      JWT_EXPIRATION: 7200
      GITHUB_CLIENT_ID: ${GITHUB_CLIENT_ID}
      GITHUB_CLIENT_SECRET: ${GITHUB_CLIENT_SECRET}
      GOOGLE_CLIENT_ID: ${GOOGLE_CLIENT_ID}
      GOOGLE_CLIENT_SECRET: ${GOOGLE_CLIENT_SECRET}
      OAUTH_REDIRECT_BASE: https://auth.example.com
    restart: unless-stopped
```

Start the service:
```bash
docker-compose up -d
```

#### Reverse Proxy Configuration (Nginx)

```nginx
server {
    listen 80;
    server_name auth.example.com;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

For HTTPS, use Let's Encrypt:
```bash
certbot --nginx -d auth.example.com
```

## Mod Installation

### Server Installation

1. **Download the Mod**: Get the latest mod file from the [Releases](https://github.com/Summpot/beacon_auth/releases) page
   - For Fabric: `beaconauth-fabric-1.0.0.jar`
   - For Forge: `beaconauth-forge-1.0.0.jar`

2. **Install the Mod**:
   - Place the jar file in your server's `mods/` directory
   - Restart the server

3. **Configure the Mod**: Edit `config/beaconauth-server.toml` (see [Mod Configuration](#mod-configuration))

### Client Installation

1. **Download the Mod**: Same mod file as the server version

2. **Install the Mod**:
   - Place the jar file in your client's `mods/` directory
   - The mod will automatically handle the client-side authentication flow

3. **Requirements**:
   - Fabric Loader 0.18.0+ or Forge 47.4.10+
   - Minecraft 1.20.1

### Mod Configuration

After the first server startup, a configuration file will be generated at `config/beaconauth-server.toml`:

```toml
# BeaconAuth Server Configuration

# Authentication server base URL
# This should point to your deployed auth server
auth_server_url = "http://localhost:8080"

# JWKS URL for JWT validation
# The mod will fetch the public key from this endpoint
jwks_url = "http://localhost:8080/.well-known/jwks.json"

# JWT validation settings
[jwt]
# Expected issuer claim
issuer = "http://localhost:8080"
# Expected audience claim
audience = "minecraft-client"
# Allow clock skew in seconds (for exp validation)
clock_skew = 60
```

**Important**: Update `auth_server_url` and `jwks_url` to match your deployed auth server's address.

For production deployments:
```toml
auth_server_url = "https://auth.example.com"
jwks_url = "https://auth.example.com/.well-known/jwks.json"

[jwt]
issuer = "https://auth.example.com"
audience = "minecraft-client"
clock_skew = 60
```

## Development Guide

### Project Structure

This is a monorepo containing three distinct projects:

```
beacon_auth/
├── crates/                      # Rust workspace (Auth Server)
│   ├── beacon/                  # Main server binary
│   │   ├── src/
│   │   │   ├── main.rs          # CLI entry point
│   │   │   ├── server.rs        # HTTP server setup
│   │   │   ├── handlers.rs      # API handlers
│   │   │   ├── crypto.rs        # JWT/ECDSA utilities
│   │   │   ├── config.rs        # Configuration
│   │   │   └── ...
│   │   ├── build.rs             # Frontend build script
│   │   └── Cargo.toml
│   ├── entity/                  # Sea-ORM entities
│   └── migration/               # Database migrations
├── src/                         # Frontend (React/Rsbuild)
│   ├── routes/                  # TanStack Router pages
│   │   ├── index.tsx            # Login page
│   │   ├── register.tsx         # Registration page
│   │   └── ...
│   └── ...
├── modSrc/                      # Minecraft Mod (Kotlin/Gradle)
│   ├── common/                  # Shared code
│   │   └── src/main/kotlin/
│   │       ├── client/          # Client-side code
│   │       │   ├── AuthClient.kt
│   │       │   └── ...
│   │       ├── server/          # Server-side code
│   │       │   ├── AuthServer.kt
│   │       │   └── ...
│   │       ├── network/         # Network packets
│   │       ├── config/          # Configuration
│   │       └── ...
│   ├── fabric/                  # Fabric implementation
│   └── forge/                   # Forge implementation
├── .github/workflows/           # CI/CD workflows
├── Dockerfile                   # Docker image definition
├── package.json                 # Frontend dependencies
└── Cargo.toml                   # Rust workspace definition
```

### Development Setup

#### Auth Server Development

1. **Install dependencies**:
   ```bash
   # Install Rust
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   
   # Install Node.js and pnpm
   curl -fsSL https://get.pnpm.io/install.sh | sh -
   
   # Install frontend dependencies
   pnpm install
   ```

2. **Run in development mode**:
   ```bash
   # Terminal 1: Run frontend dev server
   pnpm dev
   
   # Terminal 2: Run backend
   cargo run --bin beacon serve
   ```

3. **Access the application**:
   - Frontend dev server: `http://localhost:5173`
   - Backend API: `http://localhost:8080`

#### Mod Development

1. **Open in IDE**:
   - IntelliJ IDEA: Open `modSrc/build.gradle.kts`
   - Eclipse: Import as Gradle project

2. **Build the mod**:
   ```bash
   cd modSrc
   ./gradlew build
   ```

3. **Run development server**:
   ```bash
   # Fabric
   ./gradlew :fabric:runServer
   
   # Forge
   ./gradlew :forge:runServer
   ```

4. **Run development client**:
   ```bash
   # Fabric
   ./gradlew :fabric:runClient
   
   # Forge
   ./gradlew :forge:runClient
   ```

### Building Components

#### Build Auth Server

```bash
# Debug build
cargo build --workspace

# Release build (optimized)
cargo build --workspace --release

# Cross-compile for different targets
cargo install cargo-zigbuild
cargo zigbuild --target x86_64-unknown-linux-musl --release
```

#### Build Frontend Only

```bash
pnpm build
```

Output will be in `dist/`.

#### Build Mod

```bash
cd modSrc

# Build all loaders
./gradlew build

# Build specific loader
./gradlew :fabric:build
./gradlew :forge:build
```

Artifacts:
- Fabric: `modSrc/fabric/build/libs/beaconauth-fabric-*.jar`
- Forge: `modSrc/forge/build/libs/beaconauth-forge-*.jar`

### Testing

#### Auth Server Tests

```bash
# Run all tests
cargo test --workspace

# Run specific package tests
cargo test -p beacon
cargo test -p entity

# Run with logging
RUST_LOG=debug cargo test --workspace -- --nocapture
```

#### Frontend Tests

```bash
pnpm test
```

#### Mod Tests

```bash
cd modSrc
./gradlew test
```

## API Documentation

### Authentication Endpoints

#### POST `/api/v1/login`

Authenticate a user with username and password. Sets HttpOnly session cookies.

**Request**:
```json
{
  "username": "player123",
  "password": "secure_password"
}
```

**Response** (200 OK):
```json
{
  "success": true
}
```

**Cookies Set**:
- `access_token` - ES256 JWT valid for 15 minutes
- `refresh_token` - Random token valid for 7 days

#### POST `/api/v1/register`

Register a new user account. Auto-logs in the user by setting session cookies.

**Request**:
```json
{
  "username": "newplayer",
  "password": "secure_password"
}
```

**Response** (201 Created):
```json
{
  "success": true
}
```

**Cookies Set**:
- `access_token` - ES256 JWT valid for 15 minutes
- `refresh_token` - Random token valid for 7 days

#### POST `/api/v1/refresh`

Refresh an expired access token using a valid refresh token.

**Request**: Requires `refresh_token` cookie

**Response** (200 OK):
```json
{
  "success": true
}
```

**Cookies Set**:
- `access_token` - New ES256 JWT valid for 15 minutes

#### POST `/api/v1/minecraft-jwt`

Generate a Minecraft-specific JWT for mod authentication. Requires valid session.

**Request**:
```json
{
  "challenge": "PKCE_challenge_string",
  "redirect_port": 38125
}
```

**Response** (200 OK):
```json
{
  "redirectUrl": "http://localhost:38125/auth-callback?jwt=eyJ..."
}
```

#### POST `/api/v1/oauth/start`

Initiate OAuth authentication flow.

**Request**:
```json
{
  "provider": "github",
  "challenge": "PKCE_challenge_string",
  "redirect_port": 38125
}
```

**Response** (200 OK):
```json
{
  "authorizationUrl": "https://github.com/login/oauth/authorize?..."
}
```

#### GET `/api/v1/oauth/callback`

OAuth provider callback endpoint.

**Query Parameters**:
- `code`: Authorization code from OAuth provider
- `state`: State token for validation

**Response**: HTTP 302 redirect to mod callback URL with JWT

### Public Endpoints

#### GET `/.well-known/jwks.json`

Retrieve JSON Web Key Set for JWT verification.

**Response** (200 OK):
```json
{
  "keys": [
    {
      "kty": "EC",
      "use": "sig",
      "crv": "P-256",
      "kid": "beacon-auth-key-1",
      "x": "...",
      "y": "...",
      "alg": "ES256"
    }
  ]
}
```

## Troubleshooting

### Common Issues

#### Server won't start

**Problem**: Database connection error

**Solution**:
```bash
# Ensure database directory exists
mkdir -p data

# Run migrations
beacon migrate --database-url sqlite://./data/beacon_auth.db
```

#### Frontend build fails in Docker

**Problem**: `pnpm: command not found`

**Solution**: The `build.rs` script automatically handles frontend builds. Ensure pnpm is installed in your system PATH.

#### Mod authentication fails

**Problem**: "Failed to validate JWT"

**Solutions**:
1. Check that `jwks_url` in mod config matches your server
2. Verify server is accessible from client
3. Check server logs for JWT validation errors
4. Ensure system clocks are synchronized (use NTP)

#### OAuth redirect fails

**Problem**: "Invalid redirect URI"

**Solutions**:
1. Verify OAuth app callback URL matches exactly: `http://yourserver:8080/api/v1/oauth/callback`
2. Check `OAUTH_REDIRECT_BASE` environment variable
3. For production, use HTTPS and proper domain

### Debug Logging

Enable detailed logging:

**Auth Server**:
```bash
RUST_LOG=debug beacon serve
```

**Mod (server log)**:
Look for `[BeaconAuth]` prefix in server logs.

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`cargo test --workspace && cd modSrc && ./gradlew test`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Code Style

- **Rust**: Follow standard Rust conventions (`cargo fmt`, `cargo clippy`)
- **TypeScript**: Use Biome formatter (`pnpm check`)
- **Kotlin**: Follow Kotlin conventions (configured in `.editorconfig`)

### Commit Messages

Use conventional commit format:
- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `chore:` Maintenance tasks
- `test:` Test additions or modifications

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Actix-web](https://actix.rs/) - Rust web framework
- [Sea-ORM](https://www.sea-ql.org/SeaORM/) - Rust ORM
- [Architectury](https://architectury.dev/) - Multi-loader mod framework
- [Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt) - JWT library for Java

## Support

- **Issues**: [GitHub Issues](https://github.com/Summpot/beacon_auth/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Summpot/beacon_auth/discussions)

---

**Made with ❤️ by Summpot**
