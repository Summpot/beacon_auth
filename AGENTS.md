# Instructions for Summpot/BeaconAuth

## 1) Execution Principles

* Prefer completing tasks in a single integrated pass.
* If a task is truly large, create a concrete plan and still deliver a complete end-to-end implementation (do not land partial behavior).
* Integration over isolation: when adding or changing functionality, also update imports, wiring, and call sites in the same pass.
* Ask for user confirmation only when genuinely ambiguous (requirements, security tradeoffs, or irreversible changes).

### TEMPORARY (Pre-release) Rule

This project has not been released yet.

* You do NOT need to consider backwards compatibility.
* If you need to adjust the database schema, you MAY directly edit the existing migration files (instead of creating additive migrations).
* This rule is temporary and will be removed at release time.

## 2) Language & Communication

* User-facing chat responses: use the same language as the user’s request.
* Repository artifacts (code comments, docs, commit messages, logs, error messages): MUST be in English.

## 3) Research First (MANDATORY: DeepWiki MCP when unsure)

When you are not sure about usage, conventions, or existing patterns in this repo, you MUST consult DeepWiki MCP BEFORE implementing.

* Mandatory tool: `mcp_cognitionai_d_ask_question` (DeepWiki MCP)
* Scope: APIs, auth flows, crypto/JWKS/JWT handling, DB patterns, error conventions, configuration/env usage, and any new dependency.
* Ask targeted questions that reference the exact crate/module/file and desired behavior.

If DeepWiki does not contain enough information:

* Record what is missing and proceed with the best available evidence (code search, existing modules), keeping changes minimal and consistent.
* Do NOT use `cargo doc --open`.

## 4) Correctness Bar (No stubs / no shortcuts)

Never ship simplified, stubbed, placeholder, or “temporary” implementations.

This is especially strict for:

* Authentication & authorization
* Cryptography / key management / JWT / JWKS
* OAuth and WebAuthn/passkeys
* Protocol compatibility (wire formats, redirects, cookies)

Requirements:

* Match intended behavior exactly, including edge cases.
* No TODO stubs, no placeholder returns, no “just for now” workarounds.
* Handle errors fully and consistently; include actionable English error messages.

## 5) Verification (Build/Check)

Do not consider a change complete until it is verified.

* Rust: after any Rust change, run `cargo check --all-targets`.
* Avoid local `--release` builds.
* Use debug-mode builds only when needed for additional validation (e.g., `cargo build --all-targets`).

## 6) Testing Strategy

* Avoid running the full test suite locally unless you changed tests or the change has broad blast radius.
* Prefer fast validation first (e.g., `cargo check --workspace`) and then run only the relevant tests/modules when needed.

## 7) Dependency Management

* Rust: `cargo add -p <crate-name>`
* Node.js: prefer `pnpm add` in this repo (avoid introducing additional package managers).
* Python: `pip install` or `poetry add` depending on the project setup.

Before adding any new dependency/crate/package:

* MUST consult DeepWiki MCP for existing patterns/approved libraries.
* Justify why it is needed and why existing dependencies are insufficient.

## 8) Multi-language Workspace Rules (Rust + TypeScript/React + Gradle/Kotlin)

This repository is multi-language. When you touch one part, ensure the relevant toolchain still builds.

### Rust (server + shared crates)

* Source lives under `crates/`.
* Required after Rust changes: `cargo check --all-targets`.
* Do not add new crates lightly; consider optional features for platform-specific code (e.g., serverless).
* Distributed deployments: avoid per-process in-memory coordination for OAuth/Passkey start→finish unless you require sticky sessions.
* Ensure JWT/JWKS keys are stable across instances.

### TypeScript/React (Web UI)

* Frontend source lives under `src/` and uses `pnpm`.
* When backend API shape changes, update frontend calls/types in the same pass.
* Formatting/linting uses Biome (`biome.json`). Do not introduce a second formatter.

### Gradle/Kotlin (Mod source)

* Source lives under `modSrc/`.
* Keep server-side protocol/auth changes compatible with the mod’s expectations (JWKS, redirect URLs, cookie/auth flow).
* Never hardcode secrets in Gradle files.

## 9) Cross-cutting Operational Rules

* Prefer configuration via environment variables or CLI flags.
* Keep HTTP app construction reusable for serverless targets; gate serverless-only code behind Cargo features and `required-features` binaries.