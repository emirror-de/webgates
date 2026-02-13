# webgates

[![Crates.io](https://img.shields.io/crates/v/webgates.svg)](https://crates.io/crates/webgates)
[![Documentation](https://docs.rs/webgates/badge.svg)](https://docs.rs/webgates)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Build Status](https://github.com/emirror-de/webgates/workflows/CI/badge.svg)](https://github.com/emirror-de/webgates/actions)

Flexible, type-safe authentication and authorization for Axum using JWTs and optional OAuth2.

- Cookie and bearer authentication
- OAuth2 Authorization Code + PKCE flow that issues first-party JWT cookies
- Hierarchical roles, groups, and string-based permissions
- Ready-to-use login/logout handlers
- Optional anonymous user context and static-token mode for internal services
- In-memory and database-backed repositories provided by the companion `webgates-repositories` crate
- Feature-gated audit logging and Prometheus metrics

## Crate split

This workspace now ships two crates:

- `webgates` (this crate): core domain types, gates, codecs, handlers, validation utilities.
- `webgates-repositories`: all repository/backing-store implementations (in-memory, SeaORM, SurrealDB) plus repo-specific services. Enable backend features (`repo-seaorm`, `repo-surrealdb`) on that crate, not on `webgates`.

The legacy `storage-seaorm` / `storage-surrealdb` feature flags no longer exist on `webgates`.

## Install

Core crate (server defaults enabled):

```toml
[dependencies]
axum = "0.8"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
webgates = { version = "1" }
```

Add repositories (choose the backend features you need):

```toml
[dependencies]
webgates = { version = "1" }
webgates-repositories = { version = "1", features = ["repo-seaorm"] }
# or
webgates-repositories = { version = "1", features = ["repo-surrealdb"] }
# in-memory backend requires no extra feature flags
```

## Core features (webgates)

- `default` = `["server"]`
- `server`: pulls in tokio, serde_json, subtle, tracing and other server-side deps
- `audit-logging`: structured audit events (uses `tracing`)
- `prometheus`: metrics for audit (implies `audit-logging`)
- `insecure-fast-hash`: faster Argon2 preset for development only
- `wasm`: build core types for WASM (no server dependencies)

## Repository features (webgates-repositories)

- `default` = `["server"]`
- `server`: shared when used in server environments (tokio, macros)
- `repo-seaorm`: SeaORM-backed repositories (requires database driver via SeaORM)
- `repo-surrealdb`: SurrealDB-backed repositories
- `audit-logging`: enable audit hooks within repositories

See `webgates-repositories/README.md` for backend-specific configuration.

## Core concepts

- Gate layer
  - `Gate::cookie("issuer", codec)`: JWT via HTTP-only cookies (web apps)
  - `Gate::bearer("issuer", codec)`: JWT via `Authorization: Bearer` header (APIs)
  - `Gate::bearer(...).with_static_token("...")`: shared-secret mode (internal services)
  - `Gate::oauth2::<R, G>()`: OAuth2 Authorization Code + PKCE flow builder; or `Gate::oauth2_with_jwt("issuer", codec, ttl_secs)` to also mint first-party JWT cookies
  - `allow_anonymous_with_optional_user()`: never block; inserts optional user context
  - `require_login()`: allow baseline role and all supervisors (hierarchy)
- Access policies
  - `require_role(..)`, `require_role_or_supervisor(..)`
  - `require_group(..)`
  - `require_permission("domain:action")` — deterministic hashing to `PermissionId`; use `validate_permissions!` to catch collisions at test-time
- Login/logout
  - `route_handlers::login`: verifies credentials and sets the auth cookie
  - `route_handlers::logout`: removes the auth cookie
- JWT codec
  - `codecs::jwt::JsonWebToken` with `JsonWebTokenOptions` (use persistent keys in production)

## Choosing a repository backend

- In-memory: development/testing; lives in `webgates-repositories` with no extra feature flags.
- SeaORM: enable `repo-seaorm` on `webgates-repositories`. Suitable for relational databases supported by SeaORM.
- SurrealDB: enable `repo-surrealdb` on `webgates-repositories`. See the BUSL notice below.

## Examples and docs

Full API docs: https://docs.rs/webgates

The workspace includes runnable examples:
- `examples/simple-usage` (in-memory)
- `examples/distributed`
- `examples/oauth2-github`
- `examples/permission-registry`
- `examples/prometheus`
- `examples/rate-limiting`
- `webgates-repositories/examples/sea-orm` (SeaORM backend)
- `webgates-repositories/examples/surrealdb` (SurrealDB backend)

## Security

- Use a persistent JWT key; do not rely on the default random key in production.
- Keep the issuer consistent between gate configuration and registered claims.
- Use secure cookie settings in production (HttpOnly, Secure, appropriate SameSite).
- Rate-limit sensitive endpoints (e.g., login).
- Enable `audit-logging` and `prometheus` for observability; never log secrets, tokens, or cookie values.
- SurrealDB (BUSL-1.1) notice (applies when enabling `repo-surrealdb` in `webgates-repositories`):
  - SurrealDB is licensed under the Business Source License 1.1 (not OSI-approved).
  - BUSL restricts Production Use unless allowed by the licensor or after the project's Change Date.
  - If you build or distribute binaries that enable this feature, you must comply with SurrealDB's BUSL terms or obtain a commercial license.
  - When distributing binaries that include SurrealDB, include third-party notices and the SurrealDB license text.

## MSRV and license

- MSRV: 1.88
- License: MIT
- The subtle dependency’s NOTICE is included in this repository; retain it when redistributing.