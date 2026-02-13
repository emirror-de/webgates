# webgates

[![Crates.io](https://img.shields.io/crates/v/webgates.svg)](https://crates.io/crates/webgates)
[![Documentation](https://docs.rs/webgates/badge.svg)](https://docs.rs/webgates)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Build Status](https://github.com/emirror-de/webgates/workflows/CI/badge.svg)](https://github.com/emirror-de/webgates/actions)

Flexible, type-safe authentication and authorization primitives and integrations for Rust web services.

This repository is a workspace split into focused crates:

- `webgates` — core domain models and services (JWT codecs, permissions, roles, domain types).
- `webgates-axum` — Axum integration layer (extractors, middleware, route handlers for login/logout, OAuth2 flows).
- `webgates-repositories` — repository implementations (in-memory, SeaORM, SurrealDB backends, password hashing helpers).
- `examples/` — curated examples demonstrating common integrations and deployment patterns.

Feature highlights (available across the workspace):
- Cookie and bearer authentication
- OAuth2 Authorization Code + PKCE flow with optional first‑party JWT cookie issuance
- Hierarchical roles, groups, and string-based permissions
- Ready-to-use login/logout handlers and extractors for Axum
- Optional anonymous user context and static-token mode for internal services
- In-memory and optional database-backed repositories (SeaORM, SurrealDB)
- Feature-gated audit logging and Prometheus metrics

## Install

The workspace crates are intended to be consumed independently. The most common usage is to depend on the Axum integration crate which re-exports the core APIs when appropriate:

```toml
[dependencies]
axum = "0.8"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
webgates-axum = { version = "0.1", features = ["server"] }
```

If you only need domain logic (no server integration), depend on the core crate:

```toml
[dependencies]
webgates = "0.1"
```

Repository/backends are provided by the `webgates-repositories` crate and are feature-gated. Common optional features across the workspace:
- `repo-surrealdb` — SurrealDB repositories
- `repo-seaorm` — SeaORM repositories
- `audit-logging` — structured audit events
- `prometheus` — Prometheus metrics (depends on `audit-logging`)
- `insecure-fast-hash` — development-only faster Argon2 preset

Note: Feature names and exact crate versions are listed in each crate's `Cargo.toml` and documentation on docs.rs.

## Core concepts

- Gate layer (Axum helpers)
  - `Gate::cookie("issuer", codec)` — JWT via HTTP-only cookies (for browser-based apps)
  - `Gate::bearer("issuer", codec)` — JWT via `Authorization: Bearer` header (for APIs)
  - `Gate::bearer(...).with_static_token("...")` — static/shared-secret mode for internal services
  - `Gate::oauth2::<R, G>()` — OAuth2 Authorization Code + PKCE flow builder (Axum helpers)
  - `allow_anonymous_with_optional_user()` — never blocks; injects optional user context
  - `require_login()` — require authenticated user (respects role hierarchy)
- Access policies
  - `require_role(..)`, `require_role_or_supervisor(..)` — role-based guards
  - `require_group(..)` — group membership checks
  - `require_permission("domain:action")` — deterministic mapping to `PermissionId`; use the provided macros to validate registries at test-time
- Login/logout
  - Provided route handlers verify credentials and set/remove auth cookies (see `webgates-axum::route_handlers`)
- Repositories
  - In-memory implementations for quick development and tests
  - Optional database-backed repositories in `webgates-repositories` (SeaORM / SurrealDB) behind features
- JWT codec
  - `codecs::jwt::JsonWebToken` and associated options — persist keys in production; swap in different backends if needed via feature flags

## Cryptographic Backend

JWT operations use the `rust_crypto` backend where applicable (see crate documentation for configured features). Password hashing and other crypto primitives are exposed via the domain crates and repository helpers.

## Security

- Use a persistent JWT signing key in production (do not rely on ephemeral defaults)
- Keep the JWT issuer consistent between Gate configuration and registered claims
- Use secure cookie attributes in production (`HttpOnly`, `Secure`, appropriate `SameSite`)
- Rate-limit sensitive endpoints (login, token endpoints)
- Enable `audit-logging` and `prometheus` features for observability; never log secrets, tokens, or raw cookie values

## Examples and docs

- API docs for each crate are published on docs.rs:
  - `webgates`: https://docs.rs/webgates
  - `webgates-axum`: https://docs.rs/webgates-axum
  - `webgates-repositories`: https://docs.rs/webgates-repositories
- The repository contains curated examples under `examples/` (OAuth2 flows, Prometheus integration, permission validation, etc.). See the examples to understand typical wiring for Axum servers and repository setup.
- For practical debugging and common integration issues, consult `TROUBLESHOOTING.md` in the repository.

## MSRV and license

- MSRV: 1.88
- License: MIT

SurrealDB (BUSL-1.1) notice:
- Enabling the optional feature that pulls in SurrealDB (`repo-surrealdb` / `storage-surrealdb`) includes SurrealDB which is licensed under the Business Source License 1.1 (BUSL). That license places restrictions on Production Use until the project's Change Date unless you obtain a commercial license or otherwise comply with the BUSL terms.
- The SurrealDB feature is off by default. If you enable it for builds or distributions, ensure you comply with SurrealDB's BUSL terms and include required third-party notices.
- For fully open-source distributions, prefer the in-memory or SeaORM-backed repositories.

Subtle and other third-party license notices:
- Some dependencies carry additional notices (see the repository `NOTICE` file when redistributing).

---
For more details, examples, and API references, see the crate documentation and the `examples/` folder in this repository.
