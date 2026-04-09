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

Feature highlights (available across the workspace):
- Cookie and bearer authentication
- OAuth2 Authorization Code + PKCE flow with optional first‑party JWT cookie issuance
- Hierarchical roles, groups, and string-based permissions
- Ready-to-use login/logout handlers and extractors for Axum
- Optional anonymous user context and static-token mode for internal services
- In-memory and optional database-backed repositories (SeaORM, SurrealDB)
- Feature-gated audit logging and Prometheus metrics

Note on feature defaults:
- Crates in this workspace intentionally ship with no enabled default features. Enable the specific features you need (for example, enable the `codecs` and `cookies` features on `webgates` to pull in runtime- and HTTP-related modules such as `gate`, `codecs`, and `cookie_template`). This keeps dependencies minimal when you only need core domain types.

## Install

Pick only the crates and features you need. Crates are split by concern so that runtime and HTTP dependencies are opt-in.

Core-only (domain types, no server/runtime dependencies):
```toml
[dependencies]
webgates = "0.1"
```

Axum integration (recommended when you need middleware and route handlers):
```toml
[dependencies]
axum = "0.8"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
webgates-axum = "0.1"
```

Server-enabled core (if you want `Gate` and the JWT codec from the core crate directly):
```toml
[dependencies]
webgates = { version = "0.1", features = ["codecs", "cookies"] }
```

Repository/backends and optional features:
- Use `webgates-repositories` for persistence backends (in-memory, SeaORM, SurrealDB). Backend support is feature-gated in that crate.
- Enable only the features you need to avoid pulling in large transitive dependencies.

Common optional features across the workspace (examples):
- `audit-logging` — structured audit events (`tracing`) (opt-in)
- `prometheus` — Prometheus metrics (opt-in; depends on `audit-logging`)
- `insecure-fast-hash` — development-only faster Argon2 preset (intended only for tests/dev)

Note: Feature names and exact crate versions are listed in each crate's `Cargo.toml` and in the crate docs on docs.rs.

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

- MSRV: 1.91
- License: MIT

SurrealDB (BUSL-1.1) notice:
- Enabling the optional SurrealDB-backed repository feature (`surrealdb`) in `webgates-repositories` pulls in SurrealDB, which is distributed under the Business Source License 1.1 (BUSL). That license may impose restrictions on Production Use until its Change Date. If you enable this feature for development, CI, or distribution, review SurrealDB's license terms and comply with any obligations (including required notices).
- The SurrealDB-backed repositories are opt-in and off by default. Prefer in-memory or SeaORM-backed repositories for fully open-source deployments where BUSL implications are a concern.
- When enabling `surrealdb` in your project, document the choice in your release and ensure your legal/compliance process accepts the license terms.

Subtle and other third-party license notices:
- Some dependencies carry additional notices (see the repository `NOTICE` file when redistributing).

---
For more details, examples, and API references, see the crate documentation and the `examples/` folder in this repository.

## Development

Quick notes for contributors and local development:

- The workspace contains multiple crates: `webgates`, `webgates-axum`, and `webgates-repositories`.
- Run the test suite for all crates with `cargo test --workspace`.
- Example applications live under the `examples/` directory and demonstrate common setups (OAuth2, Prometheus, SurrealDB).
- Crates intentionally ship without default features; enable only the features you need during development to keep dependency scope small.

## Roadmap / Tasks

This repository tracks small, focused tasks by short identifiers. "i01" is the next task to work on and represents the initial improvements to the developer experience and project docs. Planned steps for i01:

1. Improve top-level documentation and add contributor/development notes (this change).
2. Add a basic contributing guide and checklist for CI / local setup.
3. Start a small developer-facing example that exercises the common Axum setup.

If you'd like a different scope for i01, tell me which step to prioritise next.
