# webgates (core)

Framework-agnostic authentication and authorization primitives for building gate layers (cookie, bearer) with JWTs, hierarchical roles, groups, and permissions. This crate has no web framework dependency; adapters (e.g., Axum) live elsewhere.

## When to use this crate
- You want gate configuration, codecs, domain types, and authorization logic without pulling in a web framework.
- You are writing your own adapter/middleware around the provided gates.
- You need reusable domain models (accounts, roles, groups, permissions), password hashing, and validation utilities.

If you need Axum middleware and route handlers, depend on `webgates-axum`. Repository backends live in `webgates-repositories`.

## Install

Core only (no server features):

```toml
[dependencies]
webgates = "0.1"
```

Server-enabled (runtime, Gate builders, codecs — opt-in):

```toml
[dependencies]
webgates = { version = "0.1", features = ["server"] }
```

Minimum supported Rust version: 1.88.

## Core concepts

- Gates (framework-agnostic)
  - `Gate::cookie("issuer", codec)`: JWT via HTTP-only cookies.
  - `Gate::bearer("issuer", codec)`: JWT via `Authorization: Bearer`; `with_static_token` for shared-secret mode.
  - `allow_anonymous_with_optional_user()`: never blocks; inserts optional user context.
  - `require_login()`: allow baseline role + supervisors (role hierarchy).
- Policies
  - `AccessPolicy::require_role(..)`, `require_role_or_supervisor(..)`, `require_group(..)`, `require_permission("domain:action")`.
- Codecs
  - `codecs::jwt::JsonWebToken` with `JsonWebTokenOptions`; use persistent keys in production.
- Domain
  - `accounts`, `roles`, `groups`, `permissions`, credential hashing (Argon2), deterministic permission IDs, collision validation helpers.

## Quick start (framework-agnostic gate configuration)

Note: The example below uses server-oriented APIs (`Gate`, `codecs`) that are feature-gated. Enable the `server` feature in your Cargo.toml (see the Install section) when using these pieces.

```rust
use std::sync::Arc;
use webgates::accounts::Account;
use webgates::authz::AccessPolicy;
use webgates::codecs::jwt::{JsonWebToken, JwtClaims};
use webgates::gate::Gate;
use webgates::prelude::{Group, Role};

type AppClaims = JwtClaims<Account<Role, Group>>;
let codec = Arc::new(JsonWebToken::<AppClaims>::default());

let gate = Gate::cookie::<_, Role, Group>("my-app", Arc::clone(&codec))
    .require_login() // baseline role + supervisors
    .with_policy(AccessPolicy::require_permission("admin:read"));
```

Adapt this gate in your framework by implementing the adapter traits in `gate::cookie` / `gate::bearer`.

## Features

- `default = []` (no features enabled by default)
- `server`: opt-in feature that brings runtime and server-oriented dependencies (tokio, cookie, serde_json, subtle, tracing, oauth2, argon2, etc.). Required for `Gate`, `codecs`, and other server integrations.
- `audit-logging`: structured audit events (`tracing`)
- `prometheus`: metrics for audit (implies `audit-logging`)
- `insecure-fast-hash`: faster Argon2 configuration intended for development only
- `wasm`: build core types for WASM (omits server dependencies)

## Security checklist

- Use a persistent JWT key; do not rely on the default random key.
- Keep issuer strings identical between login (claims) and gates.
- Align cookie names/templates between login writer and gate reader; set Secure/HttpOnly/SameSite appropriately.
- Rate-limit login; validate inputs at boundaries.
- Avoid logging secrets or tokens; prefer correlation IDs.
- Enable `audit-logging` and `prometheus` for observability.

## License

MIT