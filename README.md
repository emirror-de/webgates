# webgates

Flexible, type-safe authentication and authorization for Axum with JWTs and optional OAuth2. The workspace contains core types, Axum adapters, and repository backends.

- Cookie and bearer authentication
- OAuth2 Authorization Code + PKCE that can mint first-party JWT cookies
- Hierarchical roles, groups, and string-based permissions
- Ready-to-use login/logout handlers
- Optional anonymous user context and static-token mode for internal services
- In-memory and database-backed repositories (SeaORM, SurrealDB)
- Feature-gated audit logging and Prometheus metrics

## Workspace layout

- `webgates` — core domain types, gate builders (cookie/bearer), codecs, validation, hashing.
- `webgates-axum` — Axum middleware/layers and route handlers built from the core gates.
- `webgates-repositories` — repository implementations (in-memory, SeaORM, SurrealDB) and repo-facing services.

## Install (pick what you need)

Core only:

```toml
[dependencies]
webgates = { version = "0.1" }
```

Axum integration:

```toml
[dependencies]
webgates = { version = "0.1" }
webgates-axum = { version = "0.1" }
```

Repositories (choose a backend):

```toml
[dependencies]
webgates = { version = "0.1" }
webgates-repositories = { version = "0.1", features = ["repo-seaorm"] }
# or
webgates-repositories = { version = "0.1", features = ["repo-surrealdb"] }
# in-memory requires no extra feature flags
```

Minimum Rust version: 1.88

## Quick start (core, gate configuration)

```rust
use std::sync::Arc;
use webgates::authz::AccessPolicy;
use webgates::gate::Gate;
use webgates::codecs::jwt::{JsonWebToken, JwtClaims};
use webgates::accounts::Account;
use webgates::prelude::{Role, Group};

type AppClaims = JwtClaims<Account<Role, Group>>;
let codec = Arc::new(JsonWebToken::<AppClaims>::default());

let gate = Gate::cookie::<_, Role, Group>("my-app", Arc::clone(&codec))
    .require_login() // baseline role + supervisors
    .with_policy(AccessPolicy::require_permission("admin:read"));
```

- `Gate::cookie` — JWT in HTTP-only cookies (web apps).
- `Gate::bearer` — JWT in Authorization header (APIs); `with_static_token` for shared-secret mode.
- `allow_anonymous_with_optional_user` — never blocks; injects optional user context.
- `require_login` — allow baseline role and supervisors via the role hierarchy.

## Quick start (Axum)

```rust,ignore
use std::sync::Arc;
use axum::{routing::get, Router};
use webgates_axum::gate::Gate;
use webgates::authz::AccessPolicy;
use webgates::codecs::jwt::{JsonWebToken, JwtClaims};
use webgates::accounts::Account;
use webgates::prelude::{Role, Group};

type AppClaims = JwtClaims<Account<Role, Group>>;
let codec = Arc::new(JsonWebToken::<AppClaims>::default());

let app = Router::new()
    .route("/admin", get(|| async { "ok" }))
    .layer(
        Gate::cookie("my-app", Arc::clone(&codec))
            .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin)),
    );
```

- `Gate::bearer` works similarly for APIs.
- Use `with_cookie_template` or `configure_cookie_template` to align cookie name/path with your login writer.
- Optional mode inserts `Option<Account<_>>` / `Option<RegisteredClaims>` and never blocks.

## Login / logout handlers (Axum)

`webgates-axum::route_handlers::{login, logout}` set and clear the auth cookie. Ensure the cookie template and issuer match your gate configuration.

## Repository backends (`webgates-repositories`)

- In-memory: zero config, great for tests and examples.
- SeaORM (`repo-seaorm`): relational databases supported by SeaORM. Bring the DB driver via SeaORM features.
- SurrealDB (`repo-surrealdb`): SurrealDB-backed repositories (see BUSL note below).

Repository APIs return `webgates_repositories::errors::Result<T>` with a rich error stack. Keep error details internal; map to user-facing errors at your API boundary.

## Features (core)

- `default = ["server"]`
- `server`: pulls in tokio, serde_json, subtle, tracing, etc.
- `audit-logging`: structured audit events (uses `tracing`)
- `prometheus`: metrics for audit (implies `audit-logging`)
- `insecure-fast-hash`: faster Argon2 for development only
- `wasm`: build core types for WASM (no server deps)

Features (repositories):

- `default = ["server"]`
- `repo-seaorm`, `repo-surrealdb` select backends
- `audit-logging` enables repository audit hooks

## Examples (runnable)

- `examples/simple-usage` (in-memory)
- `examples/distributed`
- `examples/oauth2-github`
- `examples/permission-registry`
- `examples/prometheus`
- `examples/rate-limiting`
- `webgates-repositories/examples/sea-orm`
- `webgates-repositories/examples/surrealdb`

## Security checklist

- Use a persistent JWT key; do not rely on the default random key in production.
- Keep issuer strings identical between login (claims) and gates.
- Align cookie names/templates between login and gate; set Secure/HttpOnly/SameSite appropriately.
- Rate-limit login; validate inputs at boundaries.
- Avoid logging secrets or tokens; prefer correlation IDs.
- Enable `audit-logging` and `prometheus` for observability.

## License and notices

- License: MIT
- MSRV: 1.88
- SurrealDB (when enabling `repo-surrealdb`): BUSL-1.1. Production use is restricted by BUSL; include required third-party notices and comply with SurrealDB licensing.