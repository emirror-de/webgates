# webgates-axum

Axum integration for the `webgates` core. Provides middleware (cookie/bearer gates), OAuth2 helpers, and ready-made login/logout handlers. Use it with the `webgates` core for domain types and gate configuration, and with `webgates-repositories` for storage backends.

## Install

Pick only the crates and features you need. The workspace crates intentionally enable no default features — enable the specific features you require (for example, enable the `server` feature on `webgates` to access Gate builders and the JWT codec implementation).

Core-only (no server features; minimal dependencies):

```toml
[dependencies]
webgates = "0.1"
webgates-axum = "0.1"
```

Axum integration (recommended when you need middleware and route handlers):

```toml
[dependencies]
axum = "0.8"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
webgates-axum = "0.1"
```

If you want to use the `Gate` builders and codecs provided by the `webgates` core crate directly, enable the core's `server` feature:

```toml
[dependencies]
webgates = { version = "0.1", features = ["server"] }
```

MSRV: 1.88

## Quick start (cookie gate)

```rust,ignore
use std::sync::Arc;
use axum::{routing::get, Router};
use webgates_axum::gate::Gate;
use webgates::authz::AccessPolicy;
use webgates::codecs::jwt::{JsonWebToken, JwtClaims};
use webgates::accounts::Account;
use webgates::prelude::{Role, Group};

type Claims = JwtClaims<Account<Role, Group>>;
let codec = Arc::new(JsonWebToken::<Claims>::default());

let app = Router::new()
    .route("/admin", get(|| async { "ok" }))
    .layer(
        Gate::cookie("my-app", Arc::clone(&codec))
            .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin)),
    );
```

- `Gate::bearer` works the same for `Authorization: Bearer`.
- `allow_anonymous_with_optional_user()` never blocks; inserts `Option<Account<_>>` / `Option<RegisteredClaims>`.
- `require_login()` allows the baseline role plus supervisors (hierarchy).
- Use `with_cookie_template` / `configure_cookie_template` to align cookie name/path with your login writer.

## Login / logout handlers

`webgates-axum::route_handlers::{login, logout}` set and clear the auth cookie. The cookie template and issuer must match your gate configuration.

## OAuth2 (Authorization Code + PKCE)

`gate::oauth2` builds an OAuth2 flow; you can optionally mint first-party JWT cookies by supplying a codec and TTL. Provide an account mapper and (optionally) a repository to persist accounts before issuing the cookie.

## Features

- `audit-logging`: propagate audit logging from the core crate (opt-in)
- `prometheus`: emit Prometheus metrics for auth events (opt-in; depends on `audit-logging`)
- This crate depends on the `webgates` core crate. Feature flags are opt-in and the core crate itself has no default features; enable the core's `server` feature when you need server-facing APIs (Gate builders, codecs) from `webgates`.

## Repository backends

Use `webgates-repositories` if you need persistence. Backend features are opt-in — enable only the backends you need.

- In-memory: zero config (good for tests and examples).
- SeaORM (`repo-seaorm`): relational databases (bring the DB driver via SeaORM feature flags).
- SurrealDB (`repo-surrealdb`): SurrealDB-backed (opt-in; SurrealDB is licensed under BUSL-1.1 — review and comply with the license before enabling in production).

## Security checklist

- Keep issuer identical between login (claims) and gates.
- Align cookie names/templates between login and gate; set Secure/HttpOnly/SameSite appropriately.
- Use persistent JWT keys in production; rotate as needed.
- Rate-limit login; validate inputs at boundaries.
- Avoid logging secrets or tokens; use correlation IDs.
- Prefer short-lived JWTs; enable `audit-logging` and `prometheus` for observability.

## Examples

- `examples/simple-usage` (in-memory)
- `examples/oauth2-github`
- `examples/permission-registry`
- `examples/prometheus`
- `examples/rate-limiting`
- `webgates-repositories/examples/sea-orm`
- `webgates-repositories/examples/surrealdb`

## License

MIT (SurrealDB feature is BUSL-1.1—review and comply when enabling `repo-surrealdb`).