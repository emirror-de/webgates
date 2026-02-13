# webgates-axum

Axum integration for the `webgates` core. Provides middleware (cookie/bearer gates), OAuth2 helpers, and ready-made login/logout handlers. Use it with the `webgates` core for domain types and gate configuration, and with `webgates-repositories` for storage backends.

## Install

```toml
[dependencies]
webgates = { version = "0.1" }
webgates-axum = { version = "0.1" }
# Optional backends
webgates-repositories = { version = "0.1", features = ["repo-seaorm"] }
# or
webgates-repositories = { version = "0.1", features = ["repo-surrealdb"] }
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

- `default = ["server"]`
- `audit-logging`: propagate audit logging from core
- `prometheus`: emit Prometheus metrics for auth events
- Inherits core features transitively (`webgates`)

## Repository backends

Use `webgates-repositories` if you need persistence:
- In-memory: zero config.
- SeaORM (`repo-seaorm`): relational databases (add the DB driver via SeaORM features).
- SurrealDB (`repo-surrealdb`): SurrealDB-backed (BUSL-1.1; comply with licensing).

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