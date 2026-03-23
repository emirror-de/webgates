# webgates-axum

Axum integration for the `webgates` core.

This crate is the Axum-facing adapter layer for `webgates`. It exposes a small public API:

- `webgates_axum::gate::Gate` as the canonical entry point for cookie, bearer, and OAuth2 integration
- `webgates_axum::route_handlers::login` and `webgates_axum::route_handlers::logout` for ready-made auth cookie handlers
- `webgates_axum::gate::bearer::StaticTokenAuthorized` for optional static-token routes

It does not replace `webgates`. You still depend on `webgates` for domain types, codecs, policies, claims, cookie templates, and repository contracts.

## Install

Most applications should depend on both crates explicitly.

Standard setup:

```toml
[dependencies]
axum = "0.8"
webgates = "0.1"
webgates-axum = "0.1"
```

If you want a narrower `webgates` dependency set, disable its defaults and enable only the required features there.

```toml
[dependencies]
axum = "0.8"
webgates = { version = "0.1", default-features = false, features = ["authn", "codecs", "cookies", "oauth2", "repositories", "secrets"] }
webgates-axum = "0.1"
```

MSRV: 1.88

## Public API

The canonical public API of this crate is intentionally small.

### Gate entry point

Use `webgates_axum::gate::Gate` to build middleware:

- `Gate::cookie(...)`
- `Gate::bearer(...)`
- `Gate::oauth2(...)`

These builders are the intended integration surface for Axum applications.

### Route handlers

Use `webgates_axum::route_handlers::login` and `webgates_axum::route_handlers::logout` when you want simple cookie-based login/logout endpoints that plug into the `webgates` core services.

### Optional static-token extraction

If you use optional static bearer token mode, handlers can read:

- `webgates_axum::gate::bearer::StaticTokenAuthorized`

This is the only bearer-mode extension helper intended for direct handler use.

### What to import directly

Prefer direct imports from stable module paths:

```rust
use webgates_axum::gate::Gate;
use webgates_axum::route_handlers::login;
use webgates_axum::route_handlers::logout;
use webgates_axum::gate::bearer::StaticTokenAuthorized;
```

Do not rely on convenience prelude-style imports. Prefer the explicit paths above.

## Quick start

### Cookie gate

```rust,ignore
use std::sync::Arc;

use axum::{routing::get, Router};
use webgates::accounts::Account;
use webgates::authz::AccessPolicy;
use webgates::codecs::jwt::{JsonWebToken, JwtClaims};
use webgates::prelude::{Group, Role};
use webgates_axum::gate::Gate;

type Claims = JwtClaims<Account<Role, Group>>;

let codec = Arc::new(JsonWebToken::<Claims>::default());

let app = Router::new()
    .route("/admin", get(|| async { "ok" }))
    .layer(
        Gate::cookie("my-app", Arc::clone(&codec))
            .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin)),
    );
```

### Bearer gate

```rust,ignore
use std::sync::Arc;

use axum::{routing::get, Router};
use webgates::accounts::Account;
use webgates::authz::AccessPolicy;
use webgates::codecs::jwt::{JsonWebToken, JwtClaims};
use webgates::prelude::{Group, Role};
use webgates_axum::gate::Gate;

type Claims = JwtClaims<Account<Role, Group>>;

let codec = Arc::new(JsonWebToken::<Claims>::default());

let app = Router::new()
    .route("/api/admin", get(|| async { "ok" }))
    .layer(
        Gate::bearer("my-api", Arc::clone(&codec))
            .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin)),
    );
```

### Optional authentication

Both cookie and JWT bearer gates support optional mode:

- `allow_anonymous_with_optional_user()` forwards all requests
- cookie mode inserts `Option<Account<_, _>>` and `Option<RegisteredClaims>`
- JWT bearer mode inserts `Option<Account<_, _>>` and `Option<RegisteredClaims>`

Use this only for routes where the handler intentionally performs any required access checks.

### Require any authenticated user

Use `require_login()` when you want the baseline role plus all of its supervisors according to your `AccessHierarchy`.

### Cookie template alignment

Use `with_cookie_template(...)` or `configure_cookie_template(...)` to keep the auth cookie configuration aligned between:

- your login cookie writer
- your cookie gate
- your OAuth2 callback cookie writer, if used

## Login / logout handlers

`webgates_axum::route_handlers::login` and `webgates_axum::route_handlers::logout` are thin HTTP adapters around the core `webgates` authentication services.

`login(...)`:

- verifies submitted credentials
- loads the matching account
- mints a JWT with the supplied registered claims
- writes the auth cookie into the returned `CookieJar`

`logout(...)`:

- removes the auth cookie using the supplied `CookieTemplate`

The cookie template and issuer must match the rest of your authentication setup.

## OAuth2

`Gate::oauth2()` configures an Authorization Code + PKCE flow for Axum.

Typical configuration includes:

- authorization URL
- token URL
- client ID
- optional client secret
- redirect URL
- requested scopes
- optional account mapper
- optional account repository/inserter
- optional first-party JWT codec for session issuance

The resulting router exposes:

- `/login`
- `/callback`

mounted under the base path you pass to `into_router(...)`.

## Features

- `default = []`
- `audit-logging`: enables audit logging integration from `webgates`
- `prometheus`: installs Prometheus metrics integration for auth events and depends on `audit-logging`

## Repository backends

Use `webgates-repositories` when you need persistence.

Backend features are opt-in:

- in-memory for tests and examples
- SeaORM for relational databases
- SurrealDB for SurrealDB-backed storage

SurrealDB support is optional and subject to SurrealDB’s BUSL-1.1 licensing. Review that license before enabling it in production.

## Security checklist

- Keep the issuer identical between token minting and gate validation.
- Keep cookie names and templates aligned across login, logout, cookie gates, and OAuth2 callback flows.
- Use secure cookie settings appropriate for production.
- Use persistent signing keys in production and rotate them deliberately.
- Apply rate limits and timeout policy to login and OAuth2 endpoints.
- Validate all request input at the HTTP boundary.
- Avoid logging secrets, raw tokens, or sensitive payloads.
- Prefer short-lived JWTs and explicit observability.

## Examples

- `examples/simple-usage`
- `examples/oauth2-github`
- `examples/permission-registry`
- `examples/prometheus`
- `examples/rate-limiting`
- `webgates-repositories/examples/sea-orm`
- `webgates-repositories/examples/surrealdb`

## License

MIT

SurrealDB support relies on the optional `surrealdb` backend feature in `webgates-repositories`. Review and comply with BUSL-1.1 when enabling that backend.