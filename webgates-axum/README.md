# webgates-axum

Axum integration for the `webgates` core.

This crate is the Axum-facing adapter layer for `webgates`. It exposes a small public API:

- `webgates_axum::gate::Gate` as the canonical entry point for cookie, bearer, and OAuth2 integration
- `webgates_axum::route_handlers::login::login` and `webgates_axum::route_handlers::logout::logout` for ready-made auth cookie handlers
- `webgates_axum::route_handlers::jwks::jwks` for canonical JWKS publication on auth authorities
- `webgates_axum::route_handlers::login::login_with_sessions` and `webgates_axum::route_handlers::logout::logout_with_sessions` for session-backed auth and refresh-cookie handlers
- `webgates_axum::route_handlers::login::SessionLoginRequest` and `webgates_axum::route_handlers::login::SessionLoginDependencies` as the constructible input types for the session-backed login handler
- `webgates_axum::session::CookieSessionLayer` for transparent cookie-backed session renewal
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

MSRV: 1.91

## Public API

The canonical public API of this crate is intentionally small.

### Gate entry point

Use `webgates_axum::gate::Gate` to build middleware:

- `Gate::cookie(...)`
- `Gate::bearer(...)`
- `Gate::oauth2(...)`

These builders are the intended integration surface for Axum applications.

### Route handlers

Use `webgates_axum::route_handlers::login::login` and `webgates_axum::route_handlers::logout::logout` when you want simple cookie-based login/logout endpoints that plug into the `webgates` core services.

Use `webgates_axum::route_handlers::login::login_with_sessions` and `webgates_axum::route_handlers::logout::logout_with_sessions` when you want session-backed auth and refresh cookies with framework-agnostic session issuance and revocation handled by `webgates::sessions`.

The session-backed login handler requires two input structs that are also publicly reachable from the `login` submodule:

- `webgates_axum::route_handlers::login::SessionLoginRequest` --- carries credentials, session configuration, cookie templates, and the issuance timestamp.
- `webgates_axum::route_handlers::login::SessionLoginDependencies` --- carries the credential verifier, account repository, session repository, and auth-token issuer.

### Optional static-token extraction

If you use optional static bearer token mode, handlers can read:

- `webgates_axum::gate::bearer::StaticTokenAuthorized`

This is the only bearer-mode extension helper intended for direct handler use.

### What to import directly

Prefer direct imports from stable module paths:

```rust
use webgates_axum::gate::Gate;
use webgates_axum::route_handlers::login::login;
use webgates_axum::route_handlers::login::login_with_sessions;
use webgates_axum::route_handlers::login::SessionLoginRequest;
use webgates_axum::route_handlers::login::SessionLoginDependencies;
use webgates_axum::route_handlers::jwks::jwks;
use webgates_axum::route_handlers::logout::logout;
use webgates_axum::route_handlers::logout::logout_with_sessions;
use webgates_axum::session::CookieSessionLayer;
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

`webgates_axum::route_handlers::login::login` and `webgates_axum::route_handlers::logout::logout` are thin HTTP adapters around the core `webgates` authentication services.

`webgates_axum::route_handlers::login::login_with_sessions` and `webgates_axum::route_handlers::logout::logout_with_sessions` are the session-backed variants. They issue and revoke auth and refresh cookies while leaving session-state orchestration in `webgates::sessions`.

`login(...)`:

- verifies submitted credentials
- loads the matching account
- mints a JWT with the supplied registered claims
- writes the auth cookie into the returned `CookieJar`

`logout(...)`:

- removes the auth cookie using the supplied `CookieTemplate`

The cookie template and issuer must match the rest of your authentication setup.

`login_with_sessions(...)`:

- verifies submitted credentials
- loads the matching account
- issues a session-backed auth token plus opaque refresh token
- writes both cookies into the returned `CookieJar`

`logout_with_sessions(...)`:

- revokes either the current session or the full session family
- removes both auth and refresh cookies from the returned `CookieJar`

For transparent renewal, compose `webgates_axum::session::CookieSessionLayer` outside `Gate::cookie(...)`. The session layer handles refresh-cookie extraction, proactive near-expiry renewal, expired-token renewal requirements, and response `Set-Cookie` updates, while the inner cookie gate remains focused on auth-token validation and authorization.

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

When using OAuth2 with JWT issuance, prefer short-lived access tokens
(for example, `JWT_TTL_SECS=900`) and keep signing in the auth authority only.

The resulting router exposes:

- `/login`
- `/callback`

mounted under the base path you pass to `into_router(...)`.

## JWKS publication endpoint

Auth authorities can expose canonical JWKS using the built-in handler:

```rust,ignore
use axum::{routing::get, Router};
use webgates::codecs::jwt::jwks::JwksProvider;
use webgates_axum::route_handlers;

let provider = JwksProvider::from_es384_public_pem(public_key_pem.as_bytes())?;
let app = Router::new().route(
    "/.well-known/jwks.json",
    get(move || {
        let provider = provider.clone();
        async move { route_handlers::jwks::jwks(provider).await }
    }),
);
# Ok::<(), Box<dyn std::error::Error>>(())
```

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

For the canonical distributed authority/resource operations model, key handling,
and rollout guidance, see `docs/distributed-sessions.md` in the repository
root.

Session-backed Axum integrations typically combine:

- `webgates::authn::SessionLoginService` and `webgates::authn::SessionLogoutService` in the core layer
- `webgates_axum::route_handlers::login::login_with_sessions` and `webgates_axum::route_handlers::logout::logout_with_sessions` at the HTTP boundary
- `webgates_axum::session::CookieSessionLayer` as the outer middleware around `Gate::cookie(...)`
- a `webgates::sessions::repository::SessionRepository` implementation such as the in-memory backend for tests or the SurrealDB backend from `webgates-repositories`

## License

MIT

SurrealDB support relies on the optional `surrealdb` backend feature in `webgates-repositories`. Review and comply with BUSL-1.1 when enabling that backend.
