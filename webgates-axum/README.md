# webgates-axum

User-focused Axum integration for the `webgates` stack.

`webgates-axum` is the crate you use when your application runs on Axum and you want to connect `webgates` authentication and authorization to real routes, middleware, cookies, login endpoints, logout endpoints, JWKS publishing, and session renewal.

`webgates` owns the framework-agnostic logic. `webgates-axum` is the transport adapter that makes that logic feel native inside an Axum application.

## Who this crate is for

Use `webgates-axum` when you want to:

- protect Axum routes with `webgates` gates
- use cookie-based or bearer-token authentication in Axum middleware
- mount ready-made login and logout handlers for browser auth flows
- publish JWKS from an Axum auth authority
- add transparent session renewal middleware for cookie-backed session flows
- keep your authentication logic in `webgates` while keeping HTTP integration in Axum

You still depend on `webgates` for domain types, policies, codecs, cookie templates, authentication services, repository contracts, and sessions.

## What this crate helps you build

Use this crate when you want one or more of these Axum-facing workflows:

- route protection with cookie, bearer, or OAuth2-based gates
- ready-made login and logout handlers for browser-facing auth flows
- session-backed login/logout plus transparent renewal middleware
- JWKS publication from an auth authority
- typed handler access to transport-level auth state such as static-token authorization

## Install

Most applications should depend on both crates explicitly.

Standard setup:

```toml
[dependencies]
axum = "0.8"
webgates = "1.0.0"
webgates-axum = "1.0.0"
```

If you want a narrower `webgates` dependency set, disable its defaults and enable only the required features there:

```toml
[dependencies]
axum = "0.8"
webgates = { version = "1.0.0", default-features = false, features = ["authn", "codecs", "cookies", "oauth2", "repositories", "secrets", "sessions"] }
webgates-axum = "1.0.0"
```

Minimum supported Rust version: `1.91`.

## The mental model

The easiest way to understand `webgates-axum` is:

1. define auth and authorization rules in `webgates`
2. adapt them into Axum layers with `webgates_axum::gate::Gate`
3. use `route_handlers` when you want ready-made HTTP endpoints for login/logout/JWKS
4. use `CookieSessionLayer` when you want transparent cookie-backed session renewal

This keeps responsibilities separate:

- `webgates` owns domain logic and session/authentication orchestration
- `webgates-axum` owns request extraction, response mapping, cookies, and middleware behavior

## Quick start

### Cookie gate

```rust,ignore
use std::sync::Arc;

use axum::{routing::get, Router};
use webgates::accounts::Account;
use webgates::authz::access_policy::AccessPolicy;
use webgates::codecs::jwt::{JsonWebToken, JwtClaims};
use webgates::groups::Group;
use webgates::roles::Role;
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
use webgates::authz::access_policy::AccessPolicy;
use webgates::codecs::jwt::{JsonWebToken, JwtClaims};
use webgates::groups::Group;
use webgates::roles::Role;
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

## Core concepts

### 1. Axum `Gate` is your main middleware entry point

Use `webgates_axum::gate::Gate` when you want to turn framework-agnostic `webgates` gate configuration into Axum middleware.

Common entry points are:

- `Gate::cookie(...)`
- `Gate::bearer(...)`
- `Gate::oauth2(...)`

These are the intended integration surface for Axum applications.

### 2. Route handlers are thin Axum adapters

The login, logout, and JWKS handlers do not implement core auth logic themselves. They adapt HTTP requests and responses around `webgates` services.

That means:

- credential verification stays in `webgates`
- account lookup stays in repository contracts
- token issuance stays in codecs or session issuers
- Axum handlers focus on request extraction, cookie writing, and response mapping

### 3. Session renewal is a separate middleware concern

Use `webgates_axum::session::CookieSessionLayer` when you want transparent renewal for cookie-backed session authentication.

The intended composition is:

1. outer layer: `CookieSessionLayer`
2. inner layer: `Gate::cookie(...)`

That separation keeps refresh-token logic and auth-token validation from getting mixed together.

## Login and logout handlers

### Cookie-only login/logout

Use these when you want a direct JWT auth-cookie flow:

- `webgates_axum::route_handlers::login::login`
- `webgates_axum::route_handlers::logout::logout`

`login(...)`:

- verifies submitted credentials
- loads the matching account
- mints a JWT with the supplied registered claims
- writes the auth cookie into the returned `CookieJar`

`logout(...)`:

- removes the auth cookie using the supplied `CookieTemplate`

### Session-backed login/logout

Use these when you want short-lived auth tokens and long-lived refresh-token-backed sessions:

- `webgates_axum::route_handlers::login::login_with_sessions`
- `webgates_axum::route_handlers::logout::logout_with_sessions`

The session-backed login handler uses two named input structs:

- `SessionLoginRequest`
- `SessionLoginDependencies`

These make the session-backed API easier to pass around and easier to document explicitly.

## Optional authentication

Both cookie and JWT bearer gates support optional mode:

- `allow_anonymous_with_optional_user()` forwards all requests
- cookie mode inserts `Option<Account<_, _>>` and `Option<RegisteredClaims>`
- JWT bearer mode inserts `Option<Account<_, _>>` and `Option<RegisteredClaims>`

Use this only for routes where the handler intentionally decides what to do with anonymous vs authenticated context.

## Require any authenticated user

Use `require_login()` when you want the baseline role plus all of its supervisors according to your `AccessHierarchy`.

## Cookie template alignment

Keep your cookie template configuration aligned between:

- login handlers that write cookies
- logout handlers that remove cookies
- cookie gates that read cookies
- OAuth2 callback flows, if used
- session renewal middleware, if used

Use `with_cookie_template(...)` or `configure_cookie_template(...)` to keep this explicit and consistent.

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

When using OAuth2 with JWT issuance, prefer short-lived access tokens and keep signing in the auth authority only.

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

Backend features are opt-in, including:

- in-memory backends for tests and examples
- SeaORM for relational databases
- SurrealDB for SurrealDB-backed storage

SurrealDB support is optional and subject to SurrealDB’s BUSL-1.1 licensing. Review that license before enabling it in production.

## Recommended onboarding path

If you are new to this crate, I recommend this order:

1. `webgates` gate and auth concepts
2. `webgates_axum::gate::Gate`
3. `route_handlers`
4. `session::CookieSessionLayer`
5. feature-specific areas like OAuth2 or Prometheus integration

## Security checklist

- keep the issuer identical between token minting and gate validation
- keep cookie names and templates aligned across login, logout, cookie gates, and OAuth2 callback flows
- use secure cookie settings appropriate for production
- use persistent signing keys in production and rotate them deliberately
- apply rate limits and timeout policy to login and OAuth2 endpoints
- validate all request input at the HTTP boundary
- avoid logging secrets, raw tokens, or sensitive payloads
- prefer short-lived JWTs and explicit observability

## Examples

- `examples/oauth2-github`
- `examples/permission-registry`
- `examples/prometheus`
- `webgates-repositories/examples/sea-orm`
- `webgates-repositories/examples/surrealdb`

For the distributed authority/resource operations guide, including key handling and rollout guidance, see `docs/distributed-sessions.md` in the repository root.

## License

MIT

SurrealDB support relies on the optional `surrealdb` backend feature in `webgates-repositories`. Review and comply with BUSL-1.1 when enabling that backend.
