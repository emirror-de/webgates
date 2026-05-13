# webgates

User-focused composition crate for building a practical `webgates` application stack.

`webgates` builds on `webgates-core` and adds optional higher-level capabilities such as authentication workflows, framework-agnostic gate builders, cookie configuration, JWT support, sessions, secrets, OAuth2, and observability.

Most application developers should start here rather than wiring lower-level crates together manually.

## Who this crate is for

Use `webgates` when you want to:

- depend on one crate as the main application-facing entry point
- configure framework-agnostic cookie, bearer, or OAuth2 gates
- use higher-level login/logout orchestration
- add optional JWT, cookie, repository, secret, and session support through features
- keep transport-specific concerns in adapter crates while application auth logic stays here

If you only need the domain model and authorization primitives, use `webgates-core` directly.

## What you work with in this crate

Most developers can approach `webgates` through four ideas:

- `gate` gives you framework-agnostic gate builders and policy composition
- `authn` gives you higher-level authentication workflows
- feature flags add lower-level capabilities such as codecs, cookies, secrets, repositories, sessions, audit logging, and Prometheus integration
- adapter crates translate this crate into framework-specific HTTP or gRPC behavior

## Install

Standard dependency declaration:

```toml
[dependencies]
webgates = "1.0.0"
```

This crate enables no optional features by default. Use `default-features = false`
when you want to make that choice explicit in your manifest or pair it with an
explicit feature list.

Minimal setup with no optional features:

```toml
[dependencies]
webgates = { version = "1.0.0", default-features = false }
```

Custom setup with only selected capabilities:

```toml
[dependencies]
webgates = { version = "1.0.0", default-features = false, features = ["codecs", "cookies", "authn"] }
```

## Quick start

```rust
use std::sync::Arc;
use webgates::accounts::Account;
use webgates::authz::access_policy::AccessPolicy;
use webgates::codecs::jwt::{JsonWebToken, JwtClaims};
use webgates::gate::Gate;
use webgates::groups::Group;
use webgates::roles::Role;

type AppClaims = JwtClaims<Account<Role, Group>>;
let codec = Arc::new(JsonWebToken::<AppClaims>::default());

let gate = Gate::cookie::<_, Role, Group>("my-app", Arc::clone(&codec))
    .require_login()
    .with_policy(AccessPolicy::<Role, Group>::require_permission("admin:read"));
```

## Core concepts

### 1. Gates are the main runtime-facing concept

Framework-agnostic access gates include:

- `Gate::cookie("issuer", codec)` for JWTs in HTTP-only cookies
- `Gate::bearer("issuer", codec)` for `Authorization: Bearer`
- `with_static_token(...)` for static bearer-token mode
- `allow_anonymous_with_optional_user()` for non-blocking optional user context
- `require_login()` for baseline role plus supervisors

### 2. Policies stay explicit and composable

Authorization policies are explicit and composable:

- `AccessPolicy::require_role(..)`
- `AccessPolicy::require_role_or_supervisor(..)`
- `AccessPolicy::require_group(..)`
- `AccessPolicy::require_permission("domain:action")`

### 3. Features control how much stack you bring in

The `webgates` crate ships with no enabled default features. Enable only the features you need.

- `default = []` (no default features)
- `full`: enables the standard composed stack
- `authn`: authentication services
- `codecs`: JWT codec support via `webgates-codecs`
- `cookies`: cookie templates and cookie-backed helpers
- `oauth2`: OAuth2 support
- `repositories`: repository contracts used by higher-level workflows
- `secrets`: hashing and secret handling via `webgates-secrets`
- `sessions`: framework-agnostic session lifecycle and renewal primitives via `webgates-sessions`
- `audit-logging`: structured audit events with `tracing`
- `prometheus`: Prometheus metrics support; implies `audit-logging`
- `wasm`: WASM-oriented build support

## Session-backed authentication

Enable the `sessions` feature when you want short-lived auth JWTs backed by long-lived refresh-token session state.

This adds access to the framework-agnostic session layer through `webgates::sessions`, including:

- typed session and session-family models
- session issuance, renewal, and revocation services
- opaque refresh-token generation and hashing primitives
- repository contracts for session persistence, rotation, leases, and revocation
- an in-memory repository for tests and local development

Typical composition for session-backed login and renewal:

```toml
[dependencies]
webgates = { version = "1.0.0", default-features = false, features = ["authn", "codecs", "cookies", "repositories", "secrets", "sessions"] }
```

For HTTP adapters, keep cookie extraction and response mutation in the adapter crate. In the Axum integration, use:

- `webgates_axum::route_handlers::login_with_sessions`
- `webgates_axum::route_handlers::logout_with_sessions`
- `webgates_axum::session::CookieSessionLayer`

## Recommended onboarding path

If you are new to this crate, I recommend this order:

1. `gate`
2. `authz::access_policy`
3. `authn` if you need login/logout workflows
4. feature-specific areas such as `codecs`, `cookies`, `sessions`, or `oauth2`
5. the adapter crate that matches your transport layer

## Security checklist

- use a persistent JWT key in production
- keep issuer strings identical between login and gates
- align cookie names and templates between writers and readers
- set `Secure`, `HttpOnly`, and `SameSite` appropriately
- rate-limit login and validate inputs at boundaries
- avoid logging secrets or tokens
- use correlation IDs for observability
- enable `audit-logging` and `prometheus` where appropriate

## License

MIT

Additional backend note:

- SurrealDB support is provided by `webgates-repositories` through its `surrealdb` feature. Review and comply with SurrealDB's BUSL-1.1 terms before enabling it in production.
