# webgates

User-focused composition crate for the `webgates` ecosystem.

`webgates` is the main application-facing crate in the workspace. It composes the core domain model with optional authentication, codec, cookie, secret, OAuth2, session, audit, and metrics support behind one dependency.

If you are building application code and do not want to wire the lower-level crates together manually, this is usually the crate to start with.

## Who this crate is for

Use `webgates` when you want to:

- start from one crate for the standard `webgates` stack
- configure framework-agnostic cookie, bearer, or OAuth2 gates
- use authentication services and cookie helpers
- add JWT codec, secret, repository, and session support through additive features
- keep your application code on the higher-level composition layer instead of wiring sibling crates directly

If you only need a narrower layer, the workspace also exposes dedicated crates such as `webgates-core`, `webgates-codecs`, `webgates-secrets`, `webgates-sessions`, and `webgates-repositories`.

## What you work with in this crate

Most developers can approach `webgates` through four ideas:

- `gate` gives you framework-agnostic gate builders and policy composition
- `authn` gives you higher-level authentication workflows
- feature flags add lower-level capabilities such as codecs, cookies, secrets, repositories, sessions, audit logging, and Prometheus integration
- transport adapters such as `webgates-axum` and `webgates-tonic` plug this crate into HTTP or gRPC frameworks

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

Minimum supported Rust version: `1.91`.

## The mental model

The easiest way to understand this crate is:

1. `webgates-core` owns the domain model
2. `webgates` composes that model with optional higher-level capabilities
3. your transport adapter calls into this crate instead of reimplementing auth logic
4. you enable only the features needed for your actual application surface

That gives you one place to express gates, auth flows, cookie behavior, and optional session-backed composition without pulling transport details into the core layer.

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

Use `webgates-axum` if you want ready-made Axum middleware and route handlers.
Use `webgates-tonic` if you want tonic server-side bearer-token integration.
If you use another framework, build an adapter around the gate runtime APIs.

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

`full` currently enables:

- `authn`
- `audit-logging`
- `codecs`
- `cookies`
- `oauth2`
- `prometheus`
- `repositories`
- `secrets`
- `sessions`

Typical choices:

- most applications: enable `full` or explicitly list the runtime features you need
- domain-only usage: `default-features = false`
- session-backed authentication: enable `sessions` together with the auth and transport features you need
- custom composition: disable defaults and enable only what you need

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

This keeps token issuance, renewal rules, replay handling, and revocation in the framework-agnostic session layer while transport-specific cookie behavior stays in `webgates-axum`.

For the distributed authority/resource operations guide, including key management and rollout guidance, see `docs/distributed-sessions.md` in the repository root.

## Recommended onboarding path

If you are new to this crate, I recommend this order:

1. `gate`
2. `authz::access_policy`
3. `authn` if you need login/logout workflows
4. feature-specific areas such as `codecs`, `cookies`, `sessions`, or `oauth2`
5. the adapter crate that matches your transport layer

## Which crate should you use?

- use `webgates` when you want the main application-facing composition layer
- use `webgates-core` when you only want domain types and authorization primitives
- use `webgates-axum` when you want Axum integration
- use `webgates-tonic` when you want tonic server-side bearer-token integration
- use `webgates-codecs` when you need JWT or codec support directly
- use `webgates-secrets` when you need hashing and secret handling directly
- use `webgates-sessions` when you need the session layer directly
- use `webgates-repositories` when you need repository contracts and storage backends directly

## Security checklist

- use a persistent JWT key in production
- keep issuer strings identical between login and gates
- align cookie names and templates between writers and readers
- set `Secure`, `HttpOnly`, and `SameSite` appropriately
- rate-limit login and validate inputs at boundaries
- avoid logging secrets or tokens
- use correlation IDs for observability
- enable `audit-logging` and `prometheus` where appropriate
- enable only the features and sibling crates you actually need

## Related crates

- `webgates-core`: domain model and authorization primitives
- `webgates-codecs`: codec implementations such as JWT support
- `webgates-secrets`: secret and hashing primitives
- `webgates-sessions`: framework-agnostic session lifecycle and renewal primitives
- `webgates-axum`: Axum integration, including session-backed login/logout handlers and transparent cookie renewal middleware
- `webgates-tonic`: tonic integration for bearer-token authentication and authorization on gRPC servers
- `webgates-repositories`: repository traits and storage backends, including session repository backends

## License

MIT

Additional backend note:

- SurrealDB support is provided by `webgates-repositories` through its `surrealdb` feature. Review and comply with SurrealDB's BUSL-1.1 terms before enabling it in production.
