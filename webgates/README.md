# webgates

User-facing composition crate for the webgates workspace.

`webgates` combines the core domain model with optional authentication, codec,
cookie, secret, and OAuth2 support behind a single dependency for application
code. Most users should depend on this crate directly.

Framework integrations live in sibling crates such as `webgates-axum`.
Persistence backends live in `webgates-repositories`.

## When to use this crate

Use `webgates` when you want:

- one crate for the standard webgates stack
- framework-agnostic gate configuration
- JWT codec support
- authentication services and cookie helpers
- secret and hashing primitives
- framework-agnostic session lifecycle and JWT auto-renewal primitives
- a small, feature-gated public surface without wiring the core sibling crates manually

If you only need a narrower layer, the workspace also exposes dedicated crates
such as:

- `webgates-core`
- `webgates-codecs`
- `webgates-secrets`
- `webgates-sessions`

## Install

Standard setup with the composed default feature set:

```toml
[dependencies]
webgates = "0.1"
```

Minimal setup without the composed defaults:

```toml
[dependencies]
webgates = { version = "0.1", default-features = false }
```

Custom setup with only selected capabilities:

```toml
[dependencies]
webgates = { version = "0.1", default-features = false, features = ["codecs", "cookies", "authn"] }
```

Minimum supported Rust version: 1.91.

## Core concepts

### Gates

Framework-agnostic access gates:

- `Gate::cookie("issuer", codec)` for JWTs in HTTP-only cookies
- `Gate::bearer("issuer", codec)` for `Authorization: Bearer`
- `with_static_token(...)` for static bearer-token mode
- `allow_anonymous_with_optional_user()` for non-blocking optional user context
- `require_login()` for baseline role plus supervisors

### Policies

Authorization policies are explicit and composable:

- `AccessPolicy::require_role(..)`
- `AccessPolicy::require_role_or_supervisor(..)`
- `AccessPolicy::require_group(..)`
- `AccessPolicy::require_permission("domain:action")`

### Codecs

JWT support is available through:

- `codecs::jwt::JsonWebToken`
- `codecs::jwt::JsonWebTokenOptions`

Use persistent ES384 keys in production.

### Domain

The crate exposes the core authentication and authorization model:

- `accounts`
- `roles`
- `groups`
- `permissions`
- credential handling and verification helpers
- deterministic permission identifiers
- collision validation helpers

## Quick start

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
    .require_login()
    .with_policy(AccessPolicy::require_permission("admin:read"));
```

Use `webgates-axum` if you want ready-made Axum middleware and route handlers.
If you use another framework, build an adapter around the gate runtime APIs.

## Features

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

Enable the `sessions` feature when you want short-lived auth JWTs backed by
long-lived refresh-token session state.

This adds access to the framework-agnostic session layer through
`webgates::sessions`, including:

- typed session and session-family models
- session issuance, renewal, and revocation services
- opaque refresh-token generation and hashing primitives
- repository contracts for session persistence, rotation, leases, and revocation
- an in-memory repository for tests and local development

Typical composition for session-backed login and renewal:

```toml
[dependencies]
webgates = { version = "0.1", default-features = false, features = ["authn", "codecs", "cookies", "repositories", "secrets", "sessions"] }
```

For HTTP adapters, keep cookie extraction and response mutation in the adapter
crate. In the Axum integration, use:

- `webgates_axum::route_handlers::login_with_sessions`
- `webgates_axum::route_handlers::logout_with_sessions`
- `webgates_axum::session::CookieSessionLayer`

This keeps token issuance, renewal rules, replay handling, and revocation in the
framework-agnostic session layer while transport-specific cookie behavior stays
in `webgates-axum`.

For the distributed authority/resource operating model and key management,
see `docs/distributed-sessions.md` in the repository root.

## Related crates

- `webgates-core`: domain model and authorization primitives
- `webgates-codecs`: codec implementations such as JWT support
- `webgates-secrets`: secret and hashing primitives
- `webgates-sessions`: framework-agnostic session lifecycle and renewal primitives
- `webgates-axum`: Axum integration, including session-backed login/logout handlers and transparent cookie renewal middleware
- `webgates-repositories`: repository traits and storage backends, including session repository backends

## Security checklist

- Use a persistent JWT key in production.
- Keep issuer strings identical between login and gates.
- Align cookie names and templates between writers and readers.
- Set `Secure`, `HttpOnly`, and `SameSite` appropriately.
- Rate-limit login and validate inputs at boundaries.
- Avoid logging secrets or tokens.
- Use correlation IDs for observability.
- Enable `audit-logging` and `prometheus` where appropriate.
- Enable only the features and sibling crates you actually need.

## License

MIT

Additional backend note:

- SurrealDB support is provided by `webgates-repositories` through its
  `surrealdb` feature. Review and comply with SurrealDB's BUSL-1.1 terms before
  enabling it in production.
