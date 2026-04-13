#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
/*!
# webgates

`webgates` extends `webgates-core` with optional authentication, codec, cookie,
OAuth2, audit, and secret-management capabilities.

This crate is not the workspace grab bag. The canonical domain and
authorization API lives in `webgates-core`. This crate keeps those core modules
available and adds only the higher-level capabilities that build on top of
them.

Framework adapters remain in sibling crates such as `webgates-axum`.
Persistence backends remain in `webgates-repositories`.

## What this crate adds

Compared with `webgates-core`, this crate adds optional modules for:

- authentication workflows via `authn`
- cookie templates via `cookie_template`
- framework-agnostic gate builders via `gate`
- audit logging via `audit`

Optional integration crates are exposed only when their corresponding feature is
enabled:

- `codecs` enables `webgates-codecs`
- `secrets` enables `webgates-secrets`
- `sessions` enables `webgates-sessions`
- `sessions` enables `webgates-sessions`

## Feature model

This crate defaults to the smallest possible surface and enables no optional
features automatically.

Available features:

- `authn` — authentication services; depends on `codecs`, `repositories`, and `secrets`
- `codecs` — re-export `webgates-codecs`
- `cookies` — cookie templates and cookie-dependent gate helpers
- `oauth2` — OAuth2 gate support; depends on `codecs`, `cookies`, and `repositories`
- `secrets` — re-export `webgates-secrets`
- `sessions` — framework-agnostic session lifecycle and renewal primitives
- `repositories` — repository contracts used by higher-level workflows
- `audit-logging` — structured audit events
- `prometheus` — Prometheus metrics for audit logging

Use `webgates-core` directly if you only need the base domain and authorization
types.

Use `webgates` when you want the core API plus the optional higher-level
capabilities defined above.

## Quick start

Core types come from the same canonical module paths as in `webgates-core`:

```rust
use webgates::accounts::Account;
use webgates::authz::access_policy::AccessPolicy;
use webgates::groups::Group;
use webgates::roles::Role;
```

Optional capabilities are enabled explicitly:

```rust
#[cfg(all(feature = "codecs", feature = "cookies"))]
{
    use std::sync::Arc;
    use webgates::accounts::Account;
    use webgates::authz::access_policy::AccessPolicy;
    use webgates::gate::Gate;
    use webgates::groups::Group;
    use webgates::roles::Role;
    use webgates::codecs::jwt::{JsonWebToken, JwtClaims};

    type AppClaims = JwtClaims<Account<Role, Group>>;
    let codec = Arc::new(JsonWebToken::<AppClaims>::default());

    let _gate = Gate::cookie::<_, Role, Group>("my-app", Arc::clone(&codec))
        .require_login()
        .with_policy(AccessPolicy::require_permission("admin:read"));
}
```

## Design notes

- `webgates-core` owns the core domain and authorization API.
- `webgates` extends that API with optional higher-level functionality.
- `webgates-axum` owns Axum-specific integration.
- `webgates-repositories` owns persistence backends and repository modules.
*/

pub use webgates_core::validate_permissions;
pub use webgates_core::{
    accounts, authz, credentials, errors_core, groups, permissions, roles, verification_result,
};

#[cfg(feature = "audit-logging")]
pub mod audit;
#[cfg(feature = "authn")]
pub mod authn;
#[cfg(feature = "cookies")]
pub use cookie;
#[cfg(feature = "codecs")]
pub use webgates_codecs as codecs;
#[cfg(feature = "cookies")]
pub mod cookie_template;
#[cfg(any(
    feature = "authn",
    feature = "codecs",
    feature = "cookies",
    feature = "secrets"
))]
pub mod errors;
#[cfg(any(feature = "codecs", feature = "cookies"))]
pub(crate) mod errors_integration;
#[cfg(any(feature = "codecs", feature = "cookies", feature = "oauth2"))]
pub mod gate;
#[cfg(feature = "secrets")]
pub use webgates_secrets as secrets;
#[cfg(feature = "sessions")]
pub use webgates_sessions as sessions;
