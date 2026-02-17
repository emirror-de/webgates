#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
/*!
# webgates

Core domain models, codecs, hashing, and authorization logic for the webgates
project. This crate is platform-agnostic by design and exposes the types and
services you need to build authentication and authorization layers (gates).
Framework-specific adapters (for example, Axum middleware and route handlers)
are provided by the sibling crate `webgates-axum`.

## What’s here

- Accounts, roles, groups, and permissions domain types
- Authorization policies and validation helpers
- JWT codecs and registered claim types
- Password hashing (Argon2) and credential verification helpers
- Result and error helpers and a user-friendly error taxonomy
- Utilities for permission validation and deterministic hashing

## Feature gating and adapters

Many server- and framework-oriented pieces in this crate are gated behind the
optional `server` feature. The following modules require the `server` feature:

- `gate` (Gate builders)
- `codecs` (JWT codec implementations)
- `authn`, `cookie_template`, `hashing`, `secrets`, `verification_result`
- Integration error helpers and other runtime utilities

The crate intentionally ships with no default features enabled. Enable the
`server` feature in your `Cargo.toml` to pull in runtime and server-facing
dependencies when you need them (for example, when creating Gate builders or
using the provided JWT codecs). If you only need the domain types (accounts,
roles, groups, permissions) and zero runtime dependencies, omit the `server`
feature.

If you plan to use Axum adapters (middleware, route handlers, OAuth helpers),
depend on `webgates-axum` which re-exports and adapts the core APIs into Axum
tower layers.

## Quick start (feature-aware)

The short example below shows core usage. Note the `server` feature is required
for `Gate` and the `codecs` module — enable it in your `Cargo.toml` when using
those APIs.

```rust
use webgates::accounts::Account;
use webgates::authz::AccessPolicy;
use webgates::prelude::{Group, Role};

// The `codecs` module and `Gate` are feature-gated behind `server`.
// The following example requires `features = ["server"]` for this crate.
#[cfg(feature = "server")]
{
    use std::sync::Arc;
    use webgates::codecs::jwt::{JsonWebToken, JwtClaims};
    use webgates::gate::Gate;

    type AppClaims = JwtClaims<Account<Role, Group>>;
    let codec = Arc::new(JsonWebToken::<AppClaims>::default());

    let gate = Gate::cookie::<_, Role, Group>("my-app", Arc::clone(&codec))
        .require_login() // baseline role + supervisors
        .with_policy(AccessPolicy::require_permission("admin:read"));
}
```

Adapt this crate into your web framework with the adapters from `webgates-axum`,
or implement your own thin adapter if you integrate with a different framework.

## Notes

- Prefer enabling only the features you need. The `server` feature pulls in
  async/runtime and HTTP-related dependencies.
- For repository-backed storage and optional persistence features, see the
  separate `webgates-repositories` crate.
*/

#[cfg(feature = "server")]
pub use cookie;
pub use jsonwebtoken;
pub use uuid;

pub mod accounts;
#[cfg(feature = "audit-logging")]
pub mod audit;
#[cfg(feature = "server")]
pub mod authn;
pub mod authz;
#[cfg(feature = "server")]
pub mod codecs;
#[cfg(feature = "server")]
pub mod cookie_template;
pub mod credentials;
#[cfg(feature = "server")]
pub mod errors;
pub mod errors_core;
#[cfg(feature = "server")]
pub(crate) mod errors_integration;
#[cfg(feature = "server")]
pub mod gate;
pub mod groups;
#[cfg(feature = "server")]
pub mod hashing;
pub mod permissions;
pub mod prelude;
pub mod roles;
#[cfg(feature = "server")]
pub mod secrets;
#[cfg(feature = "server")]
pub mod verification_result;
