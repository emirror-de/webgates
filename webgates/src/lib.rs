#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

/*!
# webgates (core)

Domain models, codecs, hashing, repositories, and authorization logic for webgates.
This crate is platform-agnostic and does **not** depend on any specific web
framework. The axum integration (middleware, handlers, cookie templates, OAuth2
routing) now lives in the sibling `webgates-axum` crate.

## What’s here

- Accounts, roles, groups, and permissions domain types
- Authorization policies and validation helpers
- JWT codecs and registered claim types
- Password hashing (Argon2) and credential verification
- Repository traits plus in-memory, SurrealDB, and SeaORM implementations
- Error taxonomy with user-friendly messaging
- Utilities for permission validation and deterministic hashing

## What moved to `webgates-axum`

- Gate builders (cookie/bearer)
- OAuth2 flow helpers and route builders
- Axum route handlers (login/logout)
- Cookie template helpers for HTTP responses

If you need to protect axum routes, depend on both crates and wire the
integration from `webgates-axum`, while keeping your core logic and models
coming from this crate.

## Quick start (core)

```rust
use webgates::accounts::Account;
use webgates::authz::AccessPolicy;
use webgates::permissions::Permissions;
use webgates::prelude::{Group, Role};

let account = Account::new("user@example.com", &[Role::User], &[Group::new("team")])
    .with_permissions(Permissions::from_iter(["read:api"]));

let policy = AccessPolicy::<Role, Group>::require_permission("read:api".into());
assert!(policy.is_authorized(&account));
```
*/

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
#[cfg(all(feature = "server", feature = "storage-seaorm"))]
pub mod comma_separated_value;
pub mod credentials;
#[cfg(feature = "server")]
pub mod errors;
pub mod groups;
#[cfg(feature = "server")]
pub mod hashing;
pub mod permissions;
pub mod prelude;
#[cfg(feature = "server")]
pub mod repositories;
pub mod roles;
#[cfg(feature = "server")]
pub mod secrets;
#[cfg(feature = "server")]
pub mod verification_result;
