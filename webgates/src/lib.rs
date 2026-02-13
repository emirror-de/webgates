#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

/*!
# webgates (core)

Domain models, codecs, hashing, and authorization logic for webgates.
This crate is platform-agnostic and does **not** depend on any specific web
framework. Gate configurations (cookie/bearer) live here; framework adapters
(e.g., Axum middleware, route handlers, OAuth2 routing) are provided by the
sibling `webgates-axum` crate.

## What’s here

- Accounts, roles, groups, and permissions domain types
- Authorization policies and validation helpers
- JWT codecs and registered claim types
- Password hashing (Argon2) and credential verification
- Result and error helpers for downstream libraries
- Error taxonomy with user-friendly messaging
- Utilities for permission validation and deterministic hashing

## What lives in `webgates-axum`

- Axum adapters for the gates (tower layers)
- OAuth2 flow helpers and route builders
- Axum route handlers (login/logout)
- HTTP cookie writer helpers

Use this crate for gate configuration and domain logic, and `webgates-axum` to
adapt them into Axum layers.

## Quick start (core)

```rust
use webgates::accounts::Account;
use webgates::authz::{AccessPolicy, AuthorizationService};
use webgates::permissions::Permissions;
use webgates::prelude::{Group, Role};

let account = Account::new("user@example.com", &[Role::User], &[Group::new("team")])
    .with_permissions(Permissions::from_iter(["read:api"]));

let policy = AccessPolicy::<Role, Group>::require_permission("read:api");
let authz = AuthorizationService::new(policy);
assert!(authz.is_authorized(&account));
```
*/

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
#[cfg(feature = "server")]
pub mod gate;

pub mod credentials;
#[cfg(feature = "server")]
pub mod errors;
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
