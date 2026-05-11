#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
/*!
# webgates-tonic

User-focused tonic server-side integration for the `webgates` stack.

This crate is the tonic-facing transport adapter for `webgates`. It applies
bearer-token authentication and authorization to incoming gRPC requests while
keeping the core auth and policy logic in the framework-agnostic `webgates`
crate.

It is **server-side only** and intentionally does not provide cookie transport,
browser-redirect OAuth2 flows, or tonic client utilities.

## When to use this crate

Use `webgates-tonic` when you want:

- tonic middleware for bearer-token authentication
- `webgates` authorization policy enforcement on gRPC services
- typed auth context in tonic request extensions
- optional JWT auth context for mixed public/authenticated methods
- static-token service-to-service authentication

## How to approach this crate

Most tonic applications can learn this crate in three steps:

1. start with [`gate`] to understand how bearer auth is enforced in middleware
2. move to [`context`] to see what handler-visible auth state becomes available
3. read [`errors`] if you need to understand or customize auth failure behavior

## Quick start

```rust,no_run
use std::sync::Arc;
use webgates::accounts::Account;
use webgates::authz::access_policy::AccessPolicy;
use webgates::roles::Role;
use webgates::groups::Group;
use webgates_codecs::jwt::{JsonWebToken, JwtClaims};
use webgates_tonic::gate::Gate;

let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
let layer = Gate::bearer("my-svc", codec)
    .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin));

let _ = layer;
```

## Getting started on docs.rs

A good reading order is:

1. [`gate`]
2. [`context`]
3. [`errors`]
4. [`gate::bearer`]
5. [`gate::remote_jwks_bearer`] if you need remote JWKS-backed verification
*/

/// Gate builders and tower middleware for tonic services.
pub mod gate;

/// Typed request-extension models inserted into tonic request extensions by the
/// gate.
///
/// See `crate::context` for `JwtAuthContext`, `OptionalJwtAuthContext`, and
/// `StaticTokenAuthorized`.
pub mod context;

/// Authentication error types and their mapping to [`tonic::Status`] codes.
pub mod errors;
