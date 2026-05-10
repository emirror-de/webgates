#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
/*!
# webgates-tonic

Tonic server-side integration layer for the `webgates` core.

This crate exposes a small, `webgates-axum`-style public API for authenticating
and authorizing incoming gRPC requests on tonic servers. It is **server-side
only** and intentionally does not provide cookie transport, browser-redirect
OAuth2 flows, or any client-side tonic utilities.

## Non-goals

- Client-side tonic authentication (token injection for outgoing calls).
- Cookie-based authentication.
- Browser-redirect or OAuth2 authorization code flows.
- Any feature that is not required for server-side bearer token validation.

## Public API

| Module | Purpose |
|---|---|
| [`gate`] | Entry point for building bearer gate middleware. |
| [`gate::Gate`] | Canonical builder for tonic bearer gates. |
| [`gate::bearer`] | Bearer gate types and handler-visible extension types. |
| [`context`] | Typed request-extension models for handlers. |
| [`errors`] | `errors::AuthError` and its mapping to [`tonic::Status`]. |

## Feature flags

| Feature | Description |
|---|---|
| `audit-logging` | Enables audit logging via `webgates/audit-logging`. |
| `prometheus` | Installs Prometheus metrics; depends on `audit-logging`. |

## Quick start

### Strict JWT bearer gate

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

// Wrap a tonic server with `.layer(layer)` before adding to a Router.
```

### Optional JWT bearer gate

```rust,no_run
use std::sync::Arc;
use webgates::accounts::Account;
use webgates::roles::Role;
use webgates::groups::Group;
use webgates_codecs::jwt::{JsonWebToken, JwtClaims};
use webgates_tonic::gate::Gate;

let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
let layer = Gate::bearer("my-svc", codec)
    .allow_anonymous_with_optional_user();
// Handlers retrieve `webgates_tonic::context::OptionalJwtAuthContext<Role, Group>`
// from request extensions.
```

### Static-token bearer gate

```rust,no_run
use std::sync::Arc;
use webgates::accounts::Account;
use webgates::roles::Role;
use webgates::groups::Group;
use webgates_codecs::jwt::{JsonWebToken, JwtClaims};
use webgates_tonic::gate::Gate;

let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
let layer = Gate::bearer("my-svc", codec)
    .with_static_token("internal-static-token");
// Handlers retrieve `webgates_tonic::context::StaticTokenAuthorized`
// from request extensions.
```

## Handler-side extension access

In strict JWT mode, retrieve the auth context from request extensions:

```rust,no_run
use webgates_tonic::context::JwtAuthContext;
use webgates::roles::Role;
use webgates::groups::Group;
use tonic::{Request, Response, Status};

struct MyRequest {}
struct MyResponse {}

async fn my_handler(
    req: Request<MyRequest>,
) -> Result<Response<MyResponse>, Status> {
    let ctx = req.extensions().get::<JwtAuthContext<Role, Group>>()
        .ok_or_else(|| Status::unauthenticated("missing auth context"))?;
    let account = ctx.account();
    // ...
    todo!()
}
```
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
///
/// See `crate::errors::AuthError`.
pub mod errors;
