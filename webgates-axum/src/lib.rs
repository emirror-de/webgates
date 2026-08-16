#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
/*!
# webgates-axum

Axum integration for `webgates` authentication, authorization, login/logout handlers, and session renewal.

This crate is the Axum-facing transport adapter for `webgates`. It takes the
framework-agnostic authentication and authorization model from `webgates` and
connects it to Axum routers, middleware layers, cookies, login/logout
handlers, JWKS routes, and session renewal flows.

## When to use this crate

Use `webgates-axum` when you want:

- Axum middleware for cookie, bearer, or OAuth2 gate flows
- ready-made login/logout HTTP handlers
- JWKS publication from an Axum auth authority
- transparent cookie-backed session renewal middleware
- a clean separation between transport concerns and core auth logic

The core domain types, authentication logic, repositories, codecs, and
framework-agnostic gate configuration still live in the sibling `webgates`
crate.

## Key modules

Most applications can learn this crate in three steps:

- start with [`gate::Gate`] when you want route protection or auth middleware
- move to [`route_handlers`] when you want ready-made login, logout, or JWKS endpoints
- add [`session`] when you want transparent cookie-backed session renewal

This crate does not provide a convenience prelude and does not re-export Axum.
Use Axum directly from your own dependency list.

## Examples

```rust
use axum::{routing::get, Router};
use std::sync::Arc;
use webgates::accounts::Account;
use webgates::authz::access_policy::AccessPolicy;
use webgates::groups::Group;
use webgates::roles::Role;
use webgates_axum::gate::Gate;
use webgates_codecs::jwt::{JsonWebToken, JwtClaims};

let jwt = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::new_with_options(
    webgates::codecs::jwt::JsonWebTokenOptions::generate_for_testing()
        .expect("generating ephemeral ES384 key pair should not fail"),
));

let app = Router::<()>::new()
    .route("/admin", get(|| async { "ok" }))
    .layer(
        Gate::cookie("my-app", jwt)
            .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin)),
    );

let _ = app;
```

## Distributed authority/resource model

In a session-backed Axum deployment, this crate typically sits at two different
HTTP boundaries:

- an **auth authority** exposes login, logout, renewal, and optional JWKS
  publication endpoints
- a **resource service** applies cookie or bearer gates, validates access
  tokens locally, and enforces authorization policy

The canonical split is to keep refresh-token handling, session mutation, and
signing-key ownership on the authority only. Resource services should validate
short-lived access tokens and should not expose refresh-token or session-
mutation endpoints.

## Getting started on docs.rs

A good reading order is:

1. [`gate`] for route protection and middleware
2. [`route_handlers`] for login/logout/JWKS endpoints
3. [`session`] for transparent session renewal middleware

That path mirrors how most Axum applications adopt the crate.
*/

/// Gate builders and middleware for Axum.
pub mod gate;

/// Session middleware for transparent cookie-backed renewal.
pub mod session;

/// Pre-built route handlers for login, logout, and JWKS flows.
///
/// Import handler functions and session-login input types from the public
/// submodules:
///
/// ```rust,ignore
/// use webgates_axum::route_handlers::login::login;
/// use webgates_axum::route_handlers::login::login_with_sessions;
/// use webgates_axum::route_handlers::login::SessionLoginRequest;
/// use webgates_axum::route_handlers::login::SessionLoginDependencies;
/// use webgates_axum::route_handlers::logout::logout;
/// use webgates_axum::route_handlers::logout::logout_with_sessions;
/// ```
pub mod route_handlers;
