#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
/*!
# webgates-axum

Axum integration layer for the `webgates` core.

This crate exposes the Axum-specific boundary for `webgates`:
- `gate` contains Axum middleware builders for cookie, bearer, and OAuth2 flows
- `route_handlers` contains ready-made login and logout handlers

The core domain types, authentication logic, repositories, codecs, and
framework-agnostic gate configuration live in the sibling `webgates` crate.

## Public API

The intended public entry points are:
- `gate::Gate`
- `gate::cookie`
- `gate::bearer`
- `gate::oauth2`
- `route_handlers`
- `route_handlers::login` --- login handlers and session-login input types
- `route_handlers::logout` --- logout handlers

This crate does not provide a convenience prelude and does not re-export Axum.
Use Axum directly from your own dependency list.

## Basic usage

```rust
use axum::{routing::get, Router};
use std::sync::Arc;
use webgates::accounts::Account;
use webgates::authz::AccessPolicy;
use webgates::groups::Group;
use webgates::roles::Role;
use webgates_axum::gate::Gate;
use webgates_codecs::jwt::{JsonWebToken, JwtClaims};

let jwt = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());

let app = Router::<()>::new()
    .route("/admin", get(|| async { "ok" }))
    .layer(
        Gate::cookie("my-app", jwt)
            .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin)),
    );
```
*/

/// Gate builders and middleware for Axum.
pub mod gate;

/// Session middleware for transparent cookie-backed renewal.
pub mod session;

/// Pre-built route handlers for login and logout flows.
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
