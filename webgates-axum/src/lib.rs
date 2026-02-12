#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
/*!
# webgates-axum

Axum integration layer for the `webgates` core. This crate provides the
middleware (“gates”) and ready‑made route handlers that plug the core
authentication/authorization models into Axum applications.

- Cookie and bearer gates as Axum tower layers
- OAuth2 helpers for Authorization Code + PKCE flows
- Pre-built login/logout handlers
- Optional audit logging and Prometheus metrics (feature-gated)

The core domain models, hashing, codecs, and repositories live in the sibling
`webgates` crate. Depend on **both** crates to secure Axum apps.

## Basic usage

```rust,ignore
use axum::{routing::get, Router};
use std::sync::Arc;
use webgates_axum::gate::Gate;
use webgates::prelude::*;
use webgates::codecs::jwt::{JsonWebToken, JwtClaims};

let jwt = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());

let app = Router::new()
    .route("/admin", get(|| async { "ok" }))
    .layer(
        Gate::cookie("my-app", jwt)
            .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin))
    );
```

*/

/// Re-export the core crate for convenience.
pub use webgates;

/// Re-export common modules from the core so gate code resolves paths unchanged.
pub use webgates::{
    accounts, authn, authz, codecs, credentials, errors, groups, hashing, permissions, prelude,
    repositories, roles, secrets, verification_result,
};

#[cfg(feature = "audit-logging")]
pub use webgates::audit;
#[cfg(all(feature = "audit-logging", feature = "prometheus"))]
pub use webgates::audit::prometheus_metrics;

/// Re-export cookie template builder from the core.
pub use webgates::cookie_template;

/// Re-export external crates that are part of the public API surface.
pub use axum;
pub use axum_extra;
pub use cookie;
pub use jsonwebtoken;
pub use uuid;

/// Prelude for convenient imports (core prelude + Gate).
pub mod prelude {
    pub use webgates::prelude::*;
    pub use webgates::cookie_template::CookieTemplate;
    pub use crate::gate::Gate;
}

/// Gate builders and middleware for Axum.
pub mod gate;

/// Pre-built route handlers (login/logout).
pub mod route_handlers;
