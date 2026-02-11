//! Gate implementation for protecting axum routes with JWT authentication.
//!
//! The `Gate` provides a high-level API for adding authentication and authorization
//! to your axum routes using JWT cookies or bearer tokens. It supports role-based
//! access control, group-based access control, and fine-grained permission systems.
//!
//! # Basic Usage
//!
//! ```rust
//! use axum::{routing::get, Router};
//! use axum_gate::prelude::*;
//! use std::sync::Arc;
//!
//! # async fn protected_handler() -> &'static str { "Protected!" }
//! let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! let cookie_template = CookieTemplate::recommended()
//!     .name("auth-token")
//!     .persistent(cookie::time::Duration::hours(24));
//!
//! let app = Router::<()>::new()
//!     .route("/admin", get(protected_handler))
//!     .layer(
//!         Gate::cookie("my-app", jwt_codec)
//!             .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin))
//!             .with_cookie_template(cookie_template)
//!     );
//! ```
//!
//! # Access Control Examples
//!
//! ## Role-Based Access
//! ```rust
//! # use axum_gate::prelude::*;
//! # use std::sync::Arc;
//! # let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! // Allow only Admin role
//! let gate = Gate::cookie("my-app", Arc::clone(&jwt_codec))
//!     .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin));
//!
//! // Allow Admin or Moderator roles
//! let gate = Gate::cookie("my-app", Arc::clone(&jwt_codec))
//!     .with_policy(
//!         AccessPolicy::<Role, Group>::require_role(Role::Admin)
//!             .or_require_role(Role::Moderator)
//!     );
//! ```
//!
//! ## Hierarchical Access
//! ```rust
//! # use axum_gate::prelude::*;
//! # use std::sync::Arc;
//! # let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! // Allow User role and all supervisor roles (Reporter, Moderator, Admin)
//! let gate = Gate::cookie("my-app", jwt_codec)
//!     .with_policy(AccessPolicy::<Role, Group>::require_role_or_supervisor(Role::User));
//! ```
//!
//! ## Permission-Based Access
//! ```rust
//! # use axum_gate::prelude::*;
//! # use std::sync::Arc;
//! # let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! let gate = Gate::cookie("my-app", jwt_codec)
//!     .with_policy(
//!         AccessPolicy::<Role, Group>::require_permission(PermissionId::from("read:api"))
//!     );
//! ```
//! ## Bearer Gate (JWT)
//! Strict bearer (JWT) example:
//! ```rust
//! # use axum::{routing::get, Router};
//! # use axum_gate::prelude::*;
//! # use std::sync::Arc;
//! # async fn handler() {}
//! let jwt = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! let app = Router::<()>::new()
//!     .route("/admin", get(handler))
//!     .layer(
//!         Gate::bearer("my-app", Arc::clone(&jwt))
//!             .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin))
//!     );
//! ```
//!
//! Optional user context (never blocks; handlers must enforce access):
//! ```rust
//! # use axum_gate::prelude::*;
//! # use std::sync::Arc;
//! let jwt = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! let gate = Gate::bearer::<JsonWebToken<JwtClaims<Account<Role, Group>>>, Role, Group>("my-app", jwt).allow_anonymous_with_optional_user();
//! // Inserts Option<Account<Role, Group>> and Option<RegisteredClaims> into request extensions.
//! ```
//!
use self::bearer::BearerGate;
use self::cookie::CookieGate;
use self::oauth2::OAuth2Gate;
use crate::accounts::Account;
use crate::authz::AccessHierarchy;
use crate::codecs::Codec;
use crate::codecs::jwt::JwtClaims;

use std::sync::Arc;

pub mod bearer;
pub mod cookie;
pub mod oauth2;

/// Main entry point for creating authentication gates.
///
/// Gates protect your axum routes from unauthorized access using JWT tokens.
/// All requests are denied by default unless explicitly granted access through
/// an access policy. Choose between cookie-based gates for web applications
/// and bearer token gates for APIs and SPAs.
#[derive(Clone)]
pub struct Gate;

impl Gate {
    /// Creates a new cookie-based gate that denies all access by default.
    ///
    /// Use this for web applications where you want automatic token handling
    /// through HTTP-only cookies. Cookie gates provide CSRF protection and
    /// work seamlessly with browser-based authentication flows.
    ///
    /// Attach an access policy using `with_policy()` to grant access. This secure-by-default
    /// approach ensures no routes are exposed until you explicitly configure a policy.
    ///
    /// # Arguments
    /// * `issuer` - The JWT issuer identifier for your application
    /// * `codec` - JWT codec for encoding/decoding tokens
    ///
    /// # Example
    /// ```rust
    /// # use axum_gate::prelude::*;
    /// # use std::sync::Arc;
    /// let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
    /// let policy = AccessPolicy::<Role, Group>::require_role(Role::Admin);
    ///
    /// let gate = Gate::cookie("my-app", jwt_codec)
    ///     .with_policy(policy);
    /// ```
    pub fn cookie<C, R, G>(issuer: &str, codec: Arc<C>) -> CookieGate<C, R, G>
    where
        C: Codec,
        R: AccessHierarchy + Eq + std::fmt::Display,
        G: Eq,
    {
        CookieGate::new_with_codec(issuer, codec)
    }

    /// Creates a new bearer-header based gate that denies all access by default.
    ///
    /// Use this for APIs, SPAs, and mobile applications where you need explicit
    /// token management. Bearer token gates require clients to include tokens
    /// in the `Authorization: Bearer <token>` header, providing fine-grained
    /// control over token lifecycle and excellent support for API integrations.
    ///
    /// This variant protects routes by expecting an `Authorization: Bearer <token>`
    /// header. Missing or invalid bearer tokens result in `401 Unauthorized`.
    ///
    /// Optional mode is supported via `allow_anonymous_with_optional_user()`. In optional mode,
    /// requests are always forwarded and the layer inserts `Option<Account<R, G>>` and
    /// `Option<RegisteredClaims>` (Some only when the token is valid). You can also transition to
    /// a static shared-secret mode via `.with_static_token("...")`.
    ///
    /// # Arguments
    /// * `issuer` - The JWT issuer identifier for your application
    /// * `codec` - JWT codec for encoding/decoding tokens
    pub fn bearer<C, R, G>(
        issuer: &str,
        codec: Arc<C>,
    ) -> BearerGate<C, R, G, bearer::JwtConfig<R, G>>
    where
        C: Codec,
        R: AccessHierarchy + Eq + std::fmt::Display,
        G: Eq + Clone,
    {
        // Delegates to the BearerGate builder (to be implemented in bearer module).
        BearerGate::new_with_codec(issuer, codec)
    }

    /// Creates a new OAuth2-based gate builder using the `oauth2` crate.
    ///
    /// This returns an OAuth2 flow builder that can mount `/login` and `/callback` routes and,
    /// on successful callback, will mint a first-party JWT via the existing CookieGate.
    pub fn oauth2<R, G>() -> OAuth2Gate<R, G>
    where
        R: AccessHierarchy + Eq + std::fmt::Display + Send + Sync + 'static,
        G: Eq + Clone + Send + Sync + 'static,
    {
        OAuth2Gate::new()
    }

    /// Creates a new OAuth2-based gate builder preconfigured with a JWT encoder.
    ///
    /// # Arguments
    /// * `issuer` - JWT issuer for your application
    /// * `codec` - JWT codec used to mint tokens for the first‑party cookie
    /// * `ttl_secs` - Expiration (seconds) for issued JWTs
    pub fn oauth2_with_jwt<C, R, G>(issuer: &str, codec: Arc<C>, ttl_secs: u64) -> OAuth2Gate<R, G>
    where
        C: Codec<Payload = JwtClaims<Account<R, G>>> + Send + Sync + 'static,
        R: AccessHierarchy + Eq + std::fmt::Display + Send + Sync + 'static,
        G: Eq + Clone + Send + Sync + 'static,
    {
        OAuth2Gate::new().with_jwt_codec(issuer, codec, ttl_secs)
    }
}
