//! Pre-built route handlers for authentication workflows.
//!
//! This module provides ready-to-use handlers for common authentication operations:
//! [`login`] for user authentication and JWT cookie creation, and [`logout`] for
//! session termination. These handlers integrate with your storage backends and
//! JWT configuration to provide secure authentication endpoints.
//!
//! # Quick Setup
//!
//! ```rust
//! use axum::{routing::post, Router, Json, extract::State};
//! use axum_gate::route_handlers::{login, logout};
//! use axum_gate::prelude::Credentials;
//! use axum_gate::codecs::jwt::{RegisteredClaims, JsonWebToken, JwtClaims};
//! use axum_gate::accounts::Account;
//! use axum_gate::prelude::{Role, Group};
//! use axum_gate::repositories::memory::{MemorySecretRepository, MemoryAccountRepository};
//! use axum_extra::extract::CookieJar;
//! use std::sync::Arc;
//!
//! type AppJwtCodec = JsonWebToken<JwtClaims<Account<Role, Group>>>;
//!
//! #[derive(Clone)]
//! struct AppState {
//!     account_repo: Arc<MemoryAccountRepository<Role, Group>>,
//!     secret_repo: Arc<MemorySecretRepository>,
//!     jwt_codec: Arc<AppJwtCodec>,
//! }
//!
//! async fn login_handler(
//!     State(state): State<AppState>,
//!     cookie_jar: CookieJar,
//!     Json(credentials): Json<Credentials<String>>,
//! ) -> Result<CookieJar, axum::http::StatusCode> {
//!     let claims = RegisteredClaims::new("my-app",
//!         chrono::Utc::now().timestamp() as u64 + 3600); // 1 hour expiry
//!
//!     let cookie_template = axum_gate::cookie_template::CookieTemplate::recommended()
//!         .name("auth-token")
//!         .secure(true)
//!         .http_only(true);
//!
//!     login(
//!         cookie_jar,
//!         credentials,
//!         claims,
//!         state.secret_repo,
//!         state.account_repo,
//!         state.jwt_codec,
//!         cookie_template,
//!     ).await
//! }
//!
//! async fn logout_handler(cookie_jar: CookieJar) -> CookieJar {
//!     let cookie_template = axum_gate::cookie_template::CookieTemplate::recommended().name("auth-token");
//!     logout(cookie_jar, cookie_template).await
//! }
//!
//! // Instantiate repositories and JWT codec for the example
//! let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
//! let secret_repo = Arc::new(MemorySecretRepository::new_with_argon2_hasher().unwrap());
//! let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//!
//! // Build application state
//! let app_state = AppState {
//!     account_repo: Arc::clone(&account_repo),
//!     secret_repo: Arc::clone(&secret_repo),
//!     jwt_codec: Arc::clone(&jwt_codec),
//! };
//!
//! // Build the router with state
//! let app: Router<AppState> = Router::new()
//!     .route("/login", post(login_handler))
//!     .route("/logout", post(logout_handler))
//!     .with_state(app_state);
//! ```
//!
//! # Security Features
//!
//! The login handler includes built-in timing attack protection:
//! - Constant-time credential verification using the `subtle` crate
//! - Always performs password hashing, even for non-existent users
//! - Unified error responses prevent user enumeration attacks
//! - Applied consistently across all storage backend implementations
pub use self::login::login;
pub use self::logout::logout;

mod login;
mod logout;
