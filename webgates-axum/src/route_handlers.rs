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
//! use webgates_axum::route_handlers::{login, logout};
//! use webgates::prelude::{Role, Group, Credentials, Account};
//! use webgates::codecs::jwt::{RegisteredClaims, JsonWebToken, JwtClaims};
//! use webgates_repositories::memory::{MemorySecretRepository, MemoryAccountRepository};
//! use axum_extra::extract::CookieJar;
//! use std::sync::Arc;
//!
//! type AppJwtCodec = JsonWebToken<JwtClaims<Account<Role, Group>>>;
//!
//! #[derive(Clone)]
//! struct AppState {
//!     account_repo: Arc<webgates_repositories::memory::MemoryAccountRepository<Role, Group>>,
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
//!     let cookie_template = webgates::cookie_template::CookieTemplate::recommended()
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
//!     let cookie_template = webgates::cookie_template::CookieTemplate::recommended().name("auth-token");
//!     logout(cookie_jar, cookie_template).await
//! }
//!
//! // Instantiate repositories and JWT codec for the example
//! let account_repo = Arc::new(webgates_repositories::memory::MemoryAccountRepository::<Role, Group>::default());
//! let secret_repo = Arc::new(webgates_repositories::memory::MemorySecretRepository::new_with_argon2_hasher().unwrap());
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
//! Security properties (constant-time verification, dummy hashing, enumeration resistance)
//! are provided by the core `webgates` login service and credential verification backends.
//! This adapter simply wires HTTP requests to those services without adding cryptographic logic.
pub use self::login::login;
pub use self::logout::logout;

mod login;
mod logout;
