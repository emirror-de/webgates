//! Axum route handlers for login and logout flows.
//!
//! This module exposes two public submodules that contain handler functions and
//! their required input types for both cookie-only and session-backed
//! authentication flows.
//!
//! The handlers are thin Axum adapters around the framework-agnostic services in
//! `webgates`. They do not implement authentication logic themselves. Credential
//! verification, account lookup, token creation, session issuance, and logout
//! semantics remain owned by the core crates.
//!
//! # Public API
//!
//! - [`login`] --- handlers and input types for cookie-only and session-backed
//!   login flows:
//!   - [`login::login`] --- cookie-only login handler
//!   - [`login::login_with_sessions`] --- session-backed login handler
//!   - [`login::SessionLoginRequest`] --- input struct for
//!     [`login::login_with_sessions`]
//!   - [`login::SessionLoginDependencies`] --- dependency struct for
//!     [`login::login_with_sessions`]
//!
//! - [`logout`] --- handlers for cookie-only and session-backed logout flows:
//!   - [`logout::logout`] --- cookie-only logout handler
//!   - [`logout::logout_with_sessions`] --- session-backed logout handler
//!
//! # Typical usage
//!
//! Mount your own HTTP routes and call these handlers from your Axum handlers so
//! you can keep request parsing, state extraction, and response mapping explicit.
//!
//! ```rust
//! use std::sync::Arc;
//!
//! use axum::{Json, Router, extract::State, routing::post};
//! use axum_extra::extract::CookieJar;
//! use webgates::codecs::jwt::{JsonWebToken, JwtClaims, RegisteredClaims};
//! use webgates::cookie_template::CookieTemplate;
//! use webgates::accounts::Account;
//! use webgates::credentials::Credentials;
//! use webgates::groups::Group;
//! use webgates::roles::Role;
//! use webgates_axum::route_handlers::login::login;
//! use webgates_axum::route_handlers::logout::logout;
//! use webgates_repositories::memory::account::MemoryAccountRepository;
//! use webgates_repositories::memory::secret::MemorySecretRepository;
//!
//! type AppJwtCodec = JsonWebToken<JwtClaims<Account<Role, Group>>>;
//!
//! #[derive(Clone)]
//! struct AppState {
//!     account_repo: Arc<MemoryAccountRepository<Role, Group>>,
//!     secret_repo: Arc<MemorySecretRepository>,
//!     jwt_codec: Arc<AppJwtCodec>,
//!     cookie_template: CookieTemplate,
//! }
//!
//! async fn login_handler(
//!     State(state): State<AppState>,
//!     cookie_jar: CookieJar,
//!     Json(credentials): Json<Credentials<String>>,
//! ) -> Result<CookieJar, axum::http::StatusCode> {
//!     let claims = RegisteredClaims::new(
//!         "my-app",
//!         chrono::Utc::now().timestamp() as u64 + 3600,
//!     );
//!
//!     login(
//!         cookie_jar,
//!         credentials,
//!         claims,
//!         Arc::clone(&state.secret_repo),
//!         Arc::clone(&state.account_repo),
//!         Arc::clone(&state.jwt_codec),
//!         state.cookie_template.clone(),
//!     )
//!     .await
//! }
//!
//! async fn logout_handler(
//!     State(state): State<AppState>,
//!     cookie_jar: CookieJar,
//! ) -> CookieJar {
//!     logout(cookie_jar, state.cookie_template.clone()).await
//! }
//!
//! let app_state = AppState {
//!     account_repo: Arc::new(MemoryAccountRepository::<Role, Group>::default()),
//!     secret_repo: Arc::new(MemorySecretRepository::new_with_argon2_hasher().unwrap()),
//!     jwt_codec: Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default()),
//!     cookie_template: CookieTemplate::recommended().name("auth-token"),
//! };
//!
//! let _app: Router<AppState> = Router::new()
//!     .route("/login", post(login_handler))
//!     .route("/logout", post(logout_handler))
//!     .with_state(app_state);
//! ```
//!
//! # Security
//!
//! Security-sensitive behavior such as constant-time secret verification,
//! enumeration resistance, and JWT issuance is provided by the underlying
//! `webgates` services and repositories. This module is only the HTTP adapter.

/// Login handlers and required input types for cookie-only and session-backed
/// authentication flows.
pub mod login;

/// Logout handlers for cookie-only and session-backed authentication flows.
pub mod logout;
