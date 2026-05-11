//! Authentication services and workflows.
//!
//! This module contains the higher-level login and logout orchestration for
//! `webgates`.
//!
//! Use it when you need more than gate configuration alone. These services help
//! you verify credentials, load accounts, issue tokens, and coordinate logout or
//! session revocation flows.
//!
//! The APIs in this module keep authentication orchestration framework-agnostic:
//!
//! - credential verification stays in service-level dependencies
//! - account lookup stays in repository traits
//! - auth-token issuance stays in codec-backed or session-backed issuers
//! - session issuance and revocation stay in `webgates::sessions`
//!
//! HTTP adapters such as `webgates-axum` should call these services and remain
//! responsible only for request parsing, cookie extraction, response mapping,
//! and cookie mutation.
//!
//! # Primary entry points
//!
//! - [`login::LoginService`] for direct auth-token login flows
//! - [`login::SessionLoginService`] for session-backed login flows
//! - [`logout::LogoutService`] for transport-level logout orchestration
//! - [`logout::SessionLogoutService`] for session revocation workflows
//! - [`login::LoginResult`] for direct login outcomes
//! - [`login::SessionLoginResult`] for session-backed login outcomes
//!
//! # When to use which service
//!
//! Use [`login::LoginService`] when you want a direct auth-token login flow
//! without server-side refresh-token session state.
//!
//! Use [`login::SessionLoginService`] when you want:
//!
//! - short-lived auth tokens
//! - long-lived refresh-token-backed sessions
//! - refresh-token rotation and replay-aware revocation
//! - transparent renewal through an adapter such as
//!   `webgates_axum::session::cookie_session_layer::CookieSessionLayer`
//!
//! Use [`logout::SessionLogoutService`] when logout should revoke either the
//! current session or the full session family instead of only clearing
//! transport-level cookies.
//!
//! # Examples
//!
//! These services are often called by adapter crates, but they can also be used
//! directly in custom application flows.
//!
//! Direct auth-token login example:
//!
//! ```rust
//! use webgates::authn::login::{LoginResult, LoginService};
//! use webgates::accounts::Account;
//! use webgates::codecs::jwt::{JsonWebToken, JwtClaims, RegisteredClaims};
//! use webgates::credentials::Credentials;
//! use webgates::groups::Group;
//! use webgates::roles::Role;
//! use webgates_repositories::memory::account::MemoryAccountRepository;
//! use webgates_repositories::memory::secret::MemorySecretRepository;
//! use std::sync::Arc;
//!
//! # tokio_test::block_on(async {
//! let login_service = LoginService::<Role, Group>::new();
//! let credentials = Credentials::new(&"user@example.com".to_string(), "password");
//! let claims = RegisteredClaims::new(
//!     "my-app",
//!     chrono::Utc::now().timestamp() as u64 + 900,
//! );
//!
//! let secret_repo = Arc::new(MemorySecretRepository::new_with_argon2_hasher().unwrap());
//! let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
//! let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//!
//! let result = login_service
//!     .authenticate(
//!         credentials,
//!         claims,
//!         secret_repo,
//!         account_repo,
//!         jwt_codec,
//!     )
//!     .await;
//!
//! match result {
//!     LoginResult::Success(token) => println!("Login successful"),
//!     LoginResult::InvalidCredentials { .. } => println!("Invalid credentials"),
//!     LoginResult::InternalError { .. } => println!("System error"),
//! }
//! # });
//! ```
//!
//! Session-backed login and revocation are exposed through
//! [`login::SessionLoginService`] and [`logout::SessionLogoutService`]. These services compose
//! with `webgates::sessions` repository contracts and are intended to sit below
//! HTTP adapters that write auth and refresh cookies.

/// Authentication-specific error types used by auth flows.
pub mod errors;
/// Login services and result types for direct-token and session-backed auth.
pub mod login;
/// Logout services for direct-token and session-backed authentication flows.
pub mod logout;
