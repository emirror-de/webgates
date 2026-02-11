//! Authentication services and workflows.
//!
//! This module provides core authentication services including login and logout
//! operations. These services handle the business logic for authenticating users
//! against credential repositories and generating authentication tokens.
//!
//! # Key Components
//!
//! - [`LoginService`] - Handles user credential verification and token generation
//! - [`LogoutService`] - Handles cleanup during user logout
//! - [`LoginResult`] - Represents the outcome of login attempts with detailed error handling
//!
//! # Usage
//!
//! These services are typically used internally by the route handlers in [`crate::route_handlers`],
//! but can be used directly for custom authentication flows:
//!
//! ```rust
//! use axum_gate::authn::{LoginService, LoginResult};
//! use axum_gate::accounts::Account;
//! use axum_gate::prelude::{Role, Group, Credentials};
//! use axum_gate::codecs::jwt::{JsonWebToken, JwtClaims, RegisteredClaims};
//! use axum_gate::repositories::memory::{MemoryAccountRepository, MemorySecretRepository};
//! use std::sync::Arc;
//!
//! # tokio_test::block_on(async {
//! let login_service = LoginService::<Role, Group>::new();
//! let credentials = Credentials::new(&"user@example.com".to_string(), "password");
//! let claims = RegisteredClaims::new("my-app",
//!     chrono::Utc::now().timestamp() as u64 + 3600);
//!
//! let secret_repo = Arc::new(MemorySecretRepository::new_with_argon2_hasher().unwrap());
//! let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
//! let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//!
//! let result = login_service.authenticate(
//!     credentials,
//!     claims,
//!     secret_repo,
//!     account_repo,
//!     jwt_codec,
//! ).await;
//!
//! match result {
//!     LoginResult::Success(token) => println!("Login successful"),
//!     LoginResult::InvalidCredentials { .. } => println!("Invalid credentials"),
//!     LoginResult::InternalError { .. } => println!("System error"),
//! }
//! # });
//! ```

mod login;
mod logout;

pub use login::{LoginResult, LoginService};
pub use logout::LogoutService;
pub mod errors;
pub use errors::{AuthenticationError, AuthnError};
