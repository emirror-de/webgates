//! Authentication-category native errors.
//!
//! This module defines category-native errors for authentication (authn) flows
//! (login, logout, session renewal) used directly in handlers, services, and middleware.
//! It reuses the existing `AuthenticationError` variants as the leaf error kinds.
//!
//! # Overview
//!
//! - `AuthnError`: category-native error enum for authentication flows
//! - `AuthenticationError`: reused leaf error variants describing authn failures
//!
//! # Examples
//!
//! Basic construction and user-facing message extraction:
//!
//! ```rust
//! use axum_gate::authn::{AuthnError, AuthenticationError};
//! use axum_gate::errors::UserFriendlyError;
//!
//! let err = AuthnError::from_authentication(AuthenticationError::InvalidCredentials, Some("login form//! ".into()));
//! assert!(err.user_message().contains("username or password"));
//! assert!(err.developer_message().contains("Authentication failure"));
//! assert!(err.support_code().starts_with("AUTHN-"));
//! ```
//!
//! Convenience constructors:
//!
//! ```rust
//! use axum_gate::authn::AuthnError;
//!
//! let _ = AuthnError::invalid_credentials(Some("signin".into()));
//! ```

use crate::errors::{ErrorSeverity, UserFriendlyError};

use thiserror::Error;

/// Leaf authentication error variants reused by the authn category.
/// Specific authentication error types for authentication flows.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthenticationError {
    /// Invalid credentials provided
    #[error("Invalid credentials provided")]
    InvalidCredentials,
}

/// Category-native authentication error.
///
/// Wraps `AuthenticationError` and provides category-oriented constructors,
/// user-friendly messaging, support codes, severity, and retryability.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthnError {
    /// Authentication flow failure (e.g., invalid credentials, expired session).
    #[error("Authentication error: {error}")]
    Authentication {
        /// The specific authentication failure kind.
        #[source]
        error: AuthenticationError,
        /// Optional context about where/how the failure occurred (non-sensitive).
        context: Option<String>,
    },
}

impl AuthnError {
    /// Construct from a leaf `AuthenticationError` with optional context.
    pub fn from_authentication(error: AuthenticationError, context: Option<String>) -> Self {
        AuthnError::Authentication { error, context }
    }

    /// Invalid credentials were provided.
    pub fn invalid_credentials(context: Option<String>) -> Self {
        Self::from_authentication(AuthenticationError::InvalidCredentials, context)
    }

    fn support_code_inner(&self) -> String {
        match self {
            AuthnError::Authentication { error, .. } => match error {
                AuthenticationError::InvalidCredentials => "AUTHN-INVALID-CREDS".to_string(),
            },
        }
    }
}

impl UserFriendlyError for AuthnError {
    fn user_message(&self) -> String {
        match self {
            AuthnError::Authentication { error, .. } => match error {
                AuthenticationError::InvalidCredentials => {
                    "The username or password you entered is incorrect. Please check your credentials and try again.".to_string()
                }
            },
        }
    }

    fn developer_message(&self) -> String {
        match self {
            AuthnError::Authentication { error, context } => {
                let context_info = context
                    .as_ref()
                    .map(|c| format!(" Context: {}", c))
                    .unwrap_or_default();
                format!("Authentication failure: {}.{}", error, context_info)
            }
        }
    }

    fn support_code(&self) -> String {
        self.support_code_inner()
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            AuthnError::Authentication { error, .. } => match error {
                AuthenticationError::InvalidCredentials => ErrorSeverity::Warning,
            },
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            AuthnError::Authentication { error, .. } => match error {
                AuthenticationError::InvalidCredentials => vec![
                    "Double-check your username and password for typos".to_string(),
                    "Ensure Caps Lock is not accidentally enabled".to_string(),
                    "Use the 'Forgot Password' link if you can't remember your password"
                        .to_string(),
                    "Contact support if you're sure your credentials are correct".to_string(),
                ],
            },
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            AuthnError::Authentication { error, .. } => match error {
                AuthenticationError::InvalidCredentials => true,
            },
        }
    }
}
