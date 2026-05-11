//! Authentication-specific error types.
//!
//! This module defines the authentication error surface used by login, logout,
//! and session-renewal workflows.
//!
//! [`AuthenticationError`] models leaf authentication failures.
//! [`AuthnError`] wraps those failures with category-level messaging for users,
//! developers, and support tooling.
//!
//! # Examples
//!
//! Basic construction and user-facing message extraction:
//!
//! ```rust
//! use webgates::authn::errors::{AuthenticationError, AuthnError};
//! use webgates::errors_core::UserFriendlyError;
//!
//! let err = AuthnError::from_authentication(
//!     AuthenticationError::InvalidCredentials,
//!     Some("login form".into()),
//! );
//! assert!(err.user_message().contains("username or password"));
//! assert!(err.developer_message().contains("Authentication failure"));
//! assert!(err.support_code().starts_with("AUTHN-"));
//! ```
//!
//! Convenience constructor:
//!
//! ```rust
//! use webgates::authn::errors::AuthnError;
//!
//! let _ = AuthnError::invalid_credentials(Some("signin".into()));
//! ```

use crate::errors_core::{ErrorSeverity, UserFriendlyError};

use thiserror::Error;

/// Leaf authentication error variants reused by [`AuthnError`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthenticationError {
    /// Invalid credentials were provided.
    #[error("Invalid credentials provided")]
    InvalidCredentials,
}

/// Category-level authentication error.
///
/// This type wraps [`AuthenticationError`] and adds user-facing messaging,
/// developer-facing detail, support codes, severity, and retryability.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthnError {
    /// Authentication flow failure, such as invalid credentials.
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
    /// Creates an `AuthnError` from a leaf authentication error and optional context.
    pub fn from_authentication(error: AuthenticationError, context: Option<String>) -> Self {
        AuthnError::Authentication { error, context }
    }

    /// Creates an invalid-credentials error.
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
