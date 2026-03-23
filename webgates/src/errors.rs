//! Unified, category-based error types exposed by this crate.
//!
//! This module contains error types you mostly need when using this crate:
//! - `Error`: root enum wrapping all category errors
//! - `Result<T>`: convenience alias
//! - `UserFriendlyError`: trait providing multiple message levels
//! - Category enums: `AuthnError`, `AuthzError`, `PermissionsError`,
//!   `CodecsError`, `JwtError`, `HashingError`, `SecretError`
//!
//! # Error Message Levels
//! Each error provides three message levels for different audiences:
//! - **User Message**: Clear, actionable message for end users
//! - **Developer Message**: Technical details for debugging
//! - **Support Code**: Unique reference code for customer support
//!
//! # When to Use Each Variant
//! - `Authn` – Authentication flows (login/logout/session/MFA/rate-limits)
//! - `Authz` – Authorization issues (permission format, collisions, hierarchy violations)
//! - `Permissions` – Permission validation/collision concerns
//! - `Codecs` – Codec/serialization problems (encode/decode/serialize/deserialize/validate)
//! - `Jwt` – JWT processing (encode/decode/validate/refresh/revoke)

//! - `Hashing` – Hashing/verification problems (hash/verify/generate_salt/update_hash)
//! - `Secrets` – Secret storage and verification (repo + hashing in secret flows)
//!
//! # Basic Example
//! ```rust
//! use webgates::errors::{Error, PermissionsError, Result, UserFriendlyError};
//!
//! fn do_permission_check(flag: bool) -> Result<()> {
//!     if !flag {
//!         let error = Error::Permissions(
//!             PermissionsError::collision(42, vec!["read:alpha".into(), "read:beta".into()])
//!         );
//!         println!("User sees: {}", error.user_message());
//!         println!("Developer sees: {}", error.developer_message());
//!         return Err(error);
//!     }
//!     Ok(())
//! }
//! ```
//!
//! # Error Handling
//! ```rust
//! use webgates::errors::{Error, UserFriendlyError};
//!
//! fn handle_error(err: &Error) -> (String, String, String) {
//!     (
//!         err.user_message(),
//!         err.developer_message(),
//!         err.support_code()
//!     )
//! }
//! ```

use thiserror::Error;

// Core error interfaces (trait + severity)
pub use crate::errors_core::{ErrorSeverity, UserFriendlyError};

// Category-based error re-exports for ergonomic imports.
pub use crate::authn::{AuthenticationError, AuthnError};
pub use crate::authz::AuthzError;
pub use crate::codecs::errors::{CodecOperation, CodecsError, JwtError, JwtOperation};
pub use crate::permissions::PermissionsError;
pub use crate::secrets::errors::SecretError;
pub use crate::secrets::hashing::errors::{HashingError, HashingOperation};

/// Result type alias using our comprehensive Error type.
///
/// This provides a convenient way to return results from functions that can fail
/// with any of the layer-specific errors defined in this module.
///
/// # Examples
///
/// ```rust
/// use webgates::errors::{Result, Error, PermissionsError};
///
/// fn validate_account(user_id: &str) -> Result<()> {
///     if user_id.is_empty() {
///         return Err(Error::Permissions(PermissionsError::collision(
///             12345,
///             vec!["invalid".to_string()]
///         )));
///     }
///     Ok(())
/// }
/// ```
pub type Result<T> = std::result::Result<T, Error>;

/// Root error type for the webgates library.
///
/// This enum represents all possible errors that can occur across different
/// architectural layers, providing a unified error handling interface while
/// maintaining clear separation of concerns.
///
/// Each error variant implements `UserFriendlyError` to provide appropriate
/// messaging for different audiences while maintaining security and consistency.
#[derive(Debug, Error)]
pub enum Error {
    /// Authentication category errors
    #[error(transparent)]
    Authn(#[from] AuthnError),

    /// Authorization category errors
    #[error(transparent)]
    Authz(#[from] AuthzError),

    /// Permissions category errors
    #[error(transparent)]
    Permissions(#[from] PermissionsError),

    /// Codec/serialization category errors
    #[error(transparent)]
    Codecs(#[from] CodecsError),

    /// JWT processing category errors
    #[error(transparent)]
    Jwt(#[from] JwtError),

    /// Hashing/verification category errors
    #[error(transparent)]
    Hashing(#[from] HashingError),

    /// Secret storage/category errors
    #[error(transparent)]
    Secrets(#[from] SecretError),
}

impl UserFriendlyError for Error {
    fn user_message(&self) -> String {
        match self {
            Error::Authn(err) => err.user_message(),
            Error::Authz(err) => err.user_message(),
            Error::Permissions(err) => err.user_message(),
            Error::Codecs(err) => err.user_message(),
            Error::Jwt(err) => err.user_message(),
            Error::Hashing(err) => err.user_message(),
            Error::Secrets(err) => err.user_message(),
        }
    }

    fn developer_message(&self) -> String {
        match self {
            Error::Authn(err) => err.developer_message(),
            Error::Authz(err) => err.developer_message(),
            Error::Permissions(err) => err.developer_message(),
            Error::Codecs(err) => err.developer_message(),
            Error::Jwt(err) => err.developer_message(),
            Error::Hashing(err) => err.developer_message(),
            Error::Secrets(err) => err.developer_message(),
        }
    }

    fn support_code(&self) -> String {
        match self {
            Error::Authn(err) => err.support_code(),
            Error::Authz(err) => err.support_code(),
            Error::Permissions(err) => err.support_code(),
            Error::Codecs(err) => err.support_code(),
            Error::Jwt(err) => err.support_code(),
            Error::Hashing(err) => err.support_code(),
            Error::Secrets(err) => err.support_code(),
        }
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            Error::Authn(err) => err.severity(),
            Error::Authz(err) => err.severity(),
            Error::Permissions(err) => err.severity(),
            Error::Codecs(err) => err.severity(),
            Error::Jwt(err) => err.severity(),
            Error::Hashing(err) => err.severity(),
            Error::Secrets(err) => err.severity(),
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            Error::Authn(err) => err.suggested_actions(),
            Error::Authz(err) => err.suggested_actions(),
            Error::Permissions(err) => err.suggested_actions(),
            Error::Codecs(err) => err.suggested_actions(),
            Error::Jwt(err) => err.suggested_actions(),
            Error::Hashing(err) => err.suggested_actions(),
            Error::Secrets(err) => err.suggested_actions(),
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            Error::Authn(err) => err.is_retryable(),
            Error::Authz(err) => err.is_retryable(),
            Error::Permissions(err) => err.is_retryable(),
            Error::Codecs(err) => err.is_retryable(),
            Error::Jwt(err) => err.is_retryable(),
            Error::Hashing(err) => err.is_retryable(),
            Error::Secrets(err) => err.is_retryable(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::errors::{
        AuthenticationError, AuthnError, AuthzError, CodecOperation, Error, ErrorSeverity,
        HashingOperation, JwtOperation, UserFriendlyError,
    };

    #[test]
    fn authz_error_permission_collision() {
        let permissions = vec!["read:file".to_string(), "write:file".to_string()];
        let error = Error::Authz(AuthzError::collision(123u64, permissions.clone()));

        // Test error structure
        match &error {
            Error::Authz(AuthzError::PermissionCollision {
                collision_count,
                hash_id,
                permissions: perms,
            }) => {
                assert_eq!(*collision_count, 2);
                assert_eq!(*hash_id, 123u64);
                assert_eq!(*perms, permissions);
            }
            _ => panic!("Expected PermissionCollision variant"),
        }

        // Test user-friendly messages
        assert!(error.user_message().contains("technical issue"));
        assert!(error.developer_message().contains("Permission collision"));
        assert!(error.support_code().starts_with("AUTHZ-PERM-COLLISION-"));
        assert_eq!(error.severity(), ErrorSeverity::Critical);
        assert!(!error.suggested_actions().is_empty());
    }

    #[test]
    fn authn_error_authentication() {
        let auth_error = AuthenticationError::InvalidCredentials;
        let error = Error::Authn(AuthnError::from_authentication(
            auth_error,
            Some("test context".to_string()),
        ));

        // Test error structure
        match &error {
            Error::Authn(AuthnError::Authentication { error, context }) => {
                matches!(error, AuthenticationError::InvalidCredentials);
                assert_eq!(*context, Some("test context".to_string()));
            }
            _ => panic!("Expected Authn::Authentication variant"),
        }

        // Test user-friendly messages
        assert!(error.user_message().contains("username or password"));
        assert!(error.developer_message().contains("Invalid credentials"));
        assert_eq!(error.severity(), ErrorSeverity::Warning);
        assert!(
            error
                .suggested_actions()
                .iter()
                .any(|action| action.contains("username") || action.contains("password"))
        );
    }

    #[test]
    fn operation_display() {
        assert_eq!(format!("{}", JwtOperation::Encode), "encode");
        assert_eq!(format!("{}", CodecOperation::Decode), "decode");
        assert_eq!(format!("{}", HashingOperation::Verify), "verify");
    }

    #[test]
    fn error_severity_levels() {
        let authz_error = Error::Authz(AuthzError::collision(123, vec!["test".to_string()]));
        assert_eq!(authz_error.severity(), ErrorSeverity::Critical);

        // Test that all severity levels work
        assert_ne!(ErrorSeverity::Critical, ErrorSeverity::Error);
        assert_ne!(ErrorSeverity::Error, ErrorSeverity::Warning);
        assert_ne!(ErrorSeverity::Warning, ErrorSeverity::Info);
    }

    #[test]
    fn error_support_codes_are_unique() {
        let authz_error = Error::Authz(AuthzError::collision(123, vec!["test".to_string()]));
        let authn_error = Error::Authn(AuthnError::invalid_credentials(None));

        assert_ne!(authz_error.support_code(), authn_error.support_code());
        assert!(authz_error.support_code().starts_with("AUTHZ-"));
        assert!(authn_error.support_code().starts_with("AUTHN-"));
    }

    #[test]
    fn error_suggested_actions() {
        let error = Error::Authn(AuthnError::invalid_credentials(None));
        let actions = error.suggested_actions();
        assert!(!actions.is_empty());
        assert!(actions.iter().any(|action| action.contains("username")
            || action.contains("password")
            || action.contains("check")));
    }
}
