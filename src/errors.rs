//! Unified, category-based error types exposed by this crate.
//!
//! This module contains error types you mostly need when using this crate:
//! - `Error`: root enum wrapping all category errors
//! - `Result<T>`: convenience alias
//! - `UserFriendlyError`: trait providing multiple message levels
//! - Category enums: `AccountsError`, `AuthnError`, `AuthzError`, `PermissionsError`,
//!   `CodecsError`, `JwtError`, `RepositoriesError`, `DatabaseError`, `HashingError`, `SecretError`
//!
//! # Error Message Levels
//! Each error provides three message levels for different audiences:
//! - **User Message**: Clear, actionable message for end users
//! - **Developer Message**: Technical details for debugging
//! - **Support Code**: Unique reference code for customer support
//!
//! # When to Use Each Variant
//! - `Accounts` – Account operations (create/update/delete/query/workflows/validation)
//! - `Authn` – Authentication flows (login/logout/session/MFA/rate-limits)
//! - `Authz` – Authorization issues (permission format, collisions, hierarchy violations)
//! - `Permissions` – Permission validation/collision concerns
//! - `Codecs` – Codec/serialization problems (encode/decode/serialize/deserialize/validate)
//! - `Jwt` – JWT processing (encode/decode/validate/refresh/revoke)
//! - `Repositories` – Repository contract/operation failures by repository type
//! - `Database` – Database driver/engine operation failures
//! - `Hashing` – Hashing/verification problems (hash/verify/generate_salt/update_hash)
//! - `Secrets` – Secret storage and verification (repo + hashing in secret flows)
//!
//! # Basic Example
//! ```rust
//! use axum_gate::errors::{Error, PermissionsError, Result, UserFriendlyError};
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
//! use axum_gate::errors::{Error, UserFriendlyError};
//!
//! fn handle_error(err: &Error) -> (String, String, String) {
//!     (
//!         err.user_message(),
//!         err.developer_message(),
//!         err.support_code()
//!     )
//! }
//! ```

use std::fmt;
use thiserror::Error;

// Category-based error re-exports for ergonomic imports.
pub use crate::accounts::errors::{AccountOperation, AccountsError};
pub use crate::authn::errors::{AuthenticationError, AuthnError};
pub use crate::authz::errors::AuthzError;
pub use crate::codecs::errors::{CodecOperation, CodecsError, JwtError, JwtOperation};
pub use crate::hashing::errors::{HashingError, HashingOperation};
pub use crate::permissions::errors::PermissionsError;
pub use crate::repositories::errors::{
    DatabaseError, DatabaseOperation, RepositoriesError, RepositoryOperation, RepositoryType,
};
pub use crate::secrets::errors::SecretError;

/// Re-export of OAuth2Error for ergonomic imports.
pub use crate::gate::oauth2::errors::OAuth2Error;
/// Trait providing user-friendly error messaging at multiple levels.
///
/// This trait ensures all errors provide appropriate messages for different
/// audiences while maintaining security and consistency.
/// Provides a consistent, multi-level error messaging interface across the crate.
///
/// Implementors must supply user-safe text via `user_message` and richer context
/// for logs and support via `developer_message` and `support_code`. The `severity`,
/// `suggested_actions`, and `is_retryable` methods help downstream handling and UX.
/// See each method for audience and usage guidance.
pub trait UserFriendlyError: fmt::Display + fmt::Debug {
    /// User-facing message that is clear, actionable, and non-technical.
    ///
    /// This message should:
    /// - Use plain language that any user can understand
    /// - Provide actionable guidance when possible
    /// - Never leak sensitive information
    /// - Be empathetic and helpful in tone
    ///
    /// # Examples
    /// - "We're experiencing technical difficulties. Please try again in a moment."
    /// - "Your session has expired. Please sign in again to continue."
    /// - "There's an issue with your account. Please contact our support team."
    fn user_message(&self) -> String;

    /// Technical message with detailed information for developers and logs.
    ///
    /// This message should:
    /// - Include precise technical details
    /// - Provide context for debugging
    /// - Include relevant identifiers and parameters
    /// - Be structured for parsing by monitoring tools
    fn developer_message(&self) -> String;

    /// Unique support reference code for customer service and troubleshooting.
    ///
    /// This code should:
    /// - Be unique and easily communicable
    /// - Allow support teams to identify the exact error
    /// - Not contain sensitive information
    /// - Be consistent across error instances
    fn support_code(&self) -> String;

    /// Error severity level for proper handling and alerting.
    fn severity(&self) -> ErrorSeverity;

    /// Suggested user actions for resolving the error.
    fn suggested_actions(&self) -> Vec<String> {
        Vec::new()
    }

    /// Whether this error should be retryable by the user.
    fn is_retryable(&self) -> bool {
        false
    }
}

/// Error severity levels for proper categorization and handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorSeverity {
    /// Critical system error requiring immediate attention
    Critical,
    /// Error that prevents normal operation
    Error,
    /// Warning that may indicate a problem
    Warning,
    /// Informational message about an expected condition
    Info,
}

/// Result type alias using our comprehensive Error type.
///
/// This provides a convenient way to return results from functions that can fail
/// with any of the layer-specific errors defined in this module.
///
/// # Examples
///
/// ```rust
/// use axum_gate::errors::{Result, Error, PermissionsError};
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

/// Root error type for the axum-gate library.
///
/// This enum represents all possible errors that can occur across different
/// architectural layers, providing a unified error handling interface while
/// maintaining clear separation of concerns.
///
/// Each error variant implements `UserFriendlyError` to provide appropriate
/// messaging for different audiences while maintaining security and consistency.
#[derive(Debug, Error)]
pub enum Error {
    /// Accounts category errors
    #[error(transparent)]
    Accounts(#[from] AccountsError),

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

    /// Repository category errors
    #[error(transparent)]
    Repositories(#[from] RepositoriesError),

    /// Database category errors
    #[error(transparent)]
    Database(#[from] DatabaseError),

    /// Hashing/verification category errors
    #[error(transparent)]
    Hashing(#[from] HashingError),

    /// Secret storage/category errors
    #[error(transparent)]
    Secrets(#[from] SecretError),

    /// OAuth2 flow errors
    #[error(transparent)]
    OAuth2(#[from] crate::gate::oauth2::errors::OAuth2Error),
}

impl UserFriendlyError for Error {
    fn user_message(&self) -> String {
        match self {
            Error::Accounts(err) => err.user_message(),
            Error::Authn(err) => err.user_message(),
            Error::Authz(err) => err.user_message(),
            Error::Permissions(err) => err.user_message(),
            Error::Codecs(err) => err.user_message(),
            Error::Jwt(err) => err.user_message(),
            Error::Repositories(err) => err.user_message(),
            Error::Database(err) => err.user_message(),
            Error::Hashing(err) => err.user_message(),
            Error::Secrets(err) => err.user_message(),
            Error::OAuth2(err) => err.user_message(),
        }
    }

    fn developer_message(&self) -> String {
        match self {
            Error::Accounts(err) => err.developer_message(),
            Error::Authn(err) => err.developer_message(),
            Error::Authz(err) => err.developer_message(),
            Error::Permissions(err) => err.developer_message(),
            Error::Codecs(err) => err.developer_message(),
            Error::Jwt(err) => err.developer_message(),
            Error::Repositories(err) => err.developer_message(),
            Error::Database(err) => err.developer_message(),
            Error::Hashing(err) => err.developer_message(),
            Error::Secrets(err) => err.developer_message(),
            Error::OAuth2(err) => err.developer_message(),
        }
    }

    fn support_code(&self) -> String {
        match self {
            Error::Accounts(err) => err.support_code(),
            Error::Authn(err) => err.support_code(),
            Error::Authz(err) => err.support_code(),
            Error::Permissions(err) => err.support_code(),
            Error::Codecs(err) => err.support_code(),
            Error::Jwt(err) => err.support_code(),
            Error::Repositories(err) => err.support_code(),
            Error::Database(err) => err.support_code(),
            Error::Hashing(err) => err.support_code(),
            Error::Secrets(err) => err.support_code(),
            Error::OAuth2(err) => err.support_code(),
        }
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            Error::Accounts(err) => err.severity(),
            Error::Authn(err) => err.severity(),
            Error::Authz(err) => err.severity(),
            Error::Permissions(err) => err.severity(),
            Error::Codecs(err) => err.severity(),
            Error::Jwt(err) => err.severity(),
            Error::Repositories(err) => err.severity(),
            Error::Database(err) => err.severity(),
            Error::Hashing(err) => err.severity(),
            Error::Secrets(err) => err.severity(),
            Error::OAuth2(err) => err.severity(),
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            Error::Accounts(err) => err.suggested_actions(),
            Error::Authn(err) => err.suggested_actions(),
            Error::Authz(err) => err.suggested_actions(),
            Error::Permissions(err) => err.suggested_actions(),
            Error::Codecs(err) => err.suggested_actions(),
            Error::Jwt(err) => err.suggested_actions(),
            Error::Repositories(err) => err.suggested_actions(),
            Error::Database(err) => err.suggested_actions(),
            Error::Hashing(err) => err.suggested_actions(),
            Error::Secrets(err) => err.suggested_actions(),
            Error::OAuth2(err) => err.suggested_actions(),
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            Error::Accounts(err) => err.is_retryable(),
            Error::Authn(err) => err.is_retryable(),
            Error::Authz(err) => err.is_retryable(),
            Error::Permissions(err) => err.is_retryable(),
            Error::Codecs(err) => err.is_retryable(),
            Error::Jwt(err) => err.is_retryable(),
            Error::Repositories(err) => err.is_retryable(),
            Error::Database(err) => err.is_retryable(),
            Error::Hashing(err) => err.is_retryable(),
            Error::Secrets(err) => err.is_retryable(),
            Error::OAuth2(err) => err.is_retryable(),
        }
    }
}

// External library error conversions
#[cfg(feature = "storage-surrealdb")]
impl From<surrealdb::Error> for Error {
    fn from(err: surrealdb::Error) -> Self {
        Error::Database(DatabaseError::with_context(
            DatabaseOperation::Query,
            format!("SurrealDB error: {}", err),
            None,
            None,
        ))
    }
}

// External library error conversions
impl From<argon2::Error> for Error {
    fn from(err: argon2::Error) -> Self {
        Error::Hashing(HashingError::with_context(
            HashingOperation::Hash,
            format!("Argon2 error: {}", err),
            Some("Argon2id".to_string()),
            None,
        ))
    }
}

// Map cookie template builder validation errors into the crate-wide Error type.
// We categorize these as codec/format issues since they reflect invalid configuration
// for building a Cookie (shape/format contract violation).
impl From<crate::cookie_template::CookieTemplateBuilderError> for Error {
    fn from(err: crate::cookie_template::CookieTemplateBuilderError) -> Self {
        Error::Codecs(CodecsError::codec_with_format(
            CodecOperation::Encode,
            format!("Invalid cookie template configuration: {}", err),
            Some("cookie::CookieBuilder".to_string()),
            Some("Invalid cookie settings".to_string()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::errors::{
        AccountOperation, AccountsError, AuthenticationError, AuthnError, AuthzError,
        CodecOperation, DatabaseError, DatabaseOperation, Error, ErrorSeverity, HashingOperation,
        JwtOperation, RepositoriesError, RepositoryOperation, RepositoryType, UserFriendlyError,
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
    fn database_error_query() {
        let error = Error::Database(DatabaseError::new(
            DatabaseOperation::Query,
            "Connection failed",
        ));

        // Test error structure
        match &error {
            Error::Database(DatabaseError::Operation {
                operation, message, ..
            }) => {
                matches!(operation, DatabaseOperation::Query);
                assert_eq!(*message, "Connection failed");
            }
            _ => panic!("Expected Database::Operation variant"),
        }

        // Test user-friendly messages
        assert!(error.user_message().contains("technical difficulties"));
        assert!(error.developer_message().contains("Database"));
        assert_eq!(error.severity(), ErrorSeverity::Error);
        assert!(error.is_retryable());
    }

    #[test]
    fn repositories_error_operation_failed() {
        let error = Error::Repositories(RepositoriesError::operation_failed(
            RepositoryType::Account,
            RepositoryOperation::Insert,
            "Insert failed",
            Some("user-123".into()),
            Some("insert_account".into()),
        ));

        // Test error structure
        match &error {
            Error::Repositories(RepositoriesError::OperationFailed {
                repository,
                operation,
                message,
                ..
            }) => {
                matches!(repository, RepositoryType::Account);
                matches!(operation, RepositoryOperation::Insert);
                assert_eq!(*message, "Insert failed");
            }
            _ => panic!("Expected Repositories::OperationFailed variant"),
        }

        // Test user-friendly messages
        assert!(error.user_message().contains("account information"));
        assert!(
            error
                .developer_message()
                .contains("Repository operation failed")
        );
        assert!(
            error.severity() == ErrorSeverity::Error || error.severity() == ErrorSeverity::Critical
        );
        assert!(error.is_retryable());
    }

    #[test]
    fn error_display() {
        let error = Error::Accounts(AccountsError::operation(
            AccountOperation::Create,
            "create failed",
            Some("acc-1".into()),
        ));
        let display = format!("{}", error);
        assert!(display.contains("Account operation"));

        // Test all message levels
        assert!(!error.user_message().is_empty());
        assert!(!error.developer_message().is_empty());
        assert!(!error.support_code().is_empty());
        assert!(!matches!(error.severity(), ErrorSeverity::Info));
    }

    #[test]
    fn operation_display() {
        assert_eq!(format!("{}", AccountOperation::Create), "create");
        assert_eq!(format!("{}", DatabaseOperation::Query), "query");
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
