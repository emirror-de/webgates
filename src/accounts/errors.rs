//! Account-category native errors.
//!
//! This module provides category-native error types for the Accounts domain,
//! used directly in handlers, services, and repositories.
//!
//! # Overview
//! - `AccountsError`: domain-specific error enum for account operations
//! - `AccountOperation`: operation discriminator used by `AccountsError`
//!
//! # Examples
//! Basic construction and user-facing message extraction:
//! ```rust
//! use axum_gate::accounts::{AccountsError, AccountOperation};
//! use axum_gate::errors::UserFriendlyError;
//!
//! let err = AccountsError::operation(
//!     AccountOperation::Create,
//!     "failed to persist account",
//!     Some("user-123".into()),
//! );
//!
//! assert!(err.user_message().contains("couldn't create your account"));
//! assert!(err.developer_message().contains("Account operation create failed"));
//! assert!(err.support_code().starts_with("ACCT-"));
//! ```

use crate::errors::{ErrorSeverity, UserFriendlyError};
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use thiserror::Error;

/// Supported account operations for structured error reporting.
#[derive(Debug, Clone)]
pub enum AccountOperation {
    /// Create account operation
    Create,
    /// Delete account operation
    Delete,
}

impl fmt::Display for AccountOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccountOperation::Create => write!(f, "create"),
            AccountOperation::Delete => write!(f, "delete"),
        }
    }
}

/// Accounts domain errors (category-native).
///
/// These errors cover account-related operation failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AccountsError {
    /// An account operation failed.
    #[error("Account operation {operation} failed: {message}")]
    Operation {
        /// The account operation that failed.
        operation: AccountOperation,
        /// Description of the failure (non-sensitive).
        message: String,
        /// Optional related account identifier (sanitized).
        account_id: Option<String>,
    },
}

impl AccountsError {
    /// Construct an operation failure.
    pub fn operation(
        operation: AccountOperation,
        message: impl Into<String>,
        account_id: Option<String>,
    ) -> Self {
        AccountsError::Operation {
            operation,
            message: message.into(),
            account_id,
        }
    }

    /// Deterministic, category-specific support code.
    fn support_code_inner(&self) -> String {
        let mut hasher = DefaultHasher::new();
        match self {
            AccountsError::Operation {
                operation,
                account_id,
                ..
            } => {
                format!("ACCT-OP-{}-{:X}", operation.to_string().to_uppercase(), {
                    format!("{:?}{:?}", operation, account_id).hash(&mut hasher);
                    hasher.finish() % 10000
                })
            }
        }
    }
}

impl UserFriendlyError for AccountsError {
    fn user_message(&self) -> String {
        match self {
            AccountsError::Operation { operation, .. } => match operation {
                AccountOperation::Create => "We couldn't create your account right now. Please try again in a moment, or contact our support team if the problem continues.".to_string(),
                AccountOperation::Delete => "We couldn't delete your account at this time. Please try again later, or contact our support team for assistance.".to_string(),
            },
        }
    }

    fn developer_message(&self) -> String {
        match self {
            AccountsError::Operation {
                operation,
                message,
                account_id,
            } => {
                let account_context = account_id
                    .as_ref()
                    .map(|id| format!(" [Account: {}]", id))
                    .unwrap_or_default();
                format!(
                    "Account operation {} failed: {}{}",
                    operation, message, account_context
                )
            }
        }
    }

    fn support_code(&self) -> String {
        self.support_code_inner()
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            AccountsError::Operation { operation, .. } => match operation {
                AccountOperation::Delete => ErrorSeverity::Critical,
                _ => ErrorSeverity::Error,
            },
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            AccountsError::Operation { operation, .. } => match operation {
                AccountOperation::Create => vec![
                    "Wait a moment and try creating your account again".to_string(),
                    "Ensure all required fields are filled out correctly".to_string(),
                    "Check your email for any verification requirements".to_string(),
                    "Contact our support team if the problem continues".to_string(),
                ],
                AccountOperation::Delete => vec![
                    "Contact our support team to assist with account deletion".to_string(),
                    "Ensure you have completed any required pre-deletion steps".to_string(),
                    "This operation may be temporarily unavailable for security reasons"
                        .to_string(),
                ],
            },
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            AccountsError::Operation { operation, .. } => {
                !matches!(operation, AccountOperation::Delete)
            }
        }
    }
}
