//! Secret-category native errors.
//!
//! Category-native error type for secret hashing and verification concerns.
//! Use these errors directly in handlers, services, and secret-management flows.
//!
//! # Overview
//! - `SecretError`: category-native error enum for hashing flows
//! - Uses `HashingOperation` for hashing context
//!
//! # Examples
//!
//! Hashing failure with algorithm context:
//! ```rust
//! use webgates_secrets::errors::SecretError;
//! use webgates_secrets::hashing::errors::HashingOperation;
//!
//! let err = SecretError::hashing_with_algorithm(
//!     HashingOperation::Verify,
//!     "password verification failed",
//!     "argon2id",
//! );
//! ```

use crate::hashing::errors::HashingOperation;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use thiserror::Error;
use webgates_core::errors_core::{ErrorSeverity, UserFriendlyError};

/// Secret-category native errors.
///
/// Use for secret repository and hashing/verification flows.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SecretError {
    /// Hashing/verification error in secret flow.
    #[error("Secret hashing error: {operation} - {message}")]
    Hashing {
        /// The hashing operation that failed.
        operation: HashingOperation,
        /// Description of the failure (non-sensitive).
        message: String,
        /// The hashing algorithm used (e.g., `argon2id`) if known.
        algorithm: Option<String>,
        /// Expected hash format (sanitized) if relevant.
        expected_format: Option<String>,
    },
}

impl SecretError {
    /// Construct a hashing error with algorithm context.
    pub fn hashing_with_algorithm(
        operation: HashingOperation,
        message: impl Into<String>,
        algorithm: impl Into<String>,
    ) -> Self {
        SecretError::Hashing {
            operation,
            message: message.into(),
            algorithm: Some(algorithm.into()),
            expected_format: None,
        }
    }

    /// Construct a hashing error with full context.
    pub fn hashing_with_context(
        operation: HashingOperation,
        message: impl Into<String>,
        algorithm: Option<String>,
        expected_format: Option<String>,
    ) -> Self {
        SecretError::Hashing {
            operation,
            message: message.into(),
            algorithm,
            expected_format,
        }
    }

    fn support_code_inner(&self) -> String {
        let mut hasher = DefaultHasher::new();
        match self {
            SecretError::Hashing {
                operation,
                algorithm,
                ..
            } => {
                format!("SECR-HASH-{}-{:X}", operation.to_string().to_uppercase(), {
                    format!("{:?}{:?}", operation, algorithm).hash(&mut hasher);
                    hasher.finish() % 10000
                })
            }
        }
    }
}

impl UserFriendlyError for SecretError {
    fn user_message(&self) -> String {
        match self {
            SecretError::Hashing { operation, .. } => match operation {
                HashingOperation::Hash => {
                    "There's an issue with the security processing system. Please try again in a moment.".to_string()
                }
                HashingOperation::Verify => {
                    "We couldn't verify your credentials due to a technical issue. Please try signing in again.".to_string()
                }
            },
        }
    }

    fn developer_message(&self) -> String {
        match self {
            SecretError::Hashing {
                operation,
                message,
                algorithm,
                expected_format,
            } => {
                let algo_s = algorithm
                    .as_ref()
                    .map(|a| format!(" [Algorithm: {}]", a))
                    .unwrap_or_default();
                let exp_s = expected_format
                    .as_ref()
                    .map(|e| format!(" [Expected: {}]", e))
                    .unwrap_or_default();
                format!(
                    "Secret hashing {} failed: {}{}{}",
                    operation, message, algo_s, exp_s
                )
            }
        }
    }

    fn support_code(&self) -> String {
        self.support_code_inner()
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            SecretError::Hashing { .. } => ErrorSeverity::Critical,
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            SecretError::Hashing { operation, .. } => match operation {
                HashingOperation::Hash => vec![
                    "This is a critical security system error".to_string(),
                    "Contact our support team immediately".to_string(),
                    "Do not retry operations that involve password or secret changes".to_string(),
                ],
                HashingOperation::Verify => vec![
                    "Double-check your password for typos".to_string(),
                    "Ensure Caps Lock is not accidentally enabled".to_string(),
                    "If you're certain your password is correct, contact support".to_string(),
                    "Try using password recovery if verification continues to fail".to_string(),
                ],
            },
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            SecretError::Hashing { operation, .. } => match operation {
                HashingOperation::Hash => false,
                HashingOperation::Verify => true,
            },
        }
    }
}
