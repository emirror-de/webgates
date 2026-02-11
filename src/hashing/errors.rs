//! Hashing-category native errors.
//!
//! This module defines category-native error types for hashing and verification,
//! used directly in handlers, services, and middleware for hashing,
//! password verification, and secret management flows.
//!
//! # Overview
//!
//! - `HashingError`: category-native error enum for hashing/verification
//! - `HashingOperation`: operation discriminator used by `HashingError`
//!
//! # Examples
//!
//! Construct a hashing error with algorithm context:
//! ```rust
//! use axum_gate::hashing::{HashingError, HashingOperation};
//!
//! let err = HashingError::with_algorithm(
//!     HashingOperation::Hash,
//!     "argon2 hashing failed",
//!     "argon2id",
//! );
//!
//! // Utility methods from the unified trait
//! use axum_gate::errors::UserFriendlyError;
//! assert!(err.user_message().contains("security processing system"));
//! assert!(err.developer_message().contains("Hash operation hash failed"));
//! assert!(err.support_code().starts_with("HASH-HASH"));
//! ```
//!
//! Construct a verification failure where retry is possible:
//! ```rust
//! use axum_gate::hashing::{HashingError, HashingOperation};
//! use axum_gate::errors::UserFriendlyError;
//!
//! let err = HashingError::with_context(
//!     HashingOperation::Verify,
//!     "password verification failed",
//!     Some("argon2id".into()),
//!     Some("$argon2id$v=19$...".into()),
//! );
//! assert!(err.is_retryable());
//! ```

use crate::errors::{ErrorSeverity, UserFriendlyError};
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use thiserror::Error;

/// Hashing operation identifiers used for structured error reporting.
#[derive(Debug, Clone)]
pub enum HashingOperation {
    /// Compute a new hash for a provided plaintext value.
    Hash,
    /// Verify a plaintext value against an existing hash.
    Verify,
}

impl fmt::Display for HashingOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashingOperation::Hash => write!(f, "hash"),
            HashingOperation::Verify => write!(f, "verify"),
        }
    }
}

/// Hashing-category native errors (hashing and verification).
///
/// Use these errors in hashing services, verification flows, and password/secret updates.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HashingError {
    /// A hashing-related operation failed.
    #[error("Hashing error: {operation} - {message}")]
    Operation {
        /// The hashing operation that failed.
        operation: HashingOperation,
        /// Description of the error (non-sensitive).
        message: String,
        /// The hashing algorithm used (e.g., `argon2id`, `bcrypt`) if known.
        algorithm: Option<String>,
        /// Expected hash format (sanitized) if relevant.
        expected_format: Option<String>,
    },
}

impl HashingError {
    /// Construct a hashing error without algorithm/format context.
    ///
    /// # Arguments
    /// - `operation`: The hashing operation that failed.
    /// - `message`: A non-sensitive description of the error.
    ///
    /// # Examples
    /// ```rust
    /// use axum_gate::hashing::{HashingError, HashingOperation};
    /// let _err = HashingError::new(HashingOperation::Hash, "failed to hash value");
    /// ```
    pub fn new(operation: HashingOperation, message: impl Into<String>) -> Self {
        HashingError::Operation {
            operation,
            message: message.into(),
            algorithm: None,
            expected_format: None,
        }
    }

    /// Construct a hashing error with algorithm context.
    ///
    /// # Arguments
    /// - `operation`: The hashing operation that failed.
    /// - `message`: A non-sensitive description of the error.
    /// - `algorithm`: The hashing algorithm (e.g., `argon2id`).
    ///
    /// # Examples
    /// ```rust
    /// use axum_gate::hashing::{HashingError, HashingOperation};
    /// let _err = HashingError::with_algorithm(HashingOperation::Verify, "verification failed", "argon2id");
    /// ```
    pub fn with_algorithm(
        operation: HashingOperation,
        message: impl Into<String>,
        algorithm: impl Into<String>,
    ) -> Self {
        HashingError::Operation {
            operation,
            message: message.into(),
            algorithm: Some(algorithm.into()),
            expected_format: None,
        }
    }

    /// Construct a hashing error with full context.
    ///
    /// # Arguments
    /// - `operation`: The hashing operation that failed.
    /// - `message`: A non-sensitive description of the error.
    /// - `algorithm`: The hashing algorithm (e.g., `argon2id`), if known.
    /// - `expected_format`: Expected hash format (sanitized), if relevant.
    ///
    /// # Examples
    /// ```rust
    /// use axum_gate::hashing::{HashingError, HashingOperation};
    /// let _err = HashingError::with_context(
    ///     HashingOperation::Verify,
    ///     "verification failed",
    ///     Some("argon2id".into()),
    ///     Some("$argon2id$v=19$...".into()),
    /// );
    /// ```
    pub fn with_context(
        operation: HashingOperation,
        message: impl Into<String>,
        algorithm: Option<String>,
        expected_format: Option<String>,
    ) -> Self {
        HashingError::Operation {
            operation,
            message: message.into(),
            algorithm,
            expected_format,
        }
    }

    /// Deterministic, category-specific support code for this error.
    fn support_code_inner(&self) -> String {
        let mut hasher = DefaultHasher::new();
        match self {
            HashingError::Operation {
                operation,
                algorithm,
                ..
            } => {
                format!("HASH-{}-{:X}", operation.to_string().to_uppercase(), {
                    format!("{:?}{:?}", operation, algorithm).hash(&mut hasher);
                    hasher.finish() % 10000
                })
            }
        }
    }
}

impl UserFriendlyError for HashingError {
    fn user_message(&self) -> String {
        match self {
            HashingError::Operation { operation, .. } => match operation {
                HashingOperation::Hash => {
                    "There's an issue with the security processing system. Please try again in a moment."
                        .to_string()
                }
                HashingOperation::Verify => {
                    "We couldn't verify your credentials due to a technical issue. Please try signing in again."
                        .to_string()
                }
            },
        }
    }

    fn developer_message(&self) -> String {
        match self {
            HashingError::Operation {
                operation,
                message,
                algorithm,
                expected_format,
            } => {
                let algorithm_context = algorithm
                    .as_ref()
                    .map(|a| format!(" [Algorithm: {}]", a))
                    .unwrap_or_default();
                let format_context = expected_format
                    .as_ref()
                    .map(|ef| format!(" [Expected: {}]", ef))
                    .unwrap_or_default();
                format!(
                    "Hash operation {} failed: {}{}{}",
                    operation, message, algorithm_context, format_context
                )
            }
        }
    }

    fn support_code(&self) -> String {
        self.support_code_inner()
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            HashingError::Operation { operation, .. } => match operation {
                HashingOperation::Hash => ErrorSeverity::Critical,
                HashingOperation::Verify => ErrorSeverity::Critical,
            },
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            HashingError::Operation { operation, .. } => match operation {
                HashingOperation::Hash => vec![
                    "This is a critical security system error".to_string(),
                    "Contact our support team immediately".to_string(),
                    "Do not retry operations that involve password or secret changes".to_string(),
                    "Use secure communication when reporting this issue".to_string(),
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
            HashingError::Operation { operation, .. } => match operation {
                HashingOperation::Hash => false,  // critical system condition
                HashingOperation::Verify => true, // user can retry with correct credentials
            },
        }
    }
}
