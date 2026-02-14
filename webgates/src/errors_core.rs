//! Core error interfaces shared across the crate.
//!
//! This module defines:
//! - `ErrorSeverity`: common severity levels
//! - `UserFriendlyError`: trait for multi-level messaging
//! - `Result<T, E = Box<dyn std::error::Error + Send + Sync>>`: lightweight alias for pure/core layers
//!
//! The goal is to keep this module free of downstream dependencies so other
//! modules can depend on it without creating cycles. Integration-specific
//! mappings (e.g., HTTP/serde/logging) should live in higher layers.

use std::fmt;

/// Error severity levels for proper categorization and handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorSeverity {
    /// Critical system error requiring immediate attention.
    Critical,
    /// Error that prevents normal operation.
    Error,
    /// Warning that may indicate a problem.
    Warning,
    /// Informational message about an expected condition.
    Info,
}

/// Trait providing user-friendly error messaging at multiple levels.
///
/// Implementors must supply user-safe text via `user_message` and richer context
/// for logs and support via `developer_message` and `support_code`. The
/// `severity`, `suggested_actions`, and `is_retryable` methods help downstream
/// handling and UX.
///
/// This trait is intentionally minimal and does not depend on integration
/// layers, keeping it usable in core/domain code.
pub trait UserFriendlyError: fmt::Display + fmt::Debug {
    /// User-facing message that is clear, actionable, and non-technical.
    ///
    /// Guidelines:
    /// - Plain language any user can understand
    /// - Actionable guidance when possible
    /// - Never leak sensitive information
    /// - Empathetic and helpful tone
    fn user_message(&self) -> String;

    /// Technical message with detailed information for developers and logs.
    ///
    /// Guidelines:
    /// - Precise technical details and context for debugging
    /// - Include relevant identifiers and parameters
    /// - Structured for parsing by monitoring tools
    fn developer_message(&self) -> String;

    /// Unique support reference code for customer service and troubleshooting.
    ///
    /// Guidelines:
    /// - Unique and easily communicable
    /// - No sensitive information
    /// - Consistent across error instances
    fn support_code(&self) -> String;

    /// Error severity level for proper handling and alerting.
    fn severity(&self) -> ErrorSeverity;

    /// Suggested user actions for resolving the error (optional).
    fn suggested_actions(&self) -> Vec<String> {
        Vec::new()
    }

    /// Whether this error should be retryable by the user (default: false).
    fn is_retryable(&self) -> bool {
        false
    }
}

/// Lightweight result alias for core layers.
///
/// This keeps the alias free of crate-specific error enums to avoid creating
/// dependency cycles. Higher layers can define richer aliases as needed.
pub type Result<T, E = Box<dyn std::error::Error + Send + Sync>> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::{ErrorSeverity, UserFriendlyError};

    #[derive(Debug)]
    struct DemoError;

    impl std::fmt::Display for DemoError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "demo error")
        }
    }

    impl UserFriendlyError for DemoError {
        fn user_message(&self) -> String {
            "Something went wrong. Please try again.".to_string()
        }

        fn developer_message(&self) -> String {
            "DemoError: example developer message".to_string()
        }

        fn support_code(&self) -> String {
            "DEMO-0001".to_string()
        }

        fn severity(&self) -> ErrorSeverity {
            ErrorSeverity::Error
        }

        fn suggested_actions(&self) -> Vec<String> {
            vec!["Retry the operation".to_string()]
        }

        fn is_retryable(&self) -> bool {
            true
        }
    }

    #[test]
    fn demo_error_behaves() {
        let err = DemoError;
        assert_eq!(
            err.user_message(),
            "Something went wrong. Please try again."
        );
        assert!(err.developer_message().contains("DemoError"));
        assert_eq!(err.support_code(), "DEMO-0001");
        assert_eq!(err.severity(), ErrorSeverity::Error);
        assert_eq!(
            err.suggested_actions(),
            vec!["Retry the operation".to_string()]
        );
        assert!(err.is_retryable());
    }

    #[test]
    fn severity_variants() {
        assert_ne!(ErrorSeverity::Critical, ErrorSeverity::Error);
        assert_ne!(ErrorSeverity::Error, ErrorSeverity::Warning);
        assert_ne!(ErrorSeverity::Warning, ErrorSeverity::Info);
    }
}
