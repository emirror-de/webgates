//! Codec-category native errors.
//!
//! This module defines category-native errors for codecs and JWT processing
//! used directly in handlers, services, and middleware for codec/serialization
//! and authentication token flows.
//!
//! # Overview
//! - `CodecsError`: codec and serialization error enum
//! - `JwtError`: JWT processing error enum
//! - Operation enums: `CodecOperation`, `JwtOperation`
//!
//! # Examples
//!
//! Codec error:
//! ```rust
//! use axum_gate::codecs::{CodecsError, CodecOperation};
//! use axum_gate::errors::UserFriendlyError;
//!
//! let err = CodecsError::codec(CodecOperation::Encode, "failed to encode payload");
//! assert!(err.user_message().contains("process your data"));
//! assert!(err.developer_message().contains("Codec contract violation"));
//! assert!(err.support_code().starts_with("CODEC-"));
//! ```
//!

//!
//! JWT error:
//! ```rust
//! use axum_gate::codecs::{JwtError, JwtOperation};
//! use axum_gate::errors::UserFriendlyError;
//!
//! let err = JwtError::processing(JwtOperation::Encode, "jwt encoding failed");
//! assert!(err.support_code().starts_with("JWT-ENCODE"));
//! assert!(err.is_retryable());
//! ```

use crate::errors::{ErrorSeverity, UserFriendlyError};
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use thiserror::Error;

/// Codec operation types.
#[derive(Debug, Clone)]
pub enum CodecOperation {
    /// Encode operation
    Encode,
    /// Decode operation
    Decode,
}

impl fmt::Display for CodecOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecOperation::Encode => write!(f, "encode"),
            CodecOperation::Decode => write!(f, "decode"),
        }
    }
}

/// JWT operation types.
#[derive(Debug, Clone)]
pub enum JwtOperation {
    /// JWT encode operation
    Encode,
    /// JWT decode operation
    Decode,
    /// JWT validation operation
    Validate,
}

impl fmt::Display for JwtOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JwtOperation::Encode => write!(f, "encode"),
            JwtOperation::Decode => write!(f, "decode"),
            JwtOperation::Validate => write!(f, "validate"),
        }
    }
}

/// Codec-category native error type (codecs + serialization).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CodecsError {
    /// Codec contract violation (encode/decode/serialize/deserialize/validate).
    #[error("Codec error: {operation} - {message}")]
    Codec {
        /// The codec operation that failed.
        operation: CodecOperation,
        /// Description of the error (non-sensitive).
        message: String,
        /// The payload type being processed.
        payload_type: Option<String>,
        /// Expected format or structure.
        expected_format: Option<String>,
    },
}

impl CodecsError {
    /// Create a codec error.
    pub fn codec(operation: CodecOperation, message: impl Into<String>) -> Self {
        CodecsError::Codec {
            operation,
            message: message.into(),
            payload_type: None,
            expected_format: None,
        }
    }

    /// Create a codec error with format context.
    pub fn codec_with_format(
        operation: CodecOperation,
        message: impl Into<String>,
        payload_type: Option<String>,
        expected_format: Option<String>,
    ) -> Self {
        CodecsError::Codec {
            operation,
            message: message.into(),
            payload_type,
            expected_format,
        }
    }

    fn support_code_inner(&self) -> String {
        let mut hasher = DefaultHasher::new();
        match self {
            CodecsError::Codec {
                operation,
                payload_type,
                ..
            } => {
                format!("CODEC-{}-{:X}", operation.to_string().to_uppercase(), {
                    format!("{:?}{:?}", operation, payload_type).hash(&mut hasher);
                    hasher.finish() % 10000
                })
            }
        }
    }
}

impl UserFriendlyError for CodecsError {
    fn user_message(&self) -> String {
        match self {
            CodecsError::Codec { operation, .. } => match operation {
                CodecOperation::Encode => {
                    "We couldn't process your data in the required format. Please check your input and try again.".to_string()
                }
                CodecOperation::Decode => {
                    "We received data in an unexpected format. This might be a temporary issue - please try again.".to_string()
                }
            },
        }
    }

    fn developer_message(&self) -> String {
        match self {
            CodecsError::Codec {
                operation,
                message,
                payload_type,
                expected_format,
            } => {
                let payload_context = payload_type
                    .as_ref()
                    .map(|pt| format!(" [Payload: {}]", pt))
                    .unwrap_or_default();
                let format_context = expected_format
                    .as_ref()
                    .map(|ef| format!(" [Expected: {}]", ef))
                    .unwrap_or_default();
                format!(
                    "Codec contract violation during {} operation: {}{}{}",
                    operation, message, payload_context, format_context
                )
            }
        }
    }

    fn support_code(&self) -> String {
        self.support_code_inner()
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            CodecsError::Codec { operation, .. } => match operation {
                CodecOperation::Encode | CodecOperation::Decode => ErrorSeverity::Error,
            },
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            CodecsError::Codec { operation, .. } => match operation {
                CodecOperation::Encode => vec![
                    "Check that all required fields are filled out correctly".to_string(),
                    "Ensure special characters are properly formatted".to_string(),
                    "Try simplifying your input and gradually add complexity".to_string(),
                    "Contact support if data formatting requirements are unclear".to_string(),
                ],
                CodecOperation::Decode => vec![
                    "This is likely a temporary system issue".to_string(),
                    "Try refreshing the page and repeating your action".to_string(),
                    "Clear your browser cache if the problem persists".to_string(),
                    "Contact support if you continue receiving malformed data".to_string(),
                ],
            },
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            CodecsError::Codec { operation, .. } => match operation {
                CodecOperation::Encode => true, // user can fix input
                CodecOperation::Decode => true, // may be temporary
            },
        }
    }
}

/// JWT-category native error type.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum JwtError {
    /// JWT processing failure.
    #[error("JWT error: {operation} - {message}")]
    Processing {
        /// The JWT operation that failed.
        operation: JwtOperation,
        /// Description of the failure (non-sensitive).
        message: String,
        /// The token that caused the error (truncated for security).
        token_preview: Option<String>,
    },
}

impl JwtError {
    /// Create a JWT processing error.
    pub fn processing(operation: JwtOperation, message: impl Into<String>) -> Self {
        JwtError::Processing {
            operation,
            message: message.into(),
            token_preview: None,
        }
    }

    /// Create a JWT processing error with token preview.
    pub fn processing_with_preview(
        operation: JwtOperation,
        message: impl Into<String>,
        token_preview: Option<String>,
    ) -> Self {
        JwtError::Processing {
            operation,
            message: message.into(),
            token_preview,
        }
    }

    fn support_code_inner(&self) -> String {
        match self {
            JwtError::Processing { operation, .. } => {
                format!("JWT-{}", operation.to_string().to_uppercase())
            }
        }
    }
}

impl UserFriendlyError for JwtError {
    fn user_message(&self) -> String {
        match self {
            JwtError::Processing { operation, .. } => match operation {
                JwtOperation::Encode => {
                    "We're having trouble with the authentication system. Please try signing in again.".to_string()
                }
                JwtOperation::Decode | JwtOperation::Validate => {
                    "Your session appears to be invalid. Please sign in again to continue.".to_string()
                }
            },
        }
    }

    fn developer_message(&self) -> String {
        match self {
            JwtError::Processing {
                operation,
                message,
                token_preview,
            } => {
                let token_context = token_preview
                    .as_ref()
                    .map(|t| format!(" [Token Preview: {}]", t))
                    .unwrap_or_default();
                format!(
                    "JWT {} operation failed: {}{}",
                    operation, message, token_context
                )
            }
        }
    }

    fn support_code(&self) -> String {
        self.support_code_inner()
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            JwtError::Processing { operation, .. } => match operation {
                JwtOperation::Encode => ErrorSeverity::Error,
                _ => ErrorSeverity::Warning,
            },
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            JwtError::Processing { operation, .. } => match operation {
                JwtOperation::Encode => vec![
                    "Try signing in again".to_string(),
                    "Clear your browser cookies and try again".to_string(),
                    "Contact support if you cannot sign in after multiple attempts".to_string(),
                ],
                JwtOperation::Decode | JwtOperation::Validate => vec![
                    "Sign out completely and sign back in".to_string(),
                    "Clear your browser cache and cookies".to_string(),
                    "Try using a different browser or incognito mode".to_string(),
                ],
            },
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            JwtError::Processing { operation, .. } => match operation {
                JwtOperation::Encode => true, // user can retry auth
                _ => true,
            },
        }
    }
}
