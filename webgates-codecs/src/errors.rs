//! Codec-category native errors.
//!
//! This module defines category-native errors for codecs and JWT processing
//! used directly in token encoding/decoding flows.

use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};

use thiserror::Error;
use webgates_core::errors_core::{ErrorSeverity, UserFriendlyError};

/// Codec operation types.
#[derive(Debug, Clone)]
pub enum CodecOperation {
    /// Encode operation.
    Encode,
    /// Decode operation.
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
    /// JWT encode operation.
    Encode,
    /// JWT decode operation.
    Decode,
    /// JWT validation operation.
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

/// Codec-category native error type.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CodecsError {
    /// Codec contract violation.
    #[error("Codec error: {operation} - {message}")]
    Codec {
        /// The codec operation that failed.
        operation: CodecOperation,
        /// Description of the error.
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
        Self::Codec {
            operation,
            message: message.into(),
            payload_type: None,
            expected_format: None,
        }
    }

    /// Create a codec error with additional format context.
    pub fn codec_with_format(
        operation: CodecOperation,
        message: impl Into<String>,
        payload_type: Option<String>,
        expected_format: Option<String>,
    ) -> Self {
        Self::Codec {
            operation,
            message: message.into(),
            payload_type,
            expected_format,
        }
    }

    fn support_code_inner(&self) -> String {
        let mut hasher = DefaultHasher::new();
        match self {
            Self::Codec {
                operation,
                payload_type,
                ..
            } => format!("CODEC-{}-{:X}", operation.to_string().to_uppercase(), {
                format!("{operation:?}{payload_type:?}").hash(&mut hasher);
                hasher.finish() % 10000
            }),
        }
    }
}

impl UserFriendlyError for CodecsError {
    fn user_message(&self) -> String {
        match self {
            Self::Codec { operation, .. } => match operation {
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
            Self::Codec {
                operation,
                message,
                payload_type,
                expected_format,
            } => {
                let payload_context = payload_type
                    .as_ref()
                    .map(|value| format!(" [Payload: {value}]"))
                    .unwrap_or_default();
                let format_context = expected_format
                    .as_ref()
                    .map(|value| format!(" [Expected: {value}]"))
                    .unwrap_or_default();

                format!(
                    "Codec contract violation during {operation} operation: {message}{payload_context}{format_context}"
                )
            }
        }
    }

    fn support_code(&self) -> String {
        self.support_code_inner()
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            Self::Codec { .. } => ErrorSeverity::Error,
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            Self::Codec { operation, .. } => match operation {
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
        true
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
        /// Description of the failure.
        message: String,
        /// The token that caused the error, truncated for safety.
        token_preview: Option<String>,
    },
}

impl JwtError {
    /// Create a JWT processing error.
    pub fn processing(operation: JwtOperation, message: impl Into<String>) -> Self {
        Self::Processing {
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
        Self::Processing {
            operation,
            message: message.into(),
            token_preview,
        }
    }

    fn support_code_inner(&self) -> String {
        match self {
            Self::Processing { operation, .. } => {
                format!("JWT-{}", operation.to_string().to_uppercase())
            }
        }
    }
}

impl UserFriendlyError for JwtError {
    fn user_message(&self) -> String {
        match self {
            Self::Processing { operation, .. } => match operation {
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
            Self::Processing {
                operation,
                message,
                token_preview,
            } => {
                let token_context = token_preview
                    .as_ref()
                    .map(|value| format!(" [Token Preview: {value}]"))
                    .unwrap_or_default();

                format!("JWT {operation} operation failed: {message}{token_context}")
            }
        }
    }

    fn support_code(&self) -> String {
        self.support_code_inner()
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            Self::Processing { operation, .. } => match operation {
                JwtOperation::Encode => ErrorSeverity::Error,
                JwtOperation::Decode | JwtOperation::Validate => ErrorSeverity::Warning,
            },
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            Self::Processing { operation, .. } => match operation {
                JwtOperation::Encode => vec![
                    "Try signing in again".to_string(),
                    "Clear your browser cookies and try again".to_string(),
                    "Contact support if you cannot sign in after multiple attempts".to_string(),
                ],
                JwtOperation::Decode | JwtOperation::Validate => vec![
                    "Sign out completely and sign back in".to_string(),
                    "Clear your browser cache and cookies".to_string(),
                    "Try using a different browser or private browsing mode".to_string(),
                ],
            },
        }
    }

    fn is_retryable(&self) -> bool {
        true
    }
}
