//! Session-layer error types.
//!
//! This module defines the minimal compiling error categories used by
//! `webgates-sessions` while the rest of the session domain is still being
//! implemented.

use thiserror::Error;

/// Result type used throughout `webgates-sessions`.
pub type Result<T> = std::result::Result<T, SessionError>;

/// Root error type for framework-agnostic session workflows.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// Configuration is invalid or internally inconsistent.
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// Token generation, hashing, validation, or rotation failed.
    #[error(transparent)]
    Token(#[from] TokenError),

    /// Renewal coordination or policy evaluation failed.
    #[error(transparent)]
    Renewal(#[from] RenewalError),

    /// Session state could not be persisted, loaded, or atomically updated.
    #[error(transparent)]
    Repository(#[from] RepositoryError),

    /// Logout or revocation failed.
    #[error(transparent)]
    Revocation(#[from] RevocationError),

    /// Placeholder error used for not-yet-implemented session functionality.
    #[error("{message}")]
    Unimplemented {
        /// Safe, caller-facing message describing the missing functionality.
        message: String,
    },
}

impl SessionError {
    /// Creates a placeholder error for not-yet-implemented session behavior.
    pub fn unimplemented(message: impl Into<String>) -> Self {
        Self::Unimplemented {
            message: message.into(),
        }
    }
}

/// Configuration-related session errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// A required duration or threshold was invalid.
    #[error("invalid session configuration")]
    Invalid,
}

/// Token and credential-material related session errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TokenError {
    /// Token generation failed.
    #[error("failed to generate token material")]
    GenerationFailed,

    /// Token hashing failed.
    #[error("failed to hash token material")]
    HashFailed,

    /// Auth token issuance failed.
    #[error("failed to issue auth token")]
    AuthIssuanceFailed,

    /// Supplied token material was malformed or unusable.
    #[error("invalid token material")]
    InvalidTokenMaterial,

    /// Refresh-token generator configuration was invalid.
    #[error("invalid refresh token length")]
    InvalidRefreshTokenLength,

    /// Token generation or validation failed for an unspecified reason.
    #[error("token operation failed")]
    Failed,
}

/// Renewal-flow errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RenewalError {
    /// The current session is not eligible for renewal.
    #[error("session is not eligible for renewal")]
    NotEligible,

    /// A lease could not be acquired because another renewal is in progress.
    #[error("renewal lease unavailable")]
    LeaseUnavailable,

    /// A refresh token replay was detected.
    #[error("refresh token replay detected")]
    ReplayDetected,

    /// Atomic rotation did not succeed.
    #[error("session rotation failed")]
    RotationFailed,
}

/// Repository boundary errors for session persistence.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RepositoryError {
    /// The requested session record was not found.
    #[error("session not found")]
    SessionNotFound,

    /// The requested session family record was not found.
    #[error("session family not found")]
    SessionFamilyNotFound,

    /// An optimistic or compare-and-swap style write lost a race.
    #[error("concurrent session update detected")]
    Conflict,

    /// Stored session data was invalid or inconsistent.
    #[error("invalid persisted session state")]
    InvalidState,

    /// A backend-specific operation failed.
    #[error("{message}")]
    Backend {
        /// Safe, caller-facing backend failure summary.
        message: String,
    },
}

impl RepositoryError {
    /// Creates a backend error with a safe, caller-facing message.
    pub fn backend(message: impl Into<String>) -> Self {
        Self::Backend {
            message: message.into(),
        }
    }
}

impl From<crate::repository::RepositoryError> for RepositoryError {
    fn from(value: crate::repository::RepositoryError) -> Self {
        match value {
            crate::repository::RepositoryError::SessionNotFound => Self::SessionNotFound,
            crate::repository::RepositoryError::SessionFamilyNotFound => {
                Self::SessionFamilyNotFound
            }
            crate::repository::RepositoryError::Conflict => Self::Conflict,
            crate::repository::RepositoryError::InvalidState => Self::InvalidState,
            crate::repository::RepositoryError::Backend { message } => Self::Backend { message },
        }
    }
}

impl From<crate::repository::RepositoryError> for SessionError {
    fn from(value: crate::repository::RepositoryError) -> Self {
        Self::Repository(value.into())
    }
}

/// Revocation and logout related errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RevocationError {
    /// The target session could not be revoked because it does not exist.
    #[error("cannot revoke missing session")]
    SessionNotFound,

    /// The target session family could not be revoked because it does not exist.
    #[error("cannot revoke missing session family")]
    SessionFamilyNotFound,

    /// The revocation operation could not be completed.
    #[error("revocation failed")]
    Failed,
}
