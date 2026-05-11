//! Error types and tonic status mapping for `webgates-tonic`.
//!
//! This module provides [`crate::errors::AuthError`], the typed error enum used by bearer gate
//! middleware when authentication or authorization fails.
//!
//! Each variant maps to a specific [`tonic::Status`] code so callers receive
//! safe, opaque gRPC status responses without internal detail being leaked.
//!
//! # Status mapping
//!
//! | `AuthError` variant | `tonic::Status` code |
//! |---|---|
//! | `MissingAuthorizationMetadata` | `UNAUTHENTICATED` |
//! | `MalformedAuthorizationMetadata` | `UNAUTHENTICATED` |
//! | `InvalidToken` | `UNAUTHENTICATED` |
//! | `InvalidIssuer` | `UNAUTHENTICATED` |
//! | `PolicyDeniesAll` | `UNAUTHENTICATED` |
//! | `PolicyDenied` | `PERMISSION_DENIED` |
//! | `Internal` | `INTERNAL` |

use thiserror::Error;
use tonic::Status;

/// All authentication and authorization failures that the bearer gate can produce.
///
/// Call [`AuthError::into_status`] to convert a failure into the appropriate
/// [`tonic::Status`] for returning from a gRPC handler.
#[derive(Debug, Error)]
pub enum AuthError {
    /// The `authorization` metadata key was not present in the request.
    #[error("missing authorization metadata")]
    MissingAuthorizationMetadata,

    /// The `authorization` metadata value was present but could not be parsed
    /// as a `Bearer <token>` pair.
    #[error("malformed authorization metadata")]
    MalformedAuthorizationMetadata,

    /// The bearer token failed cryptographic validation (bad signature,
    /// expired, or structurally invalid).
    #[error("invalid bearer token")]
    InvalidToken,

    /// The token's issuer claim did not match the issuer configured on the
    /// gate.
    #[error("invalid token issuer")]
    InvalidIssuer,

    /// The configured access policy unconditionally denies all access.
    #[error("policy denies all access")]
    PolicyDeniesAll,

    /// The token was valid, but the decoded account does not satisfy the
    /// configured access policy.
    #[error("access denied by policy")]
    PolicyDenied,

    /// An unexpected internal error occurred while processing the request.
    /// The details are intentionally opaque to the caller.
    #[error("internal authentication error")]
    Internal,
}

impl AuthError {
    /// Converts this error into the appropriate [`tonic::Status`].
    ///
    /// Token-level and metadata-level failures map to `UNAUTHENTICATED`.
    /// Policy denial after successful authentication maps to
    /// `PERMISSION_DENIED`. Unexpected internal errors map to `INTERNAL`.
    pub fn into_status(self) -> Status {
        match self {
            AuthError::MissingAuthorizationMetadata => {
                Status::unauthenticated("missing authorization metadata")
            }
            AuthError::MalformedAuthorizationMetadata => {
                Status::unauthenticated("malformed authorization metadata")
            }
            AuthError::InvalidToken => Status::unauthenticated("invalid bearer token"),
            AuthError::InvalidIssuer => Status::unauthenticated("invalid token issuer"),
            AuthError::PolicyDeniesAll => Status::unauthenticated("access denied"),
            AuthError::PolicyDenied => Status::permission_denied("access denied by policy"),
            AuthError::Internal => Status::internal("internal error"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    /// Every token and metadata failure maps to UNAUTHENTICATED.
    #[test]
    fn unauthenticated_variants() {
        let cases = [
            AuthError::MissingAuthorizationMetadata,
            AuthError::MalformedAuthorizationMetadata,
            AuthError::InvalidToken,
            AuthError::InvalidIssuer,
            AuthError::PolicyDeniesAll,
        ];
        for err in cases {
            let status = err.into_status();
            assert_eq!(
                status.code(),
                Code::Unauthenticated,
                "expected UNAUTHENTICATED"
            );
        }
    }

    /// Policy denial after authentication maps to PERMISSION_DENIED.
    #[test]
    fn permission_denied_variant() {
        let status = AuthError::PolicyDenied.into_status();
        assert_eq!(status.code(), Code::PermissionDenied);
    }

    /// Internal errors map to INTERNAL.
    #[test]
    fn internal_variant() {
        let status = AuthError::Internal.into_status();
        assert_eq!(status.code(), Code::Internal);
    }
}
