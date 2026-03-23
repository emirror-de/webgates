//! Types describing the outcome of JWT validation.
//!
//! This module contains [`JwtValidationResult`], the high-level result returned
//! by JWT validation helpers after decoding and issuer checks.

use super::JwtClaims;

/// Result of validating a JWT token.
///
/// This type separates successful validation from the two expected failure
/// categories exposed by this crate:
/// - the token could not be decoded or validated
/// - the token decoded successfully but did not match the expected issuer
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtValidationResult<T> {
    /// Token is valid and contains decoded claims.
    Valid(JwtClaims<T>),

    /// Token could not be decoded or failed JWT validation.
    ///
    /// This includes malformed tokens and tokens rejected by the configured JWT
    /// validation settings.
    InvalidToken,

    /// Token decoded successfully but has the wrong issuer.
    InvalidIssuer {
        /// Issuer expected by the validation service.
        expected: String,

        /// Issuer found in the decoded token.
        actual: String,
    },
}
