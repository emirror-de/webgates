use super::JwtClaims;

/// Result of JWT validation.
#[derive(Debug)]
pub enum JwtValidationResult<T> {
    /// Token is valid and contains the decoded claims.
    Valid(JwtClaims<T>),
    /// Token could not be decoded (invalid format, expired, etc.).
    InvalidToken,
    /// Token is valid but has wrong issuer.
    InvalidIssuer {
        /// The expected issuer value.
        expected: String,
        /// The actual issuer value found in the token.
        actual: String,
    },
}
