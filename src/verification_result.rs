//! Verification value objects for domain operations.
//!
//! This module contains value objects that represent the results
//! of verification operations in the domain layer.

/// Result of a secret / credential verification operation.
///
/// This enum is used throughout the authentication pipeline (hash verification,
/// credential repository checks, login services) to distinguish a successful
/// verification from an unauthorized outcome **without** revealing *why* it failed
/// (e.g. wrong password vs. unknown user) when higher layers deliberately collapse
/// those states to resist user enumeration.
///
/// # Semantics
/// - [`VerificationResult::Ok`] — Supplied value matched the stored/expected secret.
/// - [`VerificationResult::Unauthorized`] — Value did **not** match, or the subject/identity
///   was intentionally treated as non-existent/mismatched for security uniformity.
///
/// # Conversions
/// - `VerificationResult::from(bool)` maps `true -> Ok`, `false -> Unauthorized`.
/// - `bool::from(VerificationResult)` returns `true` for `Ok`, `false` otherwise.
///
/// # When to Use
/// Prefer this over `Result<bool, E>` when:
/// - You want an explicit success vs. unauthorized domain signal
/// - Errors/exceptions are reserved strictly for infrastructural failures
///
/// # Side‑Channel Guidance
/// Combine it with constant‑time hash verification and unified handling
/// to avoid exposing whether an identifier exists.
///
/// # Example
/// ```
/// use axum_gate::verification_result::VerificationResult;
///
/// fn check(match_flag: bool) -> VerificationResult {
///     VerificationResult::from(match_flag)
/// }
///
/// assert_eq!(check(true), VerificationResult::Ok);
/// assert_eq!(check(false), VerificationResult::Unauthorized);
/// ```
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub enum VerificationResult {
    /// The verification succeeded (value matched).
    Ok,
    /// The supplied value failed verification (non-match / unauthorized).
    Unauthorized,
}

impl From<bool> for VerificationResult {
    fn from(value: bool) -> Self {
        if value { Self::Ok } else { Self::Unauthorized }
    }
}

impl From<VerificationResult> for bool {
    fn from(result: VerificationResult) -> Self {
        matches!(result, VerificationResult::Ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bool_conversion() {
        assert_eq!(VerificationResult::Ok, VerificationResult::from(true));
        assert_eq!(
            VerificationResult::Unauthorized,
            VerificationResult::from(false)
        );
    }

    #[test]
    fn verification_result_properties() {
        let ok_result = VerificationResult::Ok;
        let unauthorized_result = VerificationResult::Unauthorized;

        // Test equality
        assert_eq!(ok_result, VerificationResult::Ok);
        assert_eq!(unauthorized_result, VerificationResult::Unauthorized);
        assert_ne!(ok_result, unauthorized_result);
    }
}
