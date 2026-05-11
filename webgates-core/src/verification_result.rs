//! Verification result values for core authentication flows.
//!
//! This module is intentionally small. It gives you a simple success-or-
//! unauthorized outcome for credential verification while keeping infrastructural
//! failures separate in your `Result` error type.

/// Result of a credential or secret verification step.
///
/// Use this enum when verification has two logical outcomes:
///
/// - the supplied secret is valid
/// - the supplied secret is not authorized
///
/// Infrastructure failures such as storage outages or backend errors should be
/// reported separately in your surrounding `Result` type.
///
/// # Conversions
/// - `VerificationResult::from(true)` returns [`VerificationResult::Ok`]
/// - `VerificationResult::from(false)` returns [`VerificationResult::Unauthorized`]
/// - `bool::from(VerificationResult::Ok)` returns `true`
/// - `bool::from(VerificationResult::Unauthorized)` returns `false`
///
/// # Example
/// ```
/// use webgates_core::verification_result::VerificationResult;
///
/// let result = VerificationResult::from(true);
///
/// assert_eq!(result, VerificationResult::Ok);
/// assert!(bool::from(result));
/// ```
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub enum VerificationResult {
    /// Verification succeeded.
    Ok,
    /// Verification failed with an unauthorized outcome.
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
    use super::VerificationResult;

    #[test]
    fn converts_from_bool() {
        assert_eq!(VerificationResult::from(true), VerificationResult::Ok);
        assert_eq!(
            VerificationResult::from(false),
            VerificationResult::Unauthorized
        );
    }

    #[test]
    fn converts_to_bool() {
        assert!(bool::from(VerificationResult::Ok));
        assert!(!bool::from(VerificationResult::Unauthorized));
    }

    #[test]
    fn variants_remain_distinct() {
        assert_ne!(VerificationResult::Ok, VerificationResult::Unauthorized);
    }
}
