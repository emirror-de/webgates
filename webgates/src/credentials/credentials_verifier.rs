use super::Credentials;
use crate::errors::Result;
use crate::verification_result::VerificationResult;

use std::future::Future;

/// Asynchronous credential verification abstraction.
///
/// Implement this trait to plug in a secret/credential verification backend (e.g.
/// database + password hash store). It is used by [`LoginService`](crate::authn::LoginService)
/// to perform *enumeration‑resistant*, constant‑time style authentication flows.
///
/// # Responsibilities
///
/// Implementors SHOULD:
/// - Perform a password (or secret) hash verification taking roughly the same time for
///   valid and invalid credentials (avoid early returns before hashing)
/// - Return [`VerificationResult::Ok`] only when the secret matches the stored hash
/// - Return [`VerificationResult::Unauthorized`] for all authentication failures
///   (including “user/ID not found”) if the calling layer expects indistinguishable outcomes
/// - Avoid leaking detailed error information through timing or error messages
///
/// It is acceptable to internally query storage by the identifier first and then
/// verify the hash; however, if used in an enumeration‑resistant context you should
/// still run a dummy verification when the identifier is absent (the higher-level
/// service in this crate handles this pattern by passing a dummy ID).
///
/// # Error Handling
///
/// Only return an `Err` for infrastructural problems (I/O failure, corruption,
/// connectivity issues, etc.). Logical “bad password” or “unknown ID” cases MUST map
/// to `Ok(VerificationResult::Unauthorized)`.
///
/// # Type Parameter
/// * `Id` - The identifier type used to look up stored credentials (e.g. `Uuid`)
pub trait CredentialsVerifier<Id> {
    /// Verifies the supplied credentials against the stored secret/hash.
    ///
    /// Parameters:
    /// - `credentials`: A credential object containing an identifier and *plaintext* secret.
    ///
    /// Returns:
    /// - `Ok(VerificationResult::Ok)` if the secret matches the stored hash
    /// - `Ok(VerificationResult::Unauthorized)` if no match / no such ID / mismatch
    /// - `Err(e)` only for backend / infrastructural failures
    ///
    /// Timing / side‑channel guidance:
    /// Implementors are encouraged to avoid observable timing differences between
    /// “not found” and “wrong password” states when used in contexts that require
    /// user enumeration resistance (the upstream login service already enforces
    /// uniformity by performing a dummy verification as needed).
    fn verify_credentials(
        &self,
        credentials: Credentials<Id>,
    ) -> impl Future<Output = Result<VerificationResult>>;
}
