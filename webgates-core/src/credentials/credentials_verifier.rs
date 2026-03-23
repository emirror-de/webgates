use super::Credentials;
use crate::errors_core::Result;
use crate::verification_result::VerificationResult;

use std::future::Future;

/// Asynchronous credential verification boundary.
///
/// Implement this trait to connect `webgates-core` to a password or secret
/// verification backend, such as a repository plus password-hash store.
///
/// This trait is intentionally small and framework-agnostic. Callers provide a
/// [`Credentials`] value containing an identifier and plaintext secret, and the
/// implementation returns a [`VerificationResult`] describing whether the secret
/// matched the stored value.
///
/// # Security expectations
///
/// Implementations should treat credential verification as a trust-boundary
/// operation:
///
/// - Verify secrets in a way that avoids leaking useful timing differences
///   between valid and invalid credentials.
/// - Return [`VerificationResult::Unauthorized`] for logical authentication
///   failures, including unknown identifiers and secret mismatches.
/// - Reserve `Err(...)` for infrastructural failures such as storage errors,
///   unavailable dependencies, or corrupted verification state.
/// - Avoid logging plaintext secrets or exposing sensitive verification details
///   in error messages.
///
pub trait CredentialsVerifier {
    /// Verifies the supplied credentials against stored credential state.
    ///
    /// # Parameters
    ///
    /// - `credentials`: User-supplied identifier and plaintext secret.
    ///
    /// # Returns
    ///
    /// - `Ok(VerificationResult::Ok)` when the supplied secret matches the
    ///   stored secret representation.
    /// - `Ok(VerificationResult::Unauthorized)` when authentication fails for
    ///   any logical reason.
    /// - `Err(...)` when verification cannot be completed because of an
    ///   infrastructural failure.
    ///
    /// # Cancellation
    ///
    /// Implementations should avoid leaving partial verification work in an
    /// inconsistent state if the returned future is dropped before completion.
    fn verify_credentials(
        &self,
        credentials: Credentials<uuid::Uuid>,
    ) -> impl Future<Output = Result<VerificationResult>> + Send;
}
