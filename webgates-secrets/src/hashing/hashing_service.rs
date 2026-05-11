use super::HashedValue;
use crate::hashing::errors::HashingError;
use webgates_core::verification_result::VerificationResult;

/// Hashes and verifies secrets.
///
/// Callers use this trait to create stored hashes and verify plaintext values
/// against them. Implementations should return opaque, self-contained hash
/// strings that are safe to persist directly.
///
/// # Implementor notes
///
/// Implementations should use a modern, memory-hard password hashing algorithm,
/// embed salts and parameters when the format supports it, and return errors
/// only for exceptional failures such as misconfiguration or backend issues.
///
/// This trait does not enforce constant-time behavior by itself, but
/// implementations should avoid obviously data-dependent early exits where
/// practical.
///
/// See [`Argon2Hasher`](crate::hashing::argon2::Argon2Hasher) for the default
/// production-ready implementation.
pub trait HashingService {
    /// Hashes a plaintext secret into an opaque, self-contained representation.
    fn hash_value(&self, plain_value: &str) -> Result<HashedValue, HashingError>;
    /// Verifies a plaintext input against a previously produced hash.
    ///
    /// Returns `Ok(VerificationResult::Ok)` if the value matches,
    /// `Ok(VerificationResult::Unauthorized)` if it does not match, and
    /// `Err(..)` only if verification could not be performed.
    fn verify_value(
        &self,
        plain_value: &str,
        hashed_value: &str,
    ) -> Result<VerificationResult, HashingError>;
}
