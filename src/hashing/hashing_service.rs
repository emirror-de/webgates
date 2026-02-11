use super::HashedValue;
use crate::errors::Result;
use crate::verification_result::VerificationResult;

/// Abstraction over password / secret hashing and verification.
///
/// Implement this trait to plug in alternative hashing algorithms or services
/// (e.g. Argon2 variants, bcrypt, scrypt, external KMS / HSM, remote API).
///
/// # Requirements
/// Implementations SHOULD:
/// - Use a modern, memory‑hard password hashing algorithm (default provided: Argon2id)
/// - Embed salt & parameters in the produced [`HashedValue`] when the format supports it
/// - Return only opaque, self‑contained hash strings (safe to store directly)
///
/// # Error Semantics
/// - Return `Ok(HashedValue)` / `Ok(VerificationResult)` for normal outcomes
/// - Return `Err(..)` only for exceptional failures (misconfiguration, resource exhaustion,
///   serialization/encoding failure, upstream service error, etc.)
///
/// # Enumeration & Timing
/// This trait itself does not enforce constant‑time behavior; callers such as
/// the login flow will layer enumeration resistance. However, implementations
/// SHOULD avoid obviously data‑dependent early exits where practical.
///
/// See [`Argon2Hasher`](crate::hashing::argon2::Argon2Hasher) for a production‑ready implementation.
pub trait HashingService {
    /// Hash a plaintext secret into an opaque, self‑contained representation.
    ///
    /// Expectations:
    /// - MUST NOT return the plaintext
    /// - SHOULD generate a cryptographically secure random salt per invocation
    /// - SHOULD embed algorithm parameters allowing future verification / upgrades
    fn hash_value(&self, plain_value: &str) -> Result<HashedValue>;
    /// Verify a plaintext input against a previously produced hash.
    ///
    /// Returns:
    /// - `Ok(VerificationResult::Ok)` if the value matches
    /// - `Ok(VerificationResult::Unauthorized)` if it does not match
    /// - `Err(..)` only if verification could not be performed (e.g. malformed hash)
    fn verify_value(&self, plain_value: &str, hashed_value: &str) -> Result<VerificationResult>;
}
