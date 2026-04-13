#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
/*!
# webgates-secrets

Secret and hashing primitives for the `webgates` ecosystem.

This crate contains the reusable, server-side security building blocks that are
shared between higher-level authentication flows and repository backends:

- Secret value objects
- Secret-category error types
- Password hashing abstractions
- Argon2 hashing implementation
- Hashing-category error types

The crate is intentionally focused on the secret/hashing boundary so repository
traits and persistence concerns can live elsewhere without creating dependency
cycles.
*/

use crate::errors::SecretError;
use crate::hashing::HashedValue;
use crate::hashing::errors::HashingOperation;
use crate::hashing::hashing_service::HashingService;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webgates_core::verification_result::VerificationResult;

/// Result type alias for secrets and hashing operations.
///
/// Crate-internal code should prefer concrete, caller-relevant error types at
/// public boundaries. This alias is primarily a convenience for internal
/// plumbing and generic implementations.
pub type Result<T, E = Box<dyn std::error::Error + Send + Sync>> = std::result::Result<T, E>;

pub mod errors;
pub mod hashing;

/// A hashed secret bound to a single account identifier.
///
/// `Secret` stores only the hashed representation of a credential. Callers create a
/// value from plaintext with [`Secret::new`] or reconstruct it from storage with
/// [`Secret::from_hashed`].
///
/// # Security properties
///
/// - Plaintext input is hashed before storage in the returned value.
/// - Verification is delegated to the configured [`HashingService`] implementation.
/// - The stored value is self-contained and suitable for persistence.
///
/// # Usage
///
/// Secrets are typically created during registration and verified during login:
///
/// ```rust
/// use webgates_core::verification_result::VerificationResult;
/// use webgates_secrets::hashing::argon2::Argon2Hasher;
/// use webgates_secrets::Secret;
/// use uuid::Uuid;
///
/// let account_id = Uuid::now_v7();
/// let hasher = Argon2Hasher::new_recommended().unwrap();
/// let secret = Secret::new(&account_id, "user_entered_password", hasher.clone())
///     .map_err(|e| e.to_string())?;
///
/// let verification = secret
///     .verify("user_entered_password", hasher)
///     .map_err(|e| e.to_string())?;
///
/// assert_eq!(verification, VerificationResult::Ok);
/// # Ok::<(), String>(())
/// ```
///
/// # Storage considerations
///
/// Persist only the hashed value and its associated `account_id`. Plaintext secrets
/// must never be stored or logged.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Secret {
    /// The account identifier this secret belongs to.
    pub account_id: Uuid,
    /// The persisted hashed secret value.
    pub secret: HashedValue,
}

impl Secret {
    /// Creates a new secret by hashing the provided plaintext input.
    ///
    /// # Parameters
    ///
    /// - `account_id`: account identifier that owns the secret
    /// - `plain_secret`: plaintext value to hash
    /// - `hasher`: hashing service implementation used to create the stored hash
    ///
    /// # Errors
    ///
    /// Returns an error when hashing fails because the configured hashing backend
    /// cannot produce a valid hash.
    ///
    /// # Example
    ///
    /// ```rust
    /// use webgates_secrets::hashing::argon2::Argon2Hasher;
    /// use webgates_secrets::Secret;
    /// use uuid::Uuid;
    ///
    /// let account_id = Uuid::now_v7();
    /// let hasher = Argon2Hasher::new_recommended().unwrap();
    /// let secret = Secret::new(&account_id, "user_password_123", hasher)
    ///     .map_err(|e| e.to_string())?;
    ///
    /// assert_eq!(secret.account_id, account_id);
    /// # Ok::<(), String>(())
    /// ```
    pub fn new<Hasher: HashingService>(
        account_id: &Uuid,
        plain_secret: &str,
        hasher: Hasher,
    ) -> std::result::Result<Self, SecretError> {
        let secret = hasher.hash_value(plain_secret).map_err(|e| {
            SecretError::hashing_with_context(
                HashingOperation::Hash,
                e.to_string(),
                Some("Argon2".to_string()),
                Some("PHC".to_string()),
            )
        })?;
        Ok(Self {
            account_id: *account_id,
            secret,
        })
    }

    /// Reconstructs a secret from a previously hashed value.
    ///
    /// Use this constructor when loading persisted secrets from storage.
    ///
    /// # Parameters
    ///
    /// - `account_id`: account identifier that owns the secret
    /// - `hashed_secret`: previously computed hashed value
    ///
    /// # Example
    ///
    /// ```rust
    /// use webgates_secrets::hashing::argon2::Argon2Hasher;
    /// use webgates_secrets::hashing::HashedValue;
    /// use webgates_secrets::Secret;
    /// use uuid::Uuid;
    ///
    /// let account_id = Uuid::now_v7();
    /// let hasher = Argon2Hasher::new_recommended().unwrap();
    /// let original_secret = Secret::new(&account_id, "password", hasher.clone())
    ///     .map_err(|e| e.to_string())?;
    /// let stored_hash: &HashedValue = &original_secret.secret;
    ///
    /// let reconstructed = Secret::from_hashed(&account_id, stored_hash);
    ///
    /// assert_eq!(reconstructed.account_id, account_id);
    /// # Ok::<(), String>(())
    /// ```
    pub fn from_hashed(account_id: &Uuid, hashed_secret: &HashedValue) -> Self {
        Self {
            account_id: *account_id,
            secret: hashed_secret.clone(),
        }
    }

    /// Verifies a plaintext secret against the stored hash.
    ///
    /// # Parameters
    ///
    /// - `plain_secret`: plaintext value to verify
    /// - `hasher`: hashing service implementation compatible with the stored hash
    ///
    /// # Returns
    ///
    /// - [`VerificationResult::Ok`] when the plaintext matches the stored hash
    /// - [`VerificationResult::Unauthorized`] when it does not match
    ///
    /// # Errors
    ///
    /// Returns an error when the stored hash cannot be parsed or verified by the
    /// provided hashing backend.
    ///
    /// # Example
    ///
    /// ```rust
    /// use webgates_core::verification_result::VerificationResult;
    /// use webgates_secrets::hashing::argon2::Argon2Hasher;
    /// use webgates_secrets::Secret;
    /// use uuid::Uuid;
    ///
    /// let account_id = Uuid::now_v7();
    /// let correct_password = "secure_password_123";
    /// let hasher = Argon2Hasher::new_recommended().unwrap();
    ///
    /// let secret = Secret::new(&account_id, correct_password, hasher.clone())
    ///     .map_err(|e| e.to_string())?;
    ///
    /// let result = secret
    ///     .verify(correct_password, hasher.clone())
    ///     .map_err(|e| e.to_string())?;
    /// assert_eq!(result, VerificationResult::Ok);
    ///
    /// let result = secret
    ///     .verify("wrong_password", hasher)
    ///     .map_err(|e| e.to_string())?;
    /// assert_eq!(result, VerificationResult::Unauthorized);
    /// # Ok::<(), String>(())
    /// ```
    pub fn verify<Hasher: HashingService>(
        &self,
        plain_secret: &str,
        hasher: Hasher,
    ) -> std::result::Result<VerificationResult, SecretError> {
        hasher
            .verify_value(plain_secret, &self.secret)
            .map_err(|error| {
                SecretError::hashing_with_context(
                    HashingOperation::Verify,
                    error.to_string(),
                    Some("Argon2".to_string()),
                    Some("PHC".to_string()),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;
    use crate::hashing::argon2::Argon2Hasher;
    use uuid::Uuid;
    use webgates_core::verification_result::VerificationResult;

    #[test]
    fn secret_verification_returns_unauthorized_for_wrong_secret() {
        let id = Uuid::now_v7();
        let correct_password = "admin_password";
        let wrong_password = "admin_wrong_password";
        let hasher = match Argon2Hasher::new_recommended() {
            Ok(hasher) => hasher,
            Err(error) => panic!(
                "recommended Argon2 hasher should be constructible in tests: {}",
                error
            ),
        };
        let secret = match Secret::new(&id, correct_password, hasher.clone()) {
            Ok(secret) => secret,
            Err(error) => panic!(
                "secret construction should hash the provided test password: {}",
                error
            ),
        };

        let verification = match secret.verify(wrong_password, hasher) {
            Ok(verification) => verification,
            Err(error) => panic!(
                "verification should return an authorization result for a valid stored hash: {}",
                error
            ),
        };

        assert_eq!(VerificationResult::Unauthorized, verification);
    }

    #[test]
    fn secret_verification_returns_ok_for_matching_secret() {
        let id = Uuid::now_v7();
        let correct_password = "admin_password";
        let hasher = match Argon2Hasher::new_recommended() {
            Ok(hasher) => hasher,
            Err(error) => panic!(
                "recommended Argon2 hasher should be constructible in tests: {}",
                error
            ),
        };
        let secret = match Secret::new(&id, correct_password, hasher.clone()) {
            Ok(secret) => secret,
            Err(error) => panic!(
                "secret construction should hash the provided test password: {}",
                error
            ),
        };

        let verification = match secret.verify(correct_password, hasher) {
            Ok(verification) => verification,
            Err(error) => panic!(
                "verification should return success for the original plaintext secret: {}",
                error
            ),
        };

        assert_eq!(VerificationResult::Ok, verification);
    }

    #[test]
    fn from_hashed_preserves_account_id_and_hash() {
        let id = Uuid::now_v7();
        let hasher = match Argon2Hasher::new_recommended() {
            Ok(hasher) => hasher,
            Err(error) => panic!(
                "recommended Argon2 hasher should be constructible in tests: {}",
                error
            ),
        };
        let secret = match Secret::new(&id, "admin_password", hasher) {
            Ok(secret) => secret,
            Err(error) => panic!(
                "secret construction should hash the provided test password: {}",
                error
            ),
        };

        let reconstructed = Secret::from_hashed(&id, &secret.secret);

        assert_eq!(reconstructed.account_id, id);
        assert_eq!(reconstructed.secret, secret.secret);
    }
}
