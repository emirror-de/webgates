//! Secrets hashing and verification models.
use crate::hashing::HashingOperation;
pub mod errors;
use crate::errors::{Error, Result};
use crate::hashing::{HashedValue, HashingService};
use crate::verification_result::VerificationResult;
pub use errors::SecretError;
pub use secret_repository::SecretRepository;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

mod secret_repository;

/// A cryptographically secure secret (password) bound to a specific user account.
///
/// This type represents a hashed password or other sensitive authentication data that is
/// cryptographically bound to a specific account through its unique identifier. The secret
/// is automatically hashed using the Argon2 algorithm when created, ensuring that plaintext
/// passwords are never stored in memory or persistent storage.
///
/// # Security Properties
///
/// - **Irreversible hashing**: Plaintext secrets cannot be recovered from the hash
/// - **Unique salting**: Each secret has a cryptographically random salt
/// - **Timing attack resistance**: Verification operations run in constant time
/// - **Account binding**: Secrets are tied to specific account IDs for additional security
///
/// # Usage in Authentication Flows
///
/// Secrets are typically created during user registration and verified during login:
///
/// ```rust
/// use axum_gate::secrets::Secret; use axum_gate::hashing::argon2::Argon2Hasher; use axum_gate::verification_result::VerificationResult;
/// use axum_gate::accounts::AccountInsertService;
/// use uuid::Uuid;
///
/// # tokio_test::block_on(async {
/// // During registration
/// let account_id = Uuid::now_v7();
/// let user_password = "user_entered_password";
/// let hasher = Argon2Hasher::new_recommended().unwrap();
///
/// let secret = Secret::new(&account_id, user_password, hasher.clone())?;
///
/// // During login verification
/// let login_attempt = "user_entered_password";
/// match secret.verify(login_attempt, hasher)? {
///     VerificationResult::Ok => {
///         // Grant access - password is correct
///         println!("Authentication successful");
///     },
///     VerificationResult::Unauthorized => {
///         // Deny access - password is incorrect
///         println!("Authentication failed");
///     }
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # });
/// ```
///
/// # Storage Considerations
///
/// Secrets should be stored separately from account data for enhanced security:
///
/// - Use dedicated secret repositories ([`SecretRepository`])
/// - Consider separate databases for account metadata vs. authentication secrets
/// - Implement appropriate access controls on secret storage
/// - Regular backup and recovery procedures for authentication data
///
/// # Performance Notes
///
/// Secret hashing and verification are intentionally computationally expensive operations
/// (typically 100-500ms) to resist brute-force attacks. Consider:
///
/// - Implementing rate limiting on authentication endpoints
/// - Using async/await to prevent blocking during verification
/// - Caching verification results appropriately (with security considerations)
///
/// The `account_id` must correspond to a valid account in an
/// [`AccountRepository`](crate::accounts::AccountRepository) to create a correct secret.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Secret {
    /// The [account id](crate::accounts::Account::account_id) that this secret belongs to.
    pub account_id: Uuid,
    /// The actual secret.
    pub secret: HashedValue,
}

impl Secret {
    /// Creates a new secret by hashing the provided plaintext password.
    ///
    /// This method takes a plaintext secret (typically a user password) and creates a new
    /// [`Secret`] instance with the secret cryptographically hashed using the provided
    /// hashing service. The original plaintext is never stored.
    ///
    /// # Parameters
    ///
    /// - `account_id`: The unique identifier of the account this secret belongs to
    /// - `plain_secret`: The plaintext password or secret to be hashed
    /// - `hasher`: The hashing service implementation (typically [`Argon2Hasher`](crate::hashing::argon2::Argon2Hasher))
    ///
    /// # Security
    ///
    /// - The plaintext secret is immediately hashed and the original value is dropped
    /// - A cryptographically secure random salt is generated for each secret
    /// - The resulting hash is computationally infeasible to reverse
    ///
    /// # Errors
    ///
    /// Returns an error if the hashing operation fails, which may occur due to:
    /// - Insufficient system resources for the hashing algorithm
    /// - Invalid parameters in the hashing service configuration
    /// - System-level cryptographic failures
    ///
    /// # Example
    ///
    /// ```rust
    /// use axum_gate::secrets::Secret; use axum_gate::hashing::argon2::Argon2Hasher;
    /// use uuid::Uuid;
    ///
    /// # tokio_test::block_on(async {
    /// let account_id = Uuid::now_v7();
    /// let password = "user_password_123";
    /// let hasher = Argon2Hasher::new_recommended().unwrap();
    ///
    /// let secret = Secret::new(&account_id, password, hasher)?;
    /// // The plaintext password is now securely hashed and cannot be recovered
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// # });
    /// ```
    pub fn new<Hasher: HashingService>(
        account_id: &Uuid,
        plain_secret: &str,
        hasher: Hasher,
    ) -> Result<Self> {
        let secret = hasher.hash_value(plain_secret).map_err(|e| {
            Error::Secrets(SecretError::hashing_with_context(
                HashingOperation::Hash,
                e.to_string(),
                Some("Argon2".to_string()),
                Some("PHC".to_string()),
            ))
        })?;
        Ok(Self {
            account_id: *account_id,
            secret,
        })
    }

    /// Creates a secret from an already-hashed value.
    ///
    /// This constructor is used when you already have a properly hashed secret value,
    /// typically when loading secrets from persistent storage or when migrating from
    /// other authentication systems.
    ///
    /// # Parameters
    ///
    /// - `account_id`: The unique identifier of the account this secret belongs to
    /// - `hashed_secret`: A previously computed hash value from a compatible hashing algorithm
    ///
    /// # Security Warning
    ///
    /// This method bypasses the normal hashing process and directly uses the provided hash.
    /// Ensure that:
    /// - The hash was created using a secure, compatible algorithm (preferably Argon2)
    /// - The hash includes proper salting
    /// - The source of the hash is trusted and verified
    ///
    /// # Use Cases
    ///
    /// - Loading secrets from database storage
    /// - Migrating authentication data between systems
    /// - Testing with pre-computed hash values
    /// - Bulk operations where hashing has already been performed
    ///
    /// # Example
    ///
    /// ```rust
    /// use axum_gate::secrets::Secret; use axum_gate::hashing::argon2::Argon2Hasher; use axum_gate::hashing::HashedValue;
    /// use uuid::Uuid;
    ///
    /// # tokio_test::block_on(async {
    /// // Typically this hash would come from your database
    /// let account_id = Uuid::now_v7();
    /// let hasher = Argon2Hasher::new_recommended().unwrap();
    /// let original_secret = Secret::new(&account_id, "password", hasher.clone())?;
    /// let stored_hash = &original_secret.secret;
    ///
    /// // Reconstruct the secret from the stored hash
    /// let reconstructed = Secret::from_hashed(&account_id, stored_hash);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// # });
    /// ```
    pub fn from_hashed(account_id: &Uuid, hashed_secret: &HashedValue) -> Self {
        Self {
            account_id: account_id.to_owned(),
            secret: hashed_secret.to_owned(),
        }
    }

    /// Verifies a plaintext secret against the stored hash.
    ///
    /// This method performs constant-time verification of a plaintext secret (typically
    /// a password entered by a user) against the stored cryptographic hash. The verification
    /// process is designed to be resistant to timing attacks.
    ///
    /// # Parameters
    ///
    /// - `plain_secret`: The plaintext secret to verify (e.g., user-entered password)
    /// - `hasher`: The hashing service to use for verification (must be compatible with the stored hash)
    ///
    /// # Returns
    ///
    /// - [`VerificationResult::Ok`] if the plaintext secret matches the stored hash
    /// - [`VerificationResult::Unauthorized`] if the secrets don't match or verification fails
    ///
    /// # Security Properties
    ///
    /// - **Constant-time operation**: Verification takes the same time regardless of correctness
    /// - **No information leakage**: Incorrect attempts don't reveal information about the stored secret
    /// - **Timing attack resistance**: Prevents attackers from using timing differences to guess secrets
    ///
    /// # Performance
    ///
    /// Secret verification is computationally intensive by design (typically 100-500ms)
    /// to make brute-force attacks impractical. This is normal and expected behavior
    /// for secure password hashing algorithms like Argon2.
    ///
    /// # Errors
    ///
    /// Returns an error if the verification process fails due to:
    /// - Incompatible hashing algorithms between creation and verification
    /// - Corrupted hash data
    /// - System-level cryptographic failures
    ///
    /// # Example
    ///
    /// ```rust
    /// use axum_gate::secrets::Secret; use axum_gate::hashing::argon2::Argon2Hasher; use axum_gate::verification_result::VerificationResult;
    /// use uuid::Uuid;
    ///
    /// # tokio_test::block_on(async {
    /// let account_id = Uuid::now_v7();
    /// let correct_password = "secure_password_123";
    /// let hasher = Argon2Hasher::new_recommended().unwrap();
    ///
    /// // Create secret during registration
    /// let secret = Secret::new(&account_id, correct_password, hasher.clone())?;
    ///
    /// // Verify during login - correct password
    /// let result = secret.verify(correct_password, hasher.clone())?;
    /// assert_eq!(result, VerificationResult::Ok);
    ///
    /// // Verify during login - incorrect password
    /// let result = secret.verify("wrong_password", hasher)?;
    /// assert_eq!(result, VerificationResult::Unauthorized);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// # });
    /// ```
    pub fn verify<Hasher: HashingService>(
        &self,
        plain_secret: &str,
        hasher: Hasher,
    ) -> Result<VerificationResult> {
        hasher.verify_value(plain_secret, &self.secret)
    }
}

#[test]
#[allow(clippy::unwrap_used)]
fn secret_verification() {
    use crate::hashing::argon2::Argon2Hasher;

    let id = Uuid::now_v7();
    let correct_password = "admin_password";
    let wrong_password = "admin_wrong_password";
    let secret = Secret::new(
        &id,
        correct_password,
        Argon2Hasher::new_recommended().unwrap(),
    )
    .unwrap();

    assert_eq!(
        VerificationResult::Unauthorized,
        secret
            .verify(wrong_password, Argon2Hasher::new_recommended().unwrap())
            .unwrap()
    );
    assert_eq!(
        VerificationResult::Ok,
        secret
            .verify(correct_password, Argon2Hasher::new_recommended().unwrap())
            .unwrap()
    );
}
