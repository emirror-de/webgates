use crate::errors::{Error as RepoError, Result};
use crate::secret_repository::SecretRepository;
use webgates_core::credentials::{Credentials, CredentialsVerifier};
use webgates_core::errors_core::Result as CoreResult;
use webgates_core::verification_result::VerificationResult;
use webgates_secrets::Secret;
use webgates_secrets::hashing::{HashingService, argon2::Argon2Hasher};

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::debug;
use uuid::Uuid;

/// In-memory repository for storing and managing user authentication secrets.
///
/// This repository stores password hashes and other authentication secrets in memory.
/// It's designed to work alongside `MemoryAccountRepository` and implements both
/// `SecretRepository` and `CredentialsVerifier` traits for complete authentication support.
///
/// # Security Note
/// While this stores password hashes (not plain passwords), the data is kept in memory
/// and will be lost when the application stops. For production use, consider persistent
/// storage implementations.
///
/// # Example Usage
/// ```rust
/// use webgates_core::credentials::{Credentials, CredentialsVerifier};
/// use webgates_core::verification_result::VerificationResult;
/// use webgates_repositories::memory::secret::MemorySecretRepository;
/// use webgates_repositories::secret_repository::SecretRepository;
/// use webgates_secrets::hashing::argon2::Argon2Hasher;
/// use webgates_secrets::Secret;
/// use uuid::Uuid;
///
/// # tokio_test::block_on(async {
/// let repo = MemorySecretRepository::new_with_argon2_hasher().unwrap();
/// let account_id = Uuid::now_v7();
///
/// // Store a secret (password hash)
/// let secret = Secret::new(&account_id, "user_password", Argon2Hasher::new_recommended().unwrap()).unwrap();
/// assert!(repo.store_secret(secret).await.unwrap());
///
/// // Verify credentials
/// let credentials = Credentials::new(&account_id, "user_password");
/// let result: VerificationResult = repo.verify_credentials(credentials).await.unwrap();
/// assert_eq!(result, VerificationResult::Ok);
///
/// // Test wrong password
/// let wrong_creds = Credentials::new(&account_id, "wrong_password");
/// let result: VerificationResult = repo.verify_credentials(wrong_creds).await.unwrap();
/// assert_eq!(result, VerificationResult::Unauthorized);
/// # });
/// ```
///
/// # Creating from Existing Data
/// ```rust
/// use webgates_repositories::memory::secret::MemorySecretRepository;
/// use webgates_secrets::hashing::argon2::Argon2Hasher;
/// use webgates_secrets::Secret;
/// use uuid::Uuid;
///
/// let secrets = vec![
///     Secret::new(&Uuid::now_v7(), "admin_pass", Argon2Hasher::new_recommended().unwrap()).unwrap(),
///     Secret::new(&Uuid::now_v7(), "user_pass", Argon2Hasher::new_recommended().unwrap()).unwrap(),
/// ];
/// let repo = MemorySecretRepository::try_from(secrets).unwrap();
/// ```
#[derive(Clone)]
pub struct MemorySecretRepository {
    store: Arc<RwLock<HashMap<Uuid, Secret>>>,
    /// Precomputed dummy hash produced with the same Argon2 preset that `Secret::new`
    /// used (via `Argon2Hasher::new_recommended()`) in this build configuration. This keeps
    /// timing of nonexistent-account verifications aligned with existing-account
    /// verifications to mitigate user enumeration via timing side channels.
    dummy_hash: String,
}

impl MemorySecretRepository {
    /// Creates a new instance with [Argon2Hasher].
    pub fn new_with_argon2_hasher() -> Result<Self> {
        let hasher = Argon2Hasher::new_recommended()?;
        let dummy_hash = hasher.hash_value("dummy_password")?;
        Ok(Self {
            store: Arc::new(RwLock::new(HashMap::new())),
            dummy_hash,
        })
    }
}

impl TryFrom<Vec<Secret>> for MemorySecretRepository {
    type Error = RepoError;
    fn try_from(value: Vec<Secret>) -> Result<Self> {
        let mut store = HashMap::with_capacity(value.len());
        value.into_iter().for_each(|v| {
            store.insert(v.account_id, v);
        });
        let store = Arc::new(RwLock::new(store));
        let dummy_hash = Argon2Hasher::new_recommended()?.hash_value("dummy_password")?;
        Ok(Self { store, dummy_hash })
    }
}

impl SecretRepository for MemorySecretRepository {
    type Error = RepoError;

    async fn bootstrap(&self) -> Result<()> {
        Ok(())
    }

    async fn store_secret(&self, secret: Secret) -> Result<bool> {
        let res: Result<_> = {
            let mut write = self.store.write().await;
            debug!("Got write lock on secret repository.");

            if write.contains_key(&secret.account_id) {
                return Ok(false);
            }

            write.insert(secret.account_id, secret);
            Ok(true)
        };
        res
    }

    async fn delete_secret(&self, id: &Uuid) -> Result<Option<Secret>> {
        let res: Result<_> = {
            let mut write = self.store.write().await;
            Ok(write.remove(id))
        };
        res
    }

    async fn update_secret(&self, secret: Secret) -> Result<()> {
        let res: Result<_> = {
            let mut write = self.store.write().await;
            write.insert(secret.account_id, secret);
            Ok(())
        };
        res
    }
}

impl CredentialsVerifier for MemorySecretRepository {
    async fn verify_credentials(
        &self,
        credentials: Credentials<Uuid>,
    ) -> CoreResult<VerificationResult> {
        use subtle::Choice;

        let res: Result<_> = {
            let read = self.store.read().await;

            let (stored_secret_str, user_exists_choice) = match read.get(&credentials.id) {
                Some(stored_secret) => (stored_secret.secret.as_str(), Choice::from(1u8)),
                None => (self.dummy_hash.as_str(), Choice::from(0u8)),
            };

            let hasher = Argon2Hasher::new_recommended()?;
            let hash_verification_result =
                hasher.verify_value(&credentials.secret, stored_secret_str)?;

            let hash_matches_choice = Choice::from(match hash_verification_result {
                VerificationResult::Ok => 1u8,
                VerificationResult::Unauthorized => 0u8,
            });

            let final_success_choice = user_exists_choice & hash_matches_choice;

            let final_result = if bool::from(final_success_choice) {
                VerificationResult::Ok
            } else {
                VerificationResult::Unauthorized
            };

            Ok(final_result)
        };
        res.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::MemorySecretRepository;
    use crate::secret_repository::SecretRepository;
    use uuid::Uuid;
    use webgates_core::credentials::{Credentials, CredentialsVerifier};
    use webgates_core::verification_result::VerificationResult;
    use webgates_secrets::Secret;
    use webgates_secrets::hashing::argon2::Argon2Hasher;

    #[tokio::test]
    async fn store_secret_returns_false_for_duplicates() {
        let repository = MemorySecretRepository::new_with_argon2_hasher().unwrap();
        let account_id = Uuid::now_v7();

        let first_secret = Secret::new(
            &account_id,
            "first-password",
            Argon2Hasher::new_recommended().unwrap(),
        )
        .unwrap();
        let second_secret = Secret::new(
            &account_id,
            "second-password",
            Argon2Hasher::new_recommended().unwrap(),
        )
        .unwrap();

        assert!(repository.store_secret(first_secret).await.unwrap());
        assert!(!repository.store_secret(second_secret).await.unwrap());

        let verification = repository
            .verify_credentials(Credentials::new(&account_id, "first-password"))
            .await
            .unwrap();
        assert_eq!(verification, VerificationResult::Ok);
    }

    #[tokio::test]
    async fn update_secret_replaces_existing_secret() {
        let repository = MemorySecretRepository::new_with_argon2_hasher().unwrap();
        let account_id = Uuid::now_v7();

        let initial_secret = Secret::new(
            &account_id,
            "initial-password",
            Argon2Hasher::new_recommended().unwrap(),
        )
        .unwrap();
        let updated_secret = Secret::new(
            &account_id,
            "updated-password",
            Argon2Hasher::new_recommended().unwrap(),
        )
        .unwrap();

        assert!(repository.store_secret(initial_secret).await.unwrap());
        repository.update_secret(updated_secret).await.unwrap();

        let old_verification = repository
            .verify_credentials(Credentials::new(&account_id, "initial-password"))
            .await
            .unwrap();
        assert_eq!(old_verification, VerificationResult::Unauthorized);

        let new_verification = repository
            .verify_credentials(Credentials::new(&account_id, "updated-password"))
            .await
            .unwrap();
        assert_eq!(new_verification, VerificationResult::Ok);
    }

    #[tokio::test]
    async fn delete_secret_returns_removed_secret() {
        let repository = MemorySecretRepository::new_with_argon2_hasher().unwrap();
        let account_id = Uuid::now_v7();

        let secret = Secret::new(
            &account_id,
            "password",
            Argon2Hasher::new_recommended().unwrap(),
        )
        .unwrap();

        assert!(repository.store_secret(secret).await.unwrap());

        let removed_secret = repository.delete_secret(&account_id).await.unwrap();
        assert!(removed_secret.is_some());

        let missing_secret = repository.delete_secret(&account_id).await.unwrap();
        assert!(missing_secret.is_none());
    }
}
