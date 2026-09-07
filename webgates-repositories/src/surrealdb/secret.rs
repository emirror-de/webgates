//! SurrealDB-backed secret repository and credentials verifier.
//!
//! This module keeps SurrealDB-specific persistence at the adapter boundary while
//! preserving the repository semantics defined by `SecretRepository`.
//!
//! Repository semantics enforced here:
//! - `store_secret` returns `Ok(true)` when a secret is inserted
//! - `store_secret` returns `Ok(false)` when a secret already exists
//! - `delete_secret` returns the removed secret when present
//! - `update_secret` replaces the stored secret for an existing record

use super::SurrealDbRepository;

use crate::errors::{DatabaseOperation, Result as RepoResult};
use crate::secret_repository::SecretRepository;
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use surrealdb_types::{RecordId, RecordIdKey, SurrealValue, Uuid as SurrealUuid};
use uuid::Uuid;
use webgates_core::credentials::Credentials;
use webgates_core::credentials::credentials_verifier::CredentialsVerifier;
use webgates_core::errors_core::Result as CoreResult;
use webgates_core::verification_result::VerificationResult;
use webgates_secrets::Secret;

/// SurrealDB persistence record for a stored account secret.
///
/// This type is the serialized adapter-layer representation used by
/// `webgates-repositories` when storing secrets in SurrealDB.
#[derive(Clone, Debug, Serialize, Deserialize, SurrealValue)]
pub struct SecretRecord {
    account_id: Uuid,
    secret: String,
}

impl SecretRecord {
    /// Creates a new SurrealDB secret persistence record.
    pub fn new(account_id: Uuid, secret: String) -> Self {
        Self { account_id, secret }
    }
}

impl From<Secret> for SecretRecord {
    fn from(value: Secret) -> Self {
        Self::new(value.account_id, value.secret)
    }
}

impl From<SecretRecord> for Secret {
    fn from(value: SecretRecord) -> Self {
        Self {
            account_id: value.account_id,
            secret: value.secret,
        }
    }
}

impl<S> SecretRepository for SurrealDbRepository<S>
where
    S: Connection,
{
    type Error = crate::errors::Error;

    async fn bootstrap(&self) -> RepoResult<()> {
        let repo = self.use_ns_db().await?;

        repo.credential_schema_initialized
            .get_or_try_init(|| async {
                let table_name = repo.scope_settings.credentials.clone();
                let query = "DEFINE TABLE IF NOT EXISTS $table SCHEMALESS;";

                repo.db
                    .query(query)
                    .bind(("table", table_name.clone()))
                    .await
                    .map_err(|error| {
                        repo.scoped_database_error(
                            DatabaseOperation::Insert,
                            &table_name,
                            format!("Failed to bootstrap secret repository: {error}"),
                            None,
                        )
                    })?;

                Ok::<(), crate::errors::Error>(())
            })
            .await?;

        Ok(())
    }

    async fn store_secret(&self, secret: Secret) -> RepoResult<bool> {
        let repo = self.use_ns_db().await?;

        let table_name = repo.scope_settings.credentials.clone();
        let account_id = secret.account_id;
        let record_id = secret_record_id(&table_name, account_id);

        let existing: Option<SecretRecord> = match repo.db.select(record_id.clone()).await {
            Ok(existing) => existing,
            Err(error) if error.to_string().contains("does not exist") => None,
            Err(error) => {
                return Err(repo.scoped_database_error(
                    DatabaseOperation::Query,
                    &table_name,
                    format!("Failed to query secret existence: {error}"),
                    Some(account_id.to_string()),
                ));
            }
        };

        if existing.is_some() {
            return Ok(false);
        }

        let inserted: Option<SecretRecord> = repo
            .db
            .insert(record_id)
            .content(SecretRecord::from(secret))
            .await
            .map_err(|error| {
                repo.scoped_database_error(
                    DatabaseOperation::Insert,
                    &table_name,
                    format!("Failed to store secret: {error}"),
                    Some(account_id.to_string()),
                )
            })?;

        Ok(inserted.is_some())
    }

    async fn delete_secret(&self, id: &Uuid) -> RepoResult<Option<Secret>> {
        let repo = self.use_ns_db().await?;

        let table_name = repo.scope_settings.credentials.clone();
        let record_id = secret_record_id(&table_name, *id);

        let deleted: Option<SecretRecord> = repo.db.delete(record_id).await.map_err(|error| {
            repo.scoped_database_error(
                DatabaseOperation::Delete,
                &table_name,
                format!("Failed to delete secret: {error}"),
                Some(id.to_string()),
            )
        })?;

        Ok(deleted.map(Secret::from))
    }

    async fn update_secret(&self, secret: Secret) -> RepoResult<()> {
        let repo = self.use_ns_db().await?;

        let table_name = repo.scope_settings.credentials.clone();
        let account_id = secret.account_id;
        let record_id = secret_record_id(&table_name, account_id);

        let _: Option<SecretRecord> = repo
            .db
            .update(record_id)
            .content(SecretRecord::from(secret))
            .await
            .map_err(|error| {
                repo.scoped_database_error(
                    DatabaseOperation::Update,
                    &table_name,
                    format!("Failed to update secret: {error}"),
                    Some(account_id.to_string()),
                )
            })?;

        Ok(())
    }
}

impl<S> CredentialsVerifier for SurrealDbRepository<S>
where
    S: Connection,
{
    async fn verify_credentials(
        &self,
        credentials: Credentials<Uuid>,
    ) -> CoreResult<VerificationResult> {
        use subtle::Choice;

        let Credentials { id, secret } = credentials;

        let result: RepoResult<_> = {
            let table_name = self.scope_settings.credentials.clone();
            let record_id = secret_record_id(&table_name, id);

            let repo = self.use_ns_db().await?;

            let query = "SELECT VALUE secret FROM ONLY $record_id";
            let mut response = repo
                .db
                .query(query)
                .bind(("record_id", record_id))
                .await
                .map_err(|error| {
                    repo.scoped_database_error(
                        DatabaseOperation::Query,
                        &table_name,
                        format!("Failed to query stored secret: {error}"),
                        None,
                    )
                })?;

            let stored_secret: Option<String> = response.take(0).map_err(|error| {
                repo.scoped_database_error(
                    DatabaseOperation::Query,
                    &table_name,
                    format!("Failed to extract stored secret: {error}"),
                    None,
                )
            })?;

            let (hash_for_verification, user_exists_choice) = match stored_secret {
                Some(secret) => (secret, Choice::from(1u8)),
                None => (repo.dummy_hash.clone(), Choice::from(0u8)),
            };

            let verify_query = "RETURN crypto::argon2::compare(type::string($stored_hash), type::string($request_secret))";
            let mut verify_response = repo
                .db
                .query(verify_query)
                .bind(("stored_hash", hash_for_verification))
                .bind(("request_secret", secret))
                .await
                .map_err(|error| {
                    repo.scoped_database_error(
                        DatabaseOperation::Query,
                        &table_name,
                        format!("Failed to verify credentials: {error}"),
                        None,
                    )
                })?;

            let hash_matches: Option<bool> = verify_response.take(0).map_err(|error| {
                repo.scoped_database_error(
                    DatabaseOperation::Query,
                    &table_name,
                    format!("Failed to extract verification result: {error}"),
                    None,
                )
            })?;

            let hash_matches_choice = Choice::from(if hash_matches.unwrap_or(false) {
                1u8
            } else {
                0u8
            });
            let final_success_choice = user_exists_choice & hash_matches_choice;

            Ok(if bool::from(final_success_choice) {
                VerificationResult::Ok
            } else {
                VerificationResult::Unauthorized
            })
        };

        result.map_err(Into::into)
    }
}

fn secret_record_id(table_name: &str, account_id: Uuid) -> RecordId {
    RecordId::new(
        table_name.to_string(),
        RecordIdKey::from(SurrealUuid::from(account_id)),
    )
}

#[cfg(test)]
mod tests {
    use super::SurrealDbRepository;
    use crate::secret_repository::SecretRepository;
    use crate::surrealdb::DatabaseScope;
    use surrealdb::Surreal;
    use surrealdb::engine::local::Mem;
    use uuid::Uuid;
    use webgates_core::credentials::Credentials;
    use webgates_core::credentials::credentials_verifier::CredentialsVerifier;
    use webgates_core::verification_result::VerificationResult;
    use webgates_secrets::Secret;
    use webgates_secrets::hashing::argon2::Argon2Hasher;

    #[tokio::test]
    async fn store_secret_returns_false_for_duplicates() {
        let db = match Surreal::new::<Mem>(()).await {
            Ok(db) => db,
            Err(error) => panic!("in-memory SurrealDB setup should succeed: {}", error),
        };
        let repository = match SurrealDbRepository::new(db, DatabaseScope::default()) {
            Ok(repository) => repository,
            Err(error) => panic!("repository construction should succeed: {}", error),
        };

        let account_id = Uuid::now_v7();
        let first_secret = match Secret::new(
            &account_id,
            "first-password",
            match Argon2Hasher::new_recommended() {
                Ok(hasher) => hasher,
                Err(error) => panic!("hasher construction should succeed: {}", error),
            },
        ) {
            Ok(secret) => secret,
            Err(error) => panic!("secret construction should succeed: {}", error),
        };
        let second_secret = match Secret::new(
            &account_id,
            "second-password",
            match Argon2Hasher::new_recommended() {
                Ok(hasher) => hasher,
                Err(error) => panic!("hasher construction should succeed: {}", error),
            },
        ) {
            Ok(secret) => secret,
            Err(error) => panic!("secret construction should succeed: {}", error),
        };

        let first_store = match repository.store_secret(first_secret).await {
            Ok(stored) => stored,
            Err(error) => panic!("first store should succeed: {}", error),
        };
        assert!(first_store);

        let second_store = match repository.store_secret(second_secret).await {
            Ok(stored) => stored,
            Err(error) => panic!("second store should succeed: {}", error),
        };
        assert!(!second_store);
    }

    #[tokio::test]
    async fn delete_secret_returns_removed_secret() {
        let db = match Surreal::new::<Mem>(()).await {
            Ok(db) => db,
            Err(error) => panic!("in-memory SurrealDB setup should succeed: {}", error),
        };
        let repository = match SurrealDbRepository::new(db, DatabaseScope::default()) {
            Ok(repository) => repository,
            Err(error) => panic!("repository construction should succeed: {}", error),
        };

        let account_id = Uuid::now_v7();
        let secret = match Secret::new(
            &account_id,
            "password",
            match Argon2Hasher::new_recommended() {
                Ok(hasher) => hasher,
                Err(error) => panic!("hasher construction should succeed: {}", error),
            },
        ) {
            Ok(secret) => secret,
            Err(error) => panic!("secret construction should succeed: {}", error),
        };

        let stored = match repository.store_secret(secret.clone()).await {
            Ok(stored) => stored,
            Err(error) => panic!("store should succeed: {}", error),
        };
        assert!(stored);

        let removed = match repository.delete_secret(&account_id).await {
            Ok(removed) => removed,
            Err(error) => panic!("delete should succeed: {}", error),
        };
        assert!(removed.is_some());

        let removed_secret = match removed {
            Some(secret) => secret,
            None => panic!("removed secret should exist"),
        };
        assert_eq!(removed_secret.account_id, secret.account_id);
        assert_eq!(removed_secret.secret, secret.secret);

        let missing = match repository.delete_secret(&account_id).await {
            Ok(missing) => missing,
            Err(error) => panic!("second delete should succeed: {}", error),
        };
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn verify_credentials_uses_updated_secret() {
        let db = match Surreal::new::<Mem>(()).await {
            Ok(db) => db,
            Err(error) => panic!("in-memory SurrealDB setup should succeed: {}", error),
        };
        let repository = match SurrealDbRepository::new(db, DatabaseScope::default()) {
            Ok(repository) => repository,
            Err(error) => panic!("repository construction should succeed: {}", error),
        };

        let account_id = Uuid::now_v7();
        let initial_secret = match Secret::new(
            &account_id,
            "initial-password",
            match Argon2Hasher::new_recommended() {
                Ok(hasher) => hasher,
                Err(error) => panic!("hasher construction should succeed: {}", error),
            },
        ) {
            Ok(secret) => secret,
            Err(error) => panic!("secret construction should succeed: {}", error),
        };
        let updated_secret = match Secret::new(
            &account_id,
            "updated-password",
            match Argon2Hasher::new_recommended() {
                Ok(hasher) => hasher,
                Err(error) => panic!("hasher construction should succeed: {}", error),
            },
        ) {
            Ok(secret) => secret,
            Err(error) => panic!("secret construction should succeed: {}", error),
        };

        let stored = match repository.store_secret(initial_secret).await {
            Ok(stored) => stored,
            Err(error) => panic!("initial store should succeed: {}", error),
        };
        assert!(stored);

        if let Err(error) = repository.update_secret(updated_secret).await {
            panic!("update should succeed: {}", error);
        }

        let old_result: VerificationResult = match repository
            .verify_credentials(Credentials::new(&account_id, "initial-password"))
            .await
        {
            Ok(result) => result,
            Err(error) => panic!("old credential verification should succeed: {}", error),
        };
        assert_eq!(old_result, VerificationResult::Unauthorized);

        let new_result: VerificationResult = match repository
            .verify_credentials(Credentials::new(&account_id, "updated-password"))
            .await
        {
            Ok(result) => result,
            Err(error) => panic!("new credential verification should succeed: {}", error),
        };
        assert_eq!(new_result, VerificationResult::Ok);
    }
}
