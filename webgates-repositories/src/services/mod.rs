//! Repository-level services for creating and deleting accounts plus their secrets.
//!
//! These services live in the `webgates-repositories` crate so consumers can
//! perform common repository workflows without pulling in higher-level crates.
//!
//! # Features
//! - Works with any `AccountRepository` / `SecretRepository` implementation.
//! - Uses Argon2 hashing via `webgates::hashing` for secrets.
//! - Optional audit logging when the `audit-logging` feature is enabled.
//!
//! # Examples
//!
//! ```rust
//! use std::sync::Arc;
//! use webgates::prelude::{Role, Group};
//! use webgates_repositories::memory::{MemoryAccountRepository, MemorySecretRepository};
//! use webgates_repositories::services::AccountInsertService;
//!
//! # tokio_test::block_on(async {
//! let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
//! let secret_repo = Arc::new(MemorySecretRepository::new_with_argon2_hasher().unwrap());
//!
//! let created = AccountInsertService::insert("user@example.com", "password")
//!     .with_roles(vec![Role::User])
//!     .with_groups(vec![Group::new("engineering")])
//!     .into_repositories(account_repo, secret_repo)
//!     .await
//!     .unwrap()
//!     .unwrap();
//! println!("Created account {}", created.user_id);
//! # });
//! ```
//!
//! ```rust
//! use std::sync::Arc;
//! use webgates::prelude::{Role, Group};
//! use webgates_repositories::memory::{MemoryAccountRepository, MemorySecretRepository};
//! use webgates_repositories::services::{AccountDeleteService, AccountInsertService};
//!
//! # tokio_test::block_on(async {
//! let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
//! let secret_repo = Arc::new(MemorySecretRepository::new_with_argon2_hasher().unwrap());
//!
//! let account = AccountInsertService::insert("deleteme@example.com", "password")
//!     .into_repositories(Arc::clone(&account_repo), Arc::clone(&secret_repo))
//!     .await
//!     .unwrap()
//!     .unwrap();
//!
//! AccountDeleteService::delete(account)
//!     .from_repositories(account_repo, secret_repo)
//!     .await
//!     .unwrap();
//! # });
//! ```

use std::sync::Arc;

use crate::errors::{
    Error as RepoError, RepositoriesError, RepositoryOperation, RepositoryType,
    Result as RepoResult,
};
use tracing::{debug, error, info, warn};
use webgates::accounts::{Account, AccountRepository};
#[cfg(feature = "audit-logging")]
use webgates::audit;
use webgates::authz::AccessHierarchy;
use webgates::hashing::argon2::Argon2Hasher;
use webgates::permissions::Permissions;
use webgates::secrets::{Secret, SecretRepository};

/// Service for creating new user accounts with their associated authentication secrets.
///
/// This service provides an ergonomic builder pattern for creating accounts with roles,
/// groups, and permissions, then storing both the account data and authentication secrets
/// in their respective repositories.
pub struct AccountInsertService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq,
{
    user_id: String,
    secret: String,
    roles: Vec<R>,
    groups: Vec<G>,
    permissions: Permissions,
}

impl<R, G> AccountInsertService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    /// Creates a new account insertion builder with the specified credentials.
    pub fn insert(user_id: &str, secret: &str) -> Self {
        Self {
            user_id: user_id.to_string(),
            secret: secret.to_string(),
            roles: vec![],
            groups: vec![],
            permissions: Permissions::new(),
        }
    }

    /// Adds roles to the account being created.
    pub fn with_roles(self, roles: Vec<R>) -> Self {
        Self { roles, ..self }
    }

    /// Adds groups to the account being created.
    pub fn with_groups(self, groups: Vec<G>) -> Self {
        Self { groups, ..self }
    }

    /// Adds custom permissions to the account being created.
    pub fn with_permissions(self, permissions: Permissions) -> Self {
        Self {
            permissions,
            ..self
        }
    }

    /// Creates the account and secret, storing them in the provided repositories.
    ///
    /// Returns:
    /// - Ok(Some(Account)) if both account and secret are stored successfully.
    /// - Ok(None) if the repository returned None for account storage.
    /// - Err(...) on any failure.
    pub async fn into_repositories<AccRepo, SecRepo>(
        self,
        account_repository: Arc<AccRepo>,
        secret_repository: Arc<SecRepo>,
    ) -> RepoResult<Option<Account<R, G>>>
    where
        AccRepo: AccountRepository<R, G, Error = RepoError>,
        SecRepo: SecretRepository<Error = RepoError>,
    {
        let account = Account::new(&self.user_id, &self.roles, &self.groups)
            .with_permissions(self.permissions);
        debug!("Created account builder payload.");
        let Some(account) = account_repository.store_account(account).await? else {
            #[cfg(feature = "audit-logging")]
            {
                audit::account_insert_failure(&self.user_id, "account_repo_none");
            }
            return Err(RepoError::Repositories(
                RepositoriesError::operation_failed(
                    RepositoryType::Account,
                    RepositoryOperation::Insert,
                    "Account repository returned None on insertion",
                    Some(self.user_id.clone()),
                    None,
                ),
            ));
        };
        #[cfg(feature = "audit-logging")]
        {
            audit::account_created(&self.user_id, &account.account_id);
        }
        debug!("Stored account in account repository.");
        let id = &account.account_id;
        let secret = Secret::new(id, &self.secret, Argon2Hasher::new_recommended()?)?;
        if !secret_repository.store_secret(secret).await? {
            #[cfg(feature = "audit-logging")]
            {
                audit::account_insert_failure(&self.user_id, "secret_store_false");
            }
            Err(RepoError::Repositories(
                RepositoriesError::operation_failed(
                    RepositoryType::Secret,
                    RepositoryOperation::Insert,
                    "Storing secret in repository returned false",
                    Some(account.account_id.to_string()),
                    None,
                ),
            ))
        } else {
            debug!("Stored secret in secret repository.");
            Ok(Some(account))
        }
    }
}

/// Removes the given account and its corresponding secret from repositories.
///
/// Implements a compensating action: if account deletion fails after removing
/// the secret, the secret is restored (best-effort) and an error is returned.
pub struct AccountDeleteService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    account: Account<R, G>,
}

impl<R, G> AccountDeleteService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    /// Creates a deletion service for the given account.
    ///
    /// This constructor is side-effect free; it does not touch any repositories.
    /// Invoke [`from_repositories`](Self::from_repositories) to perform the actual deletion with
    /// compensating secret restoration if the account removal fails.
    pub fn delete(account: Account<R, G>) -> Self {
        Self { account }
    }

    /// Performs the deletion workflow against the provided repositories.
    ///
    /// Workflow:
    /// 1. Removes (and returns) the secret associated with the account, caching it locally.
    /// 2. Attempts to delete the account.
    /// 3. If the account deletion fails, a compensating action re-inserts the cached secret
    ///    (best-effort) and an error is returned describing the restoration result.
    pub async fn from_repositories<AccRepo, SecRepo>(
        self,
        account_repository: Arc<AccRepo>,
        secret_repository: Arc<SecRepo>,
    ) -> RepoResult<()>
    where
        AccRepo: AccountRepository<R, G, Error = RepoError>,
        SecRepo: SecretRepository<Error = RepoError>,
    {
        let user_id = &self.account.user_id;
        let account_id = &self.account.account_id;

        info!(%user_id, %account_id, "Starting account deletion");
        #[cfg(feature = "audit-logging")]
        audit::account_delete_start(user_id, account_id);

        // Remove and cache the secret so it can be restored if account deletion fails.
        let Some(secret) = secret_repository.delete_secret(account_id).await? else {
            error!(%user_id, %account_id, "Secret missing for account deletion attempt");
            #[cfg(feature = "audit-logging")]
            audit::account_delete_failure(user_id, account_id, None, "secret_missing");
            return Err(RepoError::Repositories(RepositoriesError::not_found(
                RepositoryType::Secret,
                Some(account_id.to_string()),
            )));
        };
        debug!(%user_id, %account_id, "Secret removed for account");

        // Delete the account second. If this fails, attempt to restore the secret.
        if account_repository
            .delete_account(account_id)
            .await?
            .is_none()
        {
            error!(%user_id, %account_id, "Account deletion failed; attempting secret restore");
            let restore_result = secret_repository.store_secret(secret).await;
            match restore_result {
                Ok(true) => {
                    warn!(%user_id, %account_id, "Secret restored after account deletion failure");
                    #[cfg(feature = "audit-logging")]
                    audit::account_delete_failure(
                        user_id,
                        account_id,
                        Some(true),
                        "account_deletion_failed_secret_restored",
                    );
                }
                Ok(false) => {
                    error!(%user_id, %account_id, "Secret restore reported false after account deletion failure");
                    #[cfg(feature = "audit-logging")]
                    audit::account_delete_failure(
                        user_id,
                        account_id,
                        Some(false),
                        "account_deletion_failed_restore_reported_false",
                    );
                }
                Err(ref e) => {
                    error!(error = %e, %user_id, %account_id, "Secret restore failed after account deletion failure");
                    #[cfg(feature = "audit-logging")]
                    audit::account_delete_failure(
                        user_id,
                        account_id,
                        None,
                        &format!("account_deletion_failed_secret_restore_error: {}", e),
                    );
                }
            }

            return Err(RepoError::Repositories(
                RepositoriesError::operation_failed(
                    RepositoryType::Account,
                    RepositoryOperation::Delete,
                    "Account deletion failed",
                    Some(account_id.to_string()),
                    None,
                ),
            ));
        }

        info!(%user_id, %account_id, "Account deletion succeeded");
        #[cfg(feature = "audit-logging")]
        audit::account_delete_success(user_id, account_id);
        Ok(())
    }
}
