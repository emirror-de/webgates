//! Account deletion workflow for removing an account and its secret.
//!
//! This module keeps the repository-level delete orchestration separate from
//! account creation so the public service surface stays focused and easier to
//! navigate.

use std::sync::Arc;

use crate::account_repository::AccountRepository;
#[cfg(feature = "audit-logging")]
use crate::audit;
use crate::errors::{
    Error as RepoError, RepositoriesError, RepositoryOperation, RepositoryType,
    Result as RepoResult,
};
use crate::secret_repository::SecretRepository;
use tracing::{debug, error, info, warn};
use webgates_core::accounts::Account;
use webgates_core::authz::access_hierarchy::AccessHierarchy;

/// Removes the given account and its corresponding secret from repositories.
///
/// This workflow is intentionally ordered to support a compensating action:
/// the secret is removed first and cached locally, then the account is deleted.
/// If account deletion fails, the service attempts to restore the previously
/// removed secret.
///
/// # Type Parameters
/// - `R`: role type used by the account domain model
/// - `G`: group type used by the account domain model
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
    /// This constructor is side-effect free. Call
    /// [`from_repositories`](Self::from_repositories) to execute the deletion.
    pub fn delete(account: Account<R, G>) -> Self {
        Self { account }
    }

    /// Performs the deletion workflow against the provided repositories.
    ///
    /// Workflow:
    /// 1. Remove and cache the secret associated with the account.
    /// 2. Delete the account.
    /// 3. If account deletion fails, attempt a best-effort secret restore.
    ///
    /// # Errors
    /// Returns an error when:
    /// - the secret does not exist
    /// - secret deletion fails
    /// - account deletion fails
    /// - secret restoration fails after an account deletion failure
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

        let Some(secret) = secret_repository.delete_secret(account_id).await? else {
            error!(%user_id, %account_id, "Secret missing for account deletion attempt");
            #[cfg(feature = "audit-logging")]
            audit::account_delete_failure(user_id, account_id, None, "secret_missing");
            return Err(RepositoriesError::not_found(
                RepositoryType::Secret,
                Some(account_id.to_string()),
            )
            .into());
        };
        debug!(%user_id, %account_id, "Secret removed for account");

        if account_repository
            .delete_account(account_id)
            .await?
            .is_none()
        {
            error!(
                %user_id,
                %account_id,
                "Account deletion failed; attempting secret restore"
            );

            let restore_result = secret_repository.store_secret(secret).await;
            match restore_result {
                Ok(true) => {
                    warn!(
                        %user_id,
                        %account_id,
                        "Secret restored after account deletion failure"
                    );
                    #[cfg(feature = "audit-logging")]
                    audit::account_delete_failure(
                        user_id,
                        account_id,
                        Some(true),
                        "account_deletion_failed_secret_restored",
                    );
                }
                Ok(false) => {
                    error!(
                        %user_id,
                        %account_id,
                        "Secret restore reported false after account deletion failure"
                    );
                    #[cfg(feature = "audit-logging")]
                    audit::account_delete_failure(
                        user_id,
                        account_id,
                        Some(false),
                        "account_deletion_failed_restore_reported_false",
                    );
                }
                Err(ref error) => {
                    error!(
                        error = %error,
                        %user_id,
                        %account_id,
                        "Secret restore failed after account deletion failure"
                    );
                    #[cfg(feature = "audit-logging")]
                    audit::account_delete_failure(
                        user_id,
                        account_id,
                        None,
                        &format!("account_deletion_failed_secret_restore_error: {error}"),
                    );
                }
            }

            return Err(RepositoriesError::operation_failed(
                RepositoryType::Account,
                RepositoryOperation::Delete,
                "Account deletion failed",
                Some(account_id.to_string()),
                None,
            )
            .into());
        }

        info!(%user_id, %account_id, "Account deletion succeeded");
        #[cfg(feature = "audit-logging")]
        audit::account_delete_success(user_id, account_id);

        Ok(())
    }
}
