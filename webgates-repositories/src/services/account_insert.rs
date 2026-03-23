use std::sync::Arc;

use crate::account_repository::AccountRepository;
#[cfg(feature = "audit-logging")]
use crate::audit;
use crate::errors::{
    Error as RepoError, RepositoriesError, RepositoryOperation, RepositoryType,
    Result as RepoResult,
};
use crate::secret_repository::SecretRepository;
use tracing::debug;
use webgates_core::accounts::Account;
use webgates_core::authz::AccessHierarchy;
use webgates_core::permissions::Permissions;
use webgates_secrets::Secret;
use webgates_secrets::hashing::argon2::Argon2Hasher;

/// Service for creating a new account together with its authentication secret.
///
/// This service is a small boundary orchestrator:
/// - it builds a domain [`Account`]
/// - stores the account through an [`AccountRepository`]
/// - hashes and stores the corresponding [`Secret`] through a [`SecretRepository`]
///
/// The service does not own repository implementations and stays generic over the
/// storage backend.
///
/// # Examples
///
/// ```rust
/// use std::sync::Arc;
/// use webgates_core::accounts::Account;
/// use webgates_core::groups::Group;
/// use webgates_core::roles::Role;
/// use webgates_repositories::memory::account::MemoryAccountRepository;
/// use webgates_repositories::memory::secret::MemorySecretRepository;
/// use webgates_repositories::services::account_insert::AccountInsertService;
///
/// # tokio_test::block_on(async {
/// let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
/// let secret_repo = Arc::new(MemorySecretRepository::new_with_argon2_hasher().unwrap());
///
/// let created: Account<Role, Group> = AccountInsertService::insert("user@example.com", "password")
///     .with_roles(vec![Role::User])
///     .with_groups(vec![Group::new("engineering")])
///     .into_repositories(account_repo, secret_repo)
///     .await
///     .unwrap()
///     .unwrap();
///
/// assert_eq!(created.user_id, "user@example.com");
/// # });
/// ```
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
    /// Creates a new account insertion builder with the provided credentials.
    pub fn insert(user_id: &str, secret: &str) -> Self {
        Self {
            user_id: user_id.to_string(),
            secret: secret.to_string(),
            roles: Vec::new(),
            groups: Vec::new(),
            permissions: Permissions::new(),
        }
    }

    /// Replaces the account roles to be stored.
    pub fn with_roles(self, roles: Vec<R>) -> Self {
        Self { roles, ..self }
    }

    /// Replaces the account groups to be stored.
    pub fn with_groups(self, groups: Vec<G>) -> Self {
        Self { groups, ..self }
    }

    /// Replaces the account permissions to be stored.
    pub fn with_permissions(self, permissions: Permissions) -> Self {
        Self {
            permissions,
            ..self
        }
    }

    /// Stores the account and its corresponding secret in the provided repositories.
    ///
    /// # Errors
    ///
    /// Returns an error when:
    /// - account creation fails in the account repository
    /// - the account repository reports an unexpected `None`
    /// - secret hashing fails
    /// - secret storage fails
    ///
    /// # Return value
    ///
    /// Returns `Ok(Some(account))` on success.
    pub async fn into_repositories<AccRepo, SecRepo>(
        self,
        account_repository: Arc<AccRepo>,
        secret_repository: Arc<SecRepo>,
    ) -> RepoResult<Option<Account<R, G>>>
    where
        AccRepo: AccountRepository<R, G, Error = RepoError>,
        SecRepo: SecretRepository<Error = RepoError>,
    {
        let user_id = self.user_id;
        let secret = self.secret;
        let account = Account::new(user_id.clone(), self.roles, self.groups)
            .with_permissions(self.permissions);

        debug!("Created account builder payload.");

        let Some(account) = account_repository.store_account(account).await? else {
            #[cfg(feature = "audit-logging")]
            {
                audit::account_insert_failure(&user_id, "account_repo_none");
            }

            return Err(RepositoriesError::operation_failed(
                RepositoryType::Account,
                RepositoryOperation::Insert,
                "Account repository returned None on insertion",
                Some(user_id.clone()),
                None,
            )
            .into());
        };

        #[cfg(feature = "audit-logging")]
        {
            audit::account_created(&user_id, &account.account_id);
        }

        debug!("Stored account in account repository.");

        let secret = Secret::new(
            &account.account_id,
            &secret,
            Argon2Hasher::new_recommended()?,
        )?;

        if !secret_repository.store_secret(secret).await? {
            #[cfg(feature = "audit-logging")]
            {
                audit::account_insert_failure(&user_id, "secret_store_false");
            }

            return Err(RepositoriesError::operation_failed(
                RepositoryType::Secret,
                RepositoryOperation::Insert,
                "Storing secret in repository returned false",
                Some(account.account_id.to_string()),
                None,
            )
            .into());
        }

        debug!("Stored secret in secret repository.");

        Ok(Some(account))
    }
}
