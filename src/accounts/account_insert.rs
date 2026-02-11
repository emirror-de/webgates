use super::{Account, AccountRepository};
use crate::accounts::{AccountOperation, AccountsError};
#[cfg(feature = "audit-logging")]
use crate::audit;
use crate::authz::AccessHierarchy;
use crate::errors::{Error, Result};
use crate::hashing::argon2::Argon2Hasher;
use crate::permissions::Permissions;
use crate::secrets::{Secret, SecretRepository};

use std::sync::Arc;

use tracing::debug;

/// Service for creating new user accounts with their associated authentication secrets.
///
/// This service provides an ergonomic builder pattern for creating accounts with roles,
/// groups, and permissions, then storing both the account data and authentication secrets
/// in their respective repositories.
///
/// # Basic Usage
///
/// ```rust
/// use axum_gate::accounts::AccountInsertService;
/// use axum_gate::prelude::{Role, Group};
/// use axum_gate::repositories::memory::{MemoryAccountRepository, MemorySecretRepository};
/// use std::sync::Arc;
///
/// # tokio_test::block_on(async {
/// let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
/// let secret_repo = Arc::new(MemorySecretRepository::new_with_argon2_hasher().unwrap());
///
/// let account = AccountInsertService::insert("user@example.com", "secure_password")
///     .with_roles(vec![Role::User])
///     .with_groups(vec![Group::new("staff")])
///     .into_repositories(account_repo, secret_repo)
///     .await
///     .unwrap()
///     .unwrap();
///
/// println!("Created account: {}", account.user_id);
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
    /// Creates a new account insertion builder with the specified credentials.
    ///
    /// This is the starting point for creating a new account. The user ID should be
    /// unique within your application (typically an email or username), and the secret
    /// will be hashed before storage using Argon2.
    ///
    /// # Arguments
    /// * `user_id` - Unique identifier for the user (e.g., email or username)
    /// * `secret` - Plain text password that will be securely hashed
    ///
    /// # Example
    /// ```rust
    /// use axum_gate::accounts::AccountInsertService;
    /// use axum_gate::prelude::{Role, Group};
    ///
    /// let builder = AccountInsertService::<Role, Group>::insert("admin@example.com", "strong_password");
    /// // Continue with .with_roles(), .with_groups(), etc.
    /// ```
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
    ///
    /// Roles determine what actions the user can perform. Use the pre-defined
    /// `Role` enum or create your own custom role type.
    ///
    /// # Example
    /// ```rust
    /// use axum_gate::accounts::AccountInsertService;
    /// use axum_gate::prelude::{Role, Group};
    ///
    /// let builder = AccountInsertService::<Role, Group>::insert("user@example.com", "password")
    ///     .with_roles(vec![Role::User, Role::Reporter]);
    /// ```
    pub fn with_roles(self, roles: Vec<R>) -> Self {
        Self { roles, ..self }
    }

    /// Adds groups to the account being created.
    ///
    /// Groups provide organizational structure for users, such as department
    /// or team membership. They offer another dimension of access control.
    ///
    /// # Example
    /// ```rust
    /// use axum_gate::accounts::AccountInsertService;
    /// use axum_gate::prelude::{Role, Group};
    ///
    /// let builder = AccountInsertService::<Role, Group>::insert("user@example.com", "password")
    ///     .with_groups(vec![Group::new("engineering"), Group::new("backend-team")]);
    /// ```
    pub fn with_groups(self, groups: Vec<G>) -> Self {
        Self { groups, ..self }
    }

    /// Adds custom permissions to the account being created.
    ///
    /// This method allows you to set specific permissions using the zero-synchronization
    /// permission system. Permissions are stored as a compressed bitmap for efficiency.
    ///
    /// # Arguments
    /// * `permissions` - A Permissions set containing the permission names
    ///
    /// # Example
    /// ```rust
    /// use axum_gate::accounts::AccountInsertService;
    /// use axum_gate::permissions::Permissions;
    /// use axum_gate::prelude::{Role, Group};
    ///
    /// let permissions: Permissions = [
    ///     "read:api",
    ///     "write:api",
    ///     "manage:users"
    /// ].into_iter().collect();
    ///
    /// let builder = AccountInsertService::<Role, Group>::insert("admin@example.com", "password")
    ///     .with_permissions(permissions);
    /// ```
    pub fn with_permissions(self, permissions: Permissions) -> Self {
        Self {
            permissions,
            ..self
        }
    }

    /// Creates the account and secret, storing them in the provided repositories.
    ///
    /// This method consumes the builder and performs the actual account creation:
    /// 1. Creates an `Account` with the specified details
    /// 2. Stores the account in the account repository
    /// 3. Hashes the password using Argon2
    /// 4. Creates and stores the secret in the secret repository
    ///
    /// Both operations must succeed for the account to be considered created.
    ///
    /// # Arguments
    /// * `account_repository` - Repository for storing account data
    /// * `secret_repository` - Repository for storing password hashes
    ///
    /// # Returns
    /// * `Ok(Some(Account))` - Account successfully created
    /// * `Ok(None)` - Account creation failed (repository returned None)
    /// * `Err(...)` - Error during creation process
    ///
    /// # Example
    /// ```rust
    /// use axum_gate::accounts::AccountInsertService;
    /// use axum_gate::prelude::{Role, Group};
    /// use axum_gate::repositories::memory::{MemoryAccountRepository, MemorySecretRepository};
    /// use std::sync::Arc;
    ///
    /// # tokio_test::block_on(async {
    /// let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
    /// let secret_repo = Arc::new(MemorySecretRepository::new_with_argon2_hasher().unwrap());
    ///
    /// let result = AccountInsertService::insert("user@example.com", "password")
    ///     .with_roles(vec![Role::User])
    ///     .into_repositories(account_repo, secret_repo)
    ///     .await?;
    ///
    /// match result {
    ///     Some(account) => println!("Created account: {}", account.user_id),
    ///     None => println!("Account creation failed"),
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// # });
    /// ```
    pub async fn into_repositories<AccRepo, SecRepo>(
        self,
        account_repository: Arc<AccRepo>,
        secret_repository: Arc<SecRepo>,
    ) -> Result<Option<Account<R, G>>>
    where
        AccRepo: AccountRepository<R, G>,
        SecRepo: SecretRepository,
    {
        let account = Account::new(&self.user_id, &self.roles, &self.groups)
            .with_permissions(self.permissions);
        debug!("Created account.");
        let Some(account) = account_repository.store_account(account).await? else {
            #[cfg(feature = "audit-logging")]
            {
                audit::account_insert_failure(&self.user_id, "account_repo_none");
            }
            return Err(Error::Accounts(AccountsError::operation(
                AccountOperation::Create,
                "Account repository returned None on insertion",
                Some(self.user_id.clone()),
            )));
        };
        #[cfg(feature = "audit-logging")]
        {
            // Account persisted successfully in repository
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
            Err(Error::Accounts(AccountsError::operation(
                AccountOperation::Create,
                "Storing secret in repository returned false",
                Some(account.account_id.to_string()),
            )))
        } else {
            debug!("Stored secret in secret repository.");
            Ok(Some(account))
        }
    }
}
