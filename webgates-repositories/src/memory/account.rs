use crate::account_repository::AccountRepository;
use crate::errors::{
    Error as RepoError, RepositoriesError, RepositoryOperation, RepositoryType, Result,
};
use webgates_core::accounts::Account;
use webgates_core::authz::access_hierarchy::AccessHierarchy;

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use uuid::Uuid;

/// In-memory repository for storing and retrieving user accounts.
///
/// This repository stores all account data in memory using a HashMap with the user ID
/// as the key. It's thread-safe and supports concurrent access through async read/write locks.
///
/// # Performance Characteristics
/// - O(1) lookup by user ID
/// - Thread-safe with RwLock
/// - No persistence (data lost when dropped)
/// - Suitable for up to thousands of accounts
///
/// # Example
/// ```rust
/// use webgates_core::accounts::Account;
/// use webgates_core::groups::Group;
/// use webgates_core::roles::Role;
/// use webgates_repositories::account_repository::AccountRepository;
/// use webgates_repositories::memory::account::MemoryAccountRepository;
/// use std::sync::Arc;
///
/// # tokio_test::block_on(async {
/// let repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
///
/// // Store an account
/// let account = Account::<Role, Group>::new("user@example.com");
/// let stored: Option<Account<Role, Group>> = repo.store_account(account).await.unwrap();
///
/// // Query the account
/// let found: Option<Account<Role, Group>> = repo.query_account_by_user_id("user@example.com").await.unwrap();
/// assert!(stored.is_some());
/// assert!(found.is_some());
/// # });
/// ```
#[derive(Clone)]
pub struct MemoryAccountRepository<R, G>
where
    R: AccessHierarchy + Eq + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    accounts: Arc<RwLock<HashMap<String, Account<R, G>>>>,
}

impl<R, G> Default for MemoryAccountRepository<R, G>
where
    R: AccessHierarchy + Eq + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self {
            accounts: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl<R, G> From<Vec<Account<R, G>>> for MemoryAccountRepository<R, G>
where
    R: AccessHierarchy + Eq + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    fn from(value: Vec<Account<R, G>>) -> Self {
        let mut accounts = HashMap::new();
        for val in value {
            let id = val.account_id.to_string();
            accounts.insert(id, val);
        }
        let accounts = Arc::new(RwLock::new(accounts));
        Self { accounts }
    }
}

impl<R, G> AccountRepository<R, G> for MemoryAccountRepository<R, G>
where
    Account<R, G>: Clone,
    R: AccessHierarchy + Eq + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    type Error = RepoError;

    async fn bootstrap(&self) -> Result<()> {
        Ok(())
    }

    /// Lookup by the logical login identifier (`user_id`).
    ///
    /// The in-memory store's primary key is the stable `account_id` (UUID string).
    /// To fetch by `user_id` we scan the values; this is acceptable for tests and
    /// small datasets but should not be used as a model for production storage.
    async fn query_account_by_user_id(&self, user_id: &str) -> Result<Option<Account<R, G>>> {
        let res: Result<_> = {
            let read = self.accounts.read().await;
            let found = read.values().find(|acc| acc.user_id == user_id).cloned();
            Ok(found)
        };
        res
    }

    /// Query an account by its `account_id` field.
    ///
    /// The in-memory repository stores accounts keyed by the stable `account_id`
    /// (UUID string). This makes direct lookups efficient.
    async fn query_account_by_id(&self, account_id: &Uuid) -> Result<Option<Account<R, G>>> {
        let res: Result<_> = {
            let read = self.accounts.read().await;
            let key = account_id.to_string();
            Ok(read.get(&key).cloned())
        };
        res
    }

    /// Store an account using the stable `account_id` as the map key while
    /// preserving the `user_id` field inside the `Account`.
    async fn store_account(&self, account: Account<R, G>) -> Result<Option<Account<R, G>>> {
        let res: Result<_> = {
            let account_id = account.account_id.to_string();
            let user_id = account.user_id.clone();
            let mut write = self.accounts.write().await;

            if write.contains_key(&account_id) {
                return Err(RepoError::Repositories(
                    RepositoriesError::constraint_for_key(
                        RepositoryType::Account,
                        account_id,
                        "Account with the same account_id already exists",
                    ),
                ));
            }

            if write.values().any(|stored| stored.user_id == user_id) {
                return Err(RepoError::Repositories(
                    RepositoriesError::constraint_for_key(
                        RepositoryType::Account,
                        user_id,
                        "Account with the same user_id already exists",
                    ),
                ));
            }

            write.insert(account_id, account.clone());
            Ok(Some(account))
        };
        res
    }

    /// Delete an account by its stable `account_id` (UUID).
    async fn delete_account(&self, account_id: &Uuid) -> Result<Option<Account<R, G>>> {
        let res: Result<_> = {
            let mut write = self.accounts.write().await;
            let key = account_id.to_string();
            Ok(write.remove(&key))
        };
        res
    }

    async fn update_account(&self, account: Account<R, G>) -> Result<Option<Account<R, G>>> {
        let res: Result<_> = {
            let account_id = account.account_id.to_string();
            let user_id = account.user_id.clone();
            let mut write = self.accounts.write().await;

            if !write.contains_key(&account_id) {
                return Ok(None);
            }

            if write
                .values()
                .any(|stored| stored.account_id != account.account_id && stored.user_id == user_id)
            {
                return Err(RepoError::Repositories(
                    RepositoriesError::operation_failed(
                        RepositoryType::Account,
                        RepositoryOperation::Update,
                        "Account with the same user_id already exists",
                        Some(user_id),
                        None,
                    ),
                ));
            }

            write.insert(account_id, account.clone());
            Ok(Some(account))
        };
        res
    }

    async fn query_all_accounts(&self) -> Result<Vec<Account<R, G>>> {
        let res: Result<_> = {
            let read = self.accounts.read().await;
            Ok(read.values().cloned().collect())
        };
        res
    }
}
