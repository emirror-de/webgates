use std::future::Future;

use uuid::Uuid;
use webgates_core::accounts::Account;
use webgates_core::authz::access_hierarchy::AccessHierarchy;

/// Persists and retrieves [`Account`] entities.
///
/// Higher-level crates use this trait to create, update, delete, and query
/// accounts without depending on a specific storage backend.
///
/// # Identifier semantics
///
/// `user_id` is the logical login identifier used in authentication and
/// user-facing flows. `account_id` is the stable internal UUID used for
/// persistence operations such as deletes, secret storage, and cross-table
/// references.
///
/// Implementations should enforce uniqueness of both identifiers where
/// possible, and should document timing characteristics for lookups used in
/// authentication flows.
///
/// # Errors
///
/// Return `Ok(Some(account))` on successful materialization, `Ok(None)` when a
/// requested account does not exist, and `Err(..)` for exceptional backend
/// failures.
pub trait AccountRepository<R, G>
where
    Self: Send + Sync,
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    /// Backend-specific error type for repository operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Prepares the repository backend for use.
    ///
    /// Implementations may use this hook to create tables, indexes, or other
    /// storage-specific structures required for subsequent repository operations.
    fn bootstrap(&self) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Persists a new account.
    ///
    /// Implementations MUST enforce uniqueness of both `account_id` and
    /// `user_id`. Returning `Ok(Some(account))` indicates success. Returning
    /// `Ok(None)` is discouraged unless the backend intentionally exposes
    /// conditional insert semantics.
    fn store_account(
        &self,
        account: Account<R, G>,
    ) -> impl Future<Output = Result<Option<Account<R, G>>, Self::Error>> + Send;

    /// Deletes an account identified by its stable `account_id`.
    fn delete_account(
        &self,
        account_id: &Uuid,
    ) -> impl Future<Output = Result<Option<Account<R, G>>, Self::Error>> + Send;

    /// Updates an existing account.
    ///
    /// Implementations may perform either full replacement or partial
    /// persistence depending on backend capabilities.
    fn update_account(
        &self,
        account: Account<R, G>,
    ) -> impl Future<Output = Result<Option<Account<R, G>>, Self::Error>> + Send;

    /// Fetches an account by its logical user identifier (`user_id`).
    ///
    /// This lookup is commonly used during authentication flows. Implementations
    /// SHOULD take care to avoid leaking timing differences that could be used
    /// to enumerate existing user_ids.
    fn query_account_by_user_id(
        &self,
        user_id: &str,
    ) -> impl Future<Output = Result<Option<Account<R, G>>, Self::Error>> + Send;

    /// Fetches an account by its stable internal identifier (`account_id` / UUID).
    ///
    /// This is the recommended lookup form for operations that must operate on
    /// the canonical, immutable account identifier (deletions, secret operations,
    /// cross-table references).
    fn query_account_by_id(
        &self,
        account_id: &Uuid,
    ) -> impl Future<Output = Result<Option<Account<R, G>>, Self::Error>> + Send;

    /// Queries all accounts in the repository.
    ///
    /// Implementations should document ordering semantics, if any. For large
    /// datasets, prefer a paginated variant over loading all accounts into
    /// memory.
    fn query_all_accounts(
        &self,
    ) -> impl Future<Output = Result<Vec<Account<R, G>>, Self::Error>> + Send;
}
