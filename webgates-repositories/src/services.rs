//! Repository-level services for common account workflows.
//!
//! These services coordinate repository traits for common persistence workflows
//! without introducing a broader application-layer dependency.
//!
//! # Usage notes
//!
//! - works with any `AccountRepository` and `SecretRepository` implementation
//! - uses Argon2 hashing via `webgates_secrets::hashing` for secrets
//! - supports optional audit logging when the `audit-logging` feature is enabled
//!
//! # Examples
//!
//! ```rust
//! use std::sync::Arc;
//! use webgates_core::groups::Group;
//! use webgates_core::roles::Role;
//! use webgates_repositories::memory::account::MemoryAccountRepository;
//! use webgates_repositories::memory::secret::MemorySecretRepository;
//! use webgates_repositories::services::account_insert::AccountInsertService;
//!
//! # tokio_test::block_on(async {
//! let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
//! let secret_repo = Arc::new(MemorySecretRepository::new_with_argon2_hasher().unwrap());
//!
//! let created: webgates_core::accounts::Account<Role, Group> =
//!     AccountInsertService::insert("user@example.com", "password")
//!         .with_roles(vec![Role::User])
//!         .with_groups(vec![Group::new("engineering")])
//!         .into_repositories(account_repo, secret_repo)
//!         .await
//!         .unwrap()
//!         .unwrap();
//!
//! assert_eq!(created.user_id, "user@example.com");
//! # });
//! ```
//!
//! ```rust
//! use std::sync::Arc;
//! use webgates_core::groups::Group;
//! use webgates_core::roles::Role;
//! use webgates_repositories::memory::account::MemoryAccountRepository;
//! use webgates_repositories::memory::secret::MemorySecretRepository;
//! use webgates_repositories::services::account_delete::AccountDeleteService;
//! use webgates_repositories::services::account_insert::AccountInsertService;
//!
//! # tokio_test::block_on(async {
//! let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
//! let secret_repo = Arc::new(MemorySecretRepository::new_with_argon2_hasher().unwrap());
//!
//! let account: webgates_core::accounts::Account<Role, Group> =
//!     AccountInsertService::insert("deleteme@example.com", "password")
//!         .into_repositories(Arc::clone(&account_repo), Arc::clone(&secret_repo))
//!         .await
//!         .unwrap()
//!         .unwrap();
//!
//! AccountDeleteService::delete(account)
//!     .from_repositories(account_repo, secret_repo)
//!     .await
//!     .unwrap();
//! # });
//! ```

/// Account deletion workflow service.
pub mod account_delete;
/// Account insertion workflow service.
pub mod account_insert;

#[cfg(test)]
mod tests;
