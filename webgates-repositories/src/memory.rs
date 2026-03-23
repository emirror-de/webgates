//! In-memory storage implementations for development and testing.
//!
//! This module provides repository implementations that store all data in memory.
//! These are ideal for development, testing, and small applications that don't
//! require persistent storage.
//!
//! # Features
//! - Zero configuration required
//! - Fast operations (no I/O)
//! - Perfect for unit tests and development
//! - Thread-safe with async support
//! - Automatic cleanup when dropped
//!
//! # Quick Start
//!
//! ```rust
//! use std::sync::Arc;
//! use webgates_core::accounts::Account;
//! use webgates_core::groups::Group;
//! use webgates_core::roles::Role;
//! use webgates_repositories::account_repository::AccountRepository;
//! use webgates_repositories::memory::account::MemoryAccountRepository;
//! use webgates_repositories::memory::permission_mapping::MemoryPermissionMappingRepository;
//! use webgates_repositories::memory::secret::MemorySecretRepository;
//! use webgates_repositories::secret_repository::SecretRepository;
//! use webgates_secrets::hashing::argon2::Argon2Hasher;
//! use webgates_secrets::Secret;
//!
//! # tokio_test::block_on(async {
//! let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
//! let secret_repo = Arc::new(MemorySecretRepository::new_with_argon2_hasher().unwrap());
//! let _mapping_repo = Arc::new(MemoryPermissionMappingRepository::default());
//!
//! let account = Account::new(
//!     "user@example.com".to_string(),
//!     vec![Role::User],
//!     vec![Group::new("staff")],
//! );
//! let stored_account: Account<Role, Group> = account_repo.store_account(account).await.unwrap().unwrap();
//!
//! let secret = Secret::new(
//!     &stored_account.account_id,
//!     "password",
//!     Argon2Hasher::new_recommended().unwrap(),
//! ).unwrap();
//! secret_repo.store_secret(secret).await.unwrap();
//!
//! let found: Option<Account<Role, Group>> = account_repo
//!     .query_account_by_user_id("user@example.com")
//!     .await
//!     .unwrap();
//! assert!(found.is_some());
//! # });
//! ```
//!
//! # Creating from Existing Data
//!
//! ```rust
//! use webgates_core::accounts::Account;
//! use webgates_core::groups::Group;
//! use webgates_core::roles::Role;
//! use webgates_repositories::memory::account::MemoryAccountRepository;
//! use webgates_repositories::memory::secret::MemorySecretRepository;
//!
//! let accounts = vec![
//!     Account::new("admin@example.com".to_string(), vec![Role::Admin], Vec::new()),
//!     Account::new(
//!         "user@example.com".to_string(),
//!         vec![Role::User],
//!         vec![Group::new("staff")],
//!     ),
//! ];
//! let account_repo = MemoryAccountRepository::from(accounts);
//!
//! let secrets = vec![];
//! let secret_repo = MemorySecretRepository::try_from(secrets).unwrap();
//! let _ = (account_repo, secret_repo);
//! ```
/// In-memory account repository implementation.
pub mod account;
/// In-memory group repository implementation.
pub mod group;
/// In-memory permission-mapping repository implementation.
pub mod permission_mapping;
/// In-memory secret repository implementation.
pub mod secret;
