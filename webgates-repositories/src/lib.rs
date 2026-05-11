#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
/*!
# webgates-repositories

User-focused repository contracts and storage backends for the `webgates` ecosystem.

This crate is the persistence layer of the workspace. It provides repository
traits, in-memory implementations, optional database backends, shared repository
errors, and repository-scoped workflows for common account operations.

## When to use this crate

Use `webgates-repositories` when you want:

- persistence contracts for accounts, secrets, groups, and permission mappings
- in-memory repositories for tests or local development
- SeaORM or SurrealDB storage backends
- session repository implementations for `webgates-sessions`
- repository-level services such as account insert and delete

## How to approach this crate

Most developers should choose one layer first:

- start with [`account_repository`], [`secret_repository`], or the other trait modules when defining a persistence boundary
- start with [`memory`] when you want zero-configuration repositories for tests or local development
- move to [`services`] when you want repository-scoped account workflows
- enable [`surrealdb`] or [`sea_orm`] only when you are ready to connect a real backend

Use these canonical module paths instead of crate-root shortcuts.

## Quick start

In-memory repositories are the easiest way to get started:

```rust
use std::sync::Arc;
use webgates_core::groups::Group;
use webgates_core::roles::Role;
use webgates_repositories::memory::account::MemoryAccountRepository;
use webgates_repositories::memory::secret::MemorySecretRepository;

let accounts = Arc::new(MemoryAccountRepository::<Role, Group>::default());
let secrets = Arc::new(MemorySecretRepository::new_with_argon2_hasher().unwrap());

let _ = (accounts, secrets);
```

## Getting started on docs.rs

A good reading order is:

1. [`account_repository`] and [`secret_repository`]
2. [`memory`]
3. [`services`]
4. [`sea_orm`] or [`surrealdb`] if you need persistent storage
*/

/// Repository trait for account persistence backends.
pub mod account_repository;
#[cfg(feature = "audit-logging")]
pub mod audit;
#[cfg(feature = "sea-orm")]
pub mod comma_separated_value;
pub mod errors;
/// Repository trait for group persistence backends.
pub mod group_repository;
pub mod memory;
/// Repository traits for permission mapping persistence backends.
pub mod permission_mapping_repository;
#[cfg(feature = "sea-orm")]
pub mod sea_orm;
/// Repository trait for secret persistence backends.
pub mod secret_repository;
pub mod services;
#[cfg(feature = "surrealdb")]
pub mod surrealdb;

/// Stable table names used by the storage backends.
#[cfg(any(feature = "surrealdb", feature = "sea-orm"))]
#[derive(strum::Display, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[strum(serialize_all = "snake_case")]
pub enum TableName {
    /// Account storage table name.
    WebgatesAccounts,
    /// Credentials storage table name.
    WebgatesCredentials,
    /// Permission mappings storage table name.
    WebgatesPermissionMappings,
    /// Groups storage table name (used by group repository implementations).
    WebgatesGroups,
}
