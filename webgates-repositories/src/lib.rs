#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
/*!
# webgates-repositories

Repository implementations and storage backends for the `webgates` authentication
and authorization domain. Use this crate when you need persistence for accounts,
credentials, permission mappings, or groups.

## Public API

This crate exposes repository contracts and backend modules through explicit module
paths:

- [`account_repository`] — account persistence trait
- [`group_repository`] — group persistence trait
- [`permission_mapping_repository`] — permission mapping persistence traits
- [`secret_repository`] — secret persistence trait
- [`memory`] — zero-configuration, in-memory stores for development and testing
- [`surrealdb`] *(feature: `surrealdb`)* — SurrealDB-backed repositories
- [`sea_orm`] *(feature: `sea-orm`)* — SQL-backed repositories via SeaORM
- [`services`] — repository-level account workflows

Use these canonical module paths instead of crate-root shortcuts.

## Feature flags

- `surrealdb`: enable SurrealDB repositories.
- `sea-orm`: enable SeaORM repositories.
- `audit-logging`: enable structured audit events for repository workflows.

## Quick start

In-memory (no feature flags required):

```rust
use std::sync::Arc;
use webgates_core::groups::Group;
use webgates_core::roles::Role;
use webgates_repositories::memory::account::MemoryAccountRepository;
use webgates_repositories::memory::secret::MemorySecretRepository;

let accounts = Arc::new(MemoryAccountRepository::<Role, Group>::default());
let secrets = Arc::new(MemorySecretRepository::new_with_argon2_hasher().unwrap());
```

SeaORM (SQL) — requires `sea-orm`:

```rust
# #[cfg(feature = "sea-orm")]
# async fn example(db: sea_orm::DatabaseConnection) -> Result<(), Box<dyn std::error::Error>> {
use std::sync::Arc;
use webgates_repositories::sea_orm::SeaOrmRepository;

let repo = Arc::new(SeaOrmRepository::new(&db)?);
# Ok(())
# }
```

SurrealDB — requires `surrealdb`:

```rust
# #[cfg(feature = "surrealdb")]
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
use std::sync::Arc;
use surrealdb::engine::local::Mem;
use surrealdb::Surreal;
use webgates_repositories::surrealdb::{DatabaseScope, SurrealDbRepository};

let db = Surreal::new::<Mem>(()).await?;
let repo = Arc::new(SurrealDbRepository::new(db, DatabaseScope::default())?);
# Ok(())
# }
```
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
