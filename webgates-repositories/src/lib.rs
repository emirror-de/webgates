#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

/*!
# webgates-repositories

Repository implementations and storage backends for the `webgates` authentication
and authorization domain. Use this crate when you need persistence for accounts,
credentials, permission mappings, or groups.

## Backends

- [`memory`] — zero-configuration, in-memory stores for development and testing.
- [`surrealdb`] *(feature: `repo-surrealdb`)* — SurrealDB-backed repositories.
- [`sea_orm`] *(feature: `repo-seaorm`)* — SQL-backed repositories via SeaORM.

## Feature flags

- `repo-surrealdb`: enable SurrealDB repositories.
- `repo-seaorm`: enable SeaORM repositories.
- `server`: transitively pulls in async runtime support required by the backends.

## Quick start

In-memory (no feature flags required):

```rust
use std::sync::Arc;
use webgates_repositories::memory::{MemoryAccountRepository, MemorySecretRepository};
use webgates::prelude::{Group, Role};

let accounts = Arc::new(MemoryAccountRepository::<Role, Group>::default());
let secrets = Arc::new(MemorySecretRepository::new_with_argon2_hasher().unwrap());
```

SeaORM (SQL) — requires `repo-seaorm`:

```rust
# #[cfg(feature = "repo-seaorm")]
# async fn example(db: sea_orm::DatabaseConnection) -> anyhow::Result<()> {
use std::sync::Arc;
use webgates_repositories::sea_orm::SeaOrmRepository;

let repo = Arc::new(SeaOrmRepository::new(&db)?);
# Ok(())
# }
```

SurrealDB — requires `repo-surrealdb`:

```rust
# #[cfg(feature = "repo-surrealdb")]
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

#[cfg(feature = "repo-seaorm")]
pub mod comma_separated_value;
pub mod errors;
pub mod memory;
#[cfg(feature = "repo-seaorm")]
pub mod sea_orm;
#[cfg(feature = "server")]
pub mod services;
#[cfg(feature = "repo-surrealdb")]
pub mod surrealdb;

pub use errors::{
    DatabaseError, DatabaseOperation, Error, RepositoriesError, RepositoryOperation,
    RepositoryType, Result,
};

/// Stable table names used by the storage backends.
#[cfg(any(feature = "repo-surrealdb", feature = "repo-seaorm"))]
#[derive(strum::Display, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[strum(serialize_all = "snake_case")]
pub enum TableName {
    /// Account storage table name.
    AxumGateAccounts,
    /// Credentials storage table name.
    AxumGateCredentials,
    /// Permission mappings storage table name.
    AxumGatePermissionMappings,
    /// Groups storage table name (used by group repository implementations).
    AxumGateGroups,
}
