# webgates-repositories

User-focused repository contracts and storage backends for the `webgates` ecosystem.

`webgates-repositories` is the persistence layer of the workspace. It provides repository traits, in-memory implementations, backend integrations, and repository-scoped services for accounts, secrets, permission mappings, groups, and optional session storage.

If `webgates-core` defines the domain model, `webgates-repositories` defines how that model is stored and retrieved.

## Who this crate is for

Use `webgates-repositories` when you want to:

- persist accounts and hashed secrets
- load accounts during authentication flows
- store permission mappings or groups
- use in-memory repositories for tests or local development
- add SeaORM or SurrealDB persistence backends
- back `webgates-sessions` with repository implementations
- use repository-level account insert and delete workflows

If you only need domain types, use `webgates-core`.
If you want higher-level auth orchestration, use `webgates`.
If you want transport integration, use `webgates-axum` or `webgates-tonic`.

## What this crate provides

This crate exposes:

- repository traits in dedicated trait modules
- in-memory implementations under `memory`
- optional SeaORM and SurrealDB backends behind feature flags
- optional session repository backends for `webgates-sessions`
- repository-scoped services for account insertion and deletion
- shared repository error types and result aliases

## Install

Pick only the features you need:

```toml
[dependencies]
webgates-repositories = { version = "1.0.0" }
```

Session-backed auth without a persistent backend, useful for tests or local development:

```toml
[dependencies]
webgates-repositories = { version = "1.0.0", features = ["sessions"] }
```

SeaORM backend:

```toml
[dependencies]
webgates-repositories = { version = "1.0.0", features = ["sea-orm"] }
```

SurrealDB backend:

```toml
[dependencies]
webgates-repositories = { version = "1.0.0", features = ["surrealdb"] }
```

Minimum supported Rust version: `1.91`.

## The mental model

The easiest way to think about this crate is:

1. repository traits define the persistence contracts
2. in-memory or database-backed implementations satisfy those contracts
3. higher-level crates depend on the contracts rather than concrete storage
4. repository-scoped services coordinate common workflows like account insert and delete
5. optional session repository implementations let persistence back `webgates-sessions`

## How to approach this crate

The easiest way to work with this crate is to choose one layer first:

### Start with repository traits

If you are defining your own persistence backend, start with the trait modules such as:

- `account_repository`
- `secret_repository`
- `group_repository`
- `permission_mapping_repository`

Session-backed authentication uses the framework-agnostic `webgates_sessions::repository::SessionRepository` contract, with concrete backends provided by this crate.

### Start with in-memory implementations

If you want something runnable for tests or local development, start with the `memory` module and its concrete repository types.

### Move to services when you want repository-scoped workflows

Use `services::account_insert::AccountInsertService` or `services::account_delete::AccountDeleteService` when you want the repository layer to coordinate common account workflows.

### Enable backend modules only when needed

Reach for `sea_orm` or `surrealdb` only when you are ready to connect a real persistence backend.

## Feature flags

- `default = []`
- `sessions`: enables `webgates-sessions` integration and exposes in-memory session storage
- `surrealdb`: enables the SurrealDB backend; combine with `sessions` to also include the SurrealDB session backend
- `sea-orm`: enables the SeaORM backend; combine with `sessions` to also include the SeaORM session backend
- `audit-logging`: enables repository audit events

Enable only the features you need to keep the dependency scope smaller.

## Quick starts

### In-memory account and secret repositories

```rust
use std::sync::Arc;
use webgates_core::groups::Group;
use webgates_core::roles::Role;
use webgates_repositories::memory::account::MemoryAccountRepository;
use webgates_repositories::memory::secret::MemorySecretRepository;

let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
let secret_repo = Arc::new(MemorySecretRepository::new_with_argon2_hasher()?);
# let _ = (account_repo, secret_repo);
# Ok::<(), webgates_repositories::errors::Error>(())
```

### In-memory permission mapping repository

```rust
use webgates_repositories::memory::permission_mapping::MemoryPermissionMappingRepository;

let mapping_repo = MemoryPermissionMappingRepository::default();
# let _ = mapping_repo;
```

### Account insert service

```rust
use std::sync::Arc;
use webgates_core::groups::Group;
use webgates_core::roles::Role;
use webgates_repositories::memory::account::MemoryAccountRepository;
use webgates_repositories::memory::secret::MemorySecretRepository;
use webgates_repositories::services::account_insert::AccountInsertService;

# tokio_test::block_on(async {
let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
let secret_repo = Arc::new(MemorySecretRepository::new_with_argon2_hasher().unwrap());

let account = AccountInsertService::insert("user@example.com", "password")
    .with_roles(vec![Role::User])
    .with_groups(vec![Group::new("engineering")])
    .into_repositories(account_repo, secret_repo)
    .await
    .unwrap();

assert!(account.is_some());
# });
```

### SeaORM backend

```toml
webgates-repositories = { version = "1.0.0", features = ["sea-orm"] }
sea-orm = { version = "2", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
```

```rust
use sea_orm::Database;
use webgates_repositories::sea_orm::SeaOrmRepository;

# tokio_test::block_on(async {
let db = Database::connect("postgres://...").await.unwrap();
let repo = SeaOrmRepository::new(&db).unwrap();
# let _ = repo;
# });
```

### SurrealDB backend

```toml
webgates-repositories = { version = "1.0.0", features = ["surrealdb"] }
```

```rust
use surrealdb::engine::local::Mem;
use surrealdb::Surreal;
use webgates_repositories::surrealdb::{DatabaseScope, SurrealDbRepository};

# tokio_test::block_on(async {
let db = Surreal::new::<Mem>(()).await.unwrap();
let repo = SurrealDbRepository::new(db, DatabaseScope::default()).unwrap();
# let _ = repo;
# });
```

Combine the `surrealdb` and `sessions` features together to also enable the SurrealDB session repository backend for `webgates-sessions`.

## Session repositories

For session-backed login, logout, and renewal, use:

- `webgates_repositories::memory::session::MemorySessionRepository` when the `sessions` feature is enabled
- `webgates_repositories::surrealdb::session::SurrealDbSessionRepository` when the `surrealdb` feature is enabled
- `webgates_repositories::sea_orm::session::*` when the `sea-orm` feature is enabled

These backends implement `webgates_sessions::repository::SessionRepository` and support session creation, refresh-token lookup, leases, rotation, revocation, family revocation, and session touch updates.

## Errors

Use the shared error module at:

```rust
use webgates_repositories::errors::{Error, Result};
```

The module also exposes backend-oriented error types such as:

- `DatabaseError`
- `RepositoriesError`
- `ErrorSeverity`
- `UserFriendlyError`

Map these errors at application boundaries without exposing internal storage details to clients.

## Services

`AccountInsertService` and `AccountDeleteService` stay at the repository boundary and coordinate repository traits without introducing an application-layer dependency.

Canonical service paths:

- `webgates_repositories::services::account_insert::AccountInsertService`
- `webgates_repositories::services::account_delete::AccountDeleteService`

## Audit logging

Enable `audit-logging` to emit tracing events for repository workflows. Keep logs free of secrets and personal data, and prefer correlation IDs in surrounding application code.

## Recommended onboarding path

If you are new to this crate, I recommend this order:

1. repository traits such as `AccountRepository` and `SecretRepository`
2. `memory` implementations
3. `services`
4. backend modules such as `sea_orm` or `surrealdb`
5. optional session repository integrations

## Examples

- `examples/sea-orm`
- `examples/surrealdb`
- workspace examples under `../examples`

## License and notices

- License: MIT
- SurrealDB, when enabled through the `surrealdb` feature, may impose additional upstream licensing obligations. Review the SurrealDB license terms before production use.
