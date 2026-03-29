# webgates-repositories

Repository implementations and repository-facing services for the `webgates` authentication and authorization domain.

This crate exposes:
- repository traits in dedicated trait modules
- in-memory implementations under concrete module paths
- in-memory session repository support for tests and local session-backed auth flows
- optional SeaORM and SurrealDB backends behind feature flags
- session repository backends for `webgates-sessions`
- repository-scoped services for account insertion and deletion
- shared repository error types

## Install

Pick only the backend features you need:

```toml
[dependencies]
webgates-repositories = { version = "0.1" }
# or
webgates-repositories = { version = "0.1", features = ["sea-orm"] }
# or
webgates-repositories = { version = "0.1", features = ["surrealdb"] }
```

MSRV: 1.88

## Canonical public API

The public API is module-oriented.

### Repository traits

Import traits from their defining modules:

```rust
use webgates_repositories::account_repository::AccountRepository;
use webgates_repositories::group_repository::GroupRepository;
use webgates_repositories::permission_mapping_repository::PermissionMappingRepository;
use webgates_repositories::secret_repository::SecretRepository;
```

Session-backed authentication uses the framework-agnostic
`webgates_sessions::repository::SessionRepository` contract, with concrete
backends provided by this crate.

### In-memory implementations

Import concrete in-memory types from their concrete child modules:

```rust
use webgates_repositories::memory::account::MemoryAccountRepository;
use webgates_repositories::memory::group::MemoryGroupRepository;
use webgates_repositories::memory::permission_mapping::MemoryPermissionMappingRepository;
use webgates_repositories::memory::secret::MemorySecretRepository;
```

### Services

Import repository services from their defining modules:

```rust
use webgates_repositories::services::account_delete::AccountDeleteService;
use webgates_repositories::services::account_insert::AccountInsertService;
```

### Session repositories

For session-backed login, logout, and transparent renewal, use:

- `webgates_repositories::memory::session::InMemorySessionRepository`
- `webgates_repositories::surrealdb::session::SurrealDbSessionRepository` when the `surrealdb` feature is enabled

These backends implement `webgates_sessions::repository::SessionRepository`
for session creation, refresh-token lookup, lease acquisition, atomic rotation,
session revocation, family revocation, and session touch updates.

### Optional backends

- `webgates_repositories::sea_orm::SeaOrmRepository`
- `webgates_repositories::surrealdb::{DatabaseScope, SurrealDbRepository}`

## Feature flags

- `default = []`
- `surrealdb`: enables the SurrealDB backend
- `sea-orm`: enables the SeaORM backend
- `audit-logging`: enables repository audit events

Enable only the features you need to keep dependency scope smaller.

## Quick starts

### In-memory account and secret repositories

```rust
use std::sync::Arc;
use webgates_core::prelude::{Group, Role};
use webgates_repositories::memory::account::MemoryAccountRepository;
use webgates_repositories::memory::secret::MemorySecretRepository;

let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
let secret_repo = Arc::new(MemorySecretRepository::new_with_argon2_hasher()?);
```

### In-memory permission mapping repository

```rust
use webgates_repositories::memory::permission_mapping::MemoryPermissionMappingRepository;

let mapping_repo = MemoryPermissionMappingRepository::default();
```

### Account insert service

```rust
use std::sync::Arc;
use webgates_core::prelude::{Group, Role};
use webgates_repositories::memory::account::MemoryAccountRepository;
use webgates_repositories::memory::secret::MemorySecretRepository;
use webgates_repositories::services::account_insert::AccountInsertService;

let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
let secret_repo = Arc::new(MemorySecretRepository::new_with_argon2_hasher()?);

let account = AccountInsertService::insert("user@example.com", "password")
    .with_roles(vec![Role::User])
    .with_groups(vec![Group::new("engineering")])
    .into_repositories(account_repo, secret_repo)
    .await?;
```

### SeaORM

```toml
webgates-repositories = { version = "0.1", features = ["sea-orm"] }
sea-orm = { version = "2", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
```

```rust
use sea_orm::Database;
use webgates_repositories::sea_orm::SeaOrmRepository;

let db = Database::connect("postgres://...").await?;
let repo = SeaOrmRepository::new(&db)?;
```

### SurrealDB

```toml
webgates-repositories = { version = "0.1", features = ["surrealdb"] }
```

```rust
use surrealdb::engine::local::Mem;
use surrealdb::Surreal;
use webgates_repositories::surrealdb::{DatabaseScope, SurrealDbRepository};

let db = Surreal::new::<Mem>(()).await?;
let repo = SurrealDbRepository::new(db, DatabaseScope::default())?;
```

The `surrealdb` feature also enables the SurrealDB session repository backend
for `webgates-sessions`, so the same database integration can back persistent
session issuance, renewal, replay detection, and revocation flows.

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

Errors should be mapped at application boundaries without exposing internal storage details to clients.

## Services

`AccountInsertService` and `AccountDeleteService` stay at the repository boundary and coordinate repository traits without introducing an application-layer dependency.

Canonical service paths:
- `webgates_repositories::services::account_insert::AccountInsertService`
- `webgates_repositories::services::account_delete::AccountDeleteService`

## Audit logging

Enable `audit-logging` to emit tracing events for repository workflows. Keep logs free of secrets and personal data, and prefer correlation IDs in surrounding application code.

## Examples

- `examples/sea-orm`
- `examples/surrealdb`
- workspace examples under `../examples`

Session-backed integrations are typically composed with:

- `webgates::authn::SessionLoginService`
- `webgates::authn::SessionLogoutService`
- `webgates_axum::route_handlers::login_with_sessions`
- `webgates_axum::route_handlers::logout_with_sessions`
- `webgates_axum::session::CookieSessionLayer`

## License and notices

- License: MIT
- SurrealDB, when enabled through the `surrealdb` feature, may impose additional upstream licensing obligations. Review the SurrealDB license terms before production use.
