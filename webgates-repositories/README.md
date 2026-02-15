# webgates-repositories

Repository implementations and repository-facing services for the `webgates` authentication/authorization domain.

- In-memory repositories for quick starts and tests
- SeaORM-backed repositories (`repo-seaorm`)
- SurrealDB-backed repositories (`repo-surrealdb`)
- Optional audit logging hooks (`audit-logging`)
- Shared error stack tailored to repository backends

## Install

Pick the backends you need:

```toml
[dependencies]
webgates = { version = "0.1" }
webgates-repositories = { version = "0.1", features = ["repo-seaorm"] }
# or
webgates-repositories = { version = "0.1", features = ["repo-surrealdb"] }
# in-memory requires no extra features
```

MSRV: 1.88

## Feature flags

- `default = []` (no default features enabled)
- `repo-surrealdb`: SurrealDB-backed repository implementations (opt-in).
- `repo-seaorm`: SeaORM-backed repository implementations (opt-in).
- `audit-logging`: emit tracing events for repository operations (opt-in; integrates with `webgates` audit logging).

Notes:
- Enable only the features you need to avoid pulling in large transitive dependencies.
- See `Cargo.toml` for the exact feature definitions and dependency implications.

## Quick starts

### In-memory (zero config)

```rust
use webgates::gate::Gate;
use webgates::codecs::jwt::{JsonWebToken, JwtClaims};
use webgates::accounts::Account;
use webgates::prelude::{Group, Role};
use webgates_repositories::memory::{
    MemoryAccountRepository, MemorySecretRepository, MemoryPermissionMappingRepository,
};
use std::sync::Arc;

type Claims = JwtClaims<Account<Role, Group>>;
let codec = Arc::new(JsonWebToken::<Claims>::default());

let gate = Gate::cookie::<_, Role, Group>("issuer", Arc::clone(&codec))
    .with_policy(webgates::authz::AccessPolicy::require_role(Role::Admin));

let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
let secret_repo = Arc::new(MemorySecretRepository::new_with_argon2_hasher()?);
let perms_repo = Arc::new(MemoryPermissionMappingRepository::new());

// use the repos in your app (login handlers, services, etc.)
```

### SeaORM (sketch)

```toml
webgates-repositories = { version = "0.1", features = ["repo-seaorm"] }
sea-orm = { version = "2", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
```

```rust
use sea_orm::Database;
use webgates_repositories::sea_orm::SeaOrmRepository;

let db = Database::connect("postgres://...").await?;
let repo = SeaOrmRepository::new(db);
```

### SurrealDB (sketch)

```toml
webgates-repositories = { version = "0.1", features = ["repo-surrealdb"] }
```

```rust
use surrealdb::engine::local::Mem;
use surrealdb::Surreal;
use webgates_repositories::surrealdb::SurrealDbRepository;

let db = Surreal::new::<Mem>(()).await?;
db.use_ns("ns").use_db("db").await?;
let repo = SurrealDbRepository::new(db);
```

## Errors

All repository APIs return `webgates_repositories::errors::Result<T>` with a rich error stack (`Error`, `DatabaseError`, `RepositoriesError`, `ErrorSeverity`, `UserFriendlyError`). Map or log errors at boundaries; avoid leaking internal details to clients.

## Services

`AccountInsertService` and `AccountDeleteService` provide convenience flows over the repository traits for provisioning and teardown. These services are asynchronous and intended to be used on an async runtime (for example, Tokio). Enable the repository backend features (`repo-seaorm`, `repo-surrealdb`) as appropriate for your persistence layer.

## Audit logging

Enable `audit-logging` to emit tracing events for repository operations. Keep logs free of secrets/PII; use correlation IDs.

## Examples

- `examples/sea-orm`
- `examples/surrealdb`
- Workspace examples under `../examples` use the in-memory backend by default.

## License and notices

- License: MIT
- SurrealDB (when enabling `repo-surrealdb`): BUSL-1.1. Production use is restricted by BUSL; include required third-party notices and comply with SurrealDB licensing.