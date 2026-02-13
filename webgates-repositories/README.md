# webgates-repositories

Repository implementations and repository-facing services for the `webgates` authentication and authorization domain.

- In-memory repositories for quick starts and tests
- Optional SeaORM-backed repositories (`repo-seaorm`)
- Optional SurrealDB-backed repositories (`repo-surrealdb`)
- Optional audit logging hooks (`audit-logging`)
- Shared `Result`/error types tailored to repository backends
- Services such as account insert/delete, gated behind the `server` feature

## Crate layout

- `src/memory`: In-memory repositories (no extra features required)
- `src/sea_orm`: SeaORM repositories and models (`repo-seaorm`)
- `src/surrealdb`: SurrealDB repositories (`repo-surrealdb`)
- `src/services`: Repository-facing services (enabled with `server`)
- `src/errors.rs`: Repository-specific error stack (`Error`, `DatabaseError`, `RepositoriesError`, `ErrorSeverity`, `UserFriendlyError`, `Result<T>`)

## Feature flags

- `default = ["server"]`
- `server`: Enables tokio/macro support and repository services
- `repo-seaorm`: SeaORM-backed repositories (requires SeaORM + database driver)
- `repo-surrealdb`: SurrealDB-backed repositories
- `audit-logging`: Enables audit hooks with `tracing`

## Add to your project

```toml
[dependencies]
webgates = { version = "1" }
webgates-repositories = { version = "1", features = ["repo-seaorm"] }
# or
webgates-repositories = { version = "1", features = ["repo-surrealdb"] }
# in-memory backend needs no extra features
```

## Choosing a backend

- **In-memory**: Development/tests, zero config.
- **SeaORM (`repo-seaorm`)**: For relational databases supported by SeaORM; bring the appropriate driver via SeaORM features.
- **SurrealDB (`repo-surrealdb`)**: For SurrealDB deployments; see BUSL notice below.

## Basic usage (in-memory)

```rust
use webgates_repositories::memory::{
    MemoryAccountRepository, MemorySecretRepository, MemoryPermissionMappingRepository,
};
use webgates::gate::Gate;
use webgates::codecs::jwt::{JsonWebToken, JsonWebTokenOptions};

let account_repo = MemoryAccountRepository::new();
let secret_repo = MemorySecretRepository::new();
let perms_repo = MemoryPermissionMappingRepository::new();

let codec = JsonWebToken::new(JsonWebTokenOptions::default());
let gate = Gate::cookie("issuer", codec)
    .with_account_repository(account_repo)
    .with_secret_repository(secret_repo)
    .with_permission_repository(perms_repo);
```

## SeaORM backend (sketch)

1) Enable the feature and add the driver via SeaORM:
```toml
webgates-repositories = { version = "1", features = ["repo-seaorm"] }
sea-orm = { version = "2", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
```

2) Initialize the connection and repository:
```rust
use sea_orm::Database;
use webgates_repositories::sea_orm::SeaOrmRepository;

let db = Database::connect("postgres://...").await?;
let repo = SeaOrmRepository::new(db);
```

## SurrealDB backend (sketch)

```toml
webgates-repositories = { version = "1", features = ["repo-surrealdb"] }
```

```rust
use surrealdb::engine::local::Mem;
use surrealdb::Surreal;
use webgates_repositories::surrealdb::SurrealDbRepository;

let db = Surreal::new::<Mem>(()).await?;
db.use_ns("ns").use_db("db").await?;
let repo = SurrealDbRepository::new(db);
```

## Error handling

All repository APIs return `webgates_repositories::errors::Result<T>` with a rich error stack (`Error`, `DatabaseError`, `RepositoriesError`, `ErrorSeverity`, and `UserFriendlyError`). Map or log errors at boundaries; avoid leaking internal details to clients.

## Audit logging

Enable `audit-logging` to emit tracing spans/events for repository operations. Keep logs free of secrets/PII; prefer correlation IDs and high-level event labels.

## Services (account insert/delete)

`AccountInsertService` and `AccountDeleteService` live under `src/services` and are gated by the `server` feature. They operate over the repository traits to simplify provisioning and teardown flows.

## Examples

- `examples/sea-orm`: SeaORM-backed usage
- `examples/surrealdb`: SurrealDB-backed usage
- Workspace examples under `../examples` use the in-memory backend by default.

## BUSL notice (SurrealDB)

Enabling `repo-surrealdb` pulls in SurrealDB, licensed under the Business Source License 1.1 (BUSL-1.1). BUSL restricts Production Use unless permitted by the licensor or after the Change Date. If you build or distribute binaries with this feature enabled, you must comply with BUSL and include required third-party notices.

## MSRV and license

- MSRV: 1.88
- License: MIT