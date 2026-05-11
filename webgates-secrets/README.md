# webgates-secrets

User-focused secret value and hashing primitives for the `webgates` ecosystem.

`webgates-secrets` is the secret and hashing layer of the workspace. It provides the server-side security building blocks used to hash credentials, verify them safely, and bind hashed secrets to account identifiers.

If `webgates-core` defines the domain model and `webgates-repositories` defines persistence, `webgates-secrets` defines how sensitive credential values are transformed into safe stored representations.

## Who this crate is for

Use `webgates-secrets` when you want to:

- hash passwords or other secrets in framework-agnostic Rust code
- verify plaintext credentials against stored hashes
- construct `Secret` values for repository storage
- use Argon2id with sensible defaults
- build custom secret storage or authentication flows outside HTTP frameworks
- work directly at the secret boundary without pulling in higher-level crates

For typical application use, the `secrets` feature on the `webgates` composition crate re-exports the same types.

## What you work with in this crate

Most developers only need to understand four pieces:

- `HashingService` defines the hashing and verification boundary
- `Argon2Hasher` is the provided implementation you will usually use
- `HashedValue` is the stored PHC-format hash string
- `Secret` binds that hash to an account identifier for persistence and verification flows

## Install

Use the `webgates` composition crate if you want these types re-exported through the higher-level stack:

```toml
[dependencies]
webgates = { version = "0.1", default-features = false, features = ["secrets"] }
```

Or depend on the crate directly:

```toml
[dependencies]
webgates-secrets = "0.1"
```

Minimum supported Rust version: `1.91`.

## The mental model

The easiest way to understand this crate is:

1. plaintext secrets should never be stored directly
2. a `HashingService` turns plaintext into a stored hash and verifies candidate input later
3. `Argon2Hasher` is the provided hashing implementation
4. `Secret` ties a stored hashed value to an account identifier
5. repositories or higher-level auth services persist and use those `Secret` values

## Quick start

### Hash and verify a password

```rust
use webgates_core::verification_result::VerificationResult;
use webgates_secrets::hashing::argon2::Argon2Hasher;
use webgates_secrets::hashing::hashing_service::HashingService;

let hasher = Argon2Hasher::new_recommended().unwrap();

let hashed = hasher.hash_value("user_password").unwrap();
let result = hasher.verify_value("user_password", &hashed).unwrap();
assert_eq!(result, VerificationResult::Ok);
```

### Create and verify a `Secret`

`Secret` ties a hashed credential to an account identifier and is the type typically stored in repositories.

```rust
use webgates_core::verification_result::VerificationResult;
use webgates_secrets::hashing::argon2::Argon2Hasher;
use webgates_secrets::Secret;
use uuid::Uuid;

let account_id = Uuid::now_v7();
let hasher = Argon2Hasher::new_recommended().unwrap();

let secret = Secret::new(&account_id, "user_entered_password", hasher.clone())
    .map_err(|e| e.to_string())?;

let verification = secret
    .verify("user_entered_password", hasher)
    .map_err(|e| e.to_string())?;

assert_eq!(verification, VerificationResult::Ok);
# Ok::<(), String>(())
```

## Core concepts

### 1. `HashingService` is the abstraction

`HashingService` defines the small contract for:

- hashing a plaintext value
- verifying a plaintext value against a stored hash

This lets higher-level crates depend on a stable hashing interface without coupling directly to one algorithm implementation.

### 2. `Argon2Hasher` is the default implementation

`Argon2Hasher` is the provided `HashingService` implementation.

It uses Argon2id, which is a strong default for password hashing because it is designed to resist brute-force and hardware-accelerated attacks better than older password hashing schemes.

### 3. `HashedValue` is what you store

A `HashedValue` is the PHC-format string produced by the hashing implementation.

It is self-contained and typically includes:

- algorithm identifier
- version
- parameters
- salt
- hash

That means you can store it directly and use it later for verification.

### 4. `Secret` binds the stored hash to an account

`Secret` is the main value object you use when secret storage needs to be associated with an account identifier.

It stores:

- `account_id`
- `secret` as a `HashedValue`

This is usually the type repositories persist.

## Security notes

- plaintext secrets are hashed immediately in `Secret::new` and never stored in the resulting value
- `Argon2Hasher::new_recommended()` uses a production-safe preset; do not weaken it for production systems
- store only `Secret::secret` and `Secret::account_id`; never store plaintext passwords
- avoid logging `HashedValue` strings; even hashed values should be treated as sensitive
- use secure password-reset and credential-rotation flows outside this crate when credentials must change

## Features

This crate has no optional features. All public types are available unconditionally.

## Which crate should you use?

- use `webgates-secrets` when you need secret hashing and verification primitives directly
- use `webgates` with the `secrets` feature when you want the same types through the higher-level composition crate
- use `webgates-repositories` when you want repository implementations that persist `Secret` values
- use `webgates-core` when you only need the domain model and not the secret layer

## Recommended onboarding path

If you are new to this crate, I recommend this order:

1. `hashing::hashing_service::HashingService`
2. `hashing::argon2::Argon2Hasher`
3. `hashing::HashedValue`
4. `Secret`
5. error types in `errors` and `hashing::errors`

## Related crates

- `webgates` - user-facing composition crate; exposes these types via the `secrets` feature
- `webgates-core` - domain types and `VerificationResult`
- `webgates-repositories` - repository implementations that persist `Secret` values

## License

MIT
