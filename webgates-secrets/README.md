# webgates-secrets

Secret value and hashing primitives for the `webgates` ecosystem.

`webgates-secrets` provides the server-side security building blocks that are shared between higher-level authentication flows and repository backends. It is intentionally focused on the secret and hashing boundary so that persistence concerns and repository traits can live in `webgates-repositories` without creating dependency cycles.

## What this crate provides

- `Secret` — a hashed secret bound to an account identifier; plaintext is hashed on construction and never stored
- `hashing::HashingService` — trait for hashing and verifying values
- `hashing::argon2::Argon2Hasher` — Argon2id implementation with a secure-by-default production profile and a fast development profile
- `hashing::HashedValue` — the PHC-format string produced by hashing
- Structured error types for hashing and secret operations

## When to use this crate directly

Depend on `webgates-secrets` directly when you:

- Need hashing or secret verification in a non-HTTP context
- Are implementing a custom repository that stores hashed credentials
- Want the smallest possible dependency for secret operations

For typical application use, the `secrets` feature on the `webgates` composition crate re-exports the same types:

```toml
[dependencies]
webgates = { version = "0.1", default-features = false, features = ["secrets"] }
```

Or depend on the crate directly:

```toml
[dependencies]
webgates-secrets = "0.1"
```

MSRV: 1.91

## Quick start

### Hash and verify a password

```rust
use webgates_core::verification_result::VerificationResult;
use webgates_secrets::hashing::argon2::Argon2Hasher;
use webgates_secrets::hashing::HashingService;

let hasher = Argon2Hasher::new_recommended().unwrap();

let hashed = hasher.hash_value("user_password").unwrap();
let result = hasher.verify_value("user_password", &hashed).unwrap();
assert_eq!(result, VerificationResult::Ok);
```

### Create and verify a `Secret`

`Secret` ties a hashed credential to an account identifier and is the type stored in account repositories.

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

## Features

This crate has no optional features. All public types are available unconditionally.

## Security notes

- Plaintext secrets are hashed immediately in `Secret::new` and never stored.
- `Argon2Hasher::new_recommended()` uses the recommended Argon2id parameters for production. These are deliberately slow to resist brute-force attacks; do not override them in production.
- Store only `Secret::secret` (the `HashedValue`) alongside `Secret::account_id`. Never store plaintext passwords.
- Avoid logging `HashedValue` strings; even hashed values should be treated as sensitive.

## Related crates

- `webgates` — user-facing composition crate; exposes these types via the `secrets` feature
- `webgates-core` — domain types; `webgates-secrets` depends on it for `VerificationResult`
- `webgates-repositories` — provides `MemorySecretRepository` backed by `Secret`

## License

MIT
