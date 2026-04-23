# webgates-codecs

Framework-agnostic JWT codecs and validation helpers for the `webgates` ecosystem.

`webgates-codecs` provides the codec layer used to encode, decode, and validate token payloads without pulling in HTTP or framework-specific integration code. It is intended for applications and crates that need JWT support plus shared token-validation building blocks.

## When to use this crate

Use `webgates-codecs` when you need:

- JWT encoding and decoding for `webgates` account claims
- issuer-aware token validation helpers
- a framework-agnostic codec abstraction
- token handling without depending on higher-level transport crates

Use other crates in the workspace when you need:

- core account, role, group, and permission types from `webgates-core`
- HTTP integration from `webgates-axum`
- higher-level authentication flows from `webgates`

## Install

```toml
[dependencies]
webgates-codecs = "0.1"
webgates-core = "0.1"
```

## What this crate provides

### Codec abstraction

The `Codec` trait defines a small pluggable interface for payload encoding and decoding:

- `Codec::encode`
- `Codec::decode`

This allows JWT support to remain replaceable behind a stable crate-local abstraction.

### Canonical public paths

Use JWT types from the `jwt` module:

- `webgates_codecs::jwt::RegisteredClaims`
- `webgates_codecs::jwt::JwtClaims`
- `webgates_codecs::jwt::JsonWebToken`
- `webgates_codecs::jwt::JsonWebTokenOptions`
- `webgates_codecs::jwt::JwtValidationService`
- `webgates_codecs::jwt::JwtValidationResult`
- `webgates_codecs::jwt::jwks::{EcP384Jwk, JwksDocument, JwksProvider}`

Use crate-root error and codec types from:

- `webgates_codecs::Codec`
- `webgates_codecs::Error`
- `webgates_codecs::CodecsError`
- `webgates_codecs::JwtError`
- `webgates_codecs::CodecOperation`
- `webgates_codecs::JwtOperation`

### JWT support

The `jwt` module provides:

- `RegisteredClaims`
- `JwtClaims<T>`
- `JsonWebToken<T>`
- `JsonWebTokenOptions`
- `JwtValidationService<C>`
- `JwtValidationResult<T>`
- `jwks` module for canonical ES384 JWKS key modeling

## Quick start

```rust
use std::sync::Arc;

use webgates_codecs::jwt::{
    JsonWebToken,
    JsonWebTokenOptions,
    JwtClaims,
    JwtValidationResult,
    JwtValidationService,
    RegisteredClaims,
};
use webgates_codecs::Codec;
use webgates_core::accounts::Account;
use webgates_core::groups::Group;
use webgates_core::permissions::Permissions;
use webgates_core::roles::Role;
use uuid::Uuid;

type AppClaims = JwtClaims<Account<Role, Group>>;

let codec = Arc::new(JsonWebToken::<AppClaims>::new_with_options(
    JsonWebTokenOptions::default(),
));

let claims = JwtClaims::new(
    Account {
        account_id: Uuid::now_v7(),
        user_id: "user@example.com".to_string(),
        roles: vec![Role::User],
        groups: vec![Group::new("engineering")],
        permissions: Permissions::new(),
    },
    RegisteredClaims::new("my-app", 4_102_444_800),
);

let encoded = codec.encode(&claims)?;
let decoded = codec.decode(&encoded)?;

assert!(decoded.has_issuer("my-app"));

let validation_service = JwtValidationService::new(Arc::clone(&codec), "my-app");

match validation_service.validate_token(std::str::from_utf8(&encoded)?) {
    JwtValidationResult::Valid(valid_claims) => {
        assert_eq!(valid_claims.custom_claims.user_id, "user@example.com");
    }
    JwtValidationResult::InvalidToken => {
        panic!("expected a valid token");
    }
    JwtValidationResult::InvalidIssuer { expected, actual } => {
        panic!("unexpected issuer mismatch: expected {expected}, got {actual}");
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Production guidance

### Use stable ES384 keys

`JsonWebTokenOptions::default()` uses an embedded ES384 development keypair. That is convenient for tests and short-lived local development, but it is not suitable when tokens must survive restarts or be validated across multiple instances.

For production, provide explicit ES384 key material and continue using the canonical `webgates_codecs::jwt::*` paths:

```rust
use webgates_codecs::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims};
use webgates_core::accounts::Account;
use webgates_core::groups::Group;
use webgates_core::roles::Role;
type AppClaims = JwtClaims<Account<Role, Group>>;

let private_pem = std::fs::read("/run/secrets/jwt-es384-private.pem")?;
let public_pem = std::fs::read("/run/secrets/jwt-es384-public.pem")?;

let codec = JsonWebToken::<AppClaims>::new_with_options(
    JsonWebTokenOptions::from_es384_pem(&private_pem, &public_pem)?,
);
# Ok::<(), Box<dyn std::error::Error>>(())
```

If a node only validates tokens and does not mint them, use verification-only options:

```rust
use webgates_codecs::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims};
use webgates_core::accounts::Account;
use webgates_core::groups::Group;
use webgates_core::roles::Role;

type AppClaims = JwtClaims<Account<Role, Group>>;

let public_pem = std::fs::read("/run/secrets/jwt-es384-public.pem")?;

let codec = JsonWebToken::<AppClaims>::new_with_options(
    JsonWebTokenOptions::for_es384_verification_only(&public_pem)?,
);
# Ok::<(), Box<dyn std::error::Error>>(())
```

For JWKS-backed verification with strict `kid` selection:

```rust,ignore
use webgates_codecs::jwt::jwks::EcP384Jwk;
use webgates_codecs::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims};
use webgates_core::accounts::Account;
use webgates_core::groups::Group;
use webgates_core::roles::Role;

type AppClaims = JwtClaims<Account<Role, Group>>;

let jwk = EcP384Jwk::from_public_key_pem("auth-key-1", public_pem.as_bytes())?;
let codec = JsonWebToken::<AppClaims>::new_with_options(
    JsonWebTokenOptions::for_es384_jwks_keys(&[jwk])?,
);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Keep private keys in a secret manager or restricted runtime secret volume. Do not hardcode production key material in source control.

### Validate at the boundary

`JwtValidationService` is useful when you need to validate raw token strings at a system boundary and also enforce an expected issuer.

This crate handles codec and JWT concerns only. Authorization and transport-layer behavior should remain in higher layers.

## Error model

This crate exposes:

- `Error`
- `CodecsError`
- `JwtError`
- `CodecOperation`
- `JwtOperation`

Use these errors when you need structured handling of codec failures and JWT processing failures.

## Feature notes

This crate is intentionally small and focused:

- no framework integration
- no HTTP handlers
- no cookie orchestration
- no repository concerns

Those responsibilities belong in other crates in the workspace.

## Related crates

- `webgates-core`: shared account, role, group, permission, and error primitives
- `webgates`: higher-level authentication and authorization services
- `webgates-axum`: Axum integration layer for routing and request handling

## Validation

Before merging changes in this crate, run:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --deny warnings
cargo test -p webgates-codecs --all-targets
```
