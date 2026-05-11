# webgates-codecs

User-focused JWT codecs and validation helpers for the `webgates` ecosystem.

`webgates-codecs` is the codec layer of the workspace. It gives you the pieces you need to encode, decode, and validate JWT payloads without pulling in HTTP, cookies, middleware, or framework-specific integration.

If `webgates-core` is the domain model and `webgates` is the higher-level auth stack, `webgates-codecs` is the crate you reach for when you specifically need token codecs and JWT validation building blocks.

## Who this crate is for

Use `webgates-codecs` when you want to:

- encode and decode JWTs in framework-agnostic Rust code
- work directly with `JwtClaims` and `RegisteredClaims`
- validate tokens against an expected issuer
- manage ES384 signing and verification keys
- publish or consume JWKS-compatible public key material
- build custom integrations that need token handling without pulling in transport layers

If you want higher-level authentication services or gates, use `webgates`.
If you want domain types only, use `webgates-core`.
If you want transport integration, use `webgates-axum` or `webgates-tonic`.

## What you work with in this crate

Most developers can approach this crate through five concepts:

- `Codec` is the abstraction for encoding and decoding payloads
- `JsonWebToken<T>` is the JWT implementation of that abstraction
- `RegisteredClaims` and `JwtClaims<T>` model token contents
- `JwtValidationService` validates raw token strings against application expectations
- `jwt::jwks` supports public-key distribution and distributed verification

## Install

```toml
[dependencies]
webgates-codecs = "1.0.0"
webgates-core = "1.0.0"
```

Minimum supported Rust version: `1.91`.

## The mental model

The easiest way to understand this crate is:

1. your application data lives in some payload type
2. `Codec` defines how payloads are encoded and decoded
3. `JsonWebToken<T>` is the JWT implementation of that codec
4. `JwtValidationService` adds application-level validation such as expected issuer checks
5. `jwt::jwks` helps model public verification keys for distributed systems

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

## Core concepts

### 1. `Codec` is the abstraction

The `Codec` trait gives you a stable way to encode and decode typed payloads.

The important methods are:

- `Codec::encode`
- `Codec::decode`

This keeps token handling behind a simple abstraction that can be reused by higher-level crates.

### 2. `JsonWebToken<T>` is the JWT implementation

`JsonWebToken<T>` is the main codec you will use in this crate.

Use it when you want to:

- sign JWTs
- verify JWTs
- work with strongly typed claims
- keep JWT behavior behind the `Codec` trait

### 3. `RegisteredClaims` and `JwtClaims<T>` model token contents

`RegisteredClaims` stores the standard JWT fields such as:

- issuer
- subject
- audience
- expiration time
- issued-at time
- token id
- optional session id

`JwtClaims<T>` combines those standard claims with your application-specific payload.

This makes it easy to carry typed account data or other application state inside the token.

### 4. `JwtValidationService` validates at the boundary

`JwtValidationService<C>` is useful when you receive a raw token string and want a clear, typed validation step.

It performs:

1. decode through the configured codec
2. issuer validation against the expected issuer

Important note: lower-level JWT checks such as signature verification, algorithm handling, and expiration checks remain owned by the configured codec.

### 5. `jwt::jwks` supports distributed verification

If your system separates token issuance and token verification, the JWKS helpers let you model public keys in a standard format.

Key types include:

- `EcP384Jwk`
- `JwksDocument`
- `JwksProvider`

These are especially useful for auth authorities and resource servers that need shared public verification material.

## Production guidance

### Use stable ES384 keys

If you want a node to bootstrap its local key files on startup, you can ask `webgates-codecs` to create them the first time the process runs and then reuse them on later starts:

```rust
use webgates_codecs::jwt::{Es384KeyPairLoader, JwtClaims};
use webgates_core::accounts::Account;
use webgates_core::groups::Group;
use webgates_core::roles::Role;

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let key_pair = Es384KeyPairLoader::new(
    "./var/keys/jwt-es384-private.pem",
    "./var/keys/jwt-es384-public.pem",
)
.initialize_if_required()
.await?;

let jwt_codec = key_pair.to_codec::<JwtClaims<Account<Role, Group>>>()?;
# let _ = jwt_codec;
# Ok(())
# }
```

This loader returns an error if only one of the two files already exists, because that usually indicates a broken or partial deployment state. It also hides the raw file reads so startup code can focus on wiring rather than filesystem details.

If your node also publishes JWKS, you can build an authority from the same loaded key pair:

```rust
use webgates_codecs::jwt::authority::JwtAuthority;
use webgates_codecs::jwt::{Es384KeyPairLoader, JwtClaims};

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let key_pair = Es384KeyPairLoader::new(
    "./var/keys/jwt-es384-private.pem",
    "./var/keys/jwt-es384-public.pem",
)
.initialize_if_required()
.await?;

let authority = key_pair.to_authority::<JwtClaims<()>>()?;
# let _ = authority;
# Ok(())
# }
```

`JsonWebTokenOptions::default()` uses an embedded ES384 development keypair. That is convenient for tests and local development, but it is not suitable when tokens must survive restarts or be validated across multiple instances.

For production, provide explicit ES384 key material:

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
# let _ = codec;
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Verification-only nodes

If a node only validates tokens and never signs them, use verification-only options:

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
# let _ = codec;
# Ok::<(), Box<dyn std::error::Error>>(())
```

### JWKS-backed verification

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
# let _ = codec;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Error model

This crate exposes:

- `Error`
- `CodecsError`
- `JwtError`
- `CodecOperation`
- `JwtOperation`

Use these when you want structured handling of codec failures and JWT processing failures.

## Which crate should you use?

- use `webgates-core` when you only want domain types and authorization primitives
- use `webgates-codecs` when you specifically need JWT codecs and validation helpers
- use `webgates` when you want the higher-level auth stack
- use `webgates-axum` when you want Axum transport integration
- use `webgates-tonic` when you want tonic server-side transport integration

## Recommended onboarding path

If you are new to this crate, I recommend this order:

1. `Codec`
2. `jwt::RegisteredClaims`
3. `jwt::JwtClaims<T>`
4. `jwt::JsonWebToken<T>`
5. `jwt::validation_service::JwtValidationService`
6. `jwt::jwks`

## Related crates

- `webgates-core` - shared account, role, group, permission, and error primitives
- `webgates` - higher-level authentication and authorization services
- `webgates-axum` - Axum integration layer for routing and request handling

## Validation

Before merging changes in this crate, run:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --deny warnings
cargo test -p webgates-codecs --all-targets
```
