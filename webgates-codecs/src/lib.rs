#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
/*!
# webgates-codecs

JWT encoding, decoding, validation, and JWKS helpers for `webgates` applications.

This crate is the codec layer of the workspace. It gives you the building blocks
for encoding, decoding, and validating JWT payloads without pulling in HTTP,
cookies, middleware, or framework-specific integration.

## When to use this crate

Use `webgates-codecs` when you want:

- a small codec abstraction via [`Codec`]
- JWT claim types and a JWT codec in [`jwt`]
- issuer-aware token validation helpers
- ES384 JWKS key modeling in [`jwt::jwks`]
- structured codec and JWT error types

The crate depends only on shared core types from `webgates-core` and keeps
transport concerns out of scope.

## Quick start

```rust
use std::sync::Arc;
use webgates_codecs::jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER as JWT_CRYPTO_PROVIDER;
use webgates_codecs::jwt::{JsonWebToken, JwtClaims, RegisteredClaims};
use webgates_codecs::jwt::validation_service::JwtValidationService;
use webgates_codecs::Codec;
use webgates_core::accounts::Account;
use webgates_core::groups::Group;
use webgates_core::roles::Role;

type Claims = JwtClaims<Account<Role, Group>>;

let _ = JWT_CRYPTO_PROVIDER.install_default();
let codec = Arc::new(JsonWebToken::<Claims>::default());
let claims = JwtClaims::new(
    Account::<Role, Group>::new("user@example.com"),
    RegisteredClaims::new("my-app", 4_102_444_800),
);

let token = codec.encode(&claims)?;
let decoded = codec.decode(&token)?;
assert!(decoded.has_issuer("my-app"));

let validator = JwtValidationService::new(Arc::clone(&codec), "my-app");
let _ = validator.validate_token(std::str::from_utf8(&token)?);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Getting started on docs.rs

A good reading order is:

1. [`Codec`]
2. [`jwt::RegisteredClaims`]
3. [`jwt::JwtClaims`]
4. [`jwt::JsonWebToken`]
5. [`jwt::validation_service::JwtValidationService`]
6. [`jwt::jwks`]
*/

use serde::{Serialize, de::DeserializeOwned};

pub mod errors;
pub mod jwt;

pub use jsonwebtoken;

use errors::{CodecsError, JwtError};

/// Result alias used by codec implementations in this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Root error type for `webgates-codecs`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Codec/serialization category errors.
    #[error(transparent)]
    Codecs(#[from] CodecsError),

    /// JWT processing category errors.
    #[error(transparent)]
    Jwt(#[from] JwtError),
}

/// Encodes and decodes typed payloads.
///
/// Higher-level crates build on this small abstraction. A codec takes a typed
/// payload, produces an opaque encoded representation, and can later decode
/// that representation back into the typed payload.
pub trait Codec
where
    Self: Clone,
    Self::Payload: Serialize + DeserializeOwned,
{
    /// Type of the payload being encoded/decoded.
    type Payload;

    /// Encodes a payload into an opaque, implementation-defined byte vector.
    ///
    /// Returns an error if serialization, signing, encryption, or other
    /// encoding steps fail.
    fn encode(&self, payload: &Self::Payload) -> Result<Vec<u8>>;

    /// Decodes a previously encoded payload.
    ///
    /// Returns an error if the value is malformed, tampered with, or otherwise
    /// fails integrity or authenticity validation.
    fn decode(&self, encoded_value: &[u8]) -> Result<Self::Payload>;
}
