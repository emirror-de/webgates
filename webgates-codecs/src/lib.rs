#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
/*!
# webgates-codecs

JWT encoding, decoding, validation, JWKS helpers, and automatic key management for `webgates` applications.

This crate is the codec layer of the workspace. It gives you the building blocks
for encoding, decoding, and validating JWT payloads—with production-ready automatic key
generation and persistence—without pulling in HTTP, cookies, middleware, or
framework-specific integration.

## When to use this crate

Use `webgates-codecs` when you want:

- a small codec abstraction via [`Codec`]
- JWT claim types and a JWT codec in [`jwt`]
- issuer-aware token validation helpers
- ES384 JWKS key modeling in [`jwt::jwks`]
- structured codec and JWT error types
- **automatic ES384 key generation and file-based persistence** for production
- development-friendly APIs that work without configuration

The crate depends only on shared core types from `webgates-core` and keeps
transport concerns out of scope.

## Key Features

- **Automatic key generation**: Fresh ES384 keys on every call (perfect for tests)
- **File-based persistence**: Keys automatically saved and reused across restarts (perfect for production)
- **Smart path handling**: Public key path auto-derived as `private_key.pub`
- **Zero configuration**: Just provide one file path
- **Secure defaults**: No hardcoded keys, ES384 algorithm enforcement, cryptographic randomness
- **Production hardened**: Proper error handling for misconfiguration, idempotent operation

## Quick start: Development (Auto-generated Keys)

Perfect for tests, examples, and local development—fresh keys every time:

```rust
use std::sync::Arc;
use webgates_codecs::jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER as JWT_CRYPTO_PROVIDER;
use webgates_codecs::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims, RegisteredClaims};
use webgates_codecs::jwt::validation_service::JwtValidationService;
use webgates_codecs::Codec;
use webgates_core::accounts::Account;
use webgates_core::groups::Group;
use webgates_core::roles::Role;

type Claims = JwtClaims<Account<Role, Group>>;

let _ = JWT_CRYPTO_PROVIDER.install_default();

// Generate fresh keys for testing/development
let options = JsonWebTokenOptions::generate_for_testing()?;
let codec = Arc::new(JsonWebToken::<Claims>::new_with_options(options));

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

## Quick start: Production (File-Based Persistence)

Perfect for production servers—keys automatically persist and reuse across restarts:

```rust
use webgates_codecs::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims};

# let unique = std::time::SystemTime::now()
#     .duration_since(std::time::UNIX_EPOCH)?
#     .as_nanos();
# let temp_dir = std::env::temp_dir().join(format!("webgates-codecs-docs-{unique}"));
# std::fs::create_dir_all(&temp_dir)?;
# let key_path = temp_dir.join("jwt.key");
# let public_key_path = temp_dir.join("jwt.key.pub");
# let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
// First run: generates and saves keys to disk.
// Subsequent runs: loads the same keys from disk.
let options = runtime.block_on(async {
    JsonWebTokenOptions::from_private_key_path(&key_path).await
})?;

let codec = JsonWebToken::<JwtClaims<()>>::new_with_options(options);
assert!(key_path.is_file());
assert!(public_key_path.is_file());

# let _ = codec;
# let _ = std::fs::remove_file(&public_key_path);
# let _ = std::fs::remove_file(&key_path);
# let _ = std::fs::remove_dir_all(&temp_dir);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Quick start: Auth Server with JWKS Publication

Publish JWKS for distributed token verification:

```rust
use webgates_codecs::jwt::JwtClaims;
use webgates_codecs::jwt::authority::JwtAuthority;

# let unique = std::time::SystemTime::now()
#     .duration_since(std::time::UNIX_EPOCH)?
#     .as_nanos();
# let temp_dir = std::env::temp_dir().join(format!("webgates-authority-docs-{unique}"));
# std::fs::create_dir_all(&temp_dir)?;
# let key_path = temp_dir.join("server.key");
# let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
// One path, everything handled automatically:
// - Keys generated on first run
// - Keys persisted across restarts
// - JWKS provider ready to publish
let authority = runtime.block_on(async {
    JwtAuthority::<JwtClaims<()>>::from_private_key_path(&key_path).await
})?;

let signing_codec = authority.codec();
let jwks_provider = authority.jwks_provider();
assert_eq!(jwks_provider.document().keys.len(), 1);
assert_eq!(authority.key_id(), jwks_provider.key_id().unwrap());

# let _ = signing_codec;
# let _ = std::fs::remove_file(temp_dir.join("server.key.pub"));
# let _ = std::fs::remove_file(&key_path);
# let _ = std::fs::remove_dir_all(&temp_dir);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Key Management Strategies

### Development (Fresh Keys Every Time)

Use [`jwt::JsonWebTokenOptions::generate_for_testing()`]:

```rust
# use webgates_codecs::jwt::JsonWebTokenOptions;
let options = JsonWebTokenOptions::generate_for_testing()?;
assert_eq!(options.verification_key_count(), 1);
# Ok::<(), Box<dyn std::error::Error>>(())
```

**Perfect for**:
- Unit and integration tests (test isolation)
- Examples and prototypes
- Local development (no file management)

### Production (Persistent Keys)

Use [`jwt::JsonWebTokenOptions::from_private_key_path()`] or [`jwt::authority::JwtAuthority::from_private_key_path()`]:

```rust
# use webgates_codecs::jwt::JsonWebTokenOptions;
# let unique = std::time::SystemTime::now()
#     .duration_since(std::time::UNIX_EPOCH)?
#     .as_nanos();
# let temp_dir = std::env::temp_dir().join(format!("webgates-strategy-docs-{unique}"));
# std::fs::create_dir_all(&temp_dir)?;
# let key_path = temp_dir.join("jwt.key");
# let public_key_path = temp_dir.join("jwt.key.pub");
# let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
// First run: generates and saves keys.
// Subsequent runs: loads existing keys.
let options = runtime.block_on(async {
    JsonWebTokenOptions::from_private_key_path(&key_path).await
})?;
assert!(key_path.is_file());
assert!(public_key_path.is_file());
# let _ = options;
# let _ = std::fs::remove_file(&public_key_path);
# let _ = std::fs::remove_file(&key_path);
# let _ = std::fs::remove_dir_all(&temp_dir);
# Ok::<(), Box<dyn std::error::Error>>(())
```

**Perfect for**:
- Production servers (keys persist across restarts)
- Docker and Kubernetes (keys survive pod restarts)
- Systemd services (keys persist between reboots)
- Any deployment requiring stable keys

**Behavior**:
- **Both files exist**: Loads keys from disk
- **Neither file exists**: Generates fresh keys and saves both
- **Only one file exists**: Returns error (prevents misconfiguration)

### Verification-Only Nodes

When a node only validates tokens and never signs them:

```rust
# use webgates_codecs::jwt::{generate_es384_key_pair_pem, JsonWebToken, JsonWebTokenOptions, JwtClaims};
# let (_private_pem, public_pem) = generate_es384_key_pair_pem()?;
let codec = JsonWebToken::<JwtClaims<()>>::new_with_options(
    JsonWebTokenOptions::for_es384_verification_only(&public_pem)?
);
# let _ = codec;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Deployment Examples

### Docker

```dockerfile
FROM rust:latest
WORKDIR /app
COPY . .
RUN cargo build --release
ENV JWT_KEY_PATH=/run/jwt/key
CMD ["./target/release/myserver"]
```

On first container start: keys generated and saved to `/run/jwt/`
On restarts: keys reused from volume mount

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-server
spec:
  template:
    spec:
      volumes:
        - name: jwt-keys
          emptyDir: {}
      containers:
        - name: app
          image: myapp:latest
          env:
            - name: JWT_KEY_PATH
              value: /etc/jwt/key
          volumeMounts:
            - name: jwt-keys
              mountPath: /etc/jwt
```

First run generates keys, which persist for the pod lifetime.

### Systemd

```ini
[Unit]
Description=Auth Server
After=network.target

[Service]
Type=simple
User=authserver
WorkingDirectory=/opt/authserver
Environment="JWT_KEY_PATH=/etc/authserver/jwt_key"
ExecStart=/opt/authserver/bin/server
Restart=always

[Install]
WantedBy=multi-user.target
```

Keys auto-generated on first run and reused on restarts.

## Security Notes

### Cryptography

- **Algorithm**: ES384 (ECDSA with NIST P-384 curve)
- **Standard**: RFC 7518 (JWS/JWT specification)
- **Key generation**: Cryptographically secure randomness via `getrandom`
- **Key format**: PKCS#8 PEM for private, SubjectPublicKeyInfo for public

### File Permissions (Unix)

After key generation, set restrictive permissions:

```bash
# Private key - readable only by the service user
chmod 600 /etc/jwt/key
chown myservice:myservice /etc/jwt/key

# Public key - can be world-readable
chmod 644 /etc/jwt/key.pub
```

### Key Rotation

To rotate keys:

```bash
# Backup old keys
cp /etc/jwt/key /etc/jwt/key.backup
cp /etc/jwt/key.pub /etc/jwt/key.pub.backup

# Remove old keys
rm /etc/jwt/key /etc/jwt/key.pub

# Restart application - new keys generated automatically
```

## Getting started on docs.rs

A good reading order is:

1. [`jwt::JsonWebTokenOptions`] - understand key management strategies
2. [`jwt::authority::JwtAuthority`] - learn the auth server pattern
3. [`Codec`] - understand the abstraction
4. [`jwt::RegisteredClaims`] - standard JWT claims
5. [`jwt::JwtClaims`] - typed application claims
6. [`jwt::JsonWebToken`] - the JWT codec implementation
7. [`jwt::validation_service::JwtValidationService`] - validation at boundaries
8. [`jwt::jwks`] - distributed verification with JWKS

## Examples

Run the included examples to see key management in action:

```bash
# Development: Auto-generated fresh keys each run
cargo run --example dev_keygen

# Production: Persistent keys across restarts
cargo run --example production_keygen
```
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
