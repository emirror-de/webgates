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
- **automatically generate and persist JWT keys for production deployments**

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
webgates-codecs = "1.1.1"
webgates-core = "1.1.1"
```

Minimum supported Rust version: `1.94`.

## Quick start

### Development: Auto-generated keys

```rust
use std::sync::Arc;
use webgates_codecs::jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER as JWT_CRYPTO_PROVIDER;
use webgates_codecs::jwt::{
    JsonWebToken,
    JsonWebTokenOptions,
    JwtClaims,
    RegisteredClaims,
};
use webgates_codecs::jwt::validation_service::JwtValidationService;
use webgates_codecs::Codec;

type AppClaims = JwtClaims<()>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = JWT_CRYPTO_PROVIDER.install_default();

    // Fresh keys generated explicitly (perfect for tests and local development)
    let codec = Arc::new(JsonWebToken::<AppClaims>::new_with_options(
        JsonWebTokenOptions::generate_for_testing()?,
    ));

    let claims = JwtClaims::new(
        (),
        RegisteredClaims::new("my-app", 4_102_444_800),
    );

    let encoded = codec.encode(&claims)?;
    let decoded = codec.decode(&encoded)?;
    assert!(decoded.has_issuer("my-app"));

    let validator = JwtValidationService::new(Arc::clone(&codec), "my-app");
    let _ = validator.validate_token(std::str::from_utf8(&encoded)?);
    Ok(())
}
```

### Production: Persistent keys from file

```rust
use webgates_codecs::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    // First run: generates keys and saves to disk.
    // Subsequent runs: loads the same keys from disk.
    let options = runtime.block_on(async {
        JsonWebTokenOptions::from_private_key_path("/etc/jwt/key").await
    })?;

    let codec = JsonWebToken::<JwtClaims<()>>::new_with_options(options);
    let _ = codec;
    Ok(())
}
```

### Full auth server with JWKS

```rust
use webgates_codecs::jwt::JwtClaims;
use webgates_codecs::jwt::authority::JwtAuthority;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    // One path, everything handled automatically.
    let authority = runtime.block_on(async {
        JwtAuthority::<JwtClaims<()>>::from_private_key_path("/etc/jwt/server.key").await
    })?;

    let signing_codec = authority.codec();
    let jwks = authority.jwks_provider();
    assert_eq!(authority.key_id(), jwks.key_id().unwrap());

    let _ = signing_codec;
    Ok(())
}
```

## Key management strategies

### For development and testing

Use explicit key generation - fresh keys every time:

```rust
use webgates_codecs::jwt::JsonWebTokenOptions;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Each invocation gets a unique key pair
    let options = JsonWebTokenOptions::generate_for_testing()?;
    assert_eq!(options.verification_key_count(), 1);
    Ok(())
}
```

**Benefits:**
- No configuration needed
- Perfect test isolation
- Each test gets fresh cryptographic material
- Keys are lost on restart (expected for tests)

### For production deployments

Use persistent file-based keys - automatically persist and reuse:

```rust
use webgates_codecs::jwt::JsonWebTokenOptions;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    // First run: generates and saves keys.
    // Subsequent runs: loads existing keys.
    let options = runtime.block_on(async {
        JsonWebTokenOptions::from_private_key_path("/etc/jwt/key").await
    })?;

    let _ = options;
    Ok(())
}
```

**How it works:**

1. **First startup**: 
   - Creates `/etc/jwt/key` (private) and `/etc/jwt/key.pub` (public)
   - Generates fresh ES384 keys using cryptographic randomness
   - Stores keys on disk for future use

2. **Subsequent startups**:
   - Finds existing files
   - Loads keys from disk
   - Reuses same keys (enables token persistence across restarts)

3. **Error cases**:
   - If only one file exists: Error (prevents misconfiguration)
   - If neither exists: Generates fresh pair
   - If both exist: Loads and reuses

**Perfect for:**
- Docker containers with volume mounts
- Kubernetes with ConfigMaps or Secrets
- Systemd services with persistent storage
- Any deployment requiring stable keys across restarts

### For loading explicit key material

When you have keys from a secure source (vault, KMS, file, etc.):

```rust
use webgates_codecs::jwt::JsonWebTokenOptions;

async fn bootstrap(vault: &VaultClient) -> Result<(), Box<dyn std::error::Error>> {
    let private_pem = vault.get_secret("jwt-private-key").await?;
    let public_pem = vault.get_secret("jwt-public-key").await?;

    let options = JsonWebTokenOptions::from_es384_pem(&private_pem, &public_pem)?;
    let _ = options;
    Ok(())
}
```

Here `VaultClient` stands in for your own KMS, secret manager, or vault client.

## Production guidance

### Path-based key management (recommended)

The simplest approach for most production deployments:

```rust
use webgates_codecs::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    // Works with environment variables.
    let key_path = std::env::var("JWT_KEY_PATH")
        .unwrap_or_else(|_| "/etc/jwt/key".to_string());

    let options = runtime.block_on(async {
        JsonWebTokenOptions::from_private_key_path(&key_path).await
    })?;
    let codec = JsonWebToken::<JwtClaims<()>>::new_with_options(options);

    let _ = codec;
    Ok(())
}
```

### With JwtAuthority for JWKS publication

```rust
use webgates_codecs::jwt::JwtClaims;
use webgates_codecs::jwt::authority::JwtAuthority;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let authority = runtime.block_on(async {
        JwtAuthority::<JwtClaims<()>>::from_private_key_path("/etc/jwt/server.key").await
    })?;

    // Signing codec
    let codec = authority.codec();

    // Publish JWKS at /.well-known/jwks.json
    let jwks = authority.jwks_provider();
    assert_eq!(authority.key_id(), jwks.key_id().unwrap());

    let _ = codec;
    Ok(())
}
```

### Verification-only nodes

If a node only validates tokens and never signs them:

```rust
use webgates_codecs::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let public_pem = std::fs::read("/run/secrets/jwt-es384-public.pem")?;
    let codec = JsonWebToken::<JwtClaims<()>>::new_with_options(
        JsonWebTokenOptions::for_es384_verification_only(&public_pem)?,
    );

    let _ = codec;
    Ok(())
}
```

### JWKS-backed verification

For strict `kid`-based key selection:

```rust
use webgates_codecs::jwt::jwks::EcP384Jwk;
use webgates_codecs::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let public_pem = std::fs::read("/run/secrets/jwt-es384-public.pem")?;
    let jwk = EcP384Jwk::from_public_key_pem("auth-key-1", &public_pem)?;
    let codec = JsonWebToken::<JwtClaims<()>>::new_with_options(
        JsonWebTokenOptions::for_es384_jwks_keys(&[jwk])?,
    );

    let _ = codec;
    Ok(())
}
```

## Deployment examples

### Docker with volume mounts

```dockerfile
FROM rust:latest
WORKDIR /app
COPY . .
RUN cargo build --release
ENV JWT_KEY_PATH=/run/jwt/key
CMD ["./target/release/myserver"]
```

On first container start: keys generated and saved to `/run/jwt/`
On subsequent starts: keys reused from volume mount

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

### Systemd service

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

## Security notes

### Cryptography

- **Algorithm**: ES384 (ECDSA with NIST P-384 curve)
- **Standard**: RFC 7518 JWS/JWT
- **Key generation**: Cryptographically secure randomness via `getrandom`
- **Key format**: PKCS#8 PEM for private, SubjectPublicKeyInfo for public

### Development vs Production

**Development** (via `JsonWebTokenOptions::generate_for_testing()`):
- Generates fresh keys explicitly
- Perfect for tests and local development
- Keys are ephemeral
- No security risk (test isolation)

**Production** (via `JsonWebTokenOptions::from_private_key_path()`):
- Keys persist across restarts
- Same keys used consistently
- Supports distributed systems
- Proper file permission handling

### File permissions

After key generation, set restrictive permissions:

```bash
# Private key - readable only by the service user
chmod 600 /etc/jwt/key
chown myservice:myservice /etc/jwt/key

# Public key - can be world-readable
chmod 644 /etc/jwt/key.pub
```

### Key rotation

To rotate keys:

```bash
# Backup old keys
cp /etc/jwt/key /etc/jwt/key.backup
cp /etc/jwt/key.pub /etc/jwt/key.pub.backup

# Remove old keys
rm /etc/jwt/key /etc/jwt/key.pub

# Restart application - new keys generated automatically
```

For gradual migration, support both old and new keys during transition period.

## Error model

This crate exposes:

- `Error`
- `CodecsError`
- `JwtError`
- `CodecOperation`
- `JwtOperation`

Use these when you want structured handling of codec failures and JWT processing failures.

## Examples

Run the included examples to see key management in action:

```bash
# Development: Auto-generated fresh keys each run
cargo run --example dev_keygen

# Production: Persistent keys across restarts
cargo run --example production_keygen
```

## Which crate should you use?

- use `webgates-core` when you only want domain types and authorization primitives
- use `webgates-codecs` when you specifically need JWT codecs and validation helpers
- use `webgates` when you want the higher-level auth stack
- use `webgates-axum` when you want Axum transport integration
- use `webgates-tonic` when you want tonic server-side transport integration

## Recommended onboarding path

If you are new to this crate, I recommend this order:

1. `Codec` - understand the abstraction
2. `jwt::RegisteredClaims` - standard JWT claims
3. `jwt::JwtClaims<T>` - typed application claims
4. `jwt::JsonWebToken<T>` - the JWT implementation
5. `JsonWebTokenOptions::generate_for_testing()` - development setup
6. `JsonWebTokenOptions::from_private_key_path()` - production setup
7. `jwt::validation_service::JwtValidationService` - validation at boundaries
8. `jwt::jwks` - distributed verification

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
