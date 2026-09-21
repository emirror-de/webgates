//! JWT claim types, codecs, validation helpers, JWKS support, and automatic key management.
//!
//! This module contains the main JWT-facing API of `webgates-codecs`, including production-ready
//! automatic key generation and file-based persistence.
//!
//! # Key Management
//!
//! This module provides three strategies for managing ES384 keys:
//!
//! ## 1. Development (Auto-Generated, Ephemeral)
//!
//! Perfect for tests and local development:
//!
//! ```rust
//! # use webgates_codecs::jwt::JsonWebTokenOptions;
//! let options = JsonWebTokenOptions::generate_for_testing()?;
//! assert_eq!(options.verification_key_count(), 1);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Each call produces a unique ES384 key pair using cryptographic randomness.
//! Keys are not persisted to disk. Perfect test isolation.
//!
//! ## 2. Production (File-Based Persistence)
//!
//! Perfect for production servers, containers, and orchestration platforms:
//!
//! ```rust
//! # use webgates_codecs::jwt::JsonWebTokenOptions;
//! # let unique = std::time::SystemTime::now()
//! #     .duration_since(std::time::UNIX_EPOCH)?
//! #     .as_nanos();
//! # let temp_dir = std::env::temp_dir().join(format!("webgates-jwt-docs-{unique}"));
//! # std::fs::create_dir_all(&temp_dir)?;
//! # let key_path = temp_dir.join("jwt.key");
//! # let public_key_path = temp_dir.join("jwt.key.pub");
//! # let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
//! // First run: generates and saves keys.
//! // Subsequent runs: loads existing keys.
//! let options = runtime.block_on(async {
//!     JsonWebTokenOptions::from_private_key_path(&key_path).await
//! })?;
//! assert!(key_path.is_file());
//! assert!(public_key_path.is_file());
//! # let _ = options;
//! # let _ = std::fs::remove_file(&public_key_path);
//! # let _ = std::fs::remove_file(&key_path);
//! # let _ = std::fs::remove_dir_all(&temp_dir);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! **How it works**:
//! - **First run**: Generates fresh ES384 keys using cryptographic randomness and saves to:
//!   - `/etc/jwt/key` (private key)
//!   - `/etc/jwt/key.pub` (public key, auto-derived)
//! - **Subsequent runs**: Loads existing keys from disk
//! - **Error case**: If only one file exists, returns error (prevents misconfiguration)
//!
//! Perfect for Docker, Kubernetes, systemd, and any stateful deployment.
//!
//! ## 3. Verification-Only (Public Key Only)
//!
//! When a node only validates tokens (never signs):
//!
//! ```rust
//! # use webgates_codecs::jwt::{generate_es384_key_pair_pem, JsonWebTokenOptions};
//! # let (_private_pem, public_pem) = generate_es384_key_pair_pem()?;
//! let options = JsonWebTokenOptions::for_es384_verification_only(&public_pem)?;
//! assert_eq!(options.verification_key_count(), 1);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Core Types
//!
//! This module provides:
//! - [`RegisteredClaims`]: Standard JWT claims (issuer, subject, expiration, etc.)
//! - [`JwtClaims<T>`]: Combined registered and application-specific claims
//! - [`JsonWebTokenOptions`]: Configuration for key management and algorithm selection
//! - [`JsonWebToken<T>`]: The JWT codec implementation
//! - [`Es384KeyPairLoader`]: Low-level file-based key loading and generation
//! - [`Es384KeyPair`]: In-memory ES384 key material
//! - [`JwtAuthority<P>`] (in [`authority`]): Auth server bundle with signing + JWKS publication
//!
//! # Validation & Verification
//!
//! See these modules:
//! - [`validation_service::JwtValidationService`]: Validate raw token strings
//! - [`validation_result::JwtValidationResult`]: Structured validation results
//! - [`remote_verifier`]: Fetch and cache public keys from remote JWKS endpoints
//!
//! # JWKS (JSON Web Key Set)
//!
//! Distributed token verification via the [`jwks`] module:
//! - [`jwks::EcP384Jwk`]: An ES384 public key in JWKS format
//! - [`jwks::JwksDocument`]: A JWKS document (collection of keys)
//! - [`jwks::JwksProvider`]: Publishes JWKS for external verification
//!
//! # Security
//!
//! - **Algorithm**: ES384 (ECDSA with NIST P-384) - RFC 7518 compliant
//! - **Randomness**: Cryptographically secure randomness via `getrandom`
//! - **Format**: PKCS#8 PEM (industry standard)
//! - **Algorithm enforcement**: Strictly requires ES384, prevents algorithm confusion attacks
//! - **No unsafe code**: `#![deny(unsafe_code)]`
//! - **No hardcoded keys**: Production and development use separate strategies
//!
//! # Examples
//!
//! See the examples in the `webgates-codecs` crate:
//! - `examples/dev_keygen.rs`: Development auto-generation patterns
//! - `examples/production_keygen.rs`: Production file-based persistence
//!
//! The implementation is framework-agnostic and depends only on shared types
//! from `webgates-core` plus the codec abstractions from this crate.
//!
//! Prefer the canonical module-owned public paths for validation helpers:
//! - [`validation_service::JwtValidationService`]
//! - [`validation_result::JwtValidationResult`]

use crate::errors::{JwtError, JwtOperation};
use crate::jwt::authority::JwtAuthority;
use crate::{Codec, Error, Result};

use std::collections::HashMap;
use std::collections::HashSet;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode_header};
use p384::elliptic_curve::Generate;
use p384::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_with::skip_serializing_none;
use uuid::Uuid;

pub mod authority;
pub mod jwks;
pub mod remote_verifier;
pub mod validation_result;
pub mod validation_service;

fn validation_with_es384_only() -> Validation {
    let mut validation = Validation::new(Algorithm::ES384);
    validation.algorithms = vec![Algorithm::ES384];
    validation
}

fn canonical_es384_header_with_kid(kid: &str) -> Header {
    let mut header = Header::new(Algorithm::ES384);
    header.typ = Some("JWT".to_string());
    header.kid = Some(kid.to_string());
    header
}

/// File paths for an ES384 key pair managed on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Es384KeyPairPaths {
    private_key_path: PathBuf,
    public_key_path: PathBuf,
}

impl Es384KeyPairPaths {
    /// Creates key pair paths from explicit private and public key locations.
    pub fn new(private_key_path: impl Into<PathBuf>, public_key_path: impl Into<PathBuf>) -> Self {
        Self {
            private_key_path: private_key_path.into(),
            public_key_path: public_key_path.into(),
        }
    }

    /// Returns the private key file path.
    pub fn private_key_path(&self) -> &Path {
        &self.private_key_path
    }

    /// Returns the public key file path.
    pub fn public_key_path(&self) -> &Path {
        &self.public_key_path
    }

    /// Returns whether both key files currently exist.
    pub fn both_exist(&self) -> bool {
        self.private_key_path.is_file() && self.public_key_path.is_file()
    }
}

/// In-memory ES384 key material loaded from disk or generated on startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Es384KeyPair {
    paths: Es384KeyPairPaths,
    private_key_pem: Vec<u8>,
    public_key_pem: Vec<u8>,
}

impl Es384KeyPair {
    /// Creates an in-memory key pair from explicit paths and PEM bytes.
    pub fn new(
        paths: Es384KeyPairPaths,
        private_key_pem: impl Into<Vec<u8>>,
        public_key_pem: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            paths,
            private_key_pem: private_key_pem.into(),
            public_key_pem: public_key_pem.into(),
        }
    }

    /// Returns the file paths associated with this key pair.
    pub fn paths(&self) -> &Es384KeyPairPaths {
        &self.paths
    }

    /// Returns the private key file path.
    pub fn private_key_path(&self) -> &Path {
        self.paths.private_key_path()
    }

    /// Returns the public key file path.
    pub fn public_key_path(&self) -> &Path {
        self.paths.public_key_path()
    }

    /// Returns the PEM-encoded private key bytes.
    pub fn private_key_pem(&self) -> &[u8] {
        &self.private_key_pem
    }

    /// Returns the PEM-encoded public key bytes.
    pub fn public_key_pem(&self) -> &[u8] {
        &self.public_key_pem
    }

    /// Converts the loaded key pair into JWT codec options.
    pub fn to_jwt_options(&self) -> Result<JsonWebTokenOptions> {
        JsonWebTokenOptions::from_es384_pem(&self.private_key_pem, &self.public_key_pem)
    }

    /// Builds a JWT codec directly from this loaded key pair.
    pub fn to_codec<P>(&self) -> Result<JsonWebToken<P>> {
        Ok(JsonWebToken::new_with_options(self.to_jwt_options()?))
    }

    /// Builds a JWT authority directly from this loaded key pair.
    pub fn to_authority<P>(&self) -> Result<JwtAuthority<P>>
    where
        P: Serialize + DeserializeOwned + Clone,
    {
        JwtAuthority::from_es384_pem(&self.private_key_pem, &self.public_key_pem)
    }
}

/// Loads or initializes an ES384 key pair from the filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Es384KeyPairLoader {
    paths: Es384KeyPairPaths,
}

impl Es384KeyPairLoader {
    /// Creates a new loader for the given private and public key paths.
    pub fn new(private_key_path: impl Into<PathBuf>, public_key_path: impl Into<PathBuf>) -> Self {
        Self {
            paths: Es384KeyPairPaths::new(private_key_path, public_key_path),
        }
    }

    /// Creates a new loader from a private key path, deriving the public key path automatically.
    ///
    /// The public key path is derived by appending `.pub` to the private key path.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use webgates_codecs::jwt::{Es384KeyPairLoader, JsonWebTokenOptions};
    /// # let unique = std::time::SystemTime::now()
    /// #     .duration_since(std::time::UNIX_EPOCH)?
    /// #     .as_nanos();
    /// # let temp_dir = std::env::temp_dir().join(format!("webgates-loader-docs-{unique}"));
    /// # std::fs::create_dir_all(&temp_dir)?;
    /// # let key_path = temp_dir.join("jwt.key");
    /// // Private key: <temp>/jwt.key
    /// // Public key:  <temp>/jwt.key.pub (derived automatically)
    /// let loader = Es384KeyPairLoader::from_private_key_path(&key_path);
    ///
    /// # let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    /// // Initialize: loads existing keys or generates + saves new ones
    /// let key_pair = runtime.block_on(async {
    ///     loader.initialize_if_required().await
    /// })?;
    ///
    /// // Use with JsonWebTokenOptions
    /// let options = JsonWebTokenOptions::from_es384_pem(
    ///     key_pair.private_key_pem(),
    ///     key_pair.public_key_pem()
    /// )?;
    /// assert_eq!(options.verification_key_count(), 1);
    /// # let _ = std::fs::remove_file(key_pair.public_key_path());
    /// # let _ = std::fs::remove_file(key_pair.private_key_path());
    /// # let _ = std::fs::remove_dir_all(&temp_dir);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Behavior
    ///
    /// - If both files exist: loads them from disk
    /// - If neither file exists: generates fresh keys and saves them
    /// - If only one exists: returns an error (prevents misconfiguration)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Only one of the key files exists
    /// - Files cannot be read/written
    /// - Keys cannot be parsed as valid ES384
    ///
    /// # Production Use
    ///
    /// This is ideal for production deployments:
    /// ```bash
    /// # First run: automatically generates keys
    /// $ ./my-server
    /// # Creates:
    /// #   /etc/jwt/key
    /// #   /etc/jwt/key.pub
    ///
    /// # Subsequent runs: reuses existing keys
    /// $ ./my-server
    /// ```
    pub fn from_private_key_path(private_key_path: impl Into<PathBuf>) -> Self {
        let private_path: PathBuf = private_key_path.into();
        let mut public_path = private_path.clone();
        let filename = match private_path.file_name() {
            Some(name) => {
                let s = name.to_string_lossy().to_string();
                format!("{}.pub", s)
            }
            None => "key.pub".to_string(),
        };
        public_path.set_file_name(&filename);
        Self::new(private_path, public_path)
    }

    /// Returns the configured key paths.
    pub fn paths(&self) -> &Es384KeyPairPaths {
        &self.paths
    }

    /// Creates the key pair if missing and then loads both PEM files.
    ///
    /// If both files already exist, they are reused unchanged. If neither file
    /// exists, a new ES384 key pair is generated, written to disk, and loaded.
    ///
    /// # Errors
    ///
    /// Returns an error when only one key file exists, when directories or
    /// files cannot be created or read, or when the resulting PEM bytes are not
    /// a valid ES384 key pair.
    pub async fn initialize_if_required(&self) -> Result<Es384KeyPair> {
        let private_exists = self.paths.private_key_path.is_file();
        let public_exists = self.paths.public_key_path.is_file();

        match (private_exists, public_exists) {
            (true, true) => self.load().await,
            (false, false) => {
                self.create_parent_directories().await?;
                let (private_key_pem, public_key_pem) = generate_es384_key_pair_pem()?;
                tokio::fs::write(&self.paths.private_key_path, &private_key_pem)
                    .await
                    .map_err(|error| {
                        Error::Jwt(JwtError::processing(
                            JwtOperation::Encode,
                            format!(
                                "failed to write ES384 private key `{}`: {error}",
                                self.paths.private_key_path.display()
                            ),
                        ))
                    })?;
                tokio::fs::write(&self.paths.public_key_path, &public_key_pem)
                    .await
                    .map_err(|error| {
                        Error::Jwt(JwtError::processing(
                            JwtOperation::Encode,
                            format!(
                                "failed to write ES384 public key `{}`: {error}",
                                self.paths.public_key_path.display()
                            ),
                        ))
                    })?;
                self.validate_loaded_pair(Es384KeyPair::new(
                    self.paths.clone(),
                    private_key_pem,
                    public_key_pem,
                ))
            }
            _ => Err(Error::Jwt(JwtError::processing(
                JwtOperation::Encode,
                format!(
                    "ES384 key initialization requires both key files to exist or neither to exist; private=`{}`, public=`{}`",
                    self.paths.private_key_path.display(),
                    self.paths.public_key_path.display()
                ),
            ))),
        }
    }

    /// Loads both PEM files from disk.
    ///
    /// # Errors
    ///
    /// Returns an error if either file cannot be read or if the loaded bytes do
    /// not form a valid ES384 key pair.
    pub async fn load(&self) -> Result<Es384KeyPair> {
        let private_key_pem = tokio::fs::read(&self.paths.private_key_path)
            .await
            .map_err(|error| {
                Error::Jwt(JwtError::processing(
                    JwtOperation::Decode,
                    format!(
                        "failed to read ES384 private key `{}`: {error}",
                        self.paths.private_key_path.display()
                    ),
                ))
            })?;
        let public_key_pem =
            tokio::fs::read(&self.paths.public_key_path)
                .await
                .map_err(|error| {
                    Error::Jwt(JwtError::processing(
                        JwtOperation::Decode,
                        format!(
                            "failed to read ES384 public key `{}`: {error}",
                            self.paths.public_key_path.display()
                        ),
                    ))
                })?;

        self.validate_loaded_pair(Es384KeyPair::new(
            self.paths.clone(),
            private_key_pem,
            public_key_pem,
        ))
    }

    async fn create_parent_directories(&self) -> Result<()> {
        if let Some(parent) = self.paths.private_key_path.parent()
            && !parent.as_os_str().is_empty()
        {
            tokio::fs::create_dir_all(parent).await.map_err(|error| {
                Error::Jwt(JwtError::processing(
                    JwtOperation::Encode,
                    format!(
                        "failed to create private key directory `{}`: {error}",
                        parent.display()
                    ),
                ))
            })?;
        }

        if let Some(parent) = self.paths.public_key_path.parent()
            && !parent.as_os_str().is_empty()
        {
            tokio::fs::create_dir_all(parent).await.map_err(|error| {
                Error::Jwt(JwtError::processing(
                    JwtOperation::Encode,
                    format!(
                        "failed to create public key directory `{}`: {error}",
                        parent.display()
                    ),
                ))
            })?;
        }

        Ok(())
    }

    fn validate_loaded_pair(&self, key_pair: Es384KeyPair) -> Result<Es384KeyPair> {
        key_pair.to_jwt_options()?;
        Ok(key_pair)
    }
}

/// Generates a fresh ES384 key pair using cryptographically secure randomness.
///
/// Returns both private and public keys in PEM format.
/// Each call produces a unique key pair.
///
/// # Errors
///
/// Returns an error if the cryptographic key generation or PEM encoding fails.
pub fn generate_es384_key_pair_pem() -> Result<(Vec<u8>, Vec<u8>)> {
    let signing_key = p384::ecdsa::SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let private_key_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|error| {
            Error::Jwt(JwtError::processing(
                JwtOperation::Encode,
                format!("failed to encode ES384 private key as PKCS#8 PEM: {error}"),
            ))
        })?
        .to_string()
        .into_bytes();
    let public_key_pem = verifying_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|error| {
            Error::Jwt(JwtError::processing(
                JwtOperation::Encode,
                format!("failed to encode ES384 public key as PEM: {error}"),
            ))
        })?
        .into_bytes();

    Ok((private_key_pem, public_key_pem))
}

/// Registered claims defined by the JWT specification.
///
/// These are the standard metadata fields that travel alongside your
/// application-specific payload in a JWT.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[skip_serializing_none]
pub struct RegisteredClaims {
    /// Issuer of the JWT.
    #[serde(rename = "iss")]
    pub issuer: String,
    /// Subject of the JWT.
    #[serde(rename = "sub")]
    pub subject: Option<String>,
    /// Recipient for which the JWT is intended.
    #[serde(rename = "aud")]
    pub audience: Option<HashSet<String>>,
    /// Time after which the JWT expires.
    #[serde(rename = "exp")]
    pub expiration_time: u64,
    /// Time before which the JWT must not be accepted for processing.
    #[serde(rename = "nbf")]
    pub not_before_time: Option<u64>,
    /// Time at which the JWT was issued.
    #[serde(rename = "iat")]
    pub issued_at_time: u64,
    /// Unique token identifier.
    #[serde(rename = "jti")]
    pub jwt_id: Option<String>,
    /// Session identifier for session-backed tokens.
    #[serde(rename = "sid")]
    pub session_id: Option<String>,
}

impl RegisteredClaims {
    /// Creates new registered claims and sets `issued_at_time` to `Utc::now()`.
    pub fn new(issuer: &str, expiration_time: u64) -> Self {
        // chrono::DateTime::timestamp() returns i64; use a checked conversion so a
        // negative timestamp (clock correction, pre-epoch test date) does not wrap
        // silently to a very large u64 and produce a malformed `iat` claim.
        let issued_at_time = u64::try_from(Utc::now().timestamp()).unwrap_or(0);
        Self {
            issuer: issuer.to_string(),
            subject: None,
            audience: None,
            expiration_time,
            not_before_time: None,
            issued_at_time,
            jwt_id: Some(Uuid::now_v7().to_string()),
            session_id: None,
        }
    }

    /// Returns updated claims with an explicit session identifier.
    #[must_use]
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }
}

/// Combined registered and application-specific JWT claims.
///
/// This is the main typed claim container used with [`JsonWebToken<T>`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct JwtClaims<CustomClaims> {
    /// Standard JWT registered claims.
    #[serde(flatten)]
    pub registered_claims: RegisteredClaims,
    /// Application-specific claims.
    #[serde(flatten)]
    pub custom_claims: CustomClaims,
}

impl<CustomClaims> JwtClaims<CustomClaims> {
    /// Creates a new combined claims value.
    pub fn new(custom_claims: CustomClaims, registered_claims: RegisteredClaims) -> Self {
        Self {
            custom_claims,
            registered_claims,
        }
    }

    /// Returns `true` when the issuer matches `issuer`.
    pub fn has_issuer(&self, issuer: &str) -> bool {
        self.registered_claims.issuer == issuer
    }
}

/// Options used to configure a [`JsonWebToken`] codec.
///
/// Use this when you need explicit control over signing keys, verification keys,
/// key identifiers, or validation settings.
#[derive(Debug, Clone)]
pub struct JsonWebTokenOptions {
    /// Key for ES384 encoding.
    encoding_key: Option<EncodingKey>,
    /// Canonical key id used when minting JWTs.
    key_id: String,
    /// Public verification keys indexed by `kid`.
    decoding_keys_by_kid: HashMap<String, DecodingKey>,
    /// Legacy fallback verification key when no `kid` was provided in the token.
    fallback_decoding_key: Option<DecodingKey>,
    /// Header used for encoding.
    header: Header,
    /// Validation options used during decoding.
    validation: Validation,
}

impl JsonWebTokenOptions {
    /// Creates ES384 JWT options from PEM-encoded private and public keys.
    ///
    /// # Errors
    ///
    /// Returns a JWT processing error when either key cannot be parsed.
    pub fn from_es384_pem(private_key_pem: &[u8], public_key_pem: &[u8]) -> Result<Self> {
        let encoding_key = EncodingKey::from_ec_pem(private_key_pem).map_err(|error| {
            Error::Jwt(JwtError::processing(
                JwtOperation::Encode,
                format!("failed to parse ES384 private key: {error}"),
            ))
        })?;
        let decoding_key = DecodingKey::from_ec_pem(public_key_pem).map_err(|error| {
            Error::Jwt(JwtError::processing(
                JwtOperation::Decode,
                format!("failed to parse ES384 public key: {error}"),
            ))
        })?;
        let key_id = jwks::es384_kid_from_public_key_pem(public_key_pem)?;
        let header = canonical_es384_header_with_kid(&key_id);
        let validation = validation_with_es384_only();
        let mut decoding_keys_by_kid = HashMap::new();
        decoding_keys_by_kid.insert(key_id.clone(), decoding_key.clone());

        Ok(Self {
            encoding_key: Some(encoding_key),
            key_id,
            decoding_keys_by_kid,
            fallback_decoding_key: Some(decoding_key),
            header,
            validation,
        })
    }

    /// Loads or generates ES384 JWT options from a private key file path.
    ///
    /// The public key path is derived by appending `.pub` to the private key path.
    ///
    /// # Behavior
    ///
    /// - **Both files exist**: Loads keys from disk and returns options
    /// - **Neither file exists**: Generates fresh keys, saves both files, returns options
    /// - **Only one file exists**: Returns an error (prevents misconfiguration)
    ///
    /// # Example
    ///
    /// ```rust
    /// # use webgates_codecs::jwt::JsonWebTokenOptions;
    /// # let unique = std::time::SystemTime::now()
    /// #     .duration_since(std::time::UNIX_EPOCH)?
    /// #     .as_nanos();
    /// # let temp_dir = std::env::temp_dir().join(format!("webgates-options-docs-{unique}"));
    /// # std::fs::create_dir_all(&temp_dir)?;
    /// # let key_path = temp_dir.join("jwt.key");
    /// # let public_key_path = temp_dir.join("jwt.key.pub");
    /// # let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    /// // First run: generates and saves keys.
    /// let first = runtime.block_on(async {
    ///     JsonWebTokenOptions::from_private_key_path(&key_path).await
    /// })?;
    ///
    /// // Subsequent runs: reuses existing keys.
    /// let second = runtime.block_on(async {
    ///     JsonWebTokenOptions::from_private_key_path(&key_path).await
    /// })?;
    ///
    /// assert_eq!(first.key_id(), second.key_id());
    /// assert!(key_path.is_file());
    /// assert!(public_key_path.is_file());
    /// # let _ = std::fs::remove_file(&public_key_path);
    /// # let _ = std::fs::remove_file(&key_path);
    /// # let _ = std::fs::remove_dir_all(&temp_dir);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Production Use
    ///
    /// This is perfect for production server startup:
    ///
    /// ```rust
    /// use webgates_codecs::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims};
    ///
    /// # let unique = std::time::SystemTime::now()
    /// #     .duration_since(std::time::UNIX_EPOCH)?
    /// #     .as_nanos();
    /// # let temp_dir = std::env::temp_dir().join(format!("webgates-codec-docs-{unique}"));
    /// # std::fs::create_dir_all(&temp_dir)?;
    /// # let key_path = temp_dir.join("server.key");
    /// # let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    /// // Loads existing keys or generates new ones on first run.
    /// let options = runtime.block_on(async {
    ///     JsonWebTokenOptions::from_private_key_path(&key_path).await
    /// })?;
    ///
    /// let codec = JsonWebToken::<JwtClaims<()>>::new_with_options(options);
    /// # let _ = codec;
    /// # let _ = std::fs::remove_file(temp_dir.join("server.key.pub"));
    /// # let _ = std::fs::remove_file(&key_path);
    /// # let _ = std::fs::remove_dir_all(&temp_dir);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Only one key file exists
    /// - Files cannot be read/written/created
    /// - Invalid key material is found
    ///
    /// # Security
    ///
    /// The generated private key files have restrictive permissions on Unix systems.
    /// Consider using proper file system ACLs or a key management system for sensitive deployments.
    pub async fn from_private_key_path(private_key_path: impl Into<PathBuf>) -> Result<Self> {
        let loader = Es384KeyPairLoader::from_private_key_path(private_key_path);
        let key_pair = loader.initialize_if_required().await?;
        Self::from_es384_pem(key_pair.private_key_pem(), key_pair.public_key_pem())
    }

    /// Creates verification-only ES384 JWT options from a PEM public key.
    ///
    /// Codecs built from these options can decode and validate tokens but will
    /// reject encoding attempts.
    ///
    /// # Errors
    ///
    /// Returns a JWT processing error when the public key cannot be parsed.
    pub fn for_es384_verification_only(public_key_pem: &[u8]) -> Result<Self> {
        let decoding_key = DecodingKey::from_ec_pem(public_key_pem).map_err(|error| {
            Error::Jwt(JwtError::processing(
                JwtOperation::Decode,
                format!("failed to parse ES384 public key: {error}"),
            ))
        })?;
        let key_id = jwks::es384_kid_from_public_key_pem(public_key_pem)?;
        let header = canonical_es384_header_with_kid(&key_id);
        let validation = validation_with_es384_only();
        let mut decoding_keys_by_kid = HashMap::new();
        decoding_keys_by_kid.insert(key_id.clone(), decoding_key.clone());

        Ok(Self {
            encoding_key: None,
            key_id,
            decoding_keys_by_kid,
            fallback_decoding_key: Some(decoding_key),
            header,
            validation,
        })
    }

    /// Creates verification-only ES384 options from JWKS keys.
    ///
    /// This enables key selection by `kid` and rejects JWTs that do not include
    /// a matching `kid`.
    ///
    /// # Errors
    ///
    /// Returns a JWT processing error if no valid ES384 verification key can be
    /// constructed from the provided JWKS entries.
    pub fn for_es384_jwks_keys(keys: &[jwks::EcP384Jwk]) -> Result<Self> {
        if keys.is_empty() {
            return Err(Error::Jwt(JwtError::processing(
                JwtOperation::Validate,
                "JWKS key set is empty",
            )));
        }

        let mut decoding_keys_by_kid = HashMap::new();
        for key in keys {
            let decoding_key = key.to_decoding_key()?;
            decoding_keys_by_kid.insert(key.kid.clone(), decoding_key);
        }

        let key_id = keys[0].kid.clone();
        let header = canonical_es384_header_with_kid(&key_id);
        let validation = validation_with_es384_only();

        Ok(Self {
            encoding_key: None,
            key_id,
            decoding_keys_by_kid,
            fallback_decoding_key: None,
            header,
            validation,
        })
    }

    /// Returns the active signing key id (`kid`).
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the number of configured verification keys.
    pub fn verification_key_count(&self) -> usize {
        self.decoding_keys_by_kid.len()
    }

    /// Returns whether verification accepts missing `kid` by using a fallback
    /// decoding key.
    pub fn allows_missing_kid_fallback(&self) -> bool {
        self.fallback_decoding_key.is_some()
    }

    /// Returns updated options with an explicit `kid` for signing.
    ///
    /// This always keeps a canonical ES384 JWT header (`alg = ES384`,
    /// `typ = JWT`, `kid = ...`).
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        let key_id = key_id.into();
        self.key_id = key_id.clone();
        self.header = canonical_es384_header_with_kid(&key_id);
        self
    }

    /// Returns updated options with a replaced verification-key map.
    ///
    /// The first key is used as fallback only when
    /// `allow_missing_kid_fallback` is `true`.
    pub fn with_verification_keys(
        mut self,
        keys: HashMap<String, DecodingKey>,
        allow_missing_kid_fallback: bool,
    ) -> Self {
        let fallback = if allow_missing_kid_fallback {
            keys.values().next().cloned()
        } else {
            None
        };
        self.decoding_keys_by_kid = keys;
        self.fallback_decoding_key = fallback;
        self
    }

    /// Returns updated options with an added verification key.
    pub fn with_added_verification_key(mut self, kid: impl Into<String>, key: DecodingKey) -> Self {
        self.decoding_keys_by_kid.insert(kid.into(), key);
        self
    }

    /// Returns updated options with custom validation settings.
    pub fn with_validation(self, validation: Validation) -> Self {
        let mut validation = validation;
        validation.algorithms = vec![Algorithm::ES384];

        Self { validation, ..self }
    }

    /// Generates a fresh ES384 key pair suitable for testing and development.
    ///
    /// # Behavior
    ///
    /// This function generates a new ES384 key pair using cryptographically secure randomness
    /// and returns it as JWT-ready options. Each call produces a unique key pair.
    ///
    /// # When to Use
    ///
    /// - **Integration tests**: Each test gets a fresh key pair, preventing key reuse
    /// - **Unit tests**: Isolate test key material
    /// - **Development**: Convenient one-liner for local setup
    /// - **Examples**: Quick prototyping without key management overhead
    /// - **CI/CD**: Automatic key generation in ephemeral environments
    ///
    /// # Example
    ///
    /// ```rust
    /// use webgates_codecs::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims};
    ///
    /// // For testing and development - generates fresh keys.
    /// let jwt_options = JsonWebTokenOptions::generate_for_testing()?;
    /// let codec = JsonWebToken::<JwtClaims<()>>::new_with_options(jwt_options);
    /// # let _ = codec;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns a JWT processing error if key generation or PEM encoding fails.
    pub fn generate_for_testing() -> Result<Self> {
        let (private_key_pem, public_key_pem) = generate_es384_key_pair_pem()?;
        Self::from_es384_pem(&private_key_pem, &public_key_pem)
    }

    /// Generates a fresh ES384 key pair and returns a signing authority.
    ///
    /// # Behavior
    ///
    /// Convenience method that combines key generation with [`JwtAuthority`] construction.
    /// Each call produces unique key material.
    ///
    /// # When to Use
    ///
    /// Use this for quick development setup when you need both token signing and verification:
    ///
    /// ```rust
    /// use webgates_codecs::jwt::{JsonWebTokenOptions, JwtClaims};
    ///
    /// let authority = JsonWebTokenOptions::generate_authority_for_testing::<JwtClaims<()>>()?;
    /// let codec = authority.codec();
    /// let jwks = authority.jwks_provider();
    /// assert_eq!(jwks.document().keys.len(), 1);
    /// assert_eq!(authority.key_id(), jwks.key_id().unwrap());
    /// # let _ = codec;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns a JWT processing error if key generation or authority initialization fails.
    pub fn generate_authority_for_testing<P>() -> Result<JwtAuthority<P>>
    where
        P: Serialize + DeserializeOwned + Clone,
    {
        let (private_key_pem, public_key_pem) = generate_es384_key_pair_pem()?;
        JwtAuthority::from_es384_pem(&private_key_pem, &public_key_pem)
    }
}

/// JWT codec backed by the `jsonwebtoken` crate.
///
/// This is the main codec implementation provided by the crate.
///
/// # Key management
///
/// The default constructor uses built-in ES384 development keys.
/// This is convenient for tests or local development.
///
/// For persistent sessions across restarts or multiple instances, construct the
/// codec with explicit keys via [`JsonWebToken::new_with_options`].
#[derive(Clone)]
pub struct JsonWebToken<P> {
    enc_key: Option<EncodingKey>,
    key_id: String,
    verification_state: std::sync::Arc<RwLock<VerificationState>>,
    header: Header,
    validation: Validation,
    phantom_payload: PhantomData<P>,
}

#[derive(Clone)]
struct VerificationState {
    dec_keys_by_kid: HashMap<String, DecodingKey>,
    fallback_dec_key: Option<DecodingKey>,
}

impl<P> JsonWebToken<P> {
    /// Creates a codec from explicit options.
    ///
    /// Use this when you need explicit signing or verification configuration.
    pub fn new_with_options(options: JsonWebTokenOptions) -> Self {
        let JsonWebTokenOptions {
            encoding_key,
            key_id,
            decoding_keys_by_kid,
            fallback_decoding_key,
            header,
            validation,
        } = options;

        Self {
            enc_key: encoding_key,
            key_id,
            verification_state: std::sync::Arc::new(RwLock::new(VerificationState {
                dec_keys_by_kid: decoding_keys_by_kid,
                fallback_dec_key: fallback_decoding_key,
            })),
            header,
            validation,
            phantom_payload: PhantomData,
        }
    }

    /// Returns the signing `kid` used by this codec.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the number of currently configured verification keys.
    pub fn verification_key_count(&self) -> usize {
        self.verification_state
            .read()
            .map(|state| state.dec_keys_by_kid.len())
            .unwrap_or(0)
    }

    /// Returns whether a verification key for the given `kid` exists.
    pub fn has_verification_key(&self, kid: &str) -> bool {
        self.verification_state
            .read()
            .map(|state| state.dec_keys_by_kid.contains_key(kid))
            .unwrap_or(false)
    }

    /// Returns whether this codec allows verification without `kid`.
    pub fn allows_missing_kid_fallback(&self) -> bool {
        self.verification_state
            .read()
            .map(|state| state.fallback_dec_key.is_some())
            .unwrap_or(false)
    }

    /// Atomically replaces all verification keys.
    pub fn replace_verification_keys(
        &self,
        keys: HashMap<String, DecodingKey>,
        allow_missing_kid_fallback: bool,
    ) {
        if let Ok(mut state) = self.verification_state.write() {
            let fallback = if allow_missing_kid_fallback {
                keys.values().next().cloned()
            } else {
                None
            };
            state.dec_keys_by_kid = keys;
            state.fallback_dec_key = fallback;
        }
    }

    /// Atomically replaces all verification keys from canonical ES384 JWK entries.
    ///
    /// # Errors
    ///
    /// Returns an error when any provided key cannot be converted.
    pub fn replace_verification_keys_from_jwks(
        &self,
        keys: &[jwks::EcP384Jwk],
        allow_missing_kid_fallback: bool,
    ) -> Result<()> {
        let mut decoding_keys = HashMap::new();
        for key in keys {
            let decoding_key = key.to_decoding_key()?;
            decoding_keys.insert(key.kid.clone(), decoding_key);
        }
        self.replace_verification_keys(decoding_keys, allow_missing_kid_fallback);
        Ok(())
    }

    fn decoding_key_for_header(&self, header: &Header) -> Result<DecodingKey> {
        if header.alg != Algorithm::ES384 {
            return Err(Error::Jwt(JwtError::processing(
                JwtOperation::Validate,
                format!(
                    "JWT header algorithm mismatch: expected ES384 but got {:?}",
                    header.alg
                ),
            )));
        }

        if header.typ.as_deref() != Some("JWT") {
            return Err(Error::Jwt(JwtError::processing(
                JwtOperation::Validate,
                "JWT header `typ` must be `JWT`",
            )));
        }

        let state = self.verification_state.read().map_err(|_| {
            Error::Jwt(JwtError::processing(
                JwtOperation::Validate,
                "verification key state lock is poisoned",
            ))
        })?;

        if let Some(kid) = header.kid.as_deref() {
            return state.dec_keys_by_kid.get(kid).cloned().ok_or_else(|| {
                Error::Jwt(JwtError::processing(
                    JwtOperation::Validate,
                    format!("JWT `kid` `{kid}` is not configured for verification"),
                ))
            });
        }

        state.fallback_dec_key.clone().ok_or_else(|| {
            Error::Jwt(JwtError::processing(
                JwtOperation::Validate,
                "JWT header is missing `kid` and no fallback verification key is configured",
            ))
        })
    }
}

impl<P> Codec for JsonWebToken<P>
where
    P: Serialize + DeserializeOwned + Clone,
{
    type Payload = P;

    fn encode(&self, payload: &Self::Payload) -> Result<Vec<u8>> {
        let Some(enc_key) = &self.enc_key else {
            return Err(Error::Jwt(JwtError::processing(
                JwtOperation::Encode,
                "JWT encoding key is not configured for this codec",
            )));
        };
        let token = jsonwebtoken::encode(&self.header, payload, enc_key).map_err(|error| {
            Error::Jwt(JwtError::processing(
                JwtOperation::Encode,
                format!("JWT encoding failed: {error}"),
            ))
        })?;

        Ok(token.into_bytes())
    }

    fn decode(&self, encoded_value: &[u8]) -> Result<Self::Payload> {
        let header = decode_header(std::str::from_utf8(encoded_value).map_err(|error| {
            Error::Jwt(JwtError::processing(
                JwtOperation::Decode,
                format!("JWT bytes are not valid UTF-8: {error}"),
            ))
        })?)
        .map_err(|error| {
            Error::Jwt(JwtError::processing_with_preview(
                JwtOperation::Decode,
                format!("JWT header decoding failed: {error}"),
                Some(format!("token_len={}", encoded_value.len())),
            ))
        })?;

        let decoding_key = self.decoding_key_for_header(&header)?;

        let claims =
            jsonwebtoken::decode::<Self::Payload>(encoded_value, &decoding_key, &self.validation)
                .map_err(|error| {
                // Do not include token bytes in the error to avoid leaking token
                // material into logs or error messages if log levels are
                // misconfigured.  Report only the byte length for diagnostics.
                Error::Jwt(JwtError::processing_with_preview(
                    JwtOperation::Decode,
                    format!("JWT decoding failed: {error}"),
                    Some(format!("token_len={}", encoded_value.len())),
                ))
            })?;

        Ok(claims.claims)
    }
}
