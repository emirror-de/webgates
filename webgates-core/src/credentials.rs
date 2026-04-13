//! User credential types and verification abstractions.
//!
//! This module exposes the credential boundary used by `webgates-core`:
//!
//! - [`Credentials`] stores a caller-provided identifier and plaintext secret
//! - [`credentials_verifier::CredentialsVerifier`] defines the async verification contract used by
//!   higher-level authentication services
//!
//! Import [`Credentials`] directly from `webgates_core::credentials` and
//! [`credentials_verifier::CredentialsVerifier`] from the owning submodule.
//!
//! # Quick Start
//!
//! ```rust
//! use webgates_core::credentials::Credentials;
//!
//! let credentials = Credentials::new(&"user@example.com".to_string(), "password123");
//!
//! let json = r#"{"id":"admin@company.com","secret":"admin_pass"}"#;
//! let parsed: Credentials<String> = serde_json::from_str(json)?;
//!
//! assert_eq!(parsed.id, "admin@company.com");
//! # let _ = credentials;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Verification Boundary
//!
//! Concrete verifier implementations belong in higher-level crates. This crate
//! only defines the shared types and the verification trait that those crates
//! implement.
//!
//! # Security Considerations
//!
//! - Credentials contain plaintext secrets and should be short-lived.
//! - Never log or persist raw credentials.
//! - Only transmit credentials over secure channels such as HTTPS/TLS.
//! - Verification backends should avoid leaking identifier existence through
//!   observable timing or error details.
use serde::{Deserialize, Serialize};

/// Async verification contract for credential backends.
pub mod credentials_verifier;

/// Authentication credentials containing a user identifier and plaintext secret.
///
/// This type represents user input at the authentication boundary. It stores
/// the caller-provided identifier together with a plaintext secret so a
/// verifier can compare it against the stored authentication material.
///
/// # Type Parameter
///
/// - `Id`: Identifier type used by the calling application, commonly [`String`]
///   or [`uuid::Uuid`]
///
/// # Security
///
/// - The `secret` field contains plaintext sensitive data.
/// - Keep instances short-lived and avoid cloning them unnecessarily.
/// - Never log, persist, or expose the raw secret.
/// - Use secure transport when credentials cross process or network boundaries.
///
/// # Examples
///
/// Create credentials from application input:
///
/// ```rust
/// use webgates_core::credentials::Credentials;
///
/// let credentials = Credentials::new(&"user@example.com".to_string(), "user_password");
///
/// assert_eq!(credentials.id, "user@example.com");
/// assert_eq!(credentials.secret, "user_password");
/// ```
///
/// Deserialize credentials from JSON:
///
/// ```rust
/// use webgates_core::credentials::Credentials;
///
/// let json = r#"{"id":"user@example.com","secret":"password123"}"#;
/// let credentials: Credentials<String> = serde_json::from_str(json)?;
///
/// assert_eq!(credentials.id, "user@example.com");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// Use a UUID identifier:
///
/// ```rust
/// use uuid::Uuid;
/// use webgates_core::credentials::Credentials;
///
/// let user_id = Uuid::now_v7();
/// let credentials = Credentials::new(&user_id, "user_password");
///
/// assert_eq!(credentials.id, user_id);
/// ```
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Credentials<Id> {
    /// The identification of the user, eg. a username.
    pub id: Id,
    /// The secret of the user, eg. a password.
    pub secret: String,
}

impl<Id> Credentials<Id> {
    /// Creates credentials from an identifier and a plaintext secret.
    ///
    /// The identifier is cloned into the returned value and the secret is stored
    /// as an owned [`String`].
    ///
    /// # Parameters
    ///
    /// - `id`: User identifier to copy into the credentials
    /// - `secret`: Plaintext secret supplied by the caller
    ///
    /// # Security
    ///
    /// The returned value contains plaintext sensitive data. Callers should keep
    /// it short-lived and avoid logging or persisting it.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use webgates_core::credentials::Credentials;
    ///
    /// let credentials = Credentials::new(&"admin@company.com".to_string(), "admin_password");
    ///
    /// assert_eq!(credentials.id, "admin@company.com");
    /// assert_eq!(credentials.secret, "admin_password");
    /// ```
    ///
    /// ```rust
    /// use uuid::Uuid;
    /// use webgates_core::credentials::Credentials;
    ///
    /// let user_id = Uuid::now_v7();
    /// let credentials = Credentials::new(&user_id, "user_secret");
    ///
    /// assert_eq!(credentials.id, user_id);
    /// ```
    pub fn new(id: &Id, secret: &str) -> Self
    where
        Id: ToOwned<Owned = Id>,
    {
        Self {
            id: id.to_owned(),
            secret: secret.to_string(),
        }
    }
}
