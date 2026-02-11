//! User credential types and verification abstractions.
//!
//! This module provides the [`Credentials`] type for handling user login data
//! and the [`CredentialsVerifier`] trait for validating credentials against
//! stored authentication secrets.
//!
//! # Quick Start
//!
//! ```rust
//! use axum_gate::prelude::Credentials;
//!
//! // Create credentials from user input
//! let credentials = Credentials::new(&"user@example.com".to_string(), "password123");
//!
//! // Use with JSON APIs
//! use serde_json;
//! let json = r#"{"id": "admin@company.com", "secret": "admin_pass"}"#;
//! let creds: Credentials<String> = serde_json::from_str(json)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Security Considerations
//!
//! **⚠️ Important Security Notes:**
//!
//! - **Contains plaintext secrets** - Handle credentials with extreme care
//! - **Never log credentials** - They contain sensitive password data
//! - **Minimize lifetime** - Process and discard credentials quickly
//! - **Use HTTPS/TLS** - Always encrypt credentials during transmission
//! - **Timing attack protection** - Built-in when using axum-gate login services
//!
//! # Integration with Authentication
//!
//! Credentials integrate seamlessly with axum-gate's authentication system:
//!
//! ```rust
//! use axum::{Json, extract::State, http::StatusCode};
//! use axum_gate::prelude::Credentials;
//! use axum_gate::route_handlers::login;
//! use axum_extra::extract::CookieJar;
//!
//! async fn login_endpoint(
//!     cookie_jar: CookieJar,
//!     Json(credentials): Json<Credentials<String>>,
//!     // State with repositories and JWT codec...
//! ) -> Result<CookieJar, StatusCode> {
//!     // Use the pre-built login handler
//!     // login(cookie_jar, credentials, claims, secret_repo, account_repo, codec, template).await
//!     # Ok(cookie_jar)
//! }
//! ```

#[cfg(feature = "server")]
pub use self::credentials_verifier::CredentialsVerifier;
use serde::{Deserialize, Serialize};

#[cfg(feature = "server")]
mod credentials_verifier;

/// Authentication credentials containing a user identifier and plaintext secret.
///
/// This type represents user login data as typically received from client applications,
/// containing a user identifier (such as email, username, or user ID) paired with a
/// plaintext secret (password). Credentials are used during the authentication process
/// to verify user identity against stored account data.
///
/// # Generic Parameter
///
/// - `Id`: The type of user identifier (commonly [`String`] for emails/usernames, or [`uuid::Uuid`] for user IDs)
///
/// # Security Considerations
///
/// **⚠️ Critical Security Notes:**
///
/// - **Plaintext secrets**: This type contains unencrypted passwords - handle with extreme care
/// - **Memory safety**: Minimize the lifetime of credential instances in memory
/// - **Logging**: Never log or print credential values - they contain sensitive data
/// - **Transport security**: Always use HTTPS/TLS when transmitting credentials
/// - **Storage**: Never store credentials directly - convert to hashed secrets for persistence
///
/// # Authentication Flow Integration
///
/// Credentials are typically used as input to authentication services:
///
/// ```rust
/// use axum_gate::prelude::Credentials;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // 1. Receive credentials from client (e.g., JSON payload)
/// let client_credentials = Credentials::new(&"user@example.com".to_string(), "user_password");
///
/// // 2. Use in authentication service
/// // The login service will:
/// // - Look up the user account
/// // - Retrieve the stored secret hash
/// // - Verify the plaintext password against the hash
/// // - Return authentication result
/// # Ok(())
/// # }
/// ```
///
/// # Timing Attack Protection
///
/// When used with the built-in [`login`](crate::route_handlers::login) handler or [`LoginService`](crate::authn::LoginService),
/// credentials are processed using constant-time operations to prevent timing-based
/// user enumeration attacks:
///
/// - Authentication takes consistent time regardless of whether the user exists
/// - Password verification always occurs, even for non-existent users
/// - Error responses don't distinguish between "user not found" and "wrong password"
///
/// # JSON Serialization
///
/// Credentials support JSON serialization for API integration:
///
/// ```rust
/// use axum_gate::prelude::Credentials;
/// use serde_json;
///
/// // Deserialize from JSON (typical in REST APIs)
/// let json = r#"{"id": "user@example.com", "secret": "password123"}"#;
/// let credentials: Credentials<String> = serde_json::from_str(json)?;
///
/// // Serialize to JSON (less common, avoid logging)
/// let json = serde_json::to_string(&credentials)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Different Identifier Types
///
/// ```rust
/// use axum_gate::prelude::Credentials;
/// use uuid::Uuid;
///
/// // String-based identifiers (email, username)
/// let email_creds = Credentials::new(&"user@domain.com".to_string(), "password");
/// let username_creds = Credentials::new(&"johndoe".to_string(), "secret123");
///
/// // UUID-based identifiers
/// let user_id = Uuid::now_v7();
/// let uuid_creds = Credentials::new(&user_id, "user_password");
///
/// // Custom identifier types work with any Clone type
/// #[derive(Clone)]
/// struct UserId(u64);
///
/// let user_id = UserId(12345);
/// let custom_creds = Credentials::new(&user_id, "password");
/// ```
///
/// # Integration with axum Extractors
///
/// ```rust
/// use axum::{Json, extract::State, http::StatusCode};
/// use axum_gate::prelude::Credentials;
///
/// // Extract credentials from JSON request body
/// async fn login_endpoint(
///     Json(credentials): Json<Credentials<String>>,
/// ) -> Result<String, StatusCode> {
///     // Process credentials...
///     Ok("Login successful".to_string())
/// }
///
/// // Extract credentials from form data
/// use axum::extract::Form;
/// async fn form_login(
///     Form(credentials): Form<Credentials<String>>,
/// ) -> Result<String, StatusCode> {
///     // Process form-submitted credentials...
///     Ok("Login successful".to_string())
/// }
/// ```
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Credentials<Id> {
    /// The identification of the user, eg. a username.
    pub id: Id,
    /// The secret of the user, eg. a password.
    pub secret: String,
}

impl<Id> Credentials<Id> {
    /// Creates new credentials with the specified identifier and plaintext secret.
    ///
    /// This constructor creates a new [`Credentials`] instance containing a user identifier
    /// and plaintext password. The identifier is cloned and the secret is converted to an
    /// owned string for storage within the credentials.
    ///
    /// # Parameters
    ///
    /// - `id`: User identifier (email, username, UUID, etc.) - must implement [`ToOwned`]
    /// - `secret`: Plaintext password or secret as received from the user
    ///
    /// # Security Warning
    ///
    /// The created credentials contain plaintext secrets. Ensure proper security practices:
    /// - Use credentials immediately for authentication
    /// - Avoid storing credentials in logs or persistent storage
    /// - Clear credentials from memory when no longer needed
    /// - Transmit only over secure channels (HTTPS/TLS)
    ///
    /// # Examples
    ///
    /// ## String-based Authentication
    ///
    /// ```rust
    /// use axum_gate::prelude::Credentials;
    ///
    /// let credentials = Credentials::new(&"user@example.com".to_string(), "secure_password");
    /// assert_eq!(credentials.id, "user@example.com");
    /// assert_eq!(credentials.secret, "secure_password");
    /// ```
    ///
    /// ## UUID-based Authentication
    ///
    /// ```rust
    /// use axum_gate::prelude::Credentials;
    /// use uuid::Uuid;
    ///
    /// let user_id = Uuid::now_v7();
    /// let credentials = Credentials::new(&user_id, "user_secret");
    /// assert_eq!(credentials.id, user_id);
    /// assert_eq!(credentials.secret, "user_secret");
    /// ```
    ///
    /// ## Usage in Authentication Flow
    ///
    /// ```rust
    /// use axum_gate::prelude::Credentials;
    ///
    /// // Typically created from user input
    /// let user_input_email = "admin@company.com";
    /// let user_input_password = "admin_password";
    ///
    /// let credentials = Credentials::new(
    ///     &user_input_email.to_string(),
    ///     user_input_password
    /// );
    ///
    /// // Credentials are now ready for authentication verification
    /// // Pass to login service or authentication handler
    /// ```
    ///
    /// # Generic Type Requirements
    ///
    /// The identifier type `Id` must implement [`ToOwned`] to allow the credentials
    /// to take ownership of the identifier value. This is automatically satisfied by
    /// common types like [`String`], [`uuid::Uuid`], and most primitive types.
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
