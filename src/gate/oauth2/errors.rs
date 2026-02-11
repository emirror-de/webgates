//! OAuth2 errors for `gate::oauth2`.
//!
//! These error types model failures that can occur while configuring or executing the
//! OAuth2 Authorization Code + PKCE flow within `OAuth2Gate`.
//!
//! Design goals:
//! - Provide a small, expressive enum for all OAuth2-related failures
//! - Keep messages safe for end users; avoid leaking sensitive details
//! - Include deterministic support codes per variant for service/support workflows
//! - Avoid hard dependencies on specific HTTP clients; store messages instead of foreign errors
//!
//! Integration:
//! - The enum implements `crate::errors::UserFriendlyError` for consistent messaging
//! - A local `Result<T>` alias is provided for gate-internal use
//! - The crate-level integration (e.g., adding a new top-level variant in `crate::errors::Error`)
//!   can be done separately if/when you want to surface OAuth2 errors consistently across the crate.

use crate::errors::{ErrorSeverity, UserFriendlyError};
use std::fmt;
use thiserror::Error;

/// OAuth2 cookie kinds used in validation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuth2CookieKind {
    /// CSRF state cookie used during the authorization redirect round-trip.
    State,
    /// PKCE verifier cookie used to complete the token exchange.
    Pkce,
    /// First‑party auth cookie (e.g., JWT) set after successful callback.
    Auth,
}

impl fmt::Display for OAuth2CookieKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OAuth2CookieKind::State => f.write_str("state"),
            OAuth2CookieKind::Pkce => f.write_str("pkce"),
            OAuth2CookieKind::Auth => f.write_str("auth"),
        }
    }
}

/// OAuth2-specific error type for `OAuth2Gate`.
///
/// This enum intentionally uses string messages for external/foreign errors to keep this module
/// decoupled from particular HTTP or OAuth client implementations. Prefer mapping concrete errors
/// into one of these variants at the boundary layers.
#[derive(Debug, Error)]
pub enum OAuth2Error {
    // Configuration and setup
    /// A required configuration field is missing on the `OAuth2Gate` builder.
    #[error("OAuth2 misconfiguration: missing {field}")]
    ConfigMissing {
        /// Name of the missing field (e.g., "auth_url", "token_url", "client_id", "redirect_url").
        field: &'static str,
    },

    /// A provided URL failed validation or parsing.
    #[error("Invalid OAuth2 URL for {field}: {reason}")]
    InvalidUrl {
        /// Which URL field failed (e.g., "auth_url", "token_url", "redirect_url").
        field: &'static str,
        /// Reason or parser message (redacted for end users).
        reason: String,
    },

    /// A cookie template used by the OAuth2 flow failed validation.
    #[error("Invalid {which} cookie template: {reason}")]
    CookieTemplateInvalid {
        /// Which cookie template failed validation (state, pkce, or auth).
        which: OAuth2CookieKind,
        /// Reason or validator message (redacted for end users).
        reason: String,
    },

    // Redirect and callback flow
    /// Required state cookie is missing at callback time.
    #[error("Missing OAuth2 state cookie")]
    MissingStateCookie,

    /// Required PKCE cookie is missing at callback time.
    #[error("Missing OAuth2 PKCE cookie")]
    MissingPkceCookie,

    /// Provider returned an error to the callback endpoint.
    #[error("OAuth2 provider returned error: {error}")]
    ProviderReturnedError {
        /// Provider error identifier.
        error: String,
        /// Optional provider-supplied description.
        description: Option<String>,
    },

    /// The state parameter from the provider did not match the stored cookie.
    #[error("OAuth2 state mismatch")]
    StateMismatch,

    /// The provider callback did not include an authorization code.
    #[error("OAuth2 callback missing authorization code")]
    MissingAuthorizationCode,

    /// Token exchange with the provider failed.
    #[error("OAuth2 token exchange failed: {message}")]
    TokenExchange {
        /// Failure message (e.g., request or response parsing reason).
        message: String,
    },

    // Session issuance after successful token exchange
    /// Mapping the provider token response to a domain `Account` failed.
    #[error("OAuth2 account mapping failed: {message}")]
    AccountMapping {
        /// Failure message (e.g., userinfo retrieval/mapping reason).
        message: String,
    },

    /// Persisting or loading the account prior to JWT issuance failed.
    #[error("OAuth2 account persistence failed: {message}")]
    AccountPersistence {
        /// Failure message (e.g., repository/backend reason).
        message: String,
    },

    /// Encoding the first‑party JWT failed.
    #[error("OAuth2 JWT encoding failed: {message}")]
    JwtEncoding {
        /// Failure message (e.g., codec/serialization reason).
        message: String,
    },

    /// The JWT produced by the encoder was not valid UTF‑8.
    #[error("OAuth2 JWT is not valid UTF‑8")]
    JwtNotUtf8,
}

impl OAuth2Error {
    // Convenience constructors

    /// Helper to construct a `ConfigMissing` error.
    #[must_use]
    pub fn missing(field: &'static str) -> Self {
        Self::ConfigMissing { field }
    }

    /// Helper to construct an `InvalidUrl` error.
    #[must_use]
    pub fn invalid_url(field: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidUrl {
            field,
            reason: reason.into(),
        }
    }

    /// Helper to construct a `CookieTemplateInvalid` error.
    #[must_use]
    pub fn cookie_invalid(which: OAuth2CookieKind, reason: impl Into<String>) -> Self {
        Self::CookieTemplateInvalid {
            which,
            reason: reason.into(),
        }
    }

    /// Helper to construct a `ProviderReturnedError` error.
    #[must_use]
    pub fn provider_error(error: impl Into<String>, description: Option<String>) -> Self {
        Self::ProviderReturnedError {
            error: error.into(),
            description,
        }
    }

    /// Helper to construct a `TokenExchange` error.
    #[must_use]
    pub fn token_exchange(message: impl Into<String>) -> Self {
        Self::TokenExchange {
            message: message.into(),
        }
    }

    /// Helper to construct an `AccountMapping` error.
    #[must_use]
    pub fn account_mapping(message: impl Into<String>) -> Self {
        Self::AccountMapping {
            message: message.into(),
        }
    }

    /// Helper to construct an `AccountPersistence` error.
    #[must_use]
    pub fn account_persistence(message: impl Into<String>) -> Self {
        Self::AccountPersistence {
            message: message.into(),
        }
    }

    /// Helper to construct a `JwtEncoding` error.
    #[must_use]
    pub fn jwt_encoding(message: impl Into<String>) -> Self {
        Self::JwtEncoding {
            message: message.into(),
        }
    }
}

/// Local `Result` alias for OAuth2 flows.
pub type Result<T> = std::result::Result<T, OAuth2Error>;

impl UserFriendlyError for OAuth2Error {
    fn user_message(&self) -> String {
        match self {
            // Configuration/validation (users see a generic message)
            OAuth2Error::ConfigMissing { .. }
            | OAuth2Error::InvalidUrl { .. }
            | OAuth2Error::CookieTemplateInvalid { .. } => {
                "We’re experiencing a technical issue with sign-in. Please try again later."
                    .to_string()
            }

            // Redirect/callback issues (safe messages)
            OAuth2Error::MissingStateCookie
            | OAuth2Error::MissingPkceCookie
            | OAuth2Error::ProviderReturnedError { .. }
            | OAuth2Error::StateMismatch
            | OAuth2Error::MissingAuthorizationCode
            | OAuth2Error::TokenExchange { .. } => {
                "We couldn’t complete the sign-in with your provider. Please try again.".to_string()
            }

            // Session issuance issues (safe messages)
            OAuth2Error::AccountMapping { .. }
            | OAuth2Error::AccountPersistence { .. }
            | OAuth2Error::JwtEncoding { .. }
            | OAuth2Error::JwtNotUtf8 => {
                "We signed you in, but couldn’t complete the session setup. Please try again."
                    .to_string()
            }
        }
    }

    fn developer_message(&self) -> String {
        match self {
            OAuth2Error::ConfigMissing { field } => {
                format!("OAuth2Gate configuration missing required field: {field}")
            }
            OAuth2Error::InvalidUrl { field, reason } => {
                format!("Invalid OAuth2 URL for {field}: {reason}")
            }
            OAuth2Error::CookieTemplateInvalid { which, reason } => {
                format!("Invalid {which} cookie template: {reason}")
            }
            OAuth2Error::MissingStateCookie => "Missing OAuth2 state cookie at callback".into(),
            OAuth2Error::MissingPkceCookie => "Missing OAuth2 PKCE cookie at callback".into(),
            OAuth2Error::ProviderReturnedError { error, description } => format!(
                "OAuth2 provider returned error: {error} {:?}",
                description.as_deref()
            ),
            OAuth2Error::StateMismatch => "OAuth2 state parameter mismatch".into(),
            OAuth2Error::MissingAuthorizationCode => {
                "OAuth2 callback missing authorization code".into()
            }
            OAuth2Error::TokenExchange { message } => {
                format!("OAuth2 token exchange failed: {message}")
            }
            OAuth2Error::AccountMapping { message } => {
                format!("OAuth2 account mapping failed: {message}")
            }
            OAuth2Error::AccountPersistence { message } => {
                format!("OAuth2 account persistence failed: {message}")
            }
            OAuth2Error::JwtEncoding { message } => {
                format!("OAuth2 JWT encoding failed: {message}")
            }
            OAuth2Error::JwtNotUtf8 => "OAuth2 JWT is not valid UTF‑8".into(),
        }
    }

    fn support_code(&self) -> String {
        // Deterministic, human-parseable support codes by variant
        match self {
            OAuth2Error::ConfigMissing { .. } => "OAUTH2-CONFIG-MISSING-001".into(),
            OAuth2Error::InvalidUrl { .. } => "OAUTH2-URL-INVALID-002".into(),
            OAuth2Error::CookieTemplateInvalid { .. } => "OAUTH2-COOKIE-INVALID-003".into(),
            OAuth2Error::MissingStateCookie => "OAUTH2-STATE-MISSING-004".into(),
            OAuth2Error::MissingPkceCookie => "OAUTH2-PKCE-MISSING-005".into(),
            OAuth2Error::ProviderReturnedError { .. } => "OAUTH2-PROVIDER-ERROR-006".into(),
            OAuth2Error::StateMismatch => "OAUTH2-STATE-MISMATCH-007".into(),
            OAuth2Error::MissingAuthorizationCode => "OAUTH2-CODE-MISSING-008".into(),
            OAuth2Error::TokenExchange { .. } => "OAUTH2-TOKEN-EXCHANGE-009".into(),
            OAuth2Error::AccountMapping { .. } => "OAUTH2-ACCOUNT-MAP-010".into(),
            OAuth2Error::AccountPersistence { .. } => "OAUTH2-ACCOUNT-PERSIST-011".into(),
            OAuth2Error::JwtEncoding { .. } => "OAUTH2-JWT-ENCODE-012".into(),
            OAuth2Error::JwtNotUtf8 => "OAUTH2-JWT-NONUTF8-013".into(),
        }
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            // Misconfiguration and invalid templates are deployment-time issues
            OAuth2Error::ConfigMissing { .. }
            | OAuth2Error::InvalidUrl { .. }
            | OAuth2Error::CookieTemplateInvalid { .. } => ErrorSeverity::Error,

            // Callback-level issues vary; treat as warnings unless systemic
            OAuth2Error::MissingStateCookie
            | OAuth2Error::MissingPkceCookie
            | OAuth2Error::ProviderReturnedError { .. }
            | OAuth2Error::StateMismatch
            | OAuth2Error::MissingAuthorizationCode => ErrorSeverity::Warning,

            // Network/exchange or backend failures
            OAuth2Error::TokenExchange { .. }
            | OAuth2Error::AccountMapping { .. }
            | OAuth2Error::AccountPersistence { .. }
            | OAuth2Error::JwtEncoding { .. }
            | OAuth2Error::JwtNotUtf8 => ErrorSeverity::Error,
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            OAuth2Error::ConfigMissing { field } => vec![format!(
                "Set OAuth2Gate builder field: {field} (auth_url, token_url, client_id, redirect_url)"
            )],
            OAuth2Error::InvalidUrl { field, .. } => {
                vec![format!("Verify URL format and scheme for {field}")]
            }
            OAuth2Error::CookieTemplateInvalid { which, .. } => vec![format!(
                "Review {} cookie template (SameSite/Secure/Max-Age). SameSite=None requires Secure=true",
                which
            )],
            OAuth2Error::MissingStateCookie | OAuth2Error::MissingPkceCookie => vec![
                "Ensure cookies are set for the same domain and path during /login → /callback"
                    .into(),
                "Check SameSite and Secure attributes for OAuth redirect round-trip".into(),
            ],
            OAuth2Error::ProviderReturnedError { .. } => vec![
                "Verify client id/secret and callback URL in provider settings".into(),
                "Check provider status and retry later".into(),
            ],
            OAuth2Error::StateMismatch => vec![
                "Ensure the same domain/protocol is used during the OAuth redirect round-trip"
                    .into(),
                "Avoid navigating away or opening multiple OAuth tabs simultaneously".into(),
            ],
            OAuth2Error::MissingAuthorizationCode => {
                vec!["Retry sign-in; ensure the provider granted access".into()]
            }
            OAuth2Error::TokenExchange { .. } => vec![
                "Verify token endpoint URL and client credentials".into(),
                "Check network egress, DNS, and request timeouts".into(),
            ],
            OAuth2Error::AccountMapping { .. } => {
                vec!["Review userinfo call and mapping logic; handle missing fields".into()]
            }
            OAuth2Error::AccountPersistence { .. } => {
                vec!["Check repository connectivity and unique constraints".into()]
            }
            OAuth2Error::JwtEncoding { .. } => {
                vec!["Verify JWT codec configuration and payload serialization".into()]
            }
            OAuth2Error::JwtNotUtf8 => {
                vec!["Ensure JWT codec returns UTF‑8 compatible bytes for transport".into()]
            }
        }
    }

    fn is_retryable(&self) -> bool {
        matches!(
            self,
            OAuth2Error::ProviderReturnedError { .. }
                | OAuth2Error::TokenExchange { .. }
                | OAuth2Error::AccountPersistence { .. }
        )
    }
}
