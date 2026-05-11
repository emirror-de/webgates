//! Shared crate-local error surface for `webgates-core`.
//!
//! This module provides the small root error enum used by fallible helper APIs
//! in the crate. If you need a single error type for permission validation and
//! related core workflows, this is usually the right one to return.
//!
//! The broader user-facing error contracts and severity taxonomy remain in
//! [`crate::errors_core`]. This module simply provides a focused wrapper that
//! keeps `webgates-core` APIs explicit and framework-agnostic.
//!
//! # Usage
//!
//! Use [`enum@Error`] and [`Result`] when returning the crate's shared error type from
//! core helpers:
//!
//! ```rust
//! use webgates_core::errors::{Error, Result};
//! use webgates_core::permissions::errors::PermissionsError;
//!
//! fn validate(flag: bool) -> Result<()> {
//!     if flag {
//!         Ok(())
//!     } else {
//!         Err(Error::Permissions(PermissionsError::collision(
//!             42,
//!             vec!["read:alpha".to_string(), "read:beta".to_string()],
//!         )))
//!     }
//! }
//! ```
//!
//! [`crate::errors_core`]: crate::errors_core

use thiserror::Error;

use crate::errors_core::{ErrorSeverity, UserFriendlyError};
use crate::permissions::errors::PermissionsError;

/// Result alias using [`enum@Error`] as the crate-local error type.
pub type Result<T> = std::result::Result<T, Error>;

/// Root error enum for `webgates-core`.
///
/// This enum keeps the public error surface small while still letting callers
/// pattern match on meaningful failure categories.
#[derive(Debug, Error)]
pub enum Error {
    /// Permission validation and collision errors.
    #[error(transparent)]
    Permissions(#[from] PermissionsError),
}

impl UserFriendlyError for Error {
    fn user_message(&self) -> String {
        match self {
            Error::Permissions(err) => err.user_message(),
        }
    }

    fn developer_message(&self) -> String {
        match self {
            Error::Permissions(err) => err.developer_message(),
        }
    }

    fn support_code(&self) -> String {
        match self {
            Error::Permissions(err) => err.support_code(),
        }
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            Error::Permissions(err) => err.severity(),
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            Error::Permissions(err) => err.suggested_actions(),
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            Error::Permissions(err) => err.is_retryable(),
        }
    }
}
