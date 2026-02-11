//! Static token authorization state for bearer token gates.
//!
//! This module provides the [`StaticTokenAuthorized`] type, which represents
//! the authorization state when using static bearer tokens. It's used internally
//! by the bearer token gate system to track whether a request has been authorized
//! via a valid static token.
//!
//! # Usage
//!
//! This type is typically used as an axum extension to indicate authorization status:
//!
//! ```rust
//! use axum::extract::Extension;
//! use axum_gate::gate::bearer::StaticTokenAuthorized;
//!
//! async fn handler(Extension(auth): Extension<StaticTokenAuthorized>) -> String {
//!     if auth.is_authorized() {
//!         "Access granted".to_string()
//!     } else {
//!         "Access denied".to_string()
//!     }
//! }
//! ```

/// Extension wrapper for static token optional/strict modes.
#[derive(Debug, Clone, Copy)]
pub struct StaticTokenAuthorized(bool);

impl StaticTokenAuthorized {
    /// Creates a new instance with the given authorized state.
    pub fn new(authorized: bool) -> Self {
        Self(authorized)
    }

    /// Returns whether the request token is authorized.
    pub fn is_authorized(&self) -> bool {
        self.0
    }
}
