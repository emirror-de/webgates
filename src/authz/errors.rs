//! Authorization-category native errors.
//!
//! This module defines category-native errors for authorization (authz) concerns,
//! focused on permission hash collisions. Use `AuthzError` directly in handlers,
//! services, and middleware.
//!
//! # Overview
//! - `AuthzError`: category-native error enum for authorization
//! - Convenience constructors: `collision`
//!
//! # Examples
//!
//! Detect a permission hash collision:
//! ```rust
//! use axum_gate::authz::AuthzError;
//! use axum_gate::errors::UserFriendlyError;
//!
//! let err = AuthzError::collision(42, vec!["read:alpha".into(), "read:beta".into()]);
//! assert!(err.support_code().starts_with("AUTHZ-PERM-COLLISION-"));
//! assert_eq!(err.severity(), axum_gate::errors::ErrorSeverity::Critical);
//! ```

use crate::errors::{ErrorSeverity, UserFriendlyError};
use thiserror::Error;

/// Authorization-category native errors.
///
/// Use these errors in authorization flows to model permission hash collisions.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthzError {
    /// Permission collision detected when multiple permissions hash to the same value.
    #[error("Permission collision: {collision_count} permissions map to hash {hash_id}")]
    PermissionCollision {
        /// Number of permissions that collide.
        collision_count: usize,
        /// The 64-bit hash ID that has collisions.
        hash_id: u64,
        /// List of permission names that collide.
        permissions: Vec<String>,
    },
}

impl AuthzError {
    /// Create a permission collision error with collision details.
    ///
    /// This constructor calculates the `collision_count` from the provided list.
    pub fn collision(hash_id: u64, permissions: Vec<String>) -> Self {
        AuthzError::PermissionCollision {
            collision_count: permissions.len(),
            hash_id,
            permissions,
        }
    }

    /// Deterministic, category-specific support code for this error.
    fn support_code_inner(&self) -> String {
        match self {
            AuthzError::PermissionCollision { hash_id, .. } => {
                format!("AUTHZ-PERM-COLLISION-{}", hash_id)
            }
        }
    }
}

impl UserFriendlyError for AuthzError {
    fn user_message(&self) -> String {
        match self {
            AuthzError::PermissionCollision { .. } => {
                "There's a technical issue with your account permissions. Our support team has been notified and will resolve this shortly. Please contact support if you need immediate assistance.".to_string()
            }
        }
    }

    fn developer_message(&self) -> String {
        match self {
            AuthzError::PermissionCollision {
                collision_count,
                hash_id,
                permissions,
            } => {
                format!(
                    "Permission collision detected: {} permissions [{}] map to hash ID {}. This indicates a critical hash collision in the permission system requiring immediate administrator attention.",
                    collision_count,
                    permissions.join(", "),
                    hash_id
                )
            }
        }
    }

    fn support_code(&self) -> String {
        self.support_code_inner()
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            AuthzError::PermissionCollision { .. } => ErrorSeverity::Critical,
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            AuthzError::PermissionCollision { .. } => vec![
                "Contact our support team immediately with the reference code below".to_string(),
                "Do not attempt to retry this operation".to_string(),
                "This is a critical system issue requiring immediate administrator attention"
                    .to_string(),
            ],
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            AuthzError::PermissionCollision { .. } => false, // Critical system-level issue
        }
    }
}
