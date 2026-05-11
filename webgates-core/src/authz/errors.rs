//! Authorization-related error values.
//!
//! In `webgates-core`, most day-to-day authorization decisions are simple `bool`
//! outcomes returned by [`crate::authz::authorization_service::AuthorizationService`].
//! This module exists for exceptional authorization-domain problems, such as a
//! permission collision that makes access decisions unsafe or ambiguous.
//!
//! Import `AuthzError` from the canonical public path
//! `webgates_core::authz::errors::AuthzError`.
//!
//! # Example
//!
//! ```rust
//! use webgates_core::authz::errors::AuthzError;
//! use webgates_core::errors_core::{ErrorSeverity, UserFriendlyError};
//!
//! let err = AuthzError::collision(42, vec!["read:alpha".into(), "read:beta".into()]);
//! assert!(err.support_code().starts_with("AUTHZ-PERM-COLLISION-"));
//! assert_eq!(err.severity(), ErrorSeverity::Critical);
//! ```

use crate::errors_core::{ErrorSeverity, UserFriendlyError};
use thiserror::Error;

/// Authorization-domain errors.
///
/// Use these errors when the authorization system itself encounters a problem,
/// rather than when a user simply lacks access. A typical example is a
/// permission collision that should be treated as a configuration or integrity
/// issue.
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
    /// Creates a permission collision error from the colliding permission names.
    ///
    /// The constructor derives `collision_count` from the provided list.
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
