//! Permission-related error values.
//!
//! These errors describe problems in the permission system itself, not ordinary
//! authorization denials. In practice, the main case is a duplicate or hash
//! collision discovered during permission validation.
//!
//! # Example
//!
//! ```rust
//! use webgates_core::errors_core::{ErrorSeverity, UserFriendlyError};
//! use webgates_core::permissions::errors::PermissionsError;
//!
//! let err = PermissionsError::collision(42, vec!["read:alpha".into(), "read:beta".into()]);
//! assert!(err.support_code().starts_with("PERM-COLLISION-"));
//! assert_eq!(err.severity(), ErrorSeverity::Critical);
//! ```

use crate::errors_core::{ErrorSeverity, UserFriendlyError};
use thiserror::Error;

/// Permission-domain errors.
///
/// Use these errors when the permission system detects an unsafe or invalid
/// condition, such as a collision between permission names.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PermissionsError {
    /// Permission collision detected when multiple permissions hash to the same value.
    #[error("Permission collision: {collision_count} permissions map to hash {hash_id}")]
    Collision {
        /// Number of permissions that collide.
        collision_count: usize,
        /// The 64-bit hash ID that has collisions.
        hash_id: u64,
        /// List of permission names that collide.
        permissions: Vec<String>,
    },
}

impl PermissionsError {
    /// Creates a permission collision error from the colliding permission names.
    ///
    /// The constructor derives `collision_count` from the provided list.
    pub fn collision(hash_id: u64, permissions: Vec<String>) -> Self {
        PermissionsError::Collision {
            collision_count: permissions.len(),
            hash_id,
            permissions,
        }
    }

    /// Generate a deterministic support code based on error content.
    fn support_code_inner(&self) -> String {
        match self {
            PermissionsError::Collision { hash_id, .. } => {
                format!("PERM-COLLISION-{}", hash_id)
            }
        }
    }
}

impl UserFriendlyError for PermissionsError {
    fn user_message(&self) -> String {
        match self {
            PermissionsError::Collision { .. } => {
                "There's a technical issue with your account permissions. Our support team has been notified and will resolve this shortly. Please contact support if you need immediate assistance.".to_string()
            }
        }
    }

    fn developer_message(&self) -> String {
        match self {
            PermissionsError::Collision {
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
            PermissionsError::Collision { .. } => ErrorSeverity::Critical,
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            PermissionsError::Collision { .. } => vec![
                "Contact our support team immediately with the reference code below".to_string(),
                "Do not attempt to retry this operation".to_string(),
                "This is a critical system issue requiring immediate administrator attention"
                    .to_string(),
            ],
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            PermissionsError::Collision { .. } => false, // Critical system-level issue
        }
    }
}
