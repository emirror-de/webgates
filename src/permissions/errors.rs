//! Permission-category native errors.
//!
//! This module defines category-native errors for permission concerns,
//! focused on collision detection. Use these errors directly in handlers,
//! services, and middleware.
//!
//! # Overview
//!
//! - `PermissionsError`: category-native error enum for permission issues
//!
//! # Examples
//!
//! Detect a permission hash collision:
//! ```rust
//! use axum_gate::permissions::PermissionsError;
//! use axum_gate::errors::UserFriendlyError;
//!
//! let err = PermissionsError::collision(42, vec!["read:alpha".into(), "read:beta".into()]);
//! assert!(err.support_code().starts_with("PERM-COLLISION-"));
//! assert_eq!(err.severity(), axum_gate::errors::ErrorSeverity::Critical);
//! ```

use crate::errors::{ErrorSeverity, UserFriendlyError};
use thiserror::Error;

/// Category-native permission errors.
///
/// These errors model permission-related problems.
/// Use directly in permission validation and authorization flows.
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
    /// Create a permission collision error with collision details.
    ///
    /// This constructor calculates the `collision_count` from the provided list.
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
