//! Trait for converting custom types to permission names.
//!
//! This module provides the [`AsPermissionName`] trait, which enables custom types
//! (especially enums) to define their string representation for use with the
//! permission system. This is useful for structured permission definitions.
//!
//! # Usage
//!
//! ```rust
//! use axum_gate::permissions::AsPermissionName;
//! use axum_gate::permissions::Permissions;
//!
//! #[derive(Debug, Clone, PartialEq)]
//! enum ApiPermission {
//!     Read,
//!     Write,
//!     Delete,
//! }
//!
//! #[derive(Debug, Clone, PartialEq)]
//! enum Permission {
//!     Api(ApiPermission),
//!     System(String),
//! }
//!
//! impl AsPermissionName for Permission {
//!     fn as_permission_name(&self) -> String {
//!         match self {
//!             Permission::Api(api) => format!("api:{:?}", api).to_lowercase(),
//!             Permission::System(sys) => format!("system:{}", sys),
//!         }
//!     }
//! }
//!
//! // Usage - convert to string representations first
//! let permissions: Permissions = [
//!     Permission::Api(ApiPermission::Read).as_permission_name(),
//!     Permission::System("health".to_string()).as_permission_name(),
//! ].into_iter().collect();
//! ```

/// Trait for types that can be converted to permission names.
///
/// This trait allows permission enums to define their string representation
/// for use with PermissionId. Typically implemented by nested permission enums
/// that provide structured permission definitions.
pub trait AsPermissionName {
    /// Convert the permission to its string representation.
    fn as_permission_name(&self) -> String;
}
