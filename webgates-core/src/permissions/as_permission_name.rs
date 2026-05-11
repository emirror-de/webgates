//! Trait for mapping custom types to permission names.
//!
//! This module provides [`crate::permissions::as_permission_name::AsPermissionName`], which is especially useful when
//! your application defines permissions as enums instead of raw string literals.
//!
//! By implementing this trait, you can keep permission definitions structured in
//! your domain model while still using the `webgates-core` permission system.
//!
//! The canonical public path is
//! `webgates_core::permissions::as_permission_name::AsPermissionName`.
//!
//! # Example
//!
//! ```rust
//! use webgates_core::permissions::as_permission_name::AsPermissionName;
//! use webgates_core::permissions::Permissions;
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
//! let mut permissions = Permissions::new();
//! let read = Permission::Api(ApiPermission::Read);
//! let health = Permission::System("health".to_string());
//!
//! permissions.grant(&read);
//! permissions.grant(&health);
//!
//! assert!(permissions.has(&read));
//! assert!(permissions.has("system:health"));
//! ```

/// Trait for types that can be converted to stable permission names.
///
/// Implement this trait for your own permission enums when you want strongly
/// typed permission definitions in application code while still interoperating
/// with [`crate::permissions::permission_id::PermissionId`] and
/// [`crate::permissions::Permissions`].
pub trait AsPermissionName {
    /// Converts the permission into its canonical string representation.
    ///
    /// Return a stable name such as `"projects:read"` or `"admin:users:write"`.
    fn as_permission_name(&self) -> String;
}
