//! Deterministic permission identifiers, sets, and validation utilities.
//!
//! This module is the canonical public entry point for permission-related types in
//! `webgates-core`.
//!
//! It exposes:
//! - [`permission_id::PermissionId`] for stable 64-bit permission identifiers
//! - [`Permissions`] for compact granted-permission storage
//! - [`application_validator::ApplicationValidator`] and [`collision_checker::PermissionCollisionChecker`] for validation
//! - [`validation_report::ValidationReport`] and [`permission_collision::PermissionCollision`] for validation results
//! - [`mapping::PermissionMapping`] and [`mapping::PermissionMappingError`] for registry-style lookups
//! - [`errors::PermissionsError`] for permission-category errors
//! - [`as_permission_name::AsPermissionName`] for application-defined permission enums
//!
//! Permission names are normalized before hashing, which keeps checks
//! deterministic across processes and deployments without requiring a central
//! registry.
//!
//! # Examples
//!
//! Validate permissions during tests:
//!
//! ```rust
//! webgates_core::validate_permissions![
//!     "read:resource1",
//!     "write:resource1",
//!     "admin:system",
//! ];
//! ```
//!
//! Build and query a permission set:
//!
//! ```rust
//! use webgates_core::permissions::permission_id::PermissionId;
//! use webgates_core::permissions::Permissions;
//!
//! let mut permissions = Permissions::new();
//! permissions
//!     .grant("read:resource1")
//!     .grant(PermissionId::from("write:resource1"));
//!
//! assert!(permissions.has("read:resource1"));
//! assert!(permissions.has(PermissionId::from("write:resource1")));
//!
//! permissions.revoke("write:resource1");
//! assert!(!permissions.has("write:resource1"));
//! ```
//!
//! Use permissions in access policies:
//!
//! ```rust
//! use webgates_core::authz::access_policy::AccessPolicy;
//! use webgates_core::groups::Group;
//! use webgates_core::permissions::permission_id::PermissionId;
//! use webgates_core::roles::Role;
//!
//! let policy: AccessPolicy<Role, Group> =
//!     AccessPolicy::require_permission(PermissionId::from("read:resource1"));
//!
//! assert!(policy.has_requirements());
//! ```
//!
//! Use application-defined permission enums:
//!
//! ```rust
//! use webgates_core::authz::access_policy::AccessPolicy;
//! use webgates_core::groups::Group;
//! use webgates_core::permissions::as_permission_name::AsPermissionName;
//! use webgates_core::permissions::Permissions;
//! use webgates_core::roles::Role;
//!
//! #[derive(Debug)]
//! enum Api {
//!     Read,
//!     Write,
//! }
//!
//! #[derive(Debug)]
//! enum AppPermission {
//!     Api(Api),
//!     System(&'static str),
//! }
//!
//! impl AsPermissionName for AppPermission {
//!     fn as_permission_name(&self) -> String {
//!         match self {
//!             AppPermission::Api(api) => format!("api:{:?}", api).to_lowercase(),
//!             AppPermission::System(name) => format!("system:{name}"),
//!         }
//!     }
//! }
//!
//! let mut permissions = Permissions::new();
//! permissions.grant(&AppPermission::Api(Api::Read));
//! assert!(permissions.has(&AppPermission::Api(Api::Read)));
//!
//! let policy: AccessPolicy<Role, Group> =
//!     AccessPolicy::require_permission(&AppPermission::Api(Api::Read));
//! assert!(policy.has_requirements());
//! ```

use permission_id::PermissionId;
use roaring::RoaringTreemap;
use serde::{Deserialize, Serialize};
use std::fmt;

/// High-level builder for validating application permission sets at startup.
pub mod application_validator;
/// Trait for application-defined permission enums that produce a name string.
pub mod as_permission_name;
/// Low-level collision checker for runtime permission validation and analysis.
pub mod collision_checker;
/// Permission-category error values.
pub mod errors;
/// Registry-style mapping between permission strings and their identifiers.
pub mod mapping;
/// Collision record produced when two permission strings share an identifier.
pub mod permission_collision;
/// Deterministic 64-bit identifier derived from a normalized permission name.
pub mod permission_id;
/// Test-time permission validation macro support.
///
/// This module contains the [`validate_permissions!`](crate::validate_permissions)
/// macro and its supporting documentation.
pub mod validate_permissions;
/// Validation outcome produced by the collision checker and application validator.
pub mod validation_report;

/// A collection of granted permissions.
///
/// Internally this type stores permission IDs in a compressed bitmap for compact
/// storage and fast membership checks. The public API accepts permission names
/// or precomputed [`PermissionId`] values and keeps the bitmap representation
/// internal to the type.
///
/// # Examples
///
/// ```rust
/// use webgates_core::permissions::Permissions;
///
/// let mut permissions = Permissions::new();
/// permissions
///     .grant("read:profile")
///     .grant("write:profile")
///     .grant("delete:profile");
///
/// assert!(permissions.has("read:profile"));
/// assert!(!permissions.has("admin:users"));
/// assert!(permissions.has_all(["read:profile", "write:profile"]));
/// assert!(permissions.has_any(["read:profile", "admin:users"]));
/// ```
///
/// Build a set immutably:
///
/// ```rust
/// use webgates_core::permissions::Permissions;
///
/// let permissions = Permissions::new()
///     .with("read:api")
///     .with("write:api")
///     .build();
///
/// assert!(permissions.has("read:api"));
/// assert!(permissions.has("write:api"));
/// ```
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Permissions {
    bitmap: RoaringTreemap,
}

impl Permissions {
    /// Creates a new empty permission set.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use webgates_core::permissions::Permissions;
    ///
    /// let permissions = Permissions::new();
    /// assert!(permissions.is_empty());
    /// ```
    pub fn new() -> Self {
        Self {
            bitmap: RoaringTreemap::new(),
        }
    }

    /// Grants a permission to this permission set.
    ///
    /// Returns a mutable reference to self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use webgates_core::permissions::permission_id::PermissionId;
    /// use webgates_core::permissions::Permissions;
    ///
    /// let mut permissions = Permissions::new();
    /// permissions
    ///     .grant("read:profile")
    ///     .grant(PermissionId::from("write:profile"));
    ///
    /// assert!(permissions.has("read:profile"));
    /// assert!(permissions.has(PermissionId::from("write:profile")));
    /// ```
    pub fn grant<P>(&mut self, permission: P) -> &mut Self
    where
        P: Into<PermissionId>,
    {
        let permission_id = permission.into();
        self.bitmap.insert(permission_id.as_u64());
        self
    }

    /// Revokes a permission from this permission set.
    ///
    /// Returns a mutable reference to self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use webgates_core::permissions::permission_id::PermissionId;
    /// use webgates_core::permissions::Permissions;
    ///
    /// let mut permissions: Permissions = ["read:profile", "write:profile"].into_iter().collect();
    /// permissions.revoke(PermissionId::from("write:profile"));
    ///
    /// assert!(permissions.has("read:profile"));
    /// assert!(!permissions.has("write:profile"));
    /// ```
    pub fn revoke<P>(&mut self, permission: P) -> &mut Self
    where
        P: Into<PermissionId>,
    {
        let permission_id = permission.into();
        self.bitmap.remove(permission_id.as_u64());
        self
    }

    /// Checks if a specific permission is granted.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use webgates_core::permissions::permission_id::PermissionId;
    /// use webgates_core::permissions::Permissions;
    ///
    /// let permissions: Permissions = ["read:profile"].into_iter().collect();
    ///
    /// assert!(permissions.has("read:profile"));
    /// assert!(permissions.has(PermissionId::from("read:profile")));
    /// assert!(!permissions.has("write:profile"));
    /// ```
    pub fn has<P>(&self, permission: P) -> bool
    where
        P: Into<PermissionId>,
    {
        let permission_id = permission.into();
        self.bitmap.contains(permission_id.as_u64())
    }

    /// Checks if all of the specified permissions are granted.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use webgates_core::permissions::permission_id::PermissionId;
    /// use webgates_core::permissions::Permissions;
    ///
    /// let permissions: Permissions = [
    ///     "read:profile",
    ///     "write:profile",
    ///     "read:posts",
    /// ].into_iter().collect();
    ///
    /// assert!(permissions.has_all(["read:profile", "write:profile"]));
    /// assert!(permissions.has_all([PermissionId::from("read:profile")]));
    /// assert!(!permissions.has_all(["read:profile", "admin:users"]));
    /// ```
    pub fn has_all<I, P>(&self, permissions: I) -> bool
    where
        I: IntoIterator<Item = P>,
        P: Into<PermissionId>,
    {
        permissions.into_iter().all(|p| self.has(p))
    }

    /// Checks if any of the specified permissions are granted.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use webgates_core::permissions::permission_id::PermissionId;
    /// use webgates_core::permissions::Permissions;
    ///
    /// let permissions: Permissions = ["read:profile"].into_iter().collect();
    ///
    /// assert!(permissions.has_any(["read:profile", "write:profile"]));
    /// assert!(permissions.has_any([PermissionId::from("read:profile")]));
    /// assert!(!permissions.has_any(["write:profile", "admin:users"]));
    /// ```
    pub fn has_any<I, P>(&self, permissions: I) -> bool
    where
        I: IntoIterator<Item = P>,
        P: Into<PermissionId>,
    {
        permissions.into_iter().any(|p| self.has(p))
    }

    /// Returns the number of permissions in this set.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use webgates_core::permissions::Permissions;
    ///
    /// let permissions: Permissions = ["read:profile", "write:profile"].into_iter().collect();
    /// assert_eq!(permissions.len(), 2);
    /// ```
    pub fn len(&self) -> usize {
        self.bitmap.len() as usize
    }

    /// Returns `true` if the permission set contains no permissions.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use webgates_core::permissions::Permissions;
    ///
    /// let permissions = Permissions::new();
    /// assert!(permissions.is_empty());
    ///
    /// let mut permissions = Permissions::new();
    /// permissions.grant("read:profile");
    /// assert!(!permissions.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.bitmap.is_empty()
    }

    /// Removes all permissions from this set.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use webgates_core::permissions::Permissions;
    ///
    /// let mut permissions: Permissions = ["read:profile", "write:profile"].into_iter().collect();
    /// assert!(!permissions.is_empty());
    ///
    /// permissions.clear();
    /// assert!(permissions.is_empty());
    /// ```
    pub fn clear(&mut self) {
        self.bitmap.clear();
    }

    /// Computes the union of this permission set with another.
    ///
    /// This grants all permissions that exist in either set.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use webgates_core::permissions::Permissions;
    ///
    /// let mut permissions1: Permissions = ["read:profile"].into_iter().collect();
    /// let permissions2: Permissions = ["write:profile"].into_iter().collect();
    ///
    /// permissions1.union(&permissions2);
    ///
    /// assert!(permissions1.has("read:profile"));
    /// assert!(permissions1.has("write:profile"));
    /// ```
    pub fn union(&mut self, other: &Permissions) -> &mut Self {
        self.bitmap |= &other.bitmap;
        self
    }

    /// Computes the intersection of this permission set with another.
    ///
    /// This keeps only permissions that exist in both sets.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use webgates_core::permissions::Permissions;
    ///
    /// let mut permissions1: Permissions = ["read:profile", "write:profile"].into_iter().collect();
    /// let permissions2: Permissions = ["read:profile", "admin:users"].into_iter().collect();
    ///
    /// permissions1.intersection(&permissions2);
    ///
    /// assert!(permissions1.has("read:profile"));
    /// assert!(!permissions1.has("write:profile"));
    /// assert!(!permissions1.has("admin:users"));
    /// ```
    pub fn intersection(&mut self, other: &Permissions) -> &mut Self {
        self.bitmap &= &other.bitmap;
        self
    }

    /// Computes the difference of this permission set with another.
    ///
    /// This removes all permissions that exist in the other set.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use webgates_core::permissions::Permissions;
    ///
    /// let mut permissions1: Permissions = ["read:profile", "write:profile"].into_iter().collect();
    /// let permissions2: Permissions = ["write:profile"].into_iter().collect();
    ///
    /// permissions1.difference(&permissions2);
    ///
    /// assert!(permissions1.has("read:profile"));
    /// assert!(!permissions1.has("write:profile"));
    /// ```
    pub fn difference(&mut self, other: &Permissions) -> &mut Self {
        self.bitmap -= &other.bitmap;
        self
    }

    /// Builder method for granting a permission (immutable version).
    ///
    /// Use this when building permissions in a functional style or when you need
    /// to create permissions without mutable access. Prefer `grant()` for
    /// performance-critical code where you're modifying existing permission sets.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use webgates_core::permissions::permission_id::PermissionId;
    /// use webgates_core::permissions::Permissions;
    ///
    /// let permissions = Permissions::new()
    ///     .with("read:profile")
    ///     .with(PermissionId::from("write:profile"))
    ///     .build();
    ///
    /// assert!(permissions.has("read:profile"));
    /// assert!(permissions.has("write:profile"));
    /// ```
    pub fn with<P>(mut self, permission: P) -> Self
    where
        P: Into<PermissionId>,
    {
        self.grant(permission);
        self
    }

    /// Finalizes the builder pattern.
    ///
    /// This method returns self unchanged, providing a clean conclusion to
    /// the builder pattern. Use this when you want to clearly signal the
    /// end of permission configuration.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use webgates_core::permissions::Permissions;
    ///
    /// let permissions = Permissions::new()
    ///     .with("read:profile")
    ///     .with("write:profile")
    ///     .build();
    /// ```
    pub fn build(self) -> Self {
        self
    }

    /// Returns an iterator over the permission IDs in this collection.
    ///
    /// Use this when you need to examine all granted permissions or integrate
    /// with external systems that work with permission IDs directly.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use webgates_core::permissions::Permissions;
    ///
    /// let permissions: Permissions = ["read:profile", "write:profile"].into_iter().collect();
    /// let ids: Vec<u64> = permissions.iter().collect();
    /// assert_eq!(ids.len(), 2);
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.bitmap.iter()
    }
}

impl Default for Permissions {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Permissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Permissions({})", self.len())
    }
}

impl From<roaring::RoaringTreemap> for Permissions {
    fn from(bitmap: roaring::RoaringTreemap) -> Self {
        Self { bitmap }
    }
}

impl From<Permissions> for roaring::RoaringTreemap {
    fn from(permissions: Permissions) -> Self {
        permissions.bitmap
    }
}

impl AsRef<roaring::RoaringTreemap> for Permissions {
    fn as_ref(&self) -> &roaring::RoaringTreemap {
        &self.bitmap
    }
}

impl<P> std::iter::FromIterator<P> for Permissions
where
    P: Into<PermissionId>,
{
    /// Creates a permission set from an iterator of permission names.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use webgates_core::permissions::Permissions;
    ///
    /// let permissions: Permissions = ["read:profile", "write:profile", "read:posts"]
    ///     .into_iter()
    ///     .collect();
    ///
    /// assert!(permissions.has("read:profile"));
    /// assert!(permissions.has("write:profile"));
    /// assert!(permissions.has("read:posts"));
    /// ```
    fn from_iter<I: IntoIterator<Item = P>>(iter: I) -> Self {
        let mut perms = Self::new();
        for permission in iter {
            perms.grant(permission);
        }
        perms
    }
}

#[cfg(test)]
mod tests {
    use super::Permissions;
    use super::as_permission_name::AsPermissionName;
    use super::permission_id::PermissionId;

    #[test]
    fn new_permissions_is_empty() {
        let permissions = Permissions::new();

        assert!(permissions.is_empty());
        assert_eq!(permissions.len(), 0);
    }

    #[test]
    fn grant_and_has_permission() {
        let mut permissions = Permissions::new();
        permissions.grant("read:profile");

        assert!(permissions.has("read:profile"));
        assert!(!permissions.has("write:profile"));
        assert_eq!(permissions.len(), 1);
        assert!(!permissions.is_empty());
    }

    #[test]
    fn grant_supports_chaining() {
        let mut permissions = Permissions::new();
        permissions
            .grant("read:profile")
            .grant("write:profile")
            .grant("delete:profile");

        assert!(permissions.has("read:profile"));
        assert!(permissions.has("write:profile"));
        assert!(permissions.has("delete:profile"));
        assert_eq!(permissions.len(), 3);
    }

    #[test]
    fn revoke_permission_removes_granted_entry() {
        let mut permissions: Permissions = ["read:profile", "write:profile"].into_iter().collect();
        permissions.revoke("write:profile");

        assert!(permissions.has("read:profile"));
        assert!(!permissions.has("write:profile"));
        assert_eq!(permissions.len(), 1);
    }

    #[test]
    fn has_all_permissions_handles_present_and_missing_values() {
        let permissions: Permissions = ["read:profile", "write:profile", "read:posts"]
            .into_iter()
            .collect();

        assert!(permissions.has_all(["read:profile", "write:profile"]));
        assert!(permissions.has_all(["read:profile"]));
        assert!(!permissions.has_all(["read:profile", "admin:users"]));
        assert!(permissions.has_all(Vec::<&str>::new()));
    }

    #[test]
    fn has_any_permission_handles_present_and_missing_values() {
        let permissions: Permissions = ["read:profile"].into_iter().collect();

        assert!(permissions.has_any(["read:profile", "write:profile"]));
        assert!(permissions.has_any(["write:profile", "read:profile"]));
        assert!(!permissions.has_any(["write:profile", "admin:users"]));
        assert!(!permissions.has_any(Vec::<&str>::new()));
    }

    #[test]
    fn clear_permissions_removes_all_entries() {
        let mut permissions: Permissions = ["read:profile", "write:profile"].into_iter().collect();

        assert!(!permissions.is_empty());

        permissions.clear();

        assert!(permissions.is_empty());
        assert_eq!(permissions.len(), 0);
    }

    #[test]
    fn union_permissions_combines_entries() {
        let mut permissions1: Permissions = ["read:profile"].into_iter().collect();
        let permissions2: Permissions = ["write:profile", "read:posts"].into_iter().collect();

        permissions1.union(&permissions2);

        assert!(permissions1.has("read:profile"));
        assert!(permissions1.has("write:profile"));
        assert!(permissions1.has("read:posts"));
        assert_eq!(permissions1.len(), 3);
    }

    #[test]
    fn intersection_permissions_keeps_only_shared_entries() {
        let mut permissions1: Permissions = ["read:profile", "write:profile"].into_iter().collect();
        let permissions2: Permissions = ["read:profile", "admin:users"].into_iter().collect();

        permissions1.intersection(&permissions2);

        assert!(permissions1.has("read:profile"));
        assert!(!permissions1.has("write:profile"));
        assert!(!permissions1.has("admin:users"));
        assert_eq!(permissions1.len(), 1);
    }

    #[test]
    fn difference_permissions_removes_other_entries() {
        let mut permissions1 = Permissions::from_iter(["read:profile", "write:profile"]);
        let permissions2 = Permissions::from_iter(["write:profile"]);

        permissions1.difference(&permissions2);

        assert!(permissions1.has("read:profile"));
        assert!(!permissions1.has("write:profile"));
        assert_eq!(permissions1.len(), 1);
    }

    #[test]
    fn builder_pattern_returns_populated_set() {
        let permissions = Permissions::new()
            .with("read:profile")
            .with("write:profile")
            .build();

        assert!(permissions.has("read:profile"));
        assert!(permissions.has("write:profile"));
        assert_eq!(permissions.len(), 2);
    }

    #[test]
    fn from_iter_builds_permissions_from_names() {
        let permissions: Permissions = ["read:profile", "write:profile", "read:posts"]
            .into_iter()
            .collect();

        assert!(permissions.has("read:profile"));
        assert!(permissions.has("write:profile"));
        assert!(permissions.has("read:posts"));
        assert_eq!(permissions.len(), 3);
    }

    #[test]
    fn permissions_are_deterministic() {
        let permissions1 = Permissions::from_iter(["read:profile"]);
        let permissions2 = Permissions::from_iter(["read:profile"]);

        assert_eq!(permissions1, permissions2);
        assert!(permissions1.has("read:profile"));
        assert!(permissions2.has("read:profile"));
    }

    #[test]
    fn supports_permission_id_values() {
        let mut permissions = Permissions::new();
        let read_profile = PermissionId::from("read:profile");

        permissions.grant(read_profile);

        assert!(permissions.has(read_profile));
        assert!(permissions.has("read:profile"));
    }

    #[test]
    fn supports_custom_permission_name_types() {
        #[derive(Debug)]
        enum AppPermission {
            ReadProfile,
            WriteProfile,
        }

        impl AsPermissionName for AppPermission {
            fn as_permission_name(&self) -> String {
                match self {
                    AppPermission::ReadProfile => "profile:read".to_string(),
                    AppPermission::WriteProfile => "profile:write".to_string(),
                }
            }
        }

        let mut permissions = Permissions::new();
        permissions.grant(&AppPermission::ReadProfile);
        permissions.grant(&AppPermission::WriteProfile);

        assert!(permissions.has(&AppPermission::ReadProfile));
        assert!(permissions.has("profile:read"));
        assert!(permissions.has_all([&AppPermission::ReadProfile, &AppPermission::WriteProfile]));
    }

    #[test]
    fn display_implementation_reports_count() {
        let permissions = Permissions::from_iter(["read:profile", "write:profile"]);

        assert_eq!(format!("{permissions}"), "Permissions(2)");
    }
}
