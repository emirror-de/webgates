//! Access policy configuration for route protection
//!
//! This module defines domain objects for configuring access requirements
//! to protected resources. Access policies are pure business logic that
//! specify what roles, groups, or permissions are required for access.

use super::{AccessHierarchy, AccessScope};
use crate::permissions::{PermissionId, Permissions};

/// Domain object representing access requirements for a protected resource.
///
/// This captures the business rules about what roles, groups, or permissions
/// are required to access a particular resource or route. Access is granted
/// if the user meets ANY of the specified requirements (OR logic).
#[derive(Debug, Clone)]
pub struct AccessPolicy<R, G>
where
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq,
{
    role_requirements: Vec<AccessScope<R>>,
    group_requirements: Vec<G>,
    permission_requirements: Permissions,
}

impl<R, G> AccessPolicy<R, G>
where
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq,
{
    /// Creates a new access policy with no requirements (denies all access).
    ///
    /// This is the secure default - no access is granted unless explicitly
    /// configured through the builder methods.
    pub fn deny_all() -> Self {
        Self {
            role_requirements: vec![],
            group_requirements: vec![],
            permission_requirements: Permissions::new(),
        }
    }

    /// Creates a policy that allows access for users with the specified role.
    ///
    /// Use this when you need exact role matching without hierarchy. For scenarios
    /// where supervisor roles should also have access, use `require_role_or_supervisor()`.
    ///
    /// # Example
    /// ```rust
    /// use axum_gate::authz::AccessPolicy;
    /// use axum_gate::prelude::{Role, Group};
    ///
    /// let policy: AccessPolicy<Role, Group> = AccessPolicy::require_role(Role::Admin);
    /// ```
    pub fn require_role(role: R) -> Self {
        Self {
            role_requirements: vec![AccessScope::new(role)],
            group_requirements: vec![],
            permission_requirements: Permissions::new(),
        }
    }

    /// Creates a policy that allows access for users with the specified role or any supervisor role.
    ///
    /// Use this when you want hierarchical access control where higher-level roles
    /// automatically inherit permissions from lower-level roles. This is ideal for
    /// organizational structures where managers should have access to employee resources.
    ///
    /// This leverages the role hierarchy defined by the `AccessHierarchy` trait.
    ///
    /// # Example
    /// ```rust
    /// use axum_gate::authz::AccessPolicy;
    /// use axum_gate::prelude::{Role, Group};
    ///
    /// // Allows Moderator role and Admin role (if Admin supervises Moderator)
    /// let policy: AccessPolicy<Role, Group> = AccessPolicy::require_role_or_supervisor(Role::Moderator);
    /// ```
    pub fn require_role_or_supervisor(role: R) -> Self {
        Self {
            role_requirements: vec![AccessScope::new(role).allow_supervisor()],
            group_requirements: vec![],
            permission_requirements: Permissions::new(),
        }
    }

    /// Creates a policy that allows access for users in the specified group.
    ///
    /// Use this for team-based or department-based access control. Groups are ideal
    /// for cross-cutting concerns that don't fit hierarchical role structures,
    /// such as project teams, geographical regions, or temporary access grants.
    ///
    /// # Example
    /// ```rust
    /// use axum_gate::authz::AccessPolicy;
    /// use axum_gate::prelude::{Role, Group};
    ///
    /// let policy = AccessPolicy::<Role, Group>::require_group(Group::new("engineering"));
    /// ```
    pub fn require_group(group: G) -> Self {
        Self {
            role_requirements: vec![],
            group_requirements: vec![group],
            permission_requirements: Permissions::new(),
        }
    }

    /// Creates a policy that allows access for users with the specified permission.
    ///
    /// # Example
    /// ```rust
    /// use axum_gate::authz::AccessPolicy;
    /// use axum_gate::permissions::PermissionId;
    /// use axum_gate::prelude::{Role, Group};
    ///
    /// // Using a permission name (hashed deterministically to 64-bit ID)
    /// let policy: AccessPolicy<Role, Group> =
    ///     AccessPolicy::require_permission(PermissionId::from("read:api"));
    ///
    /// // Or directly from &str via Into<PermissionId>
    /// let policy2: AccessPolicy<Role, Group> =
    ///     AccessPolicy::require_permission("write:api");
    /// ```
    pub fn require_permission<P: Into<PermissionId>>(permission: P) -> Self {
        let mut permissions = Permissions::new();
        let id: PermissionId = permission.into();
        permissions.bitmap_mut().insert(id.as_u64());
        Self {
            role_requirements: vec![],
            group_requirements: vec![],
            permission_requirements: permissions,
        }
    }

    /// Adds an additional role requirement to this policy.
    ///
    /// Access will be granted if the user has ANY of the configured roles.
    pub fn or_require_role(mut self, role: R) -> Self {
        self.role_requirements.push(AccessScope::new(role));
        self
    }

    /// Adds an additional role or supervisor requirement to this policy.
    ///
    /// Access will be granted if the user has the specified role or supervises it.
    pub fn or_require_role_or_supervisor(mut self, role: R) -> Self {
        self.role_requirements
            .push(AccessScope::new(role).allow_supervisor());
        self
    }

    /// Adds an additional group requirement to this policy.
    ///
    /// Access will be granted if the user is in ANY of the configured groups.
    pub fn or_require_group(mut self, group: G) -> Self {
        self.group_requirements.push(group);
        self
    }

    /// Adds an additional permission requirement to this policy.
    ///
    /// Access will be granted if the user has ANY of the configured permissions.
    pub fn or_require_permission<P: Into<PermissionId>>(mut self, permission: P) -> Self {
        let id: PermissionId = permission.into();
        self.permission_requirements
            .bitmap_mut()
            .insert(id.as_u64());
        self
    }

    /// Adds multiple additional permission requirements to this policy.
    ///
    /// Access will be granted if the user has ANY of the configured permissions.
    pub fn or_require_permissions<P: Into<PermissionId>>(mut self, permissions: Vec<P>) -> Self {
        permissions.into_iter().for_each(|p| {
            let id: PermissionId = p.into();
            self.permission_requirements
                .bitmap_mut()
                .insert(id.as_u64());
        });
        self
    }

    /// Returns the role requirements for this policy.
    pub fn role_requirements(&self) -> &[AccessScope<R>] {
        &self.role_requirements
    }

    /// Returns the group requirements for this policy.
    pub fn group_requirements(&self) -> &[G] {
        &self.group_requirements
    }

    /// Returns the permission requirements for this policy.
    pub fn permission_requirements(&self) -> &Permissions {
        &self.permission_requirements
    }

    /// Returns true if this policy has no requirements (denies all access).
    ///
    /// This is useful for validation - a policy that denies all access
    /// might indicate a configuration error.
    pub fn denies_all(&self) -> bool {
        self.role_requirements.is_empty()
            && self.group_requirements.is_empty()
            && self.permission_requirements.is_empty()
    }

    /// Returns true if this policy has at least one requirement configured.
    ///
    /// This is useful for validating that a policy is properly configured
    /// with some access requirements rather than being completely empty.
    pub fn has_requirements(&self) -> bool {
        !self.denies_all()
    }

    /// Converts this policy into the components needed by the authorization service.
    ///
    /// This is primarily used internally when bridging to the authorization service.
    pub fn into_components(self) -> (Vec<AccessScope<R>>, Vec<G>, Permissions) {
        (
            self.role_requirements,
            self.group_requirements,
            self.permission_requirements,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::Group;
    use crate::permissions::PermissionId;
    use crate::roles::Role;

    #[test]
    fn deny_all_creates_empty_policy() {
        let policy: AccessPolicy<Role, Group> = AccessPolicy::deny_all();
        assert!(policy.denies_all());
        assert!(!policy.has_requirements());
        assert!(policy.role_requirements().is_empty());
        assert!(policy.group_requirements().is_empty());
        assert!(policy.permission_requirements().is_empty());
    }

    #[test]
    fn require_role_creates_role_policy() {
        let policy: AccessPolicy<Role, Group> = AccessPolicy::require_role(Role::Admin);
        assert!(!policy.denies_all());
        assert!(policy.has_requirements());
        assert_eq!(policy.role_requirements().len(), 1);
        assert!(policy.group_requirements().is_empty());
        assert!(policy.permission_requirements().is_empty());
    }

    #[test]
    fn require_role_or_supervisor_creates_supervisor_policy() {
        let policy: AccessPolicy<Role, Group> =
            AccessPolicy::require_role_or_supervisor(Role::Moderator);
        assert!(!policy.denies_all());
        assert!(policy.has_requirements());
        assert_eq!(policy.role_requirements().len(), 1);
        assert!(policy.role_requirements()[0].allow_supervisor_access);
    }

    #[test]
    fn require_group_creates_group_policy() {
        let policy: AccessPolicy<Role, Group> =
            AccessPolicy::require_group(Group::new("engineering"));
        assert!(!policy.denies_all());
        assert!(policy.has_requirements());
        assert!(policy.role_requirements().is_empty());
        assert_eq!(policy.group_requirements().len(), 1);
        assert!(policy.permission_requirements().is_empty());
    }

    #[test]
    fn require_permission_creates_permission_policy() {
        let permission_name = "read:api";
        let expected_id = PermissionId::from(permission_name).as_u64();
        let policy: AccessPolicy<Role, Group> = AccessPolicy::require_permission(permission_name);
        assert!(!policy.denies_all());
        assert!(policy.has_requirements());
        assert!(policy.role_requirements().is_empty());
        assert!(policy.group_requirements().is_empty());
        assert!(
            policy
                .permission_requirements()
                .iter()
                .any(|id| id == expected_id)
        );
    }

    #[test]
    fn builder_methods_add_requirements() {
        let base_perms = vec!["read:api", "write:api", "admin:panel"];
        let policy: AccessPolicy<Role, Group> = AccessPolicy::require_role(Role::Admin)
            .or_require_role_or_supervisor(Role::Moderator)
            .or_require_group(Group::new("engineering"))
            .or_require_permission(base_perms[0])
            .or_require_permissions(vec![base_perms[1], base_perms[2]]);

        assert!(!policy.denies_all());
        assert!(policy.has_requirements());
        assert_eq!(policy.role_requirements().len(), 2);
        assert_eq!(policy.group_requirements().len(), 1);

        let collected: Vec<u64> = policy.permission_requirements().iter().collect();
        for name in &base_perms {
            let id = PermissionId::from(*name).as_u64();
            assert!(collected.contains(&id), "missing permission {}", name);
        }
    }

    #[test]
    fn into_components_returns_all_requirements() {
        let permission_name = "system:health";
        let expected = PermissionId::from(permission_name).as_u64();
        let policy: AccessPolicy<Role, Group> = AccessPolicy::require_role(Role::Admin)
            .or_require_group(Group::new("test"))
            .or_require_permission(permission_name);

        let (roles, groups, permissions) = policy.into_components();
        assert_eq!(roles.len(), 1);
        assert_eq!(groups.len(), 1);
        assert!(permissions.iter().any(|id| id == expected));
    }
}
