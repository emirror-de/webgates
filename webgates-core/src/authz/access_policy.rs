use crate::authz::access_hierarchy::AccessHierarchy;
use crate::authz::access_scope::AccessScope;
use crate::permissions::Permissions;
use crate::permissions::permission_id::PermissionId;

/// Domain object describing who may access a protected resource.
///
/// `AccessPolicy` is intentionally framework-agnostic. It stores the minimal
/// authorization requirements needed by the authorization service:
///
/// - exact role requirements
/// - role-or-supervisor requirements
/// - group requirements
/// - permission requirements
///
/// Access is granted when any configured requirement matches.
///
/// # Type parameters
///
/// - `R`: Role type implementing [`AccessHierarchy`]
/// - `G`: Group type compared by equality
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
    /// Creates a policy with no configured requirements.
    ///
    /// A deny-all policy is useful as a conservative default or as an explicit
    /// placeholder during policy construction.
    pub fn deny_all() -> Self {
        Self {
            role_requirements: Vec::new(),
            group_requirements: Vec::new(),
            permission_requirements: Permissions::new(),
        }
    }

    /// Creates a policy that requires an exact role match.
    ///
    /// Use this when only the specified role should satisfy the requirement.
    /// If higher-privileged roles should also match, use
    /// [`Self::require_role_or_supervisor`].
    ///
    /// # Example
    /// ```rust
    /// use webgates_core::authz::access_policy::AccessPolicy;
    /// use webgates_core::groups::Group;
    /// use webgates_core::roles::Role;
    ///
    /// let policy: AccessPolicy<Role, Group> = AccessPolicy::require_role(Role::Admin);
    /// assert!(policy.has_requirements());
    /// ```
    pub fn require_role(role: R) -> Self {
        Self {
            role_requirements: vec![AccessScope::new(role)],
            group_requirements: Vec::new(),
            permission_requirements: Permissions::new(),
        }
    }

    /// Creates a policy that requires the given role or a higher-privileged role.
    ///
    /// This uses the ordering defined by [`AccessHierarchy`]. A role satisfies
    /// the requirement when it is equal to, or supervises, the required role.
    ///
    /// # Example
    /// ```rust
    /// use webgates_core::authz::access_policy::AccessPolicy;
    /// use webgates_core::groups::Group;
    /// use webgates_core::roles::Role;
    ///
    /// let policy: AccessPolicy<Role, Group> =
    ///     AccessPolicy::require_role_or_supervisor(Role::Moderator);
    ///
    /// assert!(policy.has_requirements());
    /// ```
    pub fn require_role_or_supervisor(role: R) -> Self {
        Self {
            role_requirements: vec![AccessScope::new(role).allow_supervisor()],
            group_requirements: Vec::new(),
            permission_requirements: Permissions::new(),
        }
    }

    /// Creates a policy that requires membership in the given group.
    ///
    /// # Example
    /// ```rust
    /// use webgates_core::authz::access_policy::AccessPolicy;
    /// use webgates_core::groups::Group;
    /// use webgates_core::roles::Role;
    ///
    /// let policy = AccessPolicy::<Role, Group>::require_group(Group::new("engineering"));
    /// assert!(policy.has_requirements());
    /// ```
    pub fn require_group(group: G) -> Self {
        Self {
            role_requirements: Vec::new(),
            group_requirements: vec![group],
            permission_requirements: Permissions::new(),
        }
    }

    /// Creates a policy that requires the given permission.
    ///
    /// # Example
    /// ```rust
    /// use webgates_core::authz::access_policy::AccessPolicy;
    /// use webgates_core::groups::Group;
    /// use webgates_core::permissions::permission_id::PermissionId;
    /// use webgates_core::roles::Role;
    ///
    /// let policy: AccessPolicy<Role, Group> =
    ///     AccessPolicy::require_permission(PermissionId::from("read:api"));
    /// let policy2: AccessPolicy<Role, Group> =
    ///     AccessPolicy::require_permission("write:api");
    ///
    /// assert!(policy.has_requirements());
    /// assert!(policy2.has_requirements());
    /// ```
    pub fn require_permission<P: Into<PermissionId>>(permission: P) -> Self {
        let mut permission_requirements = Permissions::new();
        permission_requirements.grant(permission);
        Self {
            role_requirements: Vec::new(),
            group_requirements: Vec::new(),
            permission_requirements,
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

    /// Adds another permission requirement to this policy.
    ///
    /// Access is granted when the account has any configured permission.
    pub fn or_require_permission<P: Into<PermissionId>>(mut self, permission: P) -> Self {
        self.permission_requirements.grant(permission);
        self
    }

    /// Adds multiple permission requirements to this policy.
    ///
    /// Access is granted when the account has any configured permission.
    pub fn or_require_permissions<I, P>(mut self, permissions: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PermissionId>,
    {
        for permission in permissions {
            self.permission_requirements.grant(permission);
        }
        self
    }

    /// Returns the configured role requirements.
    pub fn role_requirements(&self) -> &[AccessScope<R>] {
        &self.role_requirements
    }

    /// Returns the configured group requirements.
    pub fn group_requirements(&self) -> &[G] {
        &self.group_requirements
    }

    /// Returns the configured permission requirements.
    pub fn permission_requirements(&self) -> &Permissions {
        &self.permission_requirements
    }

    /// Returns `true` when the policy contains no requirements.
    pub fn denies_all(&self) -> bool {
        self.role_requirements.is_empty()
            && self.group_requirements.is_empty()
            && self.permission_requirements.is_empty()
    }

    /// Returns `true` when the policy contains at least one requirement.
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
    use super::AccessPolicy;
    use crate::groups::Group;
    use crate::permissions::permission_id::PermissionId;
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
    fn require_role_creates_exact_role_scope() {
        let policy: AccessPolicy<Role, Group> = AccessPolicy::require_role(Role::Admin);

        assert!(!policy.denies_all());
        assert!(policy.has_requirements());
        assert_eq!(policy.role_requirements().len(), 1);
        assert!(!policy.role_requirements()[0].allows_supervisor_access());
        assert!(policy.group_requirements().is_empty());
        assert!(policy.permission_requirements().is_empty());
    }

    #[test]
    fn require_role_or_supervisor_creates_hierarchical_scope() {
        let policy: AccessPolicy<Role, Group> =
            AccessPolicy::require_role_or_supervisor(Role::Moderator);

        assert!(!policy.denies_all());
        assert!(policy.has_requirements());
        assert_eq!(policy.role_requirements().len(), 1);
        assert!(policy.role_requirements()[0].allows_supervisor_access());
    }

    #[test]
    fn require_group_creates_group_requirement() {
        let policy: AccessPolicy<Role, Group> =
            AccessPolicy::require_group(Group::new("engineering"));

        assert!(!policy.denies_all());
        assert!(policy.has_requirements());
        assert!(policy.role_requirements().is_empty());
        assert_eq!(policy.group_requirements(), &[Group::new("engineering")]);
        assert!(policy.permission_requirements().is_empty());
    }

    #[test]
    fn require_permission_creates_permission_requirement() {
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
    fn builder_methods_accumulate_all_requirement_types() {
        let base_permissions = ["read:api", "write:api", "admin:panel"];
        let policy: AccessPolicy<Role, Group> = AccessPolicy::require_role(Role::Admin)
            .or_require_role_or_supervisor(Role::Moderator)
            .or_require_group(Group::new("engineering"))
            .or_require_permission(base_permissions[0])
            .or_require_permissions([base_permissions[1], base_permissions[2]]);

        assert!(!policy.denies_all());
        assert!(policy.has_requirements());
        assert_eq!(policy.role_requirements().len(), 2);
        assert_eq!(policy.group_requirements(), &[Group::new("engineering")]);

        for permission_name in base_permissions {
            let id = PermissionId::from(permission_name).as_u64();
            assert!(
                policy
                    .permission_requirements()
                    .iter()
                    .any(|value| value == id),
                "missing permission {}",
                permission_name
            );
        }
    }

    #[test]
    fn into_components_returns_owned_policy_parts() {
        let permission_name = "system:health";
        let expected = PermissionId::from(permission_name).as_u64();
        let policy: AccessPolicy<Role, Group> = AccessPolicy::require_role(Role::Admin)
            .or_require_group(Group::new("test"))
            .or_require_permission(permission_name);

        let (roles, groups, permissions) = policy.into_components();

        assert_eq!(roles.len(), 1);
        assert_eq!(groups, vec![Group::new("test")]);
        assert!(permissions.iter().any(|id| id == expected));
    }
}
