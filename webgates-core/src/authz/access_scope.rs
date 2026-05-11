use crate::authz::access_hierarchy::AccessHierarchy;

use tracing::debug;

/// One role requirement inside an access policy.
///
/// `AccessPolicy` can contain multiple role requirements. Each one is stored as
/// an `AccessScope`, which tracks:
///
/// - the required role
/// - whether higher-privileged roles are also accepted
///
/// Most users interact with this type indirectly through
/// `AccessPolicy::require_role(...)` and `AccessPolicy::require_role_or_supervisor(...)`.
#[derive(Debug, Clone)]
pub struct AccessScope<Role> {
    role: Role,
    allow_supervisor_access: bool,
}

impl<Role> AccessScope<Role>
where
    Role: AccessHierarchy + Eq + std::fmt::Display,
{
    /// Creates a scope that requires the exact provided role.
    ///
    /// To also allow higher-privileged roles, call [`Self::allow_supervisor`].
    pub fn new(role: Role) -> Self {
        Self {
            role,
            allow_supervisor_access: false,
        }
    }

    /// Returns the role required by this scope.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Returns whether this scope accepts the required role's supervisors.
    pub fn allows_supervisor_access(&self) -> bool {
        self.allow_supervisor_access
    }

    /// Returns `true` when the provided role exactly matches the required role.
    pub fn grants_role(&self, role: &Role) -> bool {
        self.role.eq(role)
    }

    /// Returns `true` when the provided role satisfies this scope through the
    /// role hierarchy.
    ///
    /// A scope only grants supervisor access when
    /// [`Self::allow_supervisor`] has been applied. In that case, the provided
    /// role must be equal to or higher than the required role.
    ///
    /// This is what powers policy builders such as
    /// `AccessPolicy::require_role_or_supervisor(...)`.
    pub fn grants_supervisor(&self, role: &Role) -> bool {
        if !self.allow_supervisor_access {
            debug!(
                "Scope for role {} does not allow supervisor access.",
                self.role
            );
            return false;
        }

        if role >= &self.role {
            debug!(
                "Role {role} is same or supervisor of required role {} – access granted.",
                self.role
            );
            true
        } else {
            debug!(
                "Role {role} is NOT a supervisor of required role {} – access denied.",
                self.role
            );
            false
        }
    }

    /// Returns this scope configured to also accept higher-privileged roles.
    ///
    /// This enables same-or-supervisor matching according to the
    /// [`AccessHierarchy`] ordering contract.
    pub fn allow_supervisor(mut self) -> Self {
        self.allow_supervisor_access = true;
        self
    }
}
