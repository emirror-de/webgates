use super::AccessHierarchy;

use tracing::debug;

/// Contains information about the granted access scope.
#[derive(Debug, Clone)]
pub struct AccessScope<Role> {
    /// The role attached to the scope.
    pub role: Role,
    /// Whether all supervisors are granted access.
    pub allow_supervisor_access: bool,
}

impl<Role> AccessScope<Role>
where
    Role: AccessHierarchy + Eq + std::fmt::Display,
{
    /// Creates a new scope with the given role.
    pub fn new(role: Role) -> Self {
        Self {
            role,
            allow_supervisor_access: false,
        }
    }

    /// Returns `true` if the given role matches the scope.
    pub fn grants_role(&self, role: &Role) -> bool {
        self.role.eq(role)
    }

    /// Returns `true` if the given role is the required role or a supervisor
    /// (higher privilege according to the total ordering) of it.
    ///
    /// Ordering contract (enforced by AccessHierarchy marker):
    /// Higher privilege > Lower privilege
    /// So a supervisor (or same role) satisfies: user_role >= required_role
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

    /// Allows access to all supervisor of the role of the scope.
    pub fn allow_supervisor(mut self) -> Self {
        self.allow_supervisor_access = true;
        self
    }
}
