use super::{AccessHierarchy, AccessPolicy};
use crate::accounts::Account;

use tracing::debug;

/// Domain service for authorization decisions.
///
/// This service contains pure business logic for determining whether an account
/// is authorized based on an access policy. It has no external dependencies
/// and can be used across different application contexts.
#[derive(Debug, Clone)]
pub struct AuthorizationService<R, G>
where
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq + Clone,
{
    policy: AccessPolicy<R, G>,
}

impl<R, G> AuthorizationService<R, G>
where
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq + Clone,
{
    /// Creates a new authorization service with the given access policy.
    pub fn new(policy: AccessPolicy<R, G>) -> Self {
        Self { policy }
    }

    /// Determines if the account is authorized based on any of the configured criteria.
    ///
    /// Returns `true` if the account matches ANY of:
    /// - Required permissions
    /// - Required groups
    /// - Required exact roles
    /// - Required roles via supervisor relationship (ordering: higher privilege > lower privilege)
    pub fn is_authorized(&self, account: &Account<R, G>) -> bool {
        self.meets_permission_requirement(account)
            || self.meets_group_requirement(account)
            || self.meets_role_requirement(account)
            || self.meets_role_hierarchy_requirement(account)
    }

    /// Checks if the account meets any of the required roles.
    pub fn meets_role_requirement(&self, account: &Account<R, G>) -> bool {
        account.roles.iter().any(|r| {
            self.policy
                .role_requirements()
                .iter()
                .any(|scope| scope.grants_role(r))
        })
    }

    /// Checks if the account has a role that satisfies a required role via hierarchy ordering.
    ///
    /// Ordering contract: Higher privilege > Lower privilege.
    /// A supervisor or the same role satisfies: user_role >= required_role.
    pub fn meets_role_hierarchy_requirement(&self, account: &Account<R, G>) -> bool {
        debug!("Checking role hierarchy (same-or-supervisor) against required roles.");
        account.roles.iter().any(|user_role| {
            self.policy
                .role_requirements()
                .iter()
                .any(|scope| scope.grants_supervisor(user_role))
        })
    }

    /// Checks if the account meets any of the required groups.
    pub fn meets_group_requirement(&self, account: &Account<R, G>) -> bool {
        account.groups.iter().any(|r| {
            self.policy
                .group_requirements()
                .iter()
                .any(|g_scope| g_scope.eq(r))
        })
    }

    /// Checks if the account meets any of the required permissions.
    pub fn meets_permission_requirement(&self, account: &Account<R, G>) -> bool {
        // Check if any of the account's permissions match any of the required permissions
        let account_permissions: std::collections::HashSet<u64> =
            account.permissions.iter().collect();
        let required_permissions: std::collections::HashSet<u64> =
            self.policy.permission_requirements().iter().collect();

        !account_permissions.is_disjoint(&required_permissions)
    }

    /// Returns true if the policy denies all access (no requirements configured).
    pub fn policy_denies_all_access(&self) -> bool {
        self.policy.denies_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::groups::Group;
    use crate::roles::Role;

    fn create_test_account() -> Account<Role, Group> {
        use crate::permissions::Permissions;
        use uuid::Uuid;

        let mut permissions = Permissions::new();
        // Insert raw 64-bit permission IDs for testing
        permissions.bitmap_mut().insert(1u64);
        permissions.bitmap_mut().insert(5u64);

        Account {
            account_id: Uuid::new_v4(),
            user_id: "test_user".to_string(),
            roles: vec![Role::Admin],
            groups: vec![Group::new("engineering")],
            permissions,
        }
    }

    #[test]
    fn authorization_service_empty_criteria() {
        let service: AuthorizationService<Role, Group> =
            AuthorizationService::new(AccessPolicy::deny_all());
        assert!(service.policy_denies_all_access());
    }

    #[test]
    fn authorization_service_non_empty_criteria() {
        let policy = AccessPolicy::require_role(Role::Admin);
        let service: AuthorizationService<Role, Group> = AuthorizationService::new(policy);
        assert!(!service.policy_denies_all_access());
    }

    #[test]
    fn authorized_by_role_matching() {
        let account = create_test_account();
        let policy = AccessPolicy::require_role(Role::Admin);
        let service = AuthorizationService::new(policy);

        assert!(service.meets_role_requirement(&account));
    }

    #[test]
    fn authorized_by_role_not_matching() {
        let account = create_test_account();
        let policy = AccessPolicy::require_role(Role::User);
        let service = AuthorizationService::new(policy);

        assert!(!service.meets_role_requirement(&account));
    }

    #[test]
    fn authorized_by_group_matching() {
        let account = create_test_account();
        let policy = AccessPolicy::require_group(Group::new("engineering"));
        let service = AuthorizationService::new(policy);

        assert!(service.meets_group_requirement(&account));
    }

    #[test]
    fn authorized_by_group_not_matching() {
        let account = create_test_account();
        let policy = AccessPolicy::require_group(Group::new("sales"));
        let service = AuthorizationService::new(policy);

        assert!(!service.meets_group_requirement(&account));
    }

    #[test]
    fn authorized_by_permission_matching() {
        let account = create_test_account();
        let policy =
            AccessPolicy::require_permission(crate::permissions::PermissionId::from_u64(1)); // Account has permission id 1 (64-bit)
        let service = AuthorizationService::new(policy);

        assert!(service.meets_permission_requirement(&account));
    }

    #[test]
    fn authorized_by_permission_not_matching() {
        let account = create_test_account();
        let policy =
            AccessPolicy::require_permission(crate::permissions::PermissionId::from_u64(10)); // Account doesn't have permission id 10
        let service = AuthorizationService::new(policy);

        assert!(!service.meets_permission_requirement(&account));
    }

    #[test]
    fn is_authorized_returns_true_when_any_criteria_match() {
        let account = create_test_account();
        let policy = AccessPolicy::require_role(Role::User) // Won't match
            .or_require_group(Group::new("engineering")); // Will match
        let service = AuthorizationService::new(policy);

        assert!(service.is_authorized(&account));
    }

    #[test]
    fn is_authorized_returns_false_when_no_criteria_match() {
        let account = create_test_account();
        let policy = AccessPolicy::require_role(Role::User) // Won't match
            .or_require_group(Group::new("sales")); // Won't match
        let service = AuthorizationService::new(policy);

        assert!(!service.is_authorized(&account));
    }
}
