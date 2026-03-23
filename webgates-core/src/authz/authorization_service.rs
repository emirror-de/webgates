use crate::accounts::Account;
use crate::authz::{AccessHierarchy, AccessPolicy};

use std::collections::HashSet;
use tracing::debug;

/// Domain service for authorization decisions.
///
/// This service evaluates an [`AccessPolicy`] against an [`Account`] and keeps
/// the authorization logic isolated from transport, storage, and framework
/// concerns.
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
    /// Creates an authorization service for the provided access policy.
    pub fn new(policy: AccessPolicy<R, G>) -> Self {
        Self { policy }
    }

    /// Returns `true` when the account satisfies any configured policy
    /// requirement.
    ///
    /// The policy uses OR semantics across requirement categories:
    /// - exact role matches
    /// - role hierarchy matches
    /// - group membership matches
    /// - permission matches
    pub fn is_authorized(&self, account: &Account<R, G>) -> bool {
        self.meets_role_requirement(account)
            || self.meets_role_hierarchy_requirement(account)
            || self.meets_group_requirement(account)
            || self.meets_permission_requirement(account)
    }

    /// Returns `true` when the account has any exactly required role.
    pub fn meets_role_requirement(&self, account: &Account<R, G>) -> bool {
        account.roles.iter().any(|role| {
            self.policy
                .role_requirements()
                .iter()
                .any(|scope| scope.grants_role(role))
        })
    }

    /// Returns `true` when the account has any role that satisfies a
    /// same-or-supervisor requirement.
    ///
    /// Ordering contract: higher privilege is greater than lower privilege, so
    /// a supervising role satisfies `user_role >= required_role`.
    pub fn meets_role_hierarchy_requirement(&self, account: &Account<R, G>) -> bool {
        debug!("Checking role hierarchy requirements.");
        account.roles.iter().any(|user_role| {
            self.policy
                .role_requirements()
                .iter()
                .any(|scope| scope.grants_supervisor(user_role))
        })
    }

    /// Returns `true` when the account belongs to any required group.
    pub fn meets_group_requirement(&self, account: &Account<R, G>) -> bool {
        account.groups.iter().any(|group| {
            self.policy
                .group_requirements()
                .iter()
                .any(|required_group| required_group == group)
        })
    }

    /// Returns `true` when the account has any required permission.
    pub fn meets_permission_requirement(&self, account: &Account<R, G>) -> bool {
        let account_permissions: HashSet<u64> = account.permissions.iter().collect();
        let required_permissions: HashSet<u64> =
            self.policy.permission_requirements().iter().collect();

        !account_permissions.is_disjoint(&required_permissions)
    }

    /// Returns `true` when the configured policy has no requirements.
    pub fn policy_denies_all_access(&self) -> bool {
        self.policy.denies_all()
    }
}

#[cfg(test)]
mod tests {
    use super::AuthorizationService;
    use crate::accounts::Account;
    use crate::authz::access_policy::AccessPolicy;
    use crate::groups::Group;
    use crate::roles::Role;

    fn create_test_account() -> Account<Role, Group> {
        Account::new(
            "test_user".to_string(),
            vec![Role::Admin],
            vec![Group::new("engineering")],
        )
        .with_permissions(["read:api", "write:docs"].into_iter().collect())
    }

    #[test]
    fn authorization_service_reports_empty_policy() {
        let service: AuthorizationService<Role, Group> =
            AuthorizationService::new(AccessPolicy::deny_all());

        assert!(service.policy_denies_all_access());
    }

    #[test]
    fn authorization_service_reports_non_empty_policy() {
        let service: AuthorizationService<Role, Group> =
            AuthorizationService::new(AccessPolicy::require_role(Role::Admin));

        assert!(!service.policy_denies_all_access());
    }

    #[test]
    fn meets_exact_role_requirement() {
        let account = create_test_account();
        let service = AuthorizationService::new(AccessPolicy::require_role(Role::Admin));

        assert!(service.meets_role_requirement(&account));
    }

    #[test]
    fn rejects_missing_exact_role_requirement() {
        let account = create_test_account();
        let service = AuthorizationService::new(AccessPolicy::require_role(Role::User));

        assert!(!service.meets_role_requirement(&account));
    }

    #[test]
    fn meets_group_requirement() {
        let account = create_test_account();
        let service =
            AuthorizationService::new(AccessPolicy::require_group(Group::new("engineering")));

        assert!(service.meets_group_requirement(&account));
    }

    #[test]
    fn rejects_missing_group_requirement() {
        let account = create_test_account();
        let service = AuthorizationService::new(AccessPolicy::require_group(Group::new("sales")));

        assert!(!service.meets_group_requirement(&account));
    }

    #[test]
    fn meets_permission_requirement() {
        let account = create_test_account();
        let service = AuthorizationService::new(AccessPolicy::require_permission("read:api"));

        assert!(service.meets_permission_requirement(&account));
    }

    #[test]
    fn rejects_missing_permission_requirement() {
        let account = create_test_account();
        let service = AuthorizationService::new(AccessPolicy::require_permission("admin:system"));

        assert!(!service.meets_permission_requirement(&account));
    }

    #[test]
    fn meets_role_hierarchy_requirement_for_supervisor() {
        let account = create_test_account();
        let service =
            AuthorizationService::new(AccessPolicy::require_role_or_supervisor(Role::Moderator));

        assert!(service.meets_role_hierarchy_requirement(&account));
    }

    #[test]
    fn rejects_role_hierarchy_requirement_when_supervisors_are_not_allowed() {
        let account = create_test_account();
        let service = AuthorizationService::new(AccessPolicy::require_role(Role::Moderator));

        assert!(!service.meets_role_hierarchy_requirement(&account));
    }

    #[test]
    fn is_authorized_when_any_requirement_matches() {
        let account = create_test_account();
        let service = AuthorizationService::new(
            AccessPolicy::require_role(Role::User).or_require_group(Group::new("engineering")),
        );

        assert!(service.is_authorized(&account));
    }

    #[test]
    fn is_not_authorized_when_nothing_matches() {
        let account = create_test_account();
        let service = AuthorizationService::new(
            AccessPolicy::require_role(Role::User).or_require_group(Group::new("sales")),
        );

        assert!(!service.is_authorized(&account));
    }
}
