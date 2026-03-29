//! Account management and user data structures.
//!
//! This module provides the core [`Account`] type for account metadata.
//!
//! # Quick Start
//!
//! ```rust
//! use webgates_core::accounts::Account;
//! use webgates_core::groups::Group;
//! use webgates_core::permissions::Permissions;
//! use webgates_core::roles::Role;
//!
//! let account = Account::<Role, Group>::new("user@example.com")
//!     .with_groups(vec![Group::new("engineering")])
//!     .with_permissions(Permissions::from_iter(["read:api", "write:docs"]));
//! ```

use crate::authz::AccessHierarchy;
use crate::permissions::{PermissionId, Permissions};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An account contains authorization information about a user.
///
/// Accounts store user identification, roles, groups, and permissions. They are the
/// core entity for authorization decisions in webgates.
///
/// # Creating Accounts
///
/// ```rust
/// use webgates_core::accounts::Account;
/// use webgates_core::groups::Group;
/// use webgates_core::permissions::Permissions;
/// use webgates_core::roles::Role;
///
/// let account = Account::<Role, Group>::new("user123");
///
/// let permissions: Permissions = ["read:profile", "write:profile"].into_iter().collect();
/// let account = Account::<Role, Group>::new("admin@example.com")
///     .with_roles(vec![Role::Admin])
///     .with_groups(vec![Group::new("staff")])
///     .with_permissions(permissions);
/// ```
///
/// # Working with Permissions
///
/// ```rust
/// # use webgates_core::accounts::Account;
/// # use webgates_core::groups::Group;
/// # use webgates_core::permissions::PermissionId;
/// # use webgates_core::roles::Role;
/// # let mut account = Account::<Role, Group>::new("user");
/// account.grant_permission("read:api");
/// account.grant_permission(PermissionId::from("write:api"));
///
/// if account.permissions.has("read:api") {
///     println!("User can read API");
/// }
///
/// account.revoke_permission("write:api");
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Account<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    /// The unique identifier of the account generated during registration.
    ///
    /// This UUID links the account to its corresponding authentication secret
    /// in the secret repository. The separation of account data from secrets
    /// enhances security by allowing different storage backends and access controls.
    pub account_id: Uuid,
    /// The user identifier for this account (e.g., email, username).
    ///
    /// This should be unique within your application and is typically what users
    /// provide during login. It's used to look up accounts in the repository.
    pub user_id: String,
    /// Roles assigned to this account.
    ///
    /// Roles determine what actions a user can perform. If your roles implement
    /// `AccessHierarchy`, supervisor roles automatically inherit subordinate permissions.
    pub roles: Vec<R>,
    /// Groups this account belongs to.
    ///
    /// Groups provide another dimension of access control, allowing you to grant
    /// permissions based on team membership, department, or other organizational units.
    pub groups: Vec<G>,
    /// Custom permissions granted to this account.
    ///
    /// Uses a compressed bitmap for efficient storage and fast permission checks.
    /// Permissions are automatically available when referenced by name using
    /// deterministic hashing - no coordination between nodes required.
    pub permissions: Permissions,
}

impl<R, G> Account<R, G>
where
    R: AccessHierarchy + Eq + Clone + Default,
    G: Eq + Clone,
{
    /// Creates a new account with the specified user ID.
    ///
    /// A random UUID is automatically generated for the account ID. The account
    /// starts with a single default role, no groups, and no permissions. Use
    /// [`Default`] on your role type to define the initial role assigned by this
    /// constructor. Use direct field mutation or struct update patterns after
    /// construction when you need to customize roles or groups.
    ///
    /// # Parameters
    /// - `user_id`: Unique identifier for the user, such as an email or username.
    ///
    /// # Examples
    /// ```rust
    /// use webgates_core::accounts::Account;
    /// use webgates_core::groups::Group;
    /// use webgates_core::roles::Role;
    ///
    /// let account = Account::<Role, Group>::new("user@example.com");
    ///
    /// assert_eq!(account.user_id, "user@example.com");
    /// assert_eq!(account.roles, vec![Role::User]);
    /// assert!(account.groups.is_empty());
    /// ```
    pub fn new(user_id: &str) -> Self {
        Self {
            account_id: Uuid::now_v7(),
            user_id: user_id.to_string(),
            groups: Vec::new(),
            roles: vec![R::default()],
            permissions: Permissions::new(),
        }
    }

    /// Consumes this account and returns it with the specified roles.
    ///
    /// This is useful when building accounts that need explicit roles instead of
    /// the single default role assigned by [`Self::new`].
    ///
    /// # Example
    /// ```rust
    /// use webgates_core::accounts::Account;
    /// use webgates_core::groups::Group;
    /// use webgates_core::roles::Role;
    ///
    /// let account = Account::<Role, Group>::new("user@example.com")
    ///     .with_roles(vec![Role::Admin]);
    ///
    /// assert!(account.has_role(&Role::Admin));
    /// assert!(!account.has_role(&Role::User));
    /// ```
    pub fn with_roles(self, roles: Vec<R>) -> Self {
        Self { roles, ..self }
    }

    /// Consumes this account and returns it with the specified groups.
    ///
    /// This is useful when building accounts with initial group membership.
    ///
    /// # Example
    /// ```rust
    /// use webgates_core::accounts::Account;
    /// use webgates_core::groups::Group;
    /// use webgates_core::roles::Role;
    ///
    /// let account = Account::<Role, Group>::new("user@example.com")
    ///     .with_groups(vec![Group::new("engineering")]);
    ///
    /// assert!(account.is_member_of(&Group::new("engineering")));
    /// assert!(!account.is_member_of(&Group::new("marketing")));
    /// ```
    pub fn with_groups(self, groups: Vec<G>) -> Self {
        Self { groups, ..self }
    }

    /// Consumes this account and returns it with the specified permissions.
    ///
    /// This is useful when building accounts with specific permission sets.
    ///
    /// # Example
    /// ```rust
    /// use webgates_core::accounts::Account;
    /// use webgates_core::groups::Group;
    /// use webgates_core::permissions::Permissions;
    /// use webgates_core::roles::Role;
    ///
    /// let permissions: Permissions = ["read:profile", "write:profile"].into_iter().collect();
    /// let account = Account::<Role, Group>::new("user@example.com")
    ///     .with_permissions(permissions);
    /// ```
    pub fn with_permissions(self, permissions: Permissions) -> Self {
        Self {
            permissions,
            ..self
        }
    }

    /// Grants a permission to this account.
    ///
    /// # Example
    /// ```rust
    /// use webgates_core::accounts::Account;
    /// use webgates_core::groups::Group;
    /// use webgates_core::permissions::PermissionId;
    /// use webgates_core::roles::Role;
    ///
    /// let mut account = Account::<Role, Group>::new("user");
    /// account.grant_permission("read:profile");
    /// account.grant_permission(PermissionId::from("write:profile"));
    /// ```
    pub fn grant_permission<P>(&mut self, permission: P)
    where
        P: Into<PermissionId>,
    {
        self.permissions.grant(permission);
    }

    /// Revokes a permission from this account.
    ///
    /// # Example
    /// ```rust
    /// use webgates_core::accounts::Account;
    /// use webgates_core::groups::Group;
    /// use webgates_core::permissions::PermissionId;
    /// use webgates_core::roles::Role;
    ///
    /// let mut account = Account::<Role, Group>::new("user");
    /// account.grant_permission("write:profile");
    /// account.revoke_permission(PermissionId::from("write:profile"));
    /// ```
    pub fn revoke_permission<P>(&mut self, permission: P)
    where
        P: Into<PermissionId>,
    {
        self.permissions.revoke(permission);
    }

    /// Returns true if this account has the given role.
    ///
    /// # Example
    ///
    /// ```rust
    /// use webgates_core::accounts::Account;
    /// use webgates_core::groups::Group;
    /// use webgates_core::roles::Role;
    ///
    /// let account = Account::<Role, Group>::new("user@example.com");
    ///
    /// assert!(account.has_role(&Role::User));
    /// assert!(!account.has_role(&Role::Admin));
    /// ```
    pub fn has_role(&self, role: &R) -> bool {
        self.roles.contains(role)
    }

    /// Returns true if this account is a member of the given group.
    ///
    /// # Example
    ///
    /// ```rust
    /// use webgates_core::accounts::Account;
    /// use webgates_core::groups::Group;
    /// use webgates_core::roles::Role;
    ///
    /// let mut account = Account::<Role, Group>::new("user@example.com");
    /// account.groups.push(Group::new("engineering"));
    ///
    /// assert!(account.is_member_of(&Group::new("engineering")));
    /// assert!(!account.is_member_of(&Group::new("marketing")));
    /// ```
    pub fn is_member_of(&self, group: &G) -> bool {
        self.groups.contains(group)
    }

    /// Returns true if this account has the specified permission.
    ///
    /// Accepts any type that converts into `PermissionId` (e.g., `&str`, `PermissionId`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use webgates_core::accounts::Account;
    /// use webgates_core::groups::Group;
    /// use webgates_core::permissions::PermissionId;
    /// use webgates_core::roles::Role;
    ///
    /// let mut account = Account::<Role, Group>::new("user@example.com");
    /// account.grant_permission("read:api");
    /// account.grant_permission(PermissionId::from("write:docs"));
    ///
    /// assert!(account.has_permission("read:api"));
    /// assert!(account.has_permission(PermissionId::from("write:docs")));
    /// assert!(!account.has_permission("admin:system"));
    /// ```
    pub fn has_permission<P>(&self, permission: P) -> bool
    where
        P: Into<PermissionId>,
    {
        self.permissions.has(permission)
    }
}

#[cfg(test)]
mod tests {
    use super::Account;
    use crate::groups::Group;
    use crate::permissions::Permissions;
    use crate::roles::Role;

    #[test]
    fn new_uses_default_role_and_empty_groups() {
        let account = Account::<Role, Group>::new("user@example.com");

        assert_eq!(account.user_id, "user@example.com");
        assert_eq!(account.roles, vec![Role::User]);
        assert!(account.groups.is_empty());
        assert!(account.permissions.is_empty());
    }

    #[test]
    fn with_roles_replaces_default_role_set() {
        let account = Account::<Role, Group>::new("user@example.com").with_roles(vec![Role::Admin]);

        assert_eq!(account.roles, vec![Role::Admin]);
    }

    #[test]
    fn with_groups_replaces_group_set() {
        let groups = vec![Group::new("engineering"), Group::new("backend-team")];
        let account = Account::<Role, Group>::new("user@example.com").with_groups(groups.clone());

        assert_eq!(account.groups, groups);
    }

    #[test]
    fn with_permissions_replaces_permission_set() {
        let permissions = Permissions::from_iter(["read:api", "write:api"]);

        let account = Account::<Role, Group>::new("user@example.com").with_permissions(permissions);

        assert!(account.has_permission("read:api"));
        assert!(account.has_permission("write:api"));
    }

    #[test]
    fn grant_and_revoke_permission_update_account_permissions() {
        let mut account = Account::<Role, Group>::new("user@example.com");

        account.grant_permission("read:api");
        assert!(account.has_permission("read:api"));

        account.revoke_permission("read:api");
        assert!(!account.has_permission("read:api"));
    }

    #[test]
    fn role_and_group_queries_reflect_membership() {
        let mut account = Account::<Role, Group>::new("user@example.com");
        account.roles = vec![Role::Admin];
        account.groups = vec![Group::new("engineering")];

        assert!(account.has_role(&Role::Admin));
        assert!(!account.has_role(&Role::User));
        assert!(account.is_member_of(&Group::new("engineering")));
        assert!(!account.is_member_of(&Group::new("marketing")));
    }
}
