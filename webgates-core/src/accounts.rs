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
//! let account = Account::new(
//!     "user@example.com".to_string(),
//!     vec![Role::User, Role::Reporter],
//!     vec![Group::new("engineering"), Group::new("backend-team")],
//! ).with_permissions(Permissions::from_iter(["read:api", "write:docs"]));
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
/// let account = Account::new("user123".to_string(), vec![Role::User], vec![Group::new("staff")]);
///
/// let permissions: Permissions = ["read:profile", "write:profile"].into_iter().collect();
/// let account = Account::<Role, Group>::new("admin@example.com".to_string(), vec![Role::Admin], Vec::new())
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
/// # let mut account = Account::<Role, Group>::new("user".to_string(), Vec::new(), Vec::new());
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
    R: AccessHierarchy + Eq + Clone,
    G: Eq + Clone,
{
    /// Creates a new account with the specified user ID, roles, and groups.
    ///
    /// A random UUID is automatically generated for the account ID. The account
    /// starts with no permissions; use [`Self::with_permissions`] or
    /// [`Self::grant_permission`] to add them.
    ///
    /// # Parameters
    /// - `user_id`: Unique identifier for the user, such as an email or username.
    /// - `roles`: Roles assigned to this account.
    /// - `groups`: Groups this account belongs to.
    ///
    /// # Examples
    /// ```rust
    /// use webgates_core::accounts::Account;
    /// use webgates_core::groups::Group;
    /// use webgates_core::roles::Role;
    ///
    /// let account = Account::new(
    ///     "user@example.com".to_string(),
    ///     vec![Role::User, Role::Reporter],
    ///     vec![Group::new("engineering"), Group::new("backend-team")],
    /// );
    ///
    /// assert_eq!(account.user_id, "user@example.com");
    /// assert_eq!(account.roles.len(), 2);
    /// assert_eq!(account.groups.len(), 2);
    /// ```
    pub fn new(user_id: String, roles: Vec<R>, groups: Vec<G>) -> Self {
        Self {
            account_id: Uuid::now_v7(),
            user_id,
            groups,
            roles,
            permissions: Permissions::new(),
        }
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
    /// let account = Account::<Role, Group>::new("user@example.com".to_string(), vec![Role::User], Vec::new())
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
    /// let mut account = Account::<Role, Group>::new("user".to_string(), Vec::new(), Vec::new());
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
    /// let mut account = Account::<Role, Group>::new("user".to_string(), Vec::new(), Vec::new());
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
    /// let account = Account::<Role, Group>::new(
    ///     "user@example.com".to_string(),
    ///     vec![Role::User],
    ///     vec![Group::new("engineering")],
    /// );
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
    /// let account = Account::<Role, Group>::new(
    ///     "user@example.com".to_string(),
    ///     vec![Role::User],
    ///     vec![Group::new("engineering")],
    /// );
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
    /// let mut account = Account::<Role, Group>::new("user@example.com".to_string(), Vec::new(), Vec::new());
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
    fn new_preserves_owned_inputs() {
        let user_id = String::from("user@example.com");
        let roles = vec![Role::User, Role::Reporter];
        let groups = vec![Group::new("engineering"), Group::new("backend-team")];

        let account = Account::new(user_id.clone(), roles.clone(), groups.clone());

        assert_eq!(account.user_id, user_id);
        assert_eq!(account.roles, roles);
        assert_eq!(account.groups, groups);
        assert!(account.permissions.is_empty());
    }

    #[test]
    fn with_permissions_replaces_permission_set() {
        let permissions = Permissions::from_iter(["read:api", "write:api"]);

        let account = Account::<Role, Group>::new(
            String::from("user@example.com"),
            vec![Role::User],
            vec![Group::new("engineering")],
        )
        .with_permissions(permissions);

        assert!(account.has_permission("read:api"));
        assert!(account.has_permission("write:api"));
    }

    #[test]
    fn grant_and_revoke_permission_update_account_permissions() {
        let mut account =
            Account::<Role, Group>::new(String::from("user@example.com"), Vec::new(), Vec::new());

        account.grant_permission("read:api");
        assert!(account.has_permission("read:api"));

        account.revoke_permission("read:api");
        assert!(!account.has_permission("read:api"));
    }

    #[test]
    fn role_and_group_queries_reflect_membership() {
        let account = Account::<Role, Group>::new(
            String::from("user@example.com"),
            vec![Role::Admin],
            vec![Group::new("engineering")],
        );

        assert!(account.has_role(&Role::Admin));
        assert!(!account.has_role(&Role::User));
        assert!(account.is_member_of(&Group::new("engineering")));
        assert!(!account.is_member_of(&Group::new("marketing")));
    }
}
