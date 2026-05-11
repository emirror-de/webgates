//! Account types for representing the current user in authorization flows.
//!
//! This module provides [`Account`], the central domain type used throughout
//! `webgates-core`.
//!
//! If you are onboarding to the crate, this is usually the first type to learn.
//! An account brings together the data that authorization decisions care about:
//!
//! - your application-level user identifier
//! - assigned roles
//! - group membership
//! - directly granted permissions
//!
//! # Quick start
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

use crate::authz::access_hierarchy::AccessHierarchy;
use crate::permissions::Permissions;
use crate::permissions::permission_id::PermissionId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Authorization-relevant information about a user or principal.
///
/// `Account` is the main input to authorization checks in `webgates-core`.
/// It stores the user identity plus the roles, groups, and direct permissions
/// that a policy may evaluate.
///
/// In most applications, you create or load an account during authentication,
/// then pass it into an authorization service when a protected operation is
/// requested.
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
/// # use webgates_core::permissions::permission_id::PermissionId;
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
    /// Stable unique identifier for the account.
    ///
    /// This UUID is generated when the account is created. Applications can use
    /// it as the durable internal identifier that links account state to other
    /// records such as credentials, profiles, or repository entries.
    pub account_id: Uuid,
    /// Application-level user identifier, such as an email address or username.
    ///
    /// This is typically the identifier a person uses to log in and the one your
    /// application uses to look up the account.
    pub user_id: String,
    /// Roles assigned to this account.
    ///
    /// Roles usually represent broad privilege levels such as user, moderator,
    /// or admin. When the role type implements [`AccessHierarchy`], higher roles
    /// can satisfy lower-role requirements when a policy allows supervisor access.
    pub roles: Vec<R>,
    /// Groups this account belongs to.
    ///
    /// Groups model exact membership such as departments, tenants, project teams,
    /// or support rotations.
    pub groups: Vec<G>,
    /// Directly granted permissions for this account.
    ///
    /// Use direct permissions when roles or groups are too broad and you need
    /// feature-level or action-level access control.
    pub permissions: Permissions,
}

impl<R, G> Account<R, G>
where
    R: AccessHierarchy + Eq + Clone + Default,
    G: Eq + Clone,
{
    /// Creates a new account for the given user identifier.
    ///
    /// A fresh UUID is generated automatically. The new account starts with:
    ///
    /// - the default role for `R`
    /// - no groups
    /// - no direct permissions
    ///
    /// With the built-in [`crate::roles::Role`] type, the default role is
    /// `Role::User`.
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

    /// Returns this account with the provided roles.
    ///
    /// This is useful when building an account that should not keep the single
    /// default role assigned by [`Self::new`].
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

    /// Returns this account with the provided groups.
    ///
    /// This is useful when building an account with initial group membership.
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

    /// Returns this account with the provided direct permissions.
    ///
    /// This is useful when building an account that starts with a known
    /// permission set.
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

    /// Grants a direct permission to this account.
    ///
    /// # Example
    /// ```rust
    /// use webgates_core::accounts::Account;
    /// use webgates_core::groups::Group;
    /// use webgates_core::permissions::permission_id::PermissionId;
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

    /// Revokes a direct permission from this account.
    ///
    /// # Example
    /// ```rust
    /// use webgates_core::accounts::Account;
    /// use webgates_core::groups::Group;
    /// use webgates_core::permissions::permission_id::PermissionId;
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

    /// Returns `true` when this account has the given role.
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

    /// Returns `true` when this account belongs to the given group.
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

    /// Returns `true` when this account has the specified direct permission.
    ///
    /// Accepts any type that converts into [`PermissionId`], such as `&str` or
    /// `PermissionId` itself.
    ///
    /// # Example
    ///
    /// ```rust
    /// use webgates_core::accounts::Account;
    /// use webgates_core::groups::Group;
    /// use webgates_core::permissions::permission_id::PermissionId;
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
