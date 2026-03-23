//! Authorization primitives for role-, group-, and permission-based access control.
//!
//! This module exposes the public authorization surface of `webgates-core`:
//!
//! - [`AccessHierarchy`] defines how role types participate in supervisor checks
//! - [`AccessPolicy`] declares role, group, and permission requirements
//! - [`AuthorizationService`] evaluates policies against an [`crate::accounts::Account`]
//! - [`AuthzError`] contains authorization-category error values
//!
//! The public API is available directly from `webgates_core::authz`, so callers
//! can import items from one canonical module path instead of navigating nested
//! implementation modules.
//!
//! # Quick start
//!
//! ```rust
//! use webgates_core::accounts::Account;
//! use webgates_core::authz::{AccessPolicy, AuthorizationService};
//! use webgates_core::groups::Group;
//! use webgates_core::permissions::PermissionId;
//! use webgates_core::roles::Role;
//!
//! let admin_policy = AccessPolicy::<Role, Group>::require_role(Role::Admin);
//! let group_policy = AccessPolicy::<Role, Group>::require_group(Group::new("engineering"));
//! let permission_policy = AccessPolicy::<Role, Group>::require_permission(PermissionId::from("read:api"));
//!
//! let account = Account::new(
//!     "user@example.com".to_string(),
//!     vec![Role::User],
//!     vec![Group::new("engineering")],
//! );
//!
//! let auth_service = AuthorizationService::new(group_policy);
//! assert!(auth_service.is_authorized(&account));
//! assert!(!AuthorizationService::new(admin_policy).is_authorized(&account));
//! assert!(!AuthorizationService::new(permission_policy).is_authorized(&account));
//! ```
//!
//! # Policy composition
//!
//! Policies use OR semantics across configured requirements. Authorization
//! succeeds when any configured role, group, or permission requirement matches.
//!
//! ```rust
//! use webgates_core::authz::AccessPolicy;
//! use webgates_core::groups::Group;
//! use webgates_core::permissions::PermissionId;
//! use webgates_core::roles::Role;
//!
//! let policy = AccessPolicy::<Role, Group>::require_role(Role::Admin)
//!     .or_require_group(Group::new("security-team"))
//!     .or_require_permission(PermissionId::from("emergency:access"));
//!
//! assert!(policy.has_requirements());
//! ```
//!
//! # Hierarchical roles
//!
//! Use [`AccessPolicy::require_role_or_supervisor`] when a higher-privileged role
//! should satisfy a lower-privileged requirement.
//!
//! ```rust
//! use webgates_core::authz::AccessPolicy;
//! use webgates_core::groups::Group;
//! use webgates_core::roles::Role;
//!
//! let hierarchical_policy =
//!     AccessPolicy::<Role, Group>::require_role_or_supervisor(Role::User);
//!
//! assert!(hierarchical_policy.has_requirements());
//! ```

mod access_hierarchy;
mod access_policy;
mod access_scope;
mod authorization_service;
mod errors;

pub use access_hierarchy::AccessHierarchy;
pub use access_policy::AccessPolicy;
pub use authorization_service::AuthorizationService;
pub use errors::AuthzError;
