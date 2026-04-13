//! Authorization primitives for role-, group-, and permission-based access control.
//!
//! This module exposes the public authorization surface of `webgates-core`:
//!
//! - [`access_hierarchy::AccessHierarchy`] defines how role types participate in supervisor checks
//! - [`access_policy::AccessPolicy`] declares role, group, and permission requirements
//! - [`authorization_service::AuthorizationService`] evaluates policies against an [`crate::accounts::Account`]
//! - [`errors::AuthzError`] contains authorization-category error values
//!
//! Import items directly from their owning submodule for one canonical path per item.
//!
//! # Quick start
//!
//! ```rust
//! use webgates_core::accounts::Account;
//! use webgates_core::authz::access_policy::AccessPolicy;
//! use webgates_core::authz::authorization_service::AuthorizationService;
//! use webgates_core::groups::Group;
//! use webgates_core::permissions::permission_id::PermissionId;
//! use webgates_core::roles::Role;
//!
//! let admin_policy = AccessPolicy::<Role, Group>::require_role(Role::Admin);
//! let group_policy = AccessPolicy::<Role, Group>::require_group(Group::new("engineering"));
//! let permission_policy = AccessPolicy::<Role, Group>::require_permission(PermissionId::from("read:api"));
//!
//! let mut account = Account::<Role, Group>::new("user@example.com");
//! account.groups.push(Group::new("engineering"));
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
//! use webgates_core::authz::access_policy::AccessPolicy;
//! use webgates_core::groups::Group;
//! use webgates_core::permissions::permission_id::PermissionId;
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
//! Use [`access_policy::AccessPolicy::require_role_or_supervisor`] when a higher-privileged role
//! should satisfy a lower-privileged requirement.
//!
//! ```rust
//! use webgates_core::authz::access_policy::AccessPolicy;
//! use webgates_core::groups::Group;
//! use webgates_core::roles::Role;
//!
//! let hierarchical_policy =
//!     AccessPolicy::<Role, Group>::require_role_or_supervisor(Role::User);
//!
//! assert!(hierarchical_policy.has_requirements());
//! ```

/// Trait that marks a type as participating in role-hierarchy checks.
pub mod access_hierarchy;
/// Domain object describing who may access a protected resource.
pub mod access_policy;
mod access_scope;
/// Domain service for evaluating access policies against accounts.
pub mod authorization_service;
/// Authorization-category error values.
pub mod errors;
