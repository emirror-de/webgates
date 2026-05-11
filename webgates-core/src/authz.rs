//! Authorization primitives for role-, group-, and permission-based access control.
//!
//! This module is where you define **who should be allowed through** and how to
//! evaluate that decision against an account.
//!
//! If you are new to `webgates-core`, the usual flow is:
//!
//! 1. create or load an [`crate::accounts::Account`]
//! 2. build an [`access_policy::AccessPolicy`] that describes the requirement
//! 3. evaluate it with [`authorization_service::AuthorizationService`]
//!
//! ## Main types
//!
//! - [`access_hierarchy::AccessHierarchy`] defines how custom role types support supervisor checks
//! - [`access_policy::AccessPolicy`] declares role, group, and permission requirements
//! - [`authorization_service::AuthorizationService`] evaluates a policy against an account
//! - [`errors::AuthzError`] contains authorization-related error values
//!
//! Import items directly from their owning submodule for a single canonical path.
//!
//! # Quick start
//!
//! ```rust
//! use webgates_core::accounts::Account;
//! use webgates_core::authz::access_policy::AccessPolicy;
//! use webgates_core::authz::authorization_service::AuthorizationService;
//! use webgates_core::groups::Group;
//! use webgates_core::roles::Role;
//!
//! let account = Account::<Role, Group>::new("user@example.com")
//!     .with_groups(vec![Group::new("engineering")]);
//!
//! let policy = AccessPolicy::<Role, Group>::require_group(Group::new("engineering"));
//! let authz = AuthorizationService::new(policy);
//!
//! assert!(authz.is_authorized(&account));
//! ```
//!
//! # Policy composition
//!
//! Policies use **OR semantics**. Authorization succeeds when any configured
//! role, group, or permission requirement matches.
//!
//! ```rust
//! use webgates_core::authz::access_policy::AccessPolicy;
//! use webgates_core::groups::Group;
//! use webgates_core::roles::Role;
//!
//! let policy = AccessPolicy::<Role, Group>::require_role(Role::Admin)
//!     .or_require_group(Group::new("security-team"))
//!     .or_require_permission("emergency:access");
//!
//! assert!(policy.has_requirements());
//! ```
//!
//! # Hierarchical roles
//!
//! Use [`access_policy::AccessPolicy::<R, G>::require_role_or_supervisor`] when a
//! higher-privileged role should satisfy a lower-privileged requirement.
//!
//! ```rust
//! use webgates_core::authz::access_policy::AccessPolicy;
//! use webgates_core::groups::Group;
//! use webgates_core::roles::Role;
//!
//! let policy = AccessPolicy::<Role, Group>::require_role_or_supervisor(Role::Moderator);
//!
//! assert!(policy.has_requirements());
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
