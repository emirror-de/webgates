#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
//! # webgates-core
//!
//! User-focused Rust building blocks for authentication and authorization.
//!
//! `webgates-core` is the domain layer of the `webgates` ecosystem. It gives you
//! the types and services you need to represent users, declare access rules, and
//! evaluate authorization decisions without depending on any web framework,
//! transport, cookie layer, JWT implementation, or persistence backend.
//!
//! If you are onboarding to the project, the easiest mental model is:
//!
//! 1. represent the current user as an [`accounts::Account`]
//! 2. declare access requirements with an [`authz::access_policy::AccessPolicy`]
//! 3. evaluate that policy with an [`authz::authorization_service::AuthorizationService`]
//! 4. optionally connect your own login flow with [`credentials::Credentials`] and
//!    [`credentials::credentials_verifier::CredentialsVerifier`]
//!
//! ## What this crate is good for
//!
//! Use `webgates-core` when you want to:
//!
//! - keep authentication and authorization logic in pure Rust domain code
//! - model users with roles, groups, and direct permissions
//! - build your own integration for a framework not covered by sibling crates
//! - share authorization logic across HTTP services, workers, CLIs, or WASM
//! - keep dependencies small and transport-agnostic
//!
//! If you want a more batteries-included experience, start with the higher-level
//! `webgates` crate instead.
//!
//! ## Core types to learn first
//!
//! Most developers can learn the crate through this sequence:
//!
//! - [`accounts::Account`] for authenticated user state
//! - [`roles::Role`] and [`groups::Group`] for access modeling
//! - [`permissions::Permissions`] and [`permissions::permission_id::PermissionId`] for fine-grained capability checks
//! - [`authz::access_policy::AccessPolicy`] for declaring access rules
//! - [`authz::authorization_service::AuthorizationService`] for evaluating those rules
//! - [`credentials::Credentials`] and [`credentials::credentials_verifier::CredentialsVerifier`] for authentication boundaries
//! - [`verification_result::VerificationResult`] for verification outcomes
//!
//! ## A minimal end-to-end example
//!
//! ```rust
//! use webgates_core::accounts::Account;
//! use webgates_core::authz::access_policy::AccessPolicy;
//! use webgates_core::authz::authorization_service::AuthorizationService;
//! use webgates_core::groups::Group;
//! use webgates_core::roles::Role;
//!
//! let account = Account::<Role, Group>::new("alice@example.com")
//!     .with_roles(vec![Role::Moderator])
//!     .with_groups(vec![Group::new("support")]);
//!
//! let policy = AccessPolicy::<Role, Group>::require_role(Role::Admin)
//!     .or_require_group(Group::new("support"));
//!
//! let service = AuthorizationService::new(policy);
//! assert!(service.is_authorized(&account));
//! ```
//!
//! ## Important authorization behavior
//!
//! [`authz::access_policy::AccessPolicy`] uses **OR semantics** across configured
//! requirements. If any configured role, group, or permission requirement
//! matches, authorization succeeds.
//!
//! ## Getting started on docs.rs
//!
//! If you are reading this on docs.rs and want the fastest path into the crate,
//! follow this order:
//!
//! 1. Start with [`accounts::Account`] to understand what authenticated user
//!    state looks like.
//! 2. Read [`roles::Role`] and [`groups::Group`] to understand broad access
//!    modeling.
//! 3. Read [`permissions::Permissions`] if you need fine-grained capabilities.
//! 4. Read [`authz::access_policy::AccessPolicy`] to learn how access
//!    requirements are declared.
//! 5. Read [`authz::authorization_service::AuthorizationService`] to see how a
//!    policy is evaluated against an account.
//! 6. Read [`credentials::Credentials`] and
//!    [`credentials::credentials_verifier::CredentialsVerifier`] if you are
//!    implementing authentication flows.
//!
//! A good first interactive example is to create an `Account`, define an
//! `AccessPolicy`, and verify the result with `AuthorizationService`, as shown in
//! the minimal example above.

pub mod accounts;
pub mod authz;
pub mod credentials;
pub mod errors;
pub mod errors_core;
pub mod groups;
pub mod permissions;
pub mod prelude;
pub mod roles;
pub mod verification_result;
