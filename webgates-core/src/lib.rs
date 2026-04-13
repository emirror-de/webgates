#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
//! # webgates-core
//!
//! Framework-agnostic domain types and authorization primitives for the
//! `webgates` ecosystem.
//!
//! `webgates-core` exposes a small, canonical public surface for:
//!
//! - account, role, and group domain types
//! - authorization policies and evaluation services
//! - credential boundary types and verification contracts
//! - deterministic permission identifiers, sets, and validation helpers
//! - shared error traits and verification result types
//!
//! Prefer the canonical public paths exported by the owning modules:
//!
//! - [`accounts::Account`]
//! - [`authz::access_hierarchy::AccessHierarchy`], [`authz::access_policy::AccessPolicy`], [`authz::authorization_service::AuthorizationService`], [`authz::errors::AuthzError`]
//! - [`credentials::Credentials`], [`credentials::credentials_verifier::CredentialsVerifier`]
//! - [`permissions::permission_id::PermissionId`], [`permissions::Permissions`], [`permissions::application_validator::ApplicationValidator`]
//! - [`permissions::collision_checker::PermissionCollisionChecker`], [`permissions::permission_collision::PermissionCollision`], [`permissions::validation_report::ValidationReport`]
//! - [`permissions::as_permission_name::AsPermissionName`], [`permissions::errors::PermissionsError`]
//! - [`errors::Error`], [`errors::Result`]
//! - [`errors_core::ErrorSeverity`], [`errors_core::UserFriendlyError`]
//! - [`groups::Group`], [`groups::GroupEntity`]
//! - [`roles::Role`]
//! - [`verification_result::VerificationResult`]
//!
//! The crate does not preserve alternate nested export paths as part of its
//! public API. Import from the owning module instead of private implementation
//! submodules.

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
