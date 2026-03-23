//! Built-in hierarchical roles for authorization decisions.
//!
//! The built-in hierarchy is ordered from least privileged to most privileged:
//!
//! - [`Role::User`]
//! - [`Role::Reporter`]
//! - [`Role::Moderator`]
//! - [`Role::Admin`]
//!
//! This ordering matters because [`crate::authz::AccessHierarchy`] uses the type's
//! total ordering to determine whether one role is the same as, or supervises,
//! another role.
//!
//! # Examples
//!
//! ```rust
//! use webgates_core::authz::AccessPolicy;
//! use webgates_core::groups::Group;
//! use webgates_core::roles::Role;
//!
//! let exact_admin = AccessPolicy::<Role, Group>::require_role(Role::Admin);
//! let moderator_or_higher =
//!     AccessPolicy::<Role, Group>::require_role_or_supervisor(Role::Moderator);
//!
//! assert!(!exact_admin.denies_all());
//! assert!(!moderator_or_higher.denies_all());
//! ```
//!
//! # Custom role hierarchies
//!
//! If your application needs a different hierarchy, define your own enum in
//! least-privileged to most-privileged order and implement
//! [`crate::authz::AccessHierarchy`] for it.
//!
//! ```rust
//! use serde::{Deserialize, Serialize};
//! use webgates_core::authz::AccessHierarchy;
//!
//! #[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
//! enum CompanyRole {
//!     #[default]
//!     Employee,
//!     TeamLead,
//!     Manager,
//!     Director,
//! }
//!
//! impl std::fmt::Display for CompanyRole {
//!     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//!         match self {
//!             CompanyRole::Employee => write!(f, "Employee"),
//!             CompanyRole::TeamLead => write!(f, "TeamLead"),
//!             CompanyRole::Manager => write!(f, "Manager"),
//!             CompanyRole::Director => write!(f, "Director"),
//!         }
//!     }
//! }
//!
//! impl AccessHierarchy for CompanyRole {}
//! ```

use crate::authz::AccessHierarchy;
use serde::{Deserialize, Serialize};

/// Built-in roles ordered from least privileged to most privileged.
///
/// When used with [`crate::authz::AccessPolicy::require_role_or_supervisor`],
/// a higher-privileged role satisfies requirements for lower-privileged roles.
///
/// # Example
///
/// ```rust
/// use webgates_core::authz::AccessPolicy;
/// use webgates_core::groups::Group;
/// use webgates_core::roles::Role;
///
/// let moderator_or_higher =
///     AccessPolicy::<Role, Group>::require_role_or_supervisor(Role::Moderator);
/// let admin_or_moderator = AccessPolicy::<Role, Group>::require_role(Role::Admin)
///     .or_require_role(Role::Moderator);
///
/// assert!(!moderator_or_higher.denies_all());
/// assert!(!admin_or_moderator.denies_all());
/// ```
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Serialize,
    Deserialize,
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
)]
pub enum Role {
    /// Basic user role with standard application access.
    ///
    /// Users have access to core application features but limited
    /// administrative capabilities.
    #[default]
    User,
    /// Reporter role with read access and reporting capabilities.
    ///
    /// Reporters can typically view system information, generate reports,
    /// and access analytics data.
    Reporter,
    /// Moderator role with elevated privileges for content and user management.
    ///
    /// Moderators can typically manage content, moderate discussions,
    /// and have elevated access to user-facing features.
    Moderator,
    /// Administrator role with the highest level of access.
    ///
    /// Administrators typically have full system access and can perform
    /// any operation within the application.
    Admin,
}

impl AccessHierarchy for Role {}
