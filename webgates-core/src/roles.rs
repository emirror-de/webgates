//! Built-in hierarchical roles for authorization decisions.
//!
//! Use this module when the default `webgates-core` role hierarchy matches your
//! application. If not, define your own role enum and implement
//! [`crate::authz::access_hierarchy::AccessHierarchy`].
//!
//! The built-in hierarchy is ordered from least privileged to most privileged:
//!
//! - [`Role::User`]
//! - [`Role::Reporter`]
//! - [`Role::Moderator`]
//! - [`Role::Admin`]
//!
//! This ordering matters because [`crate::authz::access_hierarchy::AccessHierarchy`] uses the type's
//! total ordering to determine whether one role is the same as, or supervises,
//! another role.
//!
//! # Examples
//!
//! ```rust
//! use webgates_core::authz::access_policy::AccessPolicy;
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
//! [`crate::authz::access_hierarchy::AccessHierarchy`] for it.
//!
//! ```rust
//! use serde::{Deserialize, Serialize};
//! use webgates_core::authz::access_hierarchy::AccessHierarchy;
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

use crate::authz::access_hierarchy::AccessHierarchy;
use serde::{Deserialize, Serialize};

/// Built-in roles ordered from least privileged to most privileged.
///
/// These roles give you a ready-to-use hierarchy for common applications.
/// When used with [`crate::authz::access_policy::AccessPolicy::<Role, crate::groups::Group>::require_role_or_supervisor`],
/// a higher-privileged role can satisfy lower-role requirements.
///
/// # Example
///
/// ```rust
/// use webgates_core::authz::access_policy::AccessPolicy;
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
    /// Baseline role for regular users.
    ///
    /// This is the default role assigned by `Account::new(...)` when you use the
    /// built-in [`Role`] type.
    #[default]
    User,
    /// Role for users who primarily need read-heavy or reporting access.
    Reporter,
    /// Elevated role for moderation or operational workflows.
    Moderator,
    /// Highest built-in role.
    ///
    /// Administrators typically have full access to protected operations.
    Admin,
}

impl AccessHierarchy for Role {}
