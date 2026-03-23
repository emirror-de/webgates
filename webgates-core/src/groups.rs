//! Group identifiers for group-based authorization decisions.
//!
//! Groups model non-hierarchical membership such as departments, teams, projects,
//! or other organizational units. Unlike roles, groups are compared by exact
//! identity and do not imply privilege ordering.
//!
//! # Examples
//!
//! Create groups and use them in access policies:
//!
//! ```rust
//! use webgates_core::authz::AccessPolicy;
//! use webgates_core::groups::Group;
//! use webgates_core::roles::Role;
//!
//! let engineering = Group::new("engineering");
//! let marketing = Group::new("marketing");
//!
//! let policy = AccessPolicy::<Role, Group>::require_group(engineering.clone())
//!     .or_require_group(marketing.clone());
//!
//! assert_eq!(engineering.name(), "engineering");
//! assert_eq!(marketing.name(), "marketing");
//! assert!(!policy.denies_all());
//! ```
//!
//! Common naming patterns:
//!
//! ```rust
//! use webgates_core::groups::Group;
//!
//! let departments = vec![
//!     Group::new("engineering"),
//!     Group::new("marketing"),
//!     Group::new("support"),
//! ];
//!
//! let project_groups = vec![
//!     Group::new("project-alpha"),
//!     Group::new("project-beta"),
//! ];
//!
//! let teams = vec![
//!     Group::new("frontend-team"),
//!     Group::new("backend-team"),
//!     Group::new("qa-team"),
//! ];
//!
//! assert_eq!(departments.len(), 3);
//! assert_eq!(project_groups.len(), 2);
//! assert_eq!(teams.len(), 3);
//! ```

use serde::{Deserialize, Serialize};

/// A group identifier used for exact membership checks in authorization logic.
///
/// Groups are a simple, non-hierarchical companion to roles. They are useful for
/// modeling organizational or contextual membership such as departments, project
/// teams, or tenant-specific cohorts.
///
/// # Example
/// ```rust
/// use webgates_core::groups::Group;
///
/// let engineering = Group::new("engineering");
/// let backend_team = Group::new("backend-team");
///
/// assert_eq!(engineering.name(), "engineering");
/// assert_eq!(backend_team.name(), "backend-team");
/// ```
#[derive(Eq, PartialEq, Debug, Serialize, Deserialize, Clone)]
#[serde(transparent)]
pub struct Group(String);

impl Group {
    /// Creates a new group from its stable name.
    ///
    /// # Parameters
    /// - `group`: Group identifier such as `"engineering"` or `"project-alpha"`.
    ///
    /// # Example
    /// ```rust
    /// use webgates_core::groups::Group;
    ///
    /// let engineering = Group::new("engineering");
    /// let project_team = Group::new("project-alpha-team");
    ///
    /// assert_eq!(engineering.name(), "engineering");
    /// assert_eq!(project_team.name(), "project-alpha-team");
    /// ```
    pub fn new(group: &str) -> Self {
        Self(group.to_string())
    }

    /// Returns the stable group identifier.
    ///
    /// # Example
    /// ```rust
    /// use webgates_core::groups::Group;
    ///
    /// let group = Group::new("engineering");
    ///
    /// assert_eq!(group.name(), "engineering");
    /// ```
    pub fn name(&self) -> &str {
        &self.0
    }
}

/// Trait for types that expose a stable group identifier.
///
/// Implement this for application-specific group types when repository or mapping
/// code needs a canonical string identifier.
pub trait GroupEntity {
    /// Return the unique identifier for this group as `&str`.
    fn group_id(&self) -> &str;
}

/// Allows the built-in [`Group`] type to be used wherever a [`GroupEntity`]
/// is required.
impl GroupEntity for Group {
    fn group_id(&self) -> &str {
        self.name()
    }
}
