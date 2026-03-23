/// Marker trait for a total ordering of roles from least privileged to most privileged.
///
/// Implementors must satisfy these invariants:
/// - The type has a total order via `Ord` and `PartialOrd`.
/// - Higher privilege compares greater than lower privilege.
/// - `Default::default()` returns the least privileged role.
///
/// These constraints let authorization code express hierarchy checks with simple
/// comparisons instead of custom lookup tables.
///
/// # Supervisor checks
///
/// A role `user_role` satisfies a required role `required_role` when:
/// - `user_role == required_role` for an exact match
/// - `user_role >= required_role` when supervisor access is allowed
///
/// # Example
///
/// ```
/// #[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// enum Role {
///     #[default]
///     User,
///     Reporter,
///     Moderator,
///     Admin,
/// }
///
/// assert!(Role::Admin > Role::Moderator);
/// assert!(Role::Moderator > Role::User);
/// assert_eq!(Role::default(), Role::User);
/// assert!(Role::Admin >= Role::User);
/// ```
///
/// Reordering variants changes authorization semantics and should be treated as a
/// deliberate API change.
pub trait AccessHierarchy: Copy + Eq + Ord + Default {}
