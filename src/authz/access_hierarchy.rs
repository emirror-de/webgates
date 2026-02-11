/// Marker trait representing a linear privilege hierarchy using Rust's derived ordering.
///
/// Semantics:
/// - Implementors MUST derive (or implement) `Ord`, `PartialOrd`, `Eq`, `PartialEq`, `Copy`.
/// - Ordering direction: HIGHER privilege > LOWER privilege
///   (i.e. the greatest / largest value in ordering terms is the most privileged).
/// - The "baseline" (least privileged authenticated role) is therefore the MIN element.
///
/// Baseline Role:
/// - The baseline (lowest privilege) role MUST be returned by `Default::default()`.
/// - Implement `Default` for your role enum to return the least privileged variant.
///
/// Rationale:
/// Using total ordering plus `Default` gives:
///   - Constant‑time privilege comparisons
///   - Clear, compiler‑enforced hierarchy
///   - A uniform way (`R::default()`) to obtain the baseline for helpers like `require_login()`
///
/// Supervisor / Hierarchy Checks:
/// - A role A is the same or a supervisor (higher privilege) of role B if `A >= B`.
/// - Policies must use `user_role >= required_role`.
///
/// Example:
/// ```
/// #[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// enum Role { #[default] User, Reporter, Moderator, Admin } // Admin highest
///
/// assert!(Role::Admin > Role::Moderator);
/// assert!(Role::Moderator > Role::User);
/// assert_eq!(Role::default(), Role::User);
/// // Supervisor check (Admin supervises User): Role::Admin >= Role::User
/// ```
///
/// **NOTE**: Reordering variants changes access semantics and is a breaking change.
pub trait AccessHierarchy: Copy + Eq + Ord + Default {}
