/// A group of permission strings that share the same 64‑bit deterministic hash.
///
/// This can represent:
/// - Pure duplicates (all strings identical)
/// - A *true* collision (different strings hashing to the same 64‑bit value; extremely rare)
///
/// Use logic like:
/// ```rust
/// # use axum_gate::permissions::ValidationReport;
/// # fn analyze(report: &ValidationReport) {
/// for group in &report.collisions {
///     let all_equal = group.permissions.windows(2).all(|w| w[0] == w[1]);
///     if all_equal {
///         // handle duplicate
///     } else {
///         // handle distinct collision (critical)
///     }
/// }
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct PermissionCollision {
    /// The hash ID that has multiple permissions mapping to it (64-bit).
    pub id: u64,
    /// List of permission strings that all hash to the same value.
    pub permissions: Vec<String>,
}
