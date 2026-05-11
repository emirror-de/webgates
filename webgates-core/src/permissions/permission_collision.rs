/// A group of permission strings that share the same 64-bit deterministic ID.
///
/// This can represent either:
/// - pure duplicates, where all strings are identical
/// - a true hash collision, where different strings map to the same ID
///
/// In most applications, true collisions should be treated as critical and
/// resolved immediately by renaming at least one permission.
///
/// Example:
/// ```rust
/// # use webgates_core::permissions::validation_report::ValidationReport;
/// # fn analyze(report: &ValidationReport) {
/// for group in &report.collisions {
///     let all_equal = group.permissions.windows(2).all(|w| w[0] == w[1]);
///     if all_equal {
///         // duplicate definition
///     } else {
///         // distinct collision: fix immediately
///     }
/// }
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct PermissionCollision {
    /// The 64-bit ID shared by every permission in this collision group.
    pub id: u64,
    /// Permission strings that all map to the same ID.
    pub permissions: Vec<String>,
}
