use super::PermissionCollision;
use tracing::{info, warn};

/// Validation outcome for a set of permission strings.
///
/// Produced by:
/// - [`PermissionCollisionChecker::validate`](super::PermissionCollisionChecker::validate)
/// - [`ApplicationValidator::validate`](super::ApplicationValidator::validate)
///
/// # Terminology
/// - *Duplicate* permission: The exact same string appears more than once. These are
///   represented internally as a "collision" where every entry in the collision
///   group is identical.
/// - *Hash collision*: Two **different** normalized permission strings that deterministically
///   hash (via the 64‑bit truncated SHA‑256) to the same ID. This is extremely unlikely
///   and should be treated as a critical configuration problem if it ever occurs.
///
/// # Interpreting Results
/// - [`ValidationReport::is_valid`] is `true` when there are **no** collisions at all
///   (neither duplicates nor distinct-string collisions).
/// - [`ValidationReport::duplicates`] returns only pure duplicates (all strings in the
///   collision set are identical).
/// - Distinct collisions (same hash, different strings) are considered more severe and
///   will appear in log output / `detailed_errors` but **not** in `duplicates()`.
///
/// # Typical Actions
/// | Situation                                 | Action                                                                 | Severity            |
/// |-------------------------------------------|------------------------------------------------------------------------|---------------------|
/// | Report is valid                           | Proceed with startup / reload                                          | None                |
/// | One or more duplicates only               | Remove redundant entries (usually a config hygiene issue)             | Low / Medium        |
/// | Any non‑duplicate hash collision detected | Rename at least one colliding permission (treat as urgent)             | High (very rare)    |
///
/// # Convenience Methods
/// - [`summary`](Self::summary) gives a compact human‑readable description (good for logs / errors).
/// - [`detailed_errors`](Self::detailed_errors) enumerates each issue (useful for API / CLI feedback).
/// - [`total_issues`](Self::total_issues) counts total collision groups (duplicates + distinct collisions).
///
/// # Example
/// ```rust
/// use axum_gate::permissions::{PermissionCollisionChecker, ApplicationValidator};
///
/// // Direct checker
/// let mut checker = PermissionCollisionChecker::new(vec![
///     "user:read".into(),
///     "user:read".into(),      // duplicate
///     "admin:full".into(),
/// ]);
/// let report = checker.validate().unwrap();
/// assert!(!report.is_valid());
/// assert_eq!(report.duplicates(), vec!["user:read".to_string()]);
///
/// // Builder style
/// let report2 = ApplicationValidator::new()
///     .add_permissions(["user:read", "user:read"])
///     .validate()
///     .unwrap();
/// assert!(!report2.is_valid());
/// ```
///
/// # Performance Notes
/// The validator groups by 64‑bit IDs first; memory usage is proportional to the
/// number of *distinct* permission IDs plus total string storage. For typical
/// application-scale permission sets (≪10k) this is negligible.
///
/// # Logging
/// Use [`log_results`](Self::log_results) for structured `tracing` output. Successful validation logs
/// at `INFO`, issues at `WARN`.
#[derive(Debug, Default)]
pub struct ValidationReport {
    /// All collision groups (duplicates and *true* hash collisions).
    ///
    /// Each entry contains:
    /// - The 64‑bit permission ID (`id`)
    /// - The list of original permission strings that map to that ID
    ///
    /// Invariants:
    /// - Length >= 2 for each `permissions` vector
    /// - A "duplicate" group has every element string-equal
    /// - A "distinct collision" group has at least one differing string
    pub collisions: Vec<PermissionCollision>,
}

impl ValidationReport {
    /// Returns true if validation passed without any issues.
    ///
    /// A validation is considered successful if there are no hash collisions.
    pub fn is_valid(&self) -> bool {
        self.collisions.is_empty()
    }

    /// Returns duplicate permission strings found.
    ///
    /// Duplicates are derived from collisions where all permissions are identical.
    pub fn duplicates(&self) -> Vec<String> {
        self.collisions
            .iter()
            .filter(|collision| {
                collision.permissions.len() > 1
                    && collision.permissions.windows(2).all(|w| w[0] == w[1])
            })
            .map(|collision| collision.permissions[0].clone())
            .collect()
    }

    /// Returns a human-readable summary of validation results.
    ///
    /// For successful validations, returns a success message.
    /// For failed validations, provides details about what issues were found.
    pub fn summary(&self) -> String {
        if self.is_valid() {
            return "All permissions are valid and collision-free".to_string();
        }

        let mut parts = Vec::new();
        let duplicates = self.duplicates();

        if !duplicates.is_empty() {
            parts.push(format!(
                "{} duplicate permission string(s)",
                duplicates.len()
            ));
        }

        let non_duplicate_collisions = self
            .collisions
            .iter()
            .filter(|collision| {
                !(collision.permissions.len() > 1
                    && collision.permissions.windows(2).all(|w| w[0] == w[1]))
            })
            .count();

        if non_duplicate_collisions > 0 {
            let total_colliding = self
                .collisions
                .iter()
                .filter(|collision| {
                    !(collision.permissions.len() > 1
                        && collision.permissions.windows(2).all(|w| w[0] == w[1]))
                })
                .map(|c| c.permissions.len())
                .sum::<usize>();
            parts.push(format!(
                "{} hash collision(s) affecting {} permission(s)",
                non_duplicate_collisions, total_colliding
            ));
        }

        parts.join(", ")
    }

    /// Logs validation results using the tracing crate.
    ///
    /// This method will log at INFO level for successful validations
    /// and WARN level for any issues found.
    pub fn log_results(&self) {
        if self.is_valid() {
            info!("Permission validation passed: all permissions are valid");
            return;
        }

        let duplicates = self.duplicates();
        for duplicate in &duplicates {
            warn!("Duplicate permission string found: '{}'", duplicate);
        }

        for collision in &self.collisions {
            let is_duplicate = collision.permissions.len() > 1
                && collision.permissions.windows(2).all(|w| w[0] == w[1]);
            if !is_duplicate {
                warn!(
                    "Hash collision detected (ID: {}): permissions {:?} all hash to the same value",
                    collision.id, collision.permissions
                );
            }
        }
    }

    /// Returns detailed information about all issues found.
    ///
    /// This method provides comprehensive details suitable for debugging
    /// or detailed error reporting.
    pub fn detailed_errors(&self) -> Vec<String> {
        let mut errors = Vec::new();
        let duplicates = self.duplicates();

        for duplicate in &duplicates {
            errors.push(format!("Duplicate permission: '{}'", duplicate));
        }

        for collision in &self.collisions {
            let is_duplicate = collision.permissions.len() > 1
                && collision.permissions.windows(2).all(|w| w[0] == w[1]);
            if !is_duplicate {
                errors.push(format!(
                    "Hash collision (ID {}): {} -> {:?}",
                    collision.id,
                    collision.permissions.join(", "),
                    collision.permissions
                ));
            }
        }

        errors
    }

    /// Returns the total number of issues found.
    pub fn total_issues(&self) -> usize {
        self.collisions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::super::PermissionCollision;
    use super::*;

    #[test]
    fn validation_report_summary() {
        let mut report = ValidationReport::default();
        assert!(report.is_valid());
        assert!(report.summary().contains("valid"));

        report.collisions.push(PermissionCollision {
            id: 12345,
            permissions: vec!["test".to_string(), "test".to_string()],
        });
        assert!(!report.is_valid());
        assert!(report.summary().contains("duplicate"));

        report.collisions.push(PermissionCollision {
            id: 12345,
            permissions: vec!["perm1".to_string(), "perm2".to_string()],
        });
        assert!(report.summary().contains("collision"));
    }

    #[test]
    fn validation_report_detailed_errors() {
        let mut report = ValidationReport::default();
        report.collisions.push(PermissionCollision {
            id: 54321,
            permissions: vec!["test:duplicate".to_string(), "test:duplicate".to_string()],
        });
        report.collisions.push(PermissionCollision {
            id: 12345,
            permissions: vec!["perm1".to_string(), "perm2".to_string()],
        });

        let errors = report.detailed_errors();
        assert_eq!(errors.len(), 2);
        assert!(errors[0].contains("Duplicate"));
        assert!(errors[1].contains("Hash collision"));
    }
}
