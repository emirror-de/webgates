use crate::errors_core::Result;
use crate::permissions::{PermissionCollision, PermissionId, PermissionsError, ValidationReport};
use std::collections::HashMap;

/// Low-level permission collision checker for runtime validation and analysis.
///
/// This checker validates dynamic permission strings for duplicates and hash
/// collisions and retains a grouped collision map for follow-up inspection.
///
/// ## Use Cases
///
/// - **Runtime validation**: Validate permissions assembled from config, plugins,
///   or remote data sources.
/// - **Debugging and analysis**: Inspect collisions and per-ID groupings after
///   validation.
/// - **Custom validation workflows**: Perform validation without going through
///   a higher-level builder.
/// - **Post-validation introspection**: Reuse the checker instance after
///   `validate()` to inspect grouped results.
///
/// ## Compared to ApplicationValidator
///
/// - **State**: Stateful; it retains grouped permission data for later analysis.
/// - **Usage**: Construct directly from a complete permission list.
/// - **Methods**: Exposes inspection helpers such as
///   `get_conflicting_permissions()` and `get_permission_summary()`.
/// - **Lifecycle**: Can still be queried after validation completes.
///
/// For simple startup validation with automatic logging, prefer
/// [`ApplicationValidator`](crate::permissions::ApplicationValidator).
///
/// # Examples
///
/// ## Basic validation with post-analysis
///
/// ```
/// use webgates_core::permissions::PermissionCollisionChecker;
///
/// let permissions = vec![
///     "user:read".to_string(),
///     "user:write".to_string(),
///     "admin:full_access".to_string(),
/// ];
///
/// let mut checker = PermissionCollisionChecker::new(permissions);
/// let report = checker.validate().map_err(|error| error.to_string())?;
///
/// if report.is_valid() {
///     println!("All permissions are valid.");
///     println!("Total permissions: {}", checker.permission_count());
///     println!("Unique IDs: {}", checker.unique_id_count());
/// } else {
///     println!("Issues found: {}", report.summary());
///     let conflicts = checker.get_conflicting_permissions("user:read");
///     if !conflicts.is_empty() {
///         println!("Conflicts with user:read: {:?}", conflicts);
///     }
/// }
/// # Ok::<(), String>(())
/// ```
///
/// ## Runtime permission updates
///
/// ```
/// use webgates_core::permissions::PermissionCollisionChecker;
///
/// fn update_permissions(new_permissions: Vec<String>) -> Result<(), String> {
///     let mut checker = PermissionCollisionChecker::new(new_permissions);
///     let report = checker.validate().map_err(|error| error.to_string())?;
///
///     if !report.is_valid() {
///         for collision in &report.collisions {
///             println!("Hash ID {} has conflicts: {:?}", collision.id, collision.permissions);
///         }
///         return Err("Permission validation failed".to_string());
///     }
///
///     let summary = checker.get_permission_summary();
///     println!("Permission distribution: {:?}", summary);
///     Ok(())
/// }
/// ```
pub struct PermissionCollisionChecker {
    permissions: Vec<String>,
    collision_map: HashMap<u64, Vec<String>>,
}

impl PermissionCollisionChecker {
    /// Creates a new collision checker with the given permission strings.
    ///
    /// # Arguments
    ///
    /// * `permissions` - Vector of permission strings to validate
    pub fn new(permissions: Vec<String>) -> Self {
        Self {
            permissions,
            collision_map: HashMap::new(),
        }
    }

    /// Validates all permissions for duplicates and hash collisions.
    ///
    /// This method:
    /// - groups permissions by deterministic permission ID
    /// - records duplicate strings and true hash collisions in a
    ///   [`ValidationReport`]
    /// - rebuilds the internal collision map for later inspection
    ///
    /// # Returns
    ///
    /// - `Ok(ValidationReport)` when validation completed successfully, even if
    ///   the report contains duplicates or collisions
    /// - `Err(...)` only when the validation process itself fails unexpectedly
    ///
    /// # Examples
    ///
    /// ```
    /// use webgates_core::permissions::PermissionCollisionChecker;
    ///
    /// let permissions = vec!["read:file".to_string(), "write:file".to_string()];
    /// let mut checker = PermissionCollisionChecker::new(permissions);
    ///
    /// match checker.validate() {
    ///     Ok(report) if report.is_valid() => println!("Validation passed."),
    ///     Ok(report) => eprintln!("Validation failed: {}", report.summary()),
    ///     Err(error) => eprintln!("Validation error: {}", error),
    /// }
    /// ```
    pub fn validate(&mut self) -> Result<ValidationReport> {
        let mut report = ValidationReport::default();

        // Check for hash collisions (including duplicates)
        self.check_hash_collisions(&mut report).map_err(|e| {
            Box::new(PermissionsError::collision(
                0,
                vec![format!("Failed to check for hash collisions: {}", e)],
            )) as Box<dyn std::error::Error + Send + Sync>
        })?;

        // Generate collision map for inspection
        self.build_collision_map();

        Ok(report)
    }

    fn check_hash_collisions(&self, report: &mut ValidationReport) -> Result<()> {
        let mut id_to_permissions: HashMap<u64, Vec<String>> = HashMap::new();

        // Group permissions by their hash ID
        for permission in &self.permissions {
            let id_raw = PermissionId::from(permission.as_str()).as_u64();
            id_to_permissions
                .entry(id_raw)
                .or_default()
                .push(permission.clone());
        }

        // Find all hash IDs with multiple permissions
        for (id, permissions) in id_to_permissions {
            if permissions.len() > 1 {
                report
                    .collisions
                    .push(PermissionCollision { id, permissions });
            }
        }

        Ok(())
    }

    fn build_collision_map(&mut self) {
        self.collision_map.clear();

        for permission in &self.permissions {
            let id = PermissionId::from(permission.as_str()).as_u64();
            self.collision_map
                .entry(id)
                .or_default()
                .push(permission.clone());
        }
    }

    /// Returns permissions that hash to the same ID as the given permission.
    ///
    /// This method is useful for debugging collision issues or understanding
    /// how permissions map to hash IDs.
    ///
    /// # Arguments
    ///
    /// * `permission` - The permission string to check for conflicts
    ///
    /// # Returns
    ///
    /// Vector of permission strings that conflict with the given permission.
    /// The returned vector will not include the input permission itself.
    pub fn get_conflicting_permissions(&self, permission: &str) -> Vec<String> {
        let id = PermissionId::from(permission).as_u64();
        self.collision_map
            .get(&id)
            .map(|perms| perms.iter().filter(|p| *p != permission).cloned().collect())
            .unwrap_or_default()
    }

    /// Returns a summary of all permissions grouped by their hash ID.
    ///
    /// This method provides a complete view of how permissions are distributed
    /// across hash IDs, which can be useful for analysis and debugging.
    ///
    /// # Returns
    ///
    /// HashMap where keys are hash IDs and values are vectors of permission strings
    /// that hash to that ID.
    pub fn get_permission_summary(&self) -> HashMap<u64, Vec<String>> {
        self.collision_map.clone()
    }

    /// Returns the total number of permissions being validated.
    pub fn permission_count(&self) -> usize {
        self.permissions.len()
    }

    /// Returns the number of unique hash IDs generated from the permissions.
    pub fn unique_id_count(&self) -> usize {
        self.collision_map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::PermissionCollisionChecker;

    #[test]
    fn collision_checker_valid_permissions() {
        let permissions = vec![
            "user:read".to_string(),
            "user:write".to_string(),
            "admin:delete".to_string(),
        ];

        let mut checker = PermissionCollisionChecker::new(permissions);
        let report = checker
            .validate()
            .expect("valid permissions should produce a validation report");

        assert!(report.is_valid());
        assert!(report.duplicates().is_empty());
        assert!(report.collisions.is_empty());
    }

    #[test]
    fn collision_checker_duplicate_strings() {
        let permissions = vec![
            "user:read".to_string(),
            "user:write".to_string(),
            "user:read".to_string(),
        ];

        let mut checker = PermissionCollisionChecker::new(permissions);
        let report = checker
            .validate()
            .expect("duplicate permissions should still produce a validation report");

        assert!(!report.is_valid());
        let duplicates = report.duplicates();
        assert_eq!(duplicates.len(), 1);
        assert_eq!(duplicates[0], "user:read");
        assert_eq!(report.collisions.len(), 1);
    }

    #[test]
    fn collision_checker_conflicting_permissions() {
        let permissions = vec!["user:read".to_string(), "user:write".to_string()];

        let mut checker = PermissionCollisionChecker::new(permissions);
        checker
            .validate()
            .expect("distinct permissions should validate without processing errors");

        let conflicts = checker.get_conflicting_permissions("user:read");
        assert!(conflicts.is_empty());
    }

    #[test]
    fn permission_collision_checker_summary() {
        let permissions = vec![
            "user:read".to_string(),
            "user:write".to_string(),
            "admin:delete".to_string(),
        ];

        let mut checker = PermissionCollisionChecker::new(permissions);
        checker
            .validate()
            .expect("valid permissions should populate the collision map");

        assert_eq!(checker.permission_count(), 3);
        assert_eq!(checker.unique_id_count(), 3);

        let summary = checker.get_permission_summary();
        assert_eq!(summary.len(), 3);
    }
}
