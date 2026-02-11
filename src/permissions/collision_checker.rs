use super::{PermissionCollision, PermissionId, ValidationReport};
use crate::errors::{Error, Result};
use crate::permissions::PermissionsError;
use std::collections::HashMap;

/// Low-level permission collision checker for runtime validation and analysis.
///
/// This checker validates permission strings for duplicates and hash collisions,
/// providing detailed reports about any issues found. Unlike the compile-time
/// validation, this can handle dynamic permission strings.
///
/// ## Use Cases
///
/// - **Runtime validation**: When permissions change during application lifecycle
/// - **Debugging and analysis**: Need to inspect collision maps and conflicts
/// - **Custom validation workflows**: Require fine-grained control over validation process
/// - **Performance-critical paths**: Direct validation without builder overhead
///
/// ## Compared to ApplicationValidator
///
/// - **State**: Stateful - maintains collision map for post-validation analysis
/// - **Usage**: Direct instantiation with complete permission set
/// - **Methods**: Provides introspection methods like `get_conflicting_permissions()`
/// - **Lifecycle**: Can be reused after validation for analysis
///
/// For simple application startup validation, consider using [`ApplicationValidator`](super::ApplicationValidator)
/// which provides a more ergonomic builder pattern API.
///
/// # See Also
///
/// - [`ApplicationValidator`](super::ApplicationValidator) - High-level builder pattern validator for startup validation
///
/// # Examples
///
/// ## Basic validation with post-analysis
///
/// ```
/// use axum_gate::permissions::PermissionCollisionChecker;
///
/// let permissions = vec![
///     "user:read".to_string(),
///     "user:write".to_string(),
///     "admin:full_access".to_string(),
/// ];
///
/// let mut checker = PermissionCollisionChecker::new(permissions);
/// let report = checker.validate()?;
///
/// if report.is_valid() {
///     println!("All permissions are valid!");
///     // Can still use checker for analysis after validation
///     println!("Total permissions: {}", checker.permission_count());
///     println!("Unique IDs: {}", checker.unique_id_count());
/// } else {
///     println!("Issues found: {}", report.summary());
///     // Check for specific conflicts
///     let conflicts = checker.get_conflicting_permissions("user:read");
///     if !conflicts.is_empty() {
///         println!("Conflicts with user:read: {:?}", conflicts);
///     }
/// }
/// # Ok::<(), axum_gate::errors::Error>(())
/// ```
///
/// ## Runtime permission updates
///
/// ```
/// use axum_gate::permissions::PermissionCollisionChecker;
///
/// fn update_permissions(new_permissions: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
///     let mut checker = PermissionCollisionChecker::new(new_permissions);
///     let report = checker.validate()?;
///
///     if !report.is_valid() {
///         // Can analyze specific issues
///         for collision in &report.collisions {
///             println!("Hash ID {} has conflicts: {:?}", collision.id, collision.permissions);
///         }
///         return Err("Permission validation failed".into());
///     }
///
///     // Validation passed - can still inspect the checker
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

    /// Validates all permissions for uniqueness and collision-free hashing.
    ///
    /// This method performs comprehensive validation including:
    /// - Duplicate string detection
    /// - Hash collision detection
    /// - Internal collision map building
    ///
    /// # Returns
    ///
    /// * `Ok(ValidationReport)` - Detailed report of validation results
    /// * `Err(axum_gate::errors::Error)` - If validation process itself fails
    ///
    /// # Examples
    ///
    /// ```
    /// use axum_gate::permissions::PermissionCollisionChecker;
    ///
    /// let permissions = vec!["read:file".to_string(), "write:file".to_string()];
    /// let mut checker = PermissionCollisionChecker::new(permissions);
    ///
    /// match checker.validate() {
    ///     Ok(report) => {
    ///         if report.is_valid() {
    ///             println!("Validation passed!");
    ///         } else {
    ///             eprintln!("Validation failed: {}", report.summary());
    ///         }
    ///     }
    ///     Err(e) => eprintln!("Validation error: {}", e),
    /// }
    /// ```
    pub fn validate(&mut self) -> Result<ValidationReport> {
        let mut report = ValidationReport::default();

        // Check for hash collisions (including duplicates)
        self.check_hash_collisions(&mut report).map_err(|e| {
            Error::Permissions(PermissionsError::collision(
                0,
                vec![format!("Failed to check for hash collisions: {}", e)],
            ))
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn collision_checker_valid_permissions() {
        let permissions = vec![
            "user:read".to_string(),
            "user:write".to_string(),
            "admin:delete".to_string(),
        ];

        let mut checker = PermissionCollisionChecker::new(permissions);
        let report = checker.validate().unwrap();

        assert!(report.is_valid());
        assert!(report.duplicates().is_empty());
        assert!(report.collisions.is_empty());
    }

    #[test]
    fn collision_checker_duplicate_strings() {
        let permissions = vec![
            "user:read".to_string(),
            "user:write".to_string(),
            "user:read".to_string(), // Duplicate
        ];

        let mut checker = PermissionCollisionChecker::new(permissions);
        let report = checker.validate().unwrap();

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
        checker.validate().unwrap();

        let conflicts = checker.get_conflicting_permissions("user:read");
        // Since these shouldn't hash to the same value, conflicts should be empty
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
        checker.validate().unwrap();

        assert_eq!(checker.permission_count(), 3);
        // Should have 3 unique IDs (assuming no collisions)
        assert_eq!(checker.unique_id_count(), 3);

        let summary = checker.get_permission_summary();
        assert_eq!(summary.len(), 3);
    }
}
