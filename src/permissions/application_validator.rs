use super::{PermissionCollisionChecker, ValidationReport};
use crate::errors::{Error, Result};
use crate::permissions::PermissionsError;
use tracing::info;

/// High-level builder pattern validator for application startup validation.
///
/// This is a high-level interface for validating permissions from multiple sources
/// during application initialization. It provides an ergonomic API for collecting
/// permissions incrementally before validation.
///
/// ## Use Cases
///
/// - **Application startup**: Validate permissions loaded from config, database, etc.
/// - **Simple validation workflows**: Need basic validation with automatic logging
/// - **Builder pattern preference**: Want to incrementally add permissions from different sources
/// - **One-time validation**: Don't need post-validation analysis
///
/// ## Compared to PermissionCollisionChecker
///
/// - **State**: Stateless builder - consumed during validation
/// - **Usage**: Builder pattern with incremental permission addition
/// - **Methods**: Focus on building and validating, no post-validation introspection
/// - **Lifecycle**: Single-use - transforms into validation report
/// - **Logging**: Automatically logs validation results
///
/// For runtime validation or when you need to analyze collision details after validation,
/// use [`PermissionCollisionChecker`] directly.
///
/// # See Also
///
/// - [`PermissionCollisionChecker`] - Low-level validator with detailed analysis capabilities
///
/// # Examples
///
/// ## Application startup validation
///
/// ```
/// use axum_gate::permissions::ApplicationValidator;
///
/// # fn load_config_permissions() -> Vec<String> { vec!["user:read".to_string()] }
/// # async fn load_db_permissions() -> Result<Vec<String>, Box<dyn std::error::Error>> { Ok(vec!["admin:write".to_string()]) }
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Collect permissions from multiple sources during startup
/// let config_permissions = load_config_permissions();
/// let db_permissions = load_db_permissions().await?;
///
/// let report = ApplicationValidator::new()
///     .add_permissions(config_permissions)
///     .add_permissions(db_permissions)
///     .add_permission("system:health")  // Add individual permissions
///     .validate()?;  // Automatically logs results
///
/// if report.is_valid() {
///     println!("✓ All permissions validated - server can start");
/// } else {
///     return Err(format!("Permission validation failed: {}", report.summary()).into());
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Simple validation workflow
///
/// ```
/// use axum_gate::permissions::ApplicationValidator;
///
/// // For simple cases where you just need pass/fail validation
/// let report = ApplicationValidator::new()
///     .add_permissions(["user:read", "user:write", "admin:delete"])
///     .validate()?;
///
/// // Report is automatically logged, just check if valid
/// if !report.is_valid() {
///     panic!("Invalid permissions detected during startup");
/// }
/// # Ok::<(), axum_gate::errors::Error>(())
/// ```
///
/// ## Comparison with PermissionCollisionChecker
///
/// ```
/// use axum_gate::permissions::{ApplicationValidator, PermissionCollisionChecker};
///
/// let permissions = vec!["user:read".to_string(), "user:write".to_string()];
///
/// // ApplicationValidator: Builder pattern, single-use, automatic logging
/// let report1 = ApplicationValidator::new()
///     .add_permissions(permissions.clone())
///     .validate()?;  // Validator is consumed here
/// // Can't use validator anymore, but don't need to
///
/// // PermissionCollisionChecker: Direct instantiation, reusable, manual control
/// let mut checker = PermissionCollisionChecker::new(permissions);
/// let report2 = checker.validate()?;  // Checker is still available
///
/// // Can continue using checker for analysis
/// if !report2.is_valid() {
///     let conflicts = checker.get_conflicting_permissions("user:read");
///     println!("Conflicts found: {:?}", conflicts);
/// }
/// # Ok::<(), axum_gate::errors::Error>(())
/// ```
pub struct ApplicationValidator {
    permissions: Vec<String>,
}

impl ApplicationValidator {
    /// Creates a new application validator.
    pub fn new() -> Self {
        Self {
            permissions: Vec::new(),
        }
    }

    /// Add permissions from an iterator of string-like types.
    ///
    /// # Arguments
    ///
    /// * `permissions` - Iterator of items that can be converted to String
    pub fn add_permissions<I, S>(mut self, permissions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.permissions
            .extend(permissions.into_iter().map(|s| s.into()));
        self
    }

    /// Add permissions from a vector of strings.
    ///
    /// This is a convenience method for adding permissions that are already
    /// in String format.
    ///
    /// # Arguments
    ///
    /// * `permissions` - Vector of permission strings
    pub fn add_permission_strings(mut self, permissions: Vec<String>) -> Self {
        self.permissions.extend(permissions);
        self
    }

    /// Add a single permission string.
    ///
    /// # Arguments
    ///
    /// * `permission` - A single permission string to add
    pub fn add_permission<S: Into<String>>(mut self, permission: S) -> Self {
        self.permissions.push(permission.into());
        self
    }

    /// Validate all permissions and return detailed report.
    ///
    /// This method performs validation and logs results automatically.
    /// It returns a ValidationReport containing all validation details,
    /// regardless of whether validation passed or failed.
    ///
    /// # Returns
    ///
    /// * `Ok(ValidationReport)` - Complete validation report
    /// * `Err(axum_gate::errors::Error)` - Validation process failed
    pub fn validate(self) -> Result<ValidationReport> {
        let mut checker = PermissionCollisionChecker::new(self.permissions);
        let report = checker.validate().map_err(|e| {
            Error::Permissions(PermissionsError::collision(
                0,
                vec![format!("Permission validation process failed: {}", e)],
            ))
        })?;

        report.log_results();

        if report.is_valid() {
            info!("✓ Permission validation completed successfully");
        }

        Ok(report)
    }

    /// Returns the current number of permissions to be validated.
    pub fn permission_count(&self) -> usize {
        self.permissions.len()
    }
}

impl Default for ApplicationValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn application_validator_basic() {
        let result = ApplicationValidator::new()
            .add_permissions(["user:read", "user:write"])
            .add_permission("admin:delete")
            .validate();

        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.is_valid());
    }

    #[test]
    fn application_validator_with_duplicates() {
        let result = ApplicationValidator::new()
            .add_permissions(["user:read", "user:read"])
            .validate();

        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(!report.is_valid());
        assert!(!report.duplicates().is_empty());
    }
}
