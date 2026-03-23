use crate::errors_core::Result;
use crate::permissions::{PermissionCollisionChecker, PermissionsError, ValidationReport};
use tracing::info;

/// High-level builder for validating application permission sets at startup.
///
/// `ApplicationValidator` collects permission strings from multiple sources,
/// validates them for duplicates and hash collisions, and returns a
/// [`ValidationReport`].
///
/// Use this type when you want a small, single-use API for startup validation.
/// If you need reusable post-validation inspection helpers, use
/// [`PermissionCollisionChecker`] directly.
///
/// # Examples
///
/// ```
/// use webgates_core::permissions::ApplicationValidator;
///
/// # fn load_config_permissions() -> Vec<String> { vec!["user:read".to_string()] }
/// # async fn load_db_permissions() -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> { Ok(vec!["admin:write".to_string()]) }
/// # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
/// let config_permissions = load_config_permissions();
/// let db_permissions = load_db_permissions().await?;
///
/// let report = ApplicationValidator::new()
///     .add_permissions(config_permissions)
///     .add_permissions(db_permissions)
///     .add_permission("system:health")
///     .validate()?;
///
/// assert!(report.is_valid());
/// # Ok(())
/// # }
/// ```
///
/// ```
/// use webgates_core::permissions::{ApplicationValidator, PermissionCollisionChecker};
///
/// let permissions = vec!["user:read".to_string(), "user:write".to_string()];
///
/// let report = ApplicationValidator::new()
///     .add_permissions(permissions.clone())
///     .validate()
///     .map_err(|error| error.to_string())?;
///
/// let mut checker = PermissionCollisionChecker::new(permissions);
/// let inspected = checker.validate().map_err(|error| error.to_string())?;
///
/// assert_eq!(report.is_valid(), inspected.is_valid());
/// # Ok::<(), String>(())
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
    /// * `Err(webgates_core::errors::Error)` - Validation process failed
    pub fn validate(self) -> Result<ValidationReport, PermissionsError> {
        let mut checker = PermissionCollisionChecker::new(self.permissions);
        let report = checker.validate().map_err(|e| {
            PermissionsError::collision(
                0,
                vec![format!("Permission validation process failed: {}", e)],
            )
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
mod tests {
    use super::*;

    #[test]
    fn application_validator_basic() {
        let result = ApplicationValidator::new()
            .add_permissions(["user:read", "user:write"])
            .add_permission("admin:delete")
            .validate();

        match result {
            Ok(report) => assert!(report.is_valid()),
            Err(error) => panic!("validation unexpectedly failed: {error}"),
        }
    }

    #[test]
    fn application_validator_with_duplicates() {
        let result = ApplicationValidator::new()
            .add_permissions(["user:read", "user:read"])
            .validate();

        match result {
            Ok(report) => {
                assert!(!report.is_valid());
                assert!(!report.duplicates().is_empty());
            }
            Err(error) => panic!("validation unexpectedly failed: {error}"),
        }
    }
}
