use crate::errors_core::Result;
use crate::permissions::collision_checker::PermissionCollisionChecker;
use crate::permissions::errors::PermissionsError;
use crate::permissions::validation_report::ValidationReport;
use tracing::info;

/// High-level builder for validating your application's permission list.
///
/// `ApplicationValidator` collects permission strings from one or more sources,
/// validates them for duplicates and hash collisions, and returns a
/// [`ValidationReport`].
///
/// This is the easiest API to use at startup or in tests when you want to say:
/// "here is the full permission surface of my application; make sure it is safe."
///
/// If you need reusable post-validation inspection helpers, use
/// [`PermissionCollisionChecker`] directly.
///
/// # Examples
///
/// ```
/// use webgates_core::permissions::application_validator::ApplicationValidator;///
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
/// use webgates_core::permissions::application_validator::ApplicationValidator;
/// use webgates_core::permissions::collision_checker::PermissionCollisionChecker;
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
    /// Creates a new empty validator.
    pub fn new() -> Self {
        Self {
            permissions: Vec::new(),
        }
    }

    /// Adds permissions from an iterator of string-like values.
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

    /// Adds permissions from a vector of owned strings.
    ///
    /// This is a convenience method for callers that already have `Vec<String>`.
    ///
    /// # Arguments
    ///
    /// * `permissions` - Vector of permission strings
    pub fn add_permission_strings(mut self, permissions: Vec<String>) -> Self {
        self.permissions.extend(permissions);
        self
    }

    /// Adds one permission string.
    ///
    /// # Arguments
    ///
    /// * `permission` - A single permission string to add
    pub fn add_permission<S: Into<String>>(mut self, permission: S) -> Self {
        self.permissions.push(permission.into());
        self
    }

    /// Validates all collected permissions and returns a detailed report.
    ///
    /// This method performs validation and logs results automatically. It
    /// returns a [`ValidationReport`] whether validation succeeds or fails,
    /// unless the validation process itself encounters an unexpected error.
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

    /// Returns how many permission strings are currently queued for validation.
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
