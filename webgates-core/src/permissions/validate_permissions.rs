/// Compile-time permission validation to prevent hash collisions.
///
/// This module exposes the [`validate_permissions!`](crate::validate_permissions)
/// macro for test-time validation of permission strings.
///
/// Use it once in your application or test crate to verify that the permission
/// names you rely on do not normalize to colliding [`crate::permissions::PermissionId`]
/// values.
///
/// # Usage
///
/// ```rust
/// use webgates_core::validate_permissions;
///
/// validate_permissions![
///     "read:user",
///     "write:user",
///     "delete:user",
///     "read:admin",
///     "write:admin",
///     "system:health",
/// ];
/// ```
///
/// # How it works
///
/// The macro generates a test that:
/// 1. Converts each permission string into a [`crate::permissions::PermissionId`]
/// 2. Validates the full set with [`crate::permissions::PermissionCollisionChecker`]
/// 3. Fails the test when duplicates or hash collisions are detected
///
/// # When to use
///
/// - Required when your application depends on string-based permissions
/// - Recommended in CI so permission changes are validated automatically
/// - Best used with the complete set of permissions your application defines
///
/// # Example integration
///
/// ```rust
/// use webgates_core::validate_permissions;
///
/// validate_permissions![
///     "api:read",
///     "api:write",
///     "api:delete",
///     "user:profile:read",
///     "user:profile:write",
///     "admin:users:manage",
///     "admin:system:config",
/// ];
/// ```

/// Macro for test-time permission validation.
///
/// Use this macro to validate a complete set of permission names during tests.
/// It generates a test that checks the provided strings with
/// [`crate::permissions::PermissionCollisionChecker`].
///
/// The macro accepts both square bracket and parenthesis invocation forms.
///
/// # Examples
///
/// ```rust
/// use webgates_core::validate_permissions;
///
/// validate_permissions![
///     "read:users",
///     "write:users",
///     "delete:users",
///     "admin:system",
/// ];
///
/// validate_permissions!(
///     "read:posts",
///     "write:posts",
///     "delete:posts"
/// );
///
/// validate_permissions![
///     "api:read",
///     "api:write",
///     "admin:users",
///     "admin:system",
///     "billing:read",
///     "billing:write",
/// ];
/// ```
///
/// # Panics
///
/// The generated test fails when the provided permission strings contain
/// duplicates or hash collisions.
#[macro_export]
macro_rules! validate_permissions {
    ($($permission:expr),* $(,)?) => {
        #[cfg(test)]
        mod __webgates_permission_validation {

            #[test]
            fn validate_permission_uniqueness() {
                let permissions: Vec<String> = vec![$($permission.to_string()),*];
                let mut checker =
                    $crate::permissions::PermissionCollisionChecker::new(permissions);
                let report = checker.validate()
                    .expect("Permission validation failed: validation process error");

                if !report.is_valid() {
                    panic!("Permission validation failed: {}", report.summary());
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    // Test the macro
    validate_permissions!["test:permission1", "test:permission2", "test:permission3"];
}
