//! Compile-time permission validation to prevent hash collisions.
//!
//! This module provides the [`validate_permissions!`](crate::validate_permissions) macro for compile-time validation
//! of permission strings to ensure they don't have hash collisions. This is essential
//! for the deterministic permission system to work correctly across distributed nodes.
//!
//! # Usage
//!
//! Call the macro once in your application with all permission strings you use:
//!
//! ```rust
//! axum_gate::validate_permissions![
//!     "read:user",
//!     "write:user",
//!     "delete:user",
//!     "read:admin",
//!     "write:admin",
//!     "system:health",
//! ];
//! ```
//!
//! # How It Works
//!
//! The macro generates a test function that:
//! 1. Converts each permission string to a `PermissionId`
//! 2. Checks for hash collisions between any two permissions
//! 3. Panics during `cargo test` if collisions are found
//!
//! # When to Use
//!
//! - **Required**: When using string-based permissions in production
//! - **Recommended**: Run during CI/CD to catch collisions early
//! - **Best Practice**: Include all permissions used across your application
//!
//! # Example Integration
//!
//! ```rust
//! // In your main application or tests
//! axum_gate::validate_permissions![
//!     "api:read",
//!     "api:write",
//!     "api:delete",
//!     "user:profile:read",
//!     "user:profile:write",
//!     "admin:users:manage",
//!     "admin:system:config",
//! ];
//! ```

/// Macro for test-time permission validation.
///
/// This macro validates that the provided permission strings don't have hash collisions
/// by generating a test that runs during `cargo test`. It should be called once in your
/// application with all the permission strings you use.
///
/// The macro accepts both square brackets and parentheses syntax.
///
/// # Examples
///
/// ```rust
/// # use axum_gate::validate_permissions;
///
/// // Using square brackets (recommended style)
/// validate_permissions![
///     "read:users",
///     "write:users",
///     "delete:users",
///     "admin:system"
/// ];
///
/// // Using parentheses (also valid)
/// validate_permissions!(
///     "read:posts",
///     "write:posts",
///     "delete:posts"
/// );
///
/// // Mixed permission types
/// validate_permissions![
///     "api:read",
///     "api:write",
///     "admin:users",
///     "admin:system",
///     "billing:read",
///     "billing:write"
/// ];
/// ```
///
/// # Panics
///
/// This macro will cause a test failure if any of the permission strings
/// hash to the same value (extremely unlikely with SHA-256).
#[macro_export]
macro_rules! validate_permissions {
    ($($permission:expr),* $(,)?) => {
        #[cfg(test)]
        mod __axum_gate_permission_validation {

            #[test]
            fn validate_permission_uniqueness() {
                let permissions: Vec<String> = vec![$($permission.to_string()),*];
                let mut checker = $crate::permissions::PermissionCollisionChecker::new(permissions);
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
