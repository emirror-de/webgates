//! Comprehensive example demonstrating permission validation capabilities.
//!
//! This example shows how to use the validation module to check for permission
//! collisions and duplicates in various scenarios, including:
//! - Static permission validation
//! - Dynamic permission loading from configuration
//! - Runtime validation during application lifecycle
//! - Error handling and reporting

use axum_gate::errors::Result;
use axum_gate::permissions::{ApplicationValidator, PermissionCollisionChecker};

use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

#[derive(Debug, Serialize, Deserialize)]
struct AppConfig {
    roles: Vec<RoleConfig>,
    resources: Vec<String>,
    actions: Vec<String>,
    custom_permissions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RoleConfig {
    name: String,
    permissions: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt().with_env_filter("info").init();

    info!("🚀 Starting permission validation example");

    // Example 1: Basic static validation
    example_static_validation()?;

    // Example 2: Configuration-based validation
    example_config_validation().await?;

    // Example 3: Runtime validation during application events
    example_runtime_validation().await?;

    // Example 4: Advanced validation with detailed reporting
    example_detailed_validation().await?;

    // Example 5: Error handling scenarios
    example_error_scenarios().await?;

    info!("✅ All validation examples completed successfully");
    Ok(())
}

/// Example 1: Basic static permission validation
fn example_static_validation() -> Result<()> {
    info!("📋 Example 1: Static permission validation");

    // This should pass - all unique permissions
    let valid_permissions = [
        "user:read:profile",
        "user:write:profile",
        "user:delete:account",
        "admin:read:users",
        "admin:write:system",
        "moderator:ban:user",
    ];

    match ApplicationValidator::new()
        .add_permissions(valid_permissions)
        .validate()
    {
        Ok(report) => {
            if report.is_valid() {
                info!("  ✅ Static validation passed");
            } else {
                error!("  ❌ Static validation failed: {}", report.summary());
                return Err(axum_gate::errors::Error::Permissions(
                    axum_gate::errors::PermissionsError::collision(
                        12345,
                        vec!["static_validation_failed".to_string()],
                    ),
                ));
            }
        }
        Err(e) => {
            error!("  ❌ Static validation failed: {}", e);
            return Err(e);
        }
    }

    // Example with Application Validator
    let result = ApplicationValidator::new()
        .add_permissions(valid_permissions)
        .add_permission("guest:read:public")
        .validate();

    match result {
        Ok(report) => {
            if report.is_valid() {
                info!("  ✅ ApplicationValidator validation passed");
            } else {
                error!(
                    "  ❌ ApplicationValidator validation failed: {}",
                    report.summary()
                );
                return Err(axum_gate::errors::Error::Permissions(
                    axum_gate::errors::PermissionsError::collision(
                        54321,
                        vec!["app_validation_failed".to_string()],
                    ),
                ));
            }
        }
        Err(e) => {
            error!("  ❌ ApplicationValidator validation failed: {}", e);
            return Err(e);
        }
    }

    Ok(())
}

/// Example 2: Configuration-based validation
async fn example_config_validation() -> Result<()> {
    info!("⚙️  Example 2: Configuration-based validation");

    // Simulate loading configuration
    let config = load_app_config().await?;

    // Generate permissions from configuration
    let permissions = generate_permissions_from_config(&config)?;

    info!(
        "  📦 Generated {} permissions from config",
        permissions.len()
    );

    // Validate the generated permissions
    let validator = ApplicationValidator::new().add_permission_strings(permissions);

    match validator.validate() {
        Ok(report) => {
            if report.is_valid() {
                info!("  ✅ Configuration-based validation passed");
            } else {
                warn!(
                    "  ⚠️  Configuration validation issues: {}",
                    report.summary()
                );
                // In a real application, you might want to continue with warnings
                // rather than failing completely, depending on your requirements
            }
        }
        Err(e) => {
            warn!("  ⚠️  Configuration validation failed: {}", e);
        }
    }

    Ok(())
}

/// Example 3: Runtime validation during application events
async fn example_runtime_validation() -> Result<()> {
    info!("🔄 Example 3: Runtime validation during application events");

    // Simulate dynamic permission updates during runtime
    let mut base_permissions = vec![
        "user:read:profile".to_string(),
        "user:write:profile".to_string(),
    ];

    // Simulate adding permissions for a new feature
    let new_feature_permissions = vec![
        "user:read:notifications".to_string(),
        "user:write:notifications".to_string(),
        "user:delete:notifications".to_string(),
    ];

    base_permissions.extend(new_feature_permissions);

    // Validate after runtime changes
    let mut checker = PermissionCollisionChecker::new(base_permissions.clone());

    match checker.validate() {
        Ok(report) => {
            if report.is_valid() {
                info!("  ✅ Runtime validation passed after feature addition");
                info!("  📊 Total permissions: {}", checker.permission_count());
                info!("  🔢 Unique IDs: {}", checker.unique_id_count());
            } else {
                warn!(
                    "  ⚠️  Runtime validation found issues: {}",
                    report.summary()
                );
                report.log_results();
            }
        }
        Err(e) => {
            error!("  ❌ Runtime validation failed: {}", e);
            return Err(e);
        }
    }

    // Simulate permission cleanup
    simulate_permission_cleanup(&mut base_permissions).await?;

    Ok(())
}

/// Example 4: Advanced validation with detailed reporting
async fn example_detailed_validation() -> Result<()> {
    info!("📊 Example 4: Advanced validation with detailed reporting");

    // Create a more complex permission set with potential issues
    let complex_permissions = generate_complex_permission_set();

    let mut checker = PermissionCollisionChecker::new(complex_permissions);

    match checker.validate() {
        Ok(report) => {
            info!("  📈 Validation completed");
            info!("  📋 Summary: {}", report.summary());
            info!("  🔍 Total issues found: {}", report.total_issues());

            if !report.is_valid() {
                info!("  📝 Detailed error report:");
                for error in report.detailed_errors() {
                    info!("    - {}", error);
                }

                report.log_results();
            }

            // Demonstrate collision analysis
            let summary = checker.get_permission_summary();
            info!("  🗂️  Permission distribution analysis:");
            for (id, perms) in summary.iter().take(5) {
                // Show first 5 for brevity
                if perms.len() > 1 {
                    warn!("    ID {}: {} permissions -> {:?}", id, perms.len(), perms);
                } else {
                    info!("    ID {}: {} -> {:?}", id, perms.len(), perms);
                }
            }
        }
        Err(e) => {
            error!("  ❌ Advanced validation process failed: {}", e);
            return Err(e);
        }
    }

    Ok(())
}

/// Example 5: Error handling scenarios
async fn example_error_scenarios() -> Result<()> {
    info!("⚠️  Example 5: Error handling scenarios");

    // Scenario 1: Handling duplicate permissions
    info!("  🔍 Scenario 1: Duplicate permissions");
    let duplicate_permissions = vec![
        "user:read".to_string(),
        "user:write".to_string(),
        "user:read".to_string(), // Intentional duplicate
        "admin:manage".to_string(),
    ];

    match handle_validation_with_recovery(duplicate_permissions).await {
        Ok(()) => info!("    ✅ Handled duplicates successfully"),
        Err(e) => info!("    ℹ️  Expected error handled: {}", e),
    }

    // Scenario 2: Handling validation in a service context
    info!("  🔍 Scenario 2: Service-level validation");
    let service_permissions = load_service_permissions().await?;

    match validate_service_permissions(service_permissions).await {
        Ok(valid_count) => info!(
            "    ✅ Service validation: {} permissions validated",
            valid_count
        ),
        Err(e) => warn!("    ⚠️  Service validation warning: {}", e),
    }

    // Scenario 3: Graceful degradation
    info!("  🔍 Scenario 3: Graceful degradation");
    match validate_with_fallback().await {
        Ok(()) => info!("    ✅ Graceful degradation successful"),
        Err(e) => error!("    ❌ Graceful degradation failed: {}", e),
    }

    Ok(())
}

/// Helper function to load application configuration
async fn load_app_config() -> Result<AppConfig> {
    // Simulate loading from a config file
    let config = AppConfig {
        roles: vec![
            RoleConfig {
                name: "admin".to_string(),
                permissions: vec![
                    "read:users".to_string(),
                    "write:users".to_string(),
                    "delete:users".to_string(),
                    "manage:system".to_string(),
                ],
            },
            RoleConfig {
                name: "user".to_string(),
                permissions: vec!["read:profile".to_string(), "write:profile".to_string()],
            },
            RoleConfig {
                name: "moderator".to_string(),
                permissions: vec![
                    "read:posts".to_string(),
                    "moderate:content".to_string(),
                    "ban:users".to_string(),
                ],
            },
        ],
        resources: vec![
            "users".to_string(),
            "posts".to_string(),
            "comments".to_string(),
            "system".to_string(),
        ],
        actions: vec![
            "read".to_string(),
            "write".to_string(),
            "delete".to_string(),
            "moderate".to_string(),
        ],
        custom_permissions: vec![
            "special:admin:override".to_string(),
            "api:rate_limit:exempt".to_string(),
        ],
    };

    Ok(config)
}

/// Generate permissions from configuration
fn generate_permissions_from_config(config: &AppConfig) -> Result<Vec<String>> {
    let mut permissions = Vec::new();

    // Add role-based permissions
    for role in &config.roles {
        for permission in &role.permissions {
            permissions.push(format!("{}:{}", role.name, permission));
        }
    }

    // Generate resource-action combinations
    for resource in &config.resources {
        for action in &config.actions {
            permissions.push(format!("{}:{}", action, resource));
        }
    }

    // Add custom permissions
    permissions.extend(config.custom_permissions.clone());

    Ok(permissions)
}

/// Generate a complex permission set for testing
fn generate_complex_permission_set() -> Vec<String> {
    let mut permissions = Vec::new();

    // Generate a large set of permissions with some patterns that might collide
    let prefixes = ["user", "admin", "moderator", "guest", "service"];
    let actions = ["read", "write", "delete", "create", "update"];
    let resources = ["profile", "posts", "comments", "settings", "data"];

    for prefix in &prefixes {
        for action in &actions {
            for resource in &resources {
                permissions.push(format!("{}:{}:{}", prefix, action, resource));
            }
        }
    }

    // Add some special permissions that might have interesting hash properties
    permissions.extend(vec![
        "special:permission:123".to_string(),
        "unique:access:456".to_string(),
        "custom:feature:789".to_string(),
    ]);

    permissions
}

/// Handle validation with recovery mechanisms
async fn handle_validation_with_recovery(permissions: Vec<String>) -> Result<()> {
    let validator = ApplicationValidator::new().add_permission_strings(permissions);

    match validator.validate() {
        Ok(report) => {
            if report.is_valid() {
                info!("    Validation passed on first attempt");
                return Ok(());
            }

            // Handle duplicates by deduplication
            let duplicates = report.duplicates();
            warn!(
                "    Found {} duplicates, attempting recovery",
                duplicates.len()
            );

            if !duplicates.is_empty() {
                info!("    Applying automatic deduplication...");
                // In a real application, you might implement deduplication logic here
                return Err(axum_gate::errors::Error::Authn(
                    axum_gate::errors::AuthnError::invalid_credentials(Some(
                        "Duplicates found but recovery not implemented in example".to_string(),
                    )),
                ));
            }

            if !report.collisions.is_empty() {
                error!("    Hash collisions detected - manual intervention required");
                return Err(axum_gate::errors::Error::Permissions(
                    axum_gate::errors::PermissionsError::collision(
                        99999,
                        vec!["collision_detected".to_string()],
                    ),
                ));
            }
        }
        Err(e) => {
            error!("Failed to generate validation report: {}", e);
            return Err(e);
        }
    }

    Ok(())
}

/// Simulate loading permissions for a service
async fn load_service_permissions() -> Result<Vec<String>> {
    // Simulate async loading from database or external service
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    Ok(vec![
        "service:database:read".to_string(),
        "service:database:write".to_string(),
        "service:cache:access".to_string(),
        "service:logging:write".to_string(),
    ])
}

/// Validate service permissions with proper error handling
async fn validate_service_permissions(permissions: Vec<String>) -> Result<usize> {
    let permission_count = permissions.len();

    let mut checker = PermissionCollisionChecker::new(permissions);

    // Use strict validation for service permissions
    checker.validate().map_err(|e| {
        error!("Service permission validation failed: {}", e);
        e
    })?;

    Ok(permission_count)
}

/// Demonstrate graceful degradation when validation fails
async fn validate_with_fallback() -> Result<()> {
    let risky_permissions = vec![
        "risky:permission:1".to_string(),
        "risky:permission:2".to_string(),
        // Simulate a problematic permission that might cause issues
        "potentially:problematic".to_string(),
    ];

    let mut checker = PermissionCollisionChecker::new(risky_permissions);

    match checker.validate() {
        Ok(report) => {
            if report.is_valid() {
                info!("    Primary validation succeeded");
                return Ok(());
            }

            warn!("    Primary validation found issues, applying fallback strategy");

            // Fallback: Use a minimal safe permission set
            let safe_permissions = vec![
                "fallback:read:basic".to_string(),
                "fallback:write:basic".to_string(),
            ];

            let mut fallback_checker = PermissionCollisionChecker::new(safe_permissions);
            fallback_checker.validate().map_err(|e| {
                error!("Even fallback permissions failed validation: {}", e);
                e
            })?;

            info!("    ✅ Fallback permission set validated successfully");
            Ok(())
        }
        Err(e) => {
            error!("    Validation process failed entirely: {}", e);
            Err(e)
        }
    }
}

/// Simulate permission cleanup during application lifecycle
async fn simulate_permission_cleanup(permissions: &mut Vec<String>) -> Result<()> {
    info!("  🧹 Simulating permission cleanup");

    let initial_count = permissions.len();

    // Remove permissions that match certain patterns (simulate cleanup)
    permissions.retain(|p| !p.contains("deprecated") && !p.contains("unused"));

    let final_count = permissions.len();

    if final_count < initial_count {
        info!(
            "    Cleaned up {} permissions ({} -> {})",
            initial_count - final_count,
            initial_count,
            final_count
        );

        // Re-validate after cleanup
        let mut checker = PermissionCollisionChecker::new(permissions.clone());
        match checker.validate() {
            Ok(_) => info!("    ✅ Post-cleanup validation passed"),
            Err(e) => {
                error!("    ❌ Post-cleanup validation failed: {}", e);
                return Err(e);
            }
        }
    } else {
        info!("    No permissions were cleaned up");
    }

    Ok(())
}
