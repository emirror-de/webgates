//! Permission Mapping Registry Example
//!
//! This example demonstrates the optional permission mapping registry pattern
//! that allows reverse lookup from permission IDs back to their original
//! string representations. This is useful for debugging, logging, administrative
//! interfaces, and audit trails.
//!
//! The registry pattern works alongside the existing bitmap-based permission
//! system without replacing it, providing human-readable permission names
//! when needed while maintaining the performance benefits of ID-based storage.

use axum_gate::permissions::{
    Permissions,
    mapping::{PermissionMapping, PermissionMappingRepository},
};
use axum_gate::prelude::{Account, Group, PermissionId, Role};
use axum_gate::repositories::memory::MemoryPermissionMappingRepository;
use std::sync::Arc;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("Starting Permission Mapping Registry Example");

    // Create the permission mapping repository
    let mapping_repo = Arc::new(MemoryPermissionMappingRepository::default());

    // Demonstrate basic registry operations
    demo_basic_registry_operations(&mapping_repo).await?;

    // Demonstrate integration with permissions
    demo_permissions_integration(&mapping_repo).await?;

    // Demonstrate account permissions with registry
    demo_account_with_registry(&mapping_repo).await?;

    info!("Permission Mapping Registry Example completed successfully!");
    Ok(())
}

/// Demonstrates basic permission mapping registry operations
async fn demo_basic_registry_operations(
    repo: &Arc<MemoryPermissionMappingRepository>,
) -> anyhow::Result<()> {
    info!("=== Basic Registry Operations ===");

    // Create some permission mappings
    let mappings = vec![
        PermissionMapping::from("read:api"),
        PermissionMapping::from("write:api"),
        PermissionMapping::from("admin:users"),
        PermissionMapping::from("  DELETE:Files  "), // Test normalization
    ];

    // Store the mappings
    for mapping in &mappings {
        match repo.store_mapping(mapping.clone()).await? {
            Some(stored) => info!(
                "Stored mapping: '{}' -> ID {}",
                stored.normalized_string(),
                stored.id_as_u64()
            ),
            None => warn!("Mapping already exists: '{}'", mapping.normalized_string()),
        }
    }

    // Query by ID
    info!("\n--- Reverse Lookup (ID -> String) ---");
    for mapping in &mappings {
        let id = mapping.permission_id();
        if let Some(found) = repo.query_mapping_by_id(id).await? {
            info!(
                "ID {} -> Normalized: '{}'",
                id.as_u64(),
                found.normalized_string()
            );
        }
    }

    // Query by string (demonstrates normalization)
    info!("\n--- Forward Lookup (String -> Mapping) ---");
    let test_strings = vec![
        "read:api",
        "READ:API",     // Different case
        "  read:api  ", // Extra whitespace
        "delete:files", // Should match "  DELETE:Files  "
        "nonexistent",  // Should not be found
    ];

    for test_string in test_strings {
        match repo.query_mapping_by_string(test_string).await? {
            Some(found) => info!(
                "Query '{}' -> Found: '{}' (ID: {})",
                test_string,
                found.normalized_string(),
                found.id_as_u64()
            ),
            None => info!("Query '{}' -> Not found", test_string),
        }
    }

    // List all mappings
    info!("\n--- All Stored Mappings ---");
    let all_mappings = repo.list_all_mappings().await?;
    info!("Total mappings: {}", all_mappings.len());
    for mapping in all_mappings {
        info!("  {}", mapping);
    }

    Ok(())
}

/// Demonstrates integration with the Permissions struct
async fn demo_permissions_integration(
    repo: &Arc<MemoryPermissionMappingRepository>,
) -> anyhow::Result<()> {
    info!("\n=== Permissions Integration ===");

    // Create a permissions set
    let mut permissions = Permissions::new();

    // Grant permissions and store mappings
    let permission_strings = vec![
        "repository:read",
        "repository:write",
        "api:admin",
        "system:maintenance",
    ];

    info!("Granting permissions and storing mappings:");
    for perm_str in &permission_strings {
        // Create mapping
        let mapping = PermissionMapping::from(*perm_str);

        // Grant the permission (this uses the normalized string)
        permissions.grant(mapping.normalized_string());

        // Store the mapping for reverse lookup
        repo.store_mapping(mapping.clone()).await?;

        info!(
            "  Granted '{}' (ID: {})",
            mapping.normalized_string(),
            mapping.id_as_u64()
        );
    }

    info!("Permissions granted: {}", permissions.len());

    // Demonstrate reverse lookup of granted permissions
    info!("\n--- Reverse Lookup of Granted Permissions ---");
    for permission_id in permissions.iter() {
        if let Some(mapping) = repo
            .query_mapping_by_id(PermissionId::from_u64(permission_id))
            .await?
        {
            info!(
                "Permission ID {} = '{}'",
                permission_id,
                mapping.normalized_string()
            );
        } else {
            warn!("No mapping found for permission ID {}", permission_id);
        }
    }

    Ok(())
}

/// Demonstrates using the registry with Account permissions
async fn demo_account_with_registry(
    repo: &Arc<MemoryPermissionMappingRepository>,
) -> anyhow::Result<()> {
    info!("\n=== Account with Registry ===");

    // Create an account
    let mut account = Account::new(
        "admin@example.com",
        &[Role::Admin],
        &[Group::new("administrators")],
    );

    // Grant some permissions with descriptive names
    let admin_permissions = vec![
        ("user:create", "Create new user accounts"),
        ("user:delete", "Delete user accounts"),
        ("user:modify", "Modify existing user accounts"),
        ("system:backup", "Perform system backups"),
        ("system:restore", "Restore from backups"),
        ("audit:view", "View audit logs"),
        ("audit:export", "Export audit data"),
    ];

    info!("Granting admin permissions:");
    for (perm_name, description) in admin_permissions {
        let mapping = PermissionMapping::from(perm_name);

        // Grant to account
        account.grant_permission(mapping.normalized_string());

        // Store the main mapping first
        repo.store_mapping(mapping).await?;

        // Store mapping with description in a comment-like format for documentation
        let documented_mapping =
            PermissionMapping::from(format!("{} // {}", perm_name, description));
        repo.store_mapping(documented_mapping).await?;

        info!("  {} - {}", perm_name, description);
    }

    // Display account permissions with human-readable names
    info!("\n--- Account Permission Summary ---");
    info!("User: {}", account.user_id);
    info!("Roles: {:?}", account.roles);
    info!("Groups: {:?}", account.groups);
    info!("Direct Permissions:");

    for permission_id in account.permissions.iter() {
        let id = PermissionId::from_u64(permission_id);
        match repo.query_mapping_by_id(id).await? {
            Some(mapping) => {
                let original = mapping.normalized_string();
                if original.contains("//") {
                    let parts: Vec<&str> = original.split("//").collect();
                    info!("  {} - {}", parts[0].trim(), parts[1].trim());
                } else {
                    info!("  {} (ID: {})", original, permission_id);
                }
            }
            None => info!("  Unknown permission (ID: {})", permission_id),
        }
    }

    Ok(())
}

/// Helper function to demonstrate error handling
async fn _demo_error_handling(repo: &Arc<MemoryPermissionMappingRepository>) -> anyhow::Result<()> {
    info!("\n=== Error Handling ===");

    // Try to create an invalid mapping (this would be caught at compile time
    // with the current API, but demonstrates validation)
    let mapping = PermissionMapping::from("test:permission");

    // This should succeed
    match repo.store_mapping(mapping.clone()).await? {
        Some(_) => info!("Mapping stored successfully"),
        None => info!("Mapping already exists"),
    }

    // Try to store the same mapping again
    match repo.store_mapping(mapping).await? {
        Some(_) => info!("Unexpected: mapping was stored again"),
        None => info!("Expected: mapping already exists (no duplicate stored)"),
    }

    Ok(())
}
