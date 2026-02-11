//! Distributed system example demonstrating zero-synchronization permissions.
//!
//! This example shows how the new permission system works seamlessly across
//! distributed nodes without any coordination or synchronization.

use axum_gate::permissions::AsPermissionName;
use axum_gate::permissions::{PermissionId, Permissions};
use axum_gate::validate_permissions;
use roaring::RoaringTreemap;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter, EnumString, IntoEnumIterator};

/// Application permissions using nested enums for better organization.
///
/// These permissions work identically across all nodes without any coordination.
/// Each permission name deterministically maps to the same ID on every node.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumString, EnumIter,
)]
#[strum(serialize_all = "snake_case")]
pub enum AppPermissions {
    Repository(RepositoryPermission),
    Api(ApiPermission),
    System(SystemPermission),
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Display,
    EnumString,
    EnumIter,
    Default,
)]
#[strum(serialize_all = "snake_case")]
pub enum RepositoryPermission {
    #[default]
    Read,
    Write,
    Delete,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Display,
    EnumString,
    EnumIter,
    Default,
)]
#[strum(serialize_all = "snake_case")]
pub enum ApiPermission {
    #[default]
    Read,
    Write,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Display,
    EnumString,
    EnumIter,
    Default,
)]
#[strum(serialize_all = "snake_case")]
pub enum SystemPermission {
    #[default]
    Admin,
}

impl AppPermissions {
    /// Convert to string representation for permission checking
    pub fn as_str(&self) -> String {
        match self {
            AppPermissions::Repository(perm) => format!("repository:{}", perm),
            AppPermissions::Api(perm) => format!("api:{}", perm),
            AppPermissions::System(perm) => format!("system:{}", perm),
        }
    }

    /// Get all repository permissions
    pub fn all_repository() -> Vec<AppPermissions> {
        RepositoryPermission::iter()
            .map(AppPermissions::Repository)
            .collect()
    }

    /// Get all API permissions
    pub fn all_api() -> Vec<AppPermissions> {
        ApiPermission::iter().map(AppPermissions::Api).collect()
    }

    /// Get all system permissions
    pub fn all_system() -> Vec<AppPermissions> {
        SystemPermission::iter()
            .map(AppPermissions::System)
            .collect()
    }

    /// Get all permissions
    pub fn all() -> Vec<AppPermissions> {
        let mut permissions = Vec::new();
        permissions.extend(Self::all_repository());
        permissions.extend(Self::all_api());
        permissions.extend(Self::all_system());
        permissions
    }
}

impl AsPermissionName for AppPermissions {
    fn as_permission_name(&self) -> String {
        self.as_str()
    }
}

// Validate permissions at compile time to ensure no hash collisions
validate_permissions![
    "repository:read",
    "repository:write",
    "repository:delete",
    "api:read",
    "api:write",
    "system:admin"
];

/// Helper functions for common permission operations.
pub struct PermissionHelper;

impl PermissionHelper {
    /// Grant repository access (read + write).
    pub fn grant_repository_access(user_permissions: &mut RoaringTreemap) {
        let mut perms = Permissions::from(user_permissions.clone());
        perms.grant(AppPermissions::Repository(RepositoryPermission::Read).as_str());
        perms.grant(AppPermissions::Repository(RepositoryPermission::Write).as_str());
        *user_permissions = perms.into();
    }

    /// Grant full repository access (read + write + delete).
    pub fn grant_full_repository_access(user_permissions: &mut RoaringTreemap) {
        let mut perms = Permissions::from(user_permissions.clone());
        for permission in AppPermissions::all_repository() {
            perms.grant(permission.as_str());
        }
        *user_permissions = perms.into();
    }

    /// Grant API access (read + write).
    pub fn grant_api_access(user_permissions: &mut RoaringTreemap) {
        let mut perms = Permissions::from(user_permissions.clone());
        for permission in AppPermissions::all_api() {
            perms.grant(permission.as_str());
        }
        *user_permissions = perms.into();
    }

    /// Grant admin access (all permissions).
    pub fn grant_admin_access(user_permissions: &mut RoaringTreemap) {
        let mut perms = Permissions::from(user_permissions.clone());
        for permission in AppPermissions::all() {
            perms.grant(permission.as_str());
        }
        *user_permissions = perms.into();
    }

    /// Grant specific permission using the new AsPermissionName trait.
    pub fn grant_permission(user_permissions: &mut RoaringTreemap, permission: &AppPermissions) {
        let mut perms = Permissions::from(user_permissions.clone());
        // Use the consistent From trait approach
        perms.grant(PermissionId::from(permission));
        *user_permissions = perms.into();
    }

    /// Check if user has specific permission using the new AsPermissionName trait.
    pub fn has_permission(user_permissions: &RoaringTreemap, permission: &AppPermissions) -> bool {
        let perms = Permissions::from(user_permissions.clone());
        // Use the consistent From trait approach
        perms.has(PermissionId::from(permission))
    }

    /// Check if user can access repository data.
    pub fn can_access_repository(user_permissions: &RoaringTreemap) -> bool {
        let perms = Permissions::from(user_permissions.clone());
        perms.has(AppPermissions::Repository(RepositoryPermission::Read).as_str())
    }

    /// Check if user can modify repository data.
    pub fn can_modify_repository(user_permissions: &RoaringTreemap) -> bool {
        let perms = Permissions::from(user_permissions.clone());
        perms.has(AppPermissions::Repository(RepositoryPermission::Write).as_str())
    }

    /// Check if user can delete repository data.
    pub fn can_delete_repository(user_permissions: &RoaringTreemap) -> bool {
        let perms = Permissions::from(user_permissions.clone());
        perms.has(AppPermissions::Repository(RepositoryPermission::Delete).as_str())
    }

    /// Check if user can access API.
    pub fn can_access_api(user_permissions: &RoaringTreemap) -> bool {
        Self::has_permission(user_permissions, &AppPermissions::Api(ApiPermission::Read))
    }

    /// Check if user can write to API.
    pub fn can_write_api(user_permissions: &RoaringTreemap) -> bool {
        Self::has_permission(user_permissions, &AppPermissions::Api(ApiPermission::Write))
    }

    /// Check if user is admin.
    pub fn is_admin(user_permissions: &RoaringTreemap) -> bool {
        let perms = Permissions::from(user_permissions.clone());
        perms.has(AppPermissions::System(SystemPermission::Admin).as_str())
    }

    /// Check if user has all permissions in a category.
    pub fn has_all_repository_permissions(user_permissions: &RoaringTreemap) -> bool {
        AppPermissions::all_repository()
            .iter()
            .all(|perm| Self::has_permission(user_permissions, perm))
    }

    /// Check if user has all API permissions.
    pub fn has_all_api_permissions(user_permissions: &RoaringTreemap) -> bool {
        let perms = Permissions::from(user_permissions.clone());
        AppPermissions::all_api()
            .iter()
            .all(|perm| perms.has(perm.as_str()))
    }
}

/// Demonstrates zero-sync permission operations.
pub fn demonstrate_zero_sync() {
    println!("=== Zero-Sync Permission System Demo with Nested Enums ===\n");

    // Show enum serialization
    println!("1. Nested Enum Structure:");
    for permission in AppPermissions::all() {
        println!("  {:?} -> '{}'", permission, permission.as_str());
    }
    println!();

    // Show deterministic permission ID generation
    println!("2. Deterministic Permission IDs:");
    let read_repo_perm = AppPermissions::Repository(RepositoryPermission::Read);
    let write_repo_perm = AppPermissions::Repository(RepositoryPermission::Write);
    let read_repo_id = PermissionId::from(read_repo_perm.as_str());
    let write_repo_id = PermissionId::from(write_repo_perm.as_str());

    println!("  '{}' -> ID: {}", read_repo_perm.as_str(), read_repo_id);
    println!("  '{}' -> ID: {}", write_repo_perm.as_str(), write_repo_id);

    // Check determinism
    let same_read_id = PermissionId::from(read_repo_perm.as_str());
    println!(
        "  Same permission generates same ID: {} == {} = {}",
        read_repo_id,
        same_read_id,
        read_repo_id == same_read_id
    );
    println!();

    // Create user permissions
    println!("3. User Permission Management with Nested Enums:");
    let mut user_permissions = RoaringTreemap::new();

    // Grant some permissions
    PermissionHelper::grant_repository_access(&mut user_permissions);
    PermissionHelper::grant_permission(
        &mut user_permissions,
        &AppPermissions::Api(ApiPermission::Read),
    );

    println!("  Granted: repository access + read API");
    println!(
        "  Can access repository: {}",
        PermissionHelper::can_access_repository(&user_permissions)
    );
    println!(
        "  Can modify repository: {}",
        PermissionHelper::can_modify_repository(&user_permissions)
    );
    println!(
        "  Can delete repository: {}",
        PermissionHelper::can_delete_repository(&user_permissions)
    );
    println!(
        "  Can access API: {}",
        PermissionHelper::can_access_api(&user_permissions)
    );
    println!(
        "  Can write API: {}",
        PermissionHelper::can_write_api(&user_permissions)
    );
    println!(
        "  Is admin: {}",
        PermissionHelper::is_admin(&user_permissions)
    );
    println!(
        "  Has all repository permissions: {}",
        PermissionHelper::has_all_repository_permissions(&user_permissions)
    );
    println!();

    // Show distributed scenario
    println!("4. Distributed System Scenario:");
    println!("  Auth Node: Issues JWT with permission bitmap");
    println!("  Data Node: Validates permissions without any communication");
    println!();

    // Simulate auth node creating JWT payload
    let jwt_permission_bitmap = user_permissions.clone();
    println!(
        "  Auth Node: User has permissions bitmap: {:?}",
        jwt_permission_bitmap.iter().collect::<Vec<_>>()
    );

    // Simulate data node checking permissions
    let required_permission = AppPermissions::Repository(RepositoryPermission::Read);
    let has_access = PermissionHelper::has_permission(&jwt_permission_bitmap, &required_permission);
    println!(
        "  Data Node: Checking '{}' -> Access: {}",
        required_permission.as_str(),
        has_access
    );

    let admin_permission = AppPermissions::System(SystemPermission::Admin);
    let is_admin = PermissionHelper::has_permission(&jwt_permission_bitmap, &admin_permission);
    println!(
        "  Data Node: Checking '{}' -> Access: {}",
        admin_permission.as_str(),
        is_admin
    );
    println!();

    // Show enum iteration capabilities
    println!("5. Enum Iteration Capabilities:");
    println!("  Repository permissions:");
    for perm in RepositoryPermission::iter() {
        println!("    - {}", perm);
    }
    println!("  API permissions:");
    for perm in ApiPermission::iter() {
        println!("    - {}", perm);
    }
    println!("  System permissions:");
    for perm in SystemPermission::iter() {
        println!("    - {}", perm);
    }
    println!();

    println!("6. Key Benefits:");
    println!("  ✓ Zero coordination between nodes");
    println!("  ✓ Deterministic permission IDs");
    println!("  ✓ No synchronization required");
    println!("  ✓ Works instantly across all nodes");
    println!("  ✓ Collision-resistant (SHA-256 based)");
    println!("  ✓ Type-safe nested enum structure");
    println!("  ✓ Serialization/deserialization with strum");
    println!("  ✓ Easy permission categorization");
}

/// Main function to run the demonstration.
///
/// Run with: `cargo run --bin demo` from the distributed example directory.
pub fn main() {
    println!("🆕 NEW: AsPermissionName Trait Demonstration");
    println!("============================================");

    // Demonstrate the new AsPermissionName trait
    let repo_read = AppPermissions::Repository(RepositoryPermission::Read);
    let api_write = AppPermissions::Api(ApiPermission::Write);

    // Old way: manual string conversion
    let old_id1 = PermissionId::from(repo_read.as_str());
    let old_id2 = PermissionId::from(api_write.as_str());

    // New way: direct trait-based conversion (same as old way now!)
    let new_id1 = PermissionId::from(&repo_read);
    let new_id2 = PermissionId::from(&api_write);

    // All use the same consistent From trait approach
    let consistent_id1 = PermissionId::from(&repo_read);
    let consistent_id2 = PermissionId::from(&api_write);

    println!("Repository Read Permission:");
    println!("  String:     {} ({})", old_id1, old_id1.as_u64());
    println!("  Enum:       {} ({})", new_id1, new_id1.as_u64());
    println!(
        "  Consistent: {} ({})",
        consistent_id1,
        consistent_id1.as_u64()
    );
    println!(
        "  All equal: {}",
        old_id1 == new_id1 && new_id1 == consistent_id1
    );

    println!("\nAPI Write Permission:");
    println!("  String:     {} ({})", old_id2, old_id2.as_u64());
    println!("  Enum:       {} ({})", new_id2, new_id2.as_u64());
    println!(
        "  Consistent: {} ({})",
        consistent_id2,
        consistent_id2.as_u64()
    );
    println!(
        "  All equal: {}",
        old_id2 == new_id2 && new_id2 == consistent_id2
    );

    println!("\n{}", "=".repeat(50));
    println!("Original Zero-Sync Permission System Demo");
    println!("{}", "=".repeat(50));
    demonstrate_zero_sync();

    println!("\n=== Performance Comparison ===");

    // Show the performance advantage
    let start = std::time::Instant::now();
    for _ in 0..100_000 {
        let perm = AppPermissions::Repository(RepositoryPermission::Read);
        let _id = PermissionId::from(perm.as_str().as_str());
    }
    let duration = start.elapsed();
    println!(
        "Generated 100,000 permission IDs in: {:?} ({:.2} ns per ID)",
        duration,
        duration.as_nanos() as f64 / 100_000.0
    );

    // Show bitmap operations
    let mut permissions = RoaringTreemap::new();
    let start = std::time::Instant::now();
    for i in 0..100_000 {
        let perm_name = format!("permission:{}", i);
        let mut perms = Permissions::from(permissions.clone());
        perms.grant(perm_name);
        permissions = perms.into();
    }
    let grant_duration = start.elapsed();

    let start = std::time::Instant::now();
    for i in 0..100_000 {
        let perm_name = format!("permission:{}", i);
        let perms = Permissions::from(permissions.clone());
        let _has = perms.has(perm_name);
    }
    let check_duration = start.elapsed();

    println!(
        "Granted 100,000 permissions in: {:?} ({:.2} ns per grant)",
        grant_duration,
        grant_duration.as_nanos() as f64 / 100_000.0
    );
    println!(
        "Checked 100,000 permissions in: {:?} ({:.2} ns per check)",
        check_duration,
        check_duration.as_nanos() as f64 / 100_000.0
    );

    println!("\n=== Zero-Sync vs Traditional Sync ===");
    println!("Traditional (old) approach:");
    println!("  - Requires permission set synchronization");
    println!("  - Network calls to coordinate changes");
    println!("  - Complex deployment coordination");
    println!("  - Risk of permission corruption");
    println!();
    println!("Zero-Sync (new) approach with Nested Enums:");
    println!("  ✓ No synchronization required");
    println!("  ✓ Zero network overhead");
    println!("  ✓ Instant deployment");
    println!("  ✓ Collision-resistant");
    println!("  ✓ High performance");
    println!("  ✓ Type-safe permission management");
    println!("  ✓ Easy serialization/deserialization");
    println!("  ✓ Organized permission categories");
    println!("  ✓ Iterator support for bulk operations");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn permission_ids_are_deterministic() {
        let id1 = PermissionId::from("test:permission");
        let id2 = PermissionId::from("test:permission");
        assert_eq!(id1, id2);
    }

    #[test]
    fn different_permissions_have_different_ids() {
        let perm1 = AppPermissions::Repository(RepositoryPermission::Read);
        let perm2 = AppPermissions::Repository(RepositoryPermission::Write);
        let id1 = PermissionId::from(perm1.as_str());
        let id2 = PermissionId::from(perm2.as_str());
        assert_ne!(id1, id2);
    }

    #[test]
    fn permission_validation_works() {
        // This would panic at compile time if there were collisions
        validate_permissions![
            "test:permission:1",
            "test:permission:2",
            "test:permission:3"
        ];
    }

    #[test]
    fn helper_functions_work() {
        let mut permissions = RoaringTreemap::new();

        assert!(!PermissionHelper::can_access_repository(&permissions));

        PermissionHelper::grant_repository_access(&mut permissions);
        assert!(PermissionHelper::can_access_repository(&permissions));
        assert!(PermissionHelper::can_modify_repository(&permissions));
        assert!(!PermissionHelper::can_delete_repository(&permissions));

        assert!(!PermissionHelper::is_admin(&permissions));
        PermissionHelper::grant_admin_access(&mut permissions);
        assert!(PermissionHelper::is_admin(&permissions));
    }

    #[test]
    fn enum_serialization_works() {
        let perm = AppPermissions::Repository(RepositoryPermission::Read);
        let serialized = serde_json::to_string(&perm).unwrap();
        let deserialized: AppPermissions = serde_json::from_str(&serialized).unwrap();
        assert_eq!(perm, deserialized);
    }

    #[test]
    fn enum_string_conversion_works() {
        let perm = AppPermissions::Repository(RepositoryPermission::Read);
        let as_string = perm.to_string();
        let from_string = AppPermissions::from_str(&as_string).unwrap();
        assert_eq!(perm, from_string);
    }

    #[test]
    fn permission_categories_work() {
        assert_eq!(AppPermissions::all_repository().len(), 3);
        assert_eq!(AppPermissions::all_api().len(), 2);
        assert_eq!(AppPermissions::all_system().len(), 1);
        assert_eq!(AppPermissions::all().len(), 6);
    }

    #[test]
    fn nested_permission_checking_works() {
        let mut permissions = RoaringTreemap::new();

        // Grant only read repository permission
        PermissionHelper::grant_permission(
            &mut permissions,
            &AppPermissions::Repository(RepositoryPermission::Read),
        );

        assert!(PermissionHelper::can_access_repository(&permissions));
        assert!(!PermissionHelper::can_modify_repository(&permissions));
        assert!(!PermissionHelper::has_all_repository_permissions(
            &permissions
        ));

        // Grant full repository access
        PermissionHelper::grant_full_repository_access(&mut permissions);
        assert!(PermissionHelper::has_all_repository_permissions(
            &permissions
        ));
    }
}
