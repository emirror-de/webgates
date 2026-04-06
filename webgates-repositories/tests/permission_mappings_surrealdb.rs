#![cfg(feature = "surrealdb")]

use webgates_core::permissions::{PermissionId, PermissionMapping};
use webgates_repositories::{
    permission_mapping_repository::PermissionMappingRepository,
    surrealdb::{DatabaseScope, SurrealDbRepository},
};

use surrealdb::Surreal;
use surrealdb::engine::local::Mem;

#[tokio::test]
async fn surrealdb_permission_mapping_crud_and_queries() {
    // Prepare SurrealDB in-memory instance and repository
    let db = match Surreal::new::<Mem>(()).await {
        Ok(db) => db,
        Err(e) => panic!("Failed to create SurrealDB Mem engine: {:?}", e),
    };

    let scope = DatabaseScope::default();
    let repo = match SurrealDbRepository::new(db, scope.clone()) {
        Ok(r) => r,
        Err(e) => panic!("Failed to create SurrealDbRepository: {:?}", e),
    };

    // 1) Store a mapping
    let mapping = PermissionMapping::from("Read:API");
    let id = mapping.permission_id();

    let stored: Option<PermissionMapping> = match repo
        .store_mapping(mapping.clone())
        .await
    {
        Ok(s) => s,
        Err(e) => panic!("store_mapping failed: {:?}", e),
    };
    assert!(
        matches!(stored, Some(m) if m.permission_id() == id && m.normalized_string() == "read:api"),
        "Expected stored mapping to match input"
    );

    // 2) Query by ID
    let fetched_by_id: Option<PermissionMapping> = match repo
        .query_mapping_by_id(id)
        .await
    {
        Ok(s) => s,
        Err(e) => panic!("query_mapping_by_id failed: {:?}", e),
    };
    assert!(
        matches!(fetched_by_id, Some(m) if m.permission_id() == id && m.normalized_string() == "read:api"),
        "Query by id should return the mapping"
    );

    // 3) Query by string (with different case/whitespace)
    let fetched_by_str: Option<PermissionMapping> = match repo
        .query_mapping_by_string("  READ:api ")
        .await
    {
        Ok(s) => s,
        Err(e) => panic!("query_mapping_by_string failed: {:?}", e),
    };
    assert!(
        matches!(fetched_by_str, Some(m) if m.permission_id() == id && m.normalized_string() == "read:api"),
        "Query by string should normalize and return the mapping"
    );

    // 4) List all mappings (expect one)
    let all: Vec<PermissionMapping> = match repo
        .list_all_mappings()
        .await
    {
        Ok(s) => s,
        Err(e) => panic!("list_all_mappings failed: {:?}", e),
    };
    assert_eq!(all.len(), 1, "Expected exactly one mapping");
    assert_eq!(all[0].permission_id(), id);
    assert_eq!(all[0].normalized_string(), "read:api");

    // 5) Remove by string (with different case) and verify removal
    let removed_by_str: Option<PermissionMapping> = match repo
        .remove_mapping_by_string("READ:API")
        .await
    {
        Ok(s) => s,
        Err(e) => panic!("remove_mapping_by_string failed: {:?}", e),
    };
    assert!(
        matches!(removed_by_str, Some(m) if m.permission_id() == id),
        "Expected remove by string to return the mapping"
    );

    // Further removal should be a no-op
    let removed_again: Option<PermissionMapping> = match repo
        .remove_mapping_by_string("read:api")
        .await
    {
        Ok(s) => s,
        Err(e) => panic!("remove_mapping_by_string second call failed: {:?}", e),
    };
    assert!(removed_again.is_none(), "Second remove should return None");

    // After removal, queries should return None
    assert!(
        match repo.query_mapping_by_id(id).await {
            Ok(opt) => opt.is_none(),
            Err(e) => panic!("query by id after removal failed: {:?}", e),
        },
        "Query by id should return None after removal"
    );
    assert!(
        match repo.query_mapping_by_string("read:api").await {
            Ok(opt) => opt.is_none(),
            Err(e) => panic!("query by string after removal failed: {:?}", e),
        },
        "Query by string should return None after removal"
    );

    // 6) Store another mapping and remove by id
    let mapping2 = PermissionMapping::from("write:file");
    let id2 = mapping2.permission_id();

    let stored2: Option<PermissionMapping> = match repo
        .store_mapping(mapping2.clone())
        .await
    {
        Ok(s) => s,
        Err(e) => panic!("store_mapping mapping2 failed: {:?}", e),
    };
    assert!(stored2.is_some(), "Expected second mapping to be stored");

    // remove by id
    let removed_by_id: Option<PermissionMapping> = match repo
        .remove_mapping_by_id(id2)
        .await
    {
        Ok(s) => s,
        Err(e) => panic!("remove_mapping_by_id failed: {:?}", e),
    };
    assert!(
        matches!(removed_by_id, Some(m) if m.permission_id() == id2),
        "Expected remove by id to return the mapping"
    );

    // Nothing should remain
    let all_after: Vec<PermissionMapping> = match repo
        .list_all_mappings()
        .await
    {
        Ok(s) => s,
        Err(e) => panic!("list_all_mappings after removals failed: {:?}", e),
    };
    assert!(all_after.is_empty(), "Expected no mappings after removals");
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn surrealdb_permission_mapping_uniqueness() {
    // Prepare SurrealDB in-memory instance and repository
    let db = match Surreal::new::<Mem>(()).await {
        Ok(db) => db,
        Err(e) => panic!("Failed to create SurrealDB Mem engine: {:?}", e),
    };
    let scope = DatabaseScope::default();
    let repo = match SurrealDbRepository::new(db, scope) {
        Ok(r) => r,
        Err(e) => panic!("Failed to create SurrealDbRepository: {:?}", e),
    };

    // Store a mapping
    let m1 = PermissionMapping::from("Read:Api");
    let id1 = m1.permission_id();
    assert_eq!(m1.normalized_string(), "read:api");

    let stored1: Option<PermissionMapping> = match repo
        .store_mapping(m1.clone())
        .await
    {
        Ok(s) => s,
        Err(e) => panic!("store m1 failed: {:?}", e),
    };
    assert!(stored1.is_some(), "First store should succeed");

    // Ensure only one mapping exists
    let all: Vec<PermissionMapping> = match repo
        .list_all_mappings()
        .await
    {
        Ok(s) => s,
        Err(e) => panic!("list_all_mappings failed: {:?}", e),
    };
    assert_eq!(
        all.len(),
        1,
        "Expected exactly one mapping after uniqueness checks"
    );
    assert_eq!(all[0].permission_id(), id1);
    assert_eq!(all[0].normalized_string(), "read:api");

    let fetched_by_id = match repo
        .query_mapping_by_id(id1)
        .await
    {
        Ok(s) => s,
        Err(e) => panic!("query after duplicate store failed: {:?}", e),
    };
    assert!(
        matches!(fetched_by_id, Some(m) if m.permission_id() == id1 && m.normalized_string() == "read:api"),
        "Duplicate store must not overwrite or corrupt the stored mapping"
    );

    // Removing a non-existent mapping by id should return None
    let nonexistent_id = PermissionId::from("does:not:exist");
    assert!(
        match repo.remove_mapping_by_id(nonexistent_id).await {
            Ok(opt) => opt.is_none(),
            Err(e) => panic!("remove non-existent by id failed: {:?}", e),
        },
        "Removing non-existent id should return None"
    );

    // Removing a non-existent mapping by string should return None
    assert!(
        match repo.remove_mapping_by_string("does:not:exist").await {
            Ok(opt) => opt.is_none(),
            Err(e) => panic!("remove non-existent by string failed: {:?}", e),
        },
        "Removing non-existent string should return None"
    );
}
