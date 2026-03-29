use crate::errors::{
    Error as RepoError, RepositoriesError, RepositoryOperation, RepositoryType, Result,
};
use crate::permission_mapping_repository::{
    PermissionMappingRepository, PermissionMappingRepositoryBulk,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use webgates_core::permissions::{PermissionId, PermissionMapping};

/// In-memory implementation of [`PermissionMappingRepository`] for development and testing.
///
/// This repository stores permission mappings in memory using thread-safe data structures.
/// It's ideal for development, testing, and small applications that don't require
/// persistent storage of permission mappings.
///
/// # Thread Safety
///
/// This implementation uses `Arc<RwLock<HashMap>>` for thread-safe access to the
/// stored mappings. Multiple readers can access the data concurrently, while
/// writers have exclusive access.
///
/// # Storage Strategy
///
/// Mappings are stored in a hash map keyed by `PermissionId` for efficient lookup.
///
/// This avoids scanning a collection for common operations and makes lookups O(1)
/// on average for id-based access.
#[derive(Debug)]
pub struct MemoryPermissionMappingRepository {
    /// Primary store keyed by `PermissionId`.
    mappings_by_id: Arc<RwLock<HashMap<PermissionId, PermissionMapping>>>,
}

impl Default for MemoryPermissionMappingRepository {
    fn default() -> Self {
        Self {
            mappings_by_id: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl From<Vec<PermissionMapping>> for MemoryPermissionMappingRepository {
    fn from(mappings: Vec<PermissionMapping>) -> Self {
        let mut mappings_by_id: HashMap<PermissionId, PermissionMapping> = HashMap::new();

        for mapping in mappings {
            if let Err(error) = mapping.validate() {
                tracing::warn!("Skipping invalid permission mapping: {error}");
                continue;
            }

            let permission_id = mapping.permission_id();
            let normalized = mapping.normalized_string().to_string();

            if mappings_by_id.contains_key(&permission_id)
                || mappings_by_id
                    .values()
                    .any(|stored| stored.normalized_string() == normalized)
            {
                continue;
            }

            mappings_by_id.insert(permission_id, mapping);
        }

        Self {
            mappings_by_id: Arc::new(RwLock::new(mappings_by_id)),
        }
    }
}

impl PermissionMappingRepository for MemoryPermissionMappingRepository {
    type Error = RepoError;

    async fn bootstrap(&self) -> Result<()> {
        Ok(())
    }

    async fn store_mapping(&self, mapping: PermissionMapping) -> Result<Option<PermissionMapping>> {
        if let Err(error) = mapping.validate() {
            return Err(RepoError::Repositories(
                RepositoriesError::operation_failed(
                    RepositoryType::PermissionMapping,
                    RepositoryOperation::Insert,
                    format!("Invalid permission mapping: {error}"),
                    None,
                    Some("store".to_string()),
                ),
            ));
        }

        let permission_id = mapping.permission_id();
        let normalized = mapping.normalized_string().to_string();
        let mut mappings_by_id = self.mappings_by_id.write().await;

        if mappings_by_id.contains_key(&permission_id)
            || mappings_by_id
                .values()
                .any(|stored| stored.normalized_string() == normalized)
        {
            return Ok(None);
        }

        mappings_by_id.insert(permission_id, mapping.clone());
        Ok(Some(mapping))
    }

    async fn remove_mapping_by_id(&self, id: PermissionId) -> Result<Option<PermissionMapping>> {
        let mut mappings_by_id = self.mappings_by_id.write().await;
        Ok(mappings_by_id.remove(&id))
    }

    async fn remove_mapping_by_string(
        &self,
        permission: &str,
    ) -> Result<Option<PermissionMapping>> {
        let normalized = normalize_permission(permission);
        let mut mappings_by_id = self.mappings_by_id.write().await;

        let found_id = mappings_by_id.iter().find_map(|(id, mapping)| {
            (mapping.normalized_string() == normalized.as_str()).then_some(*id)
        });

        match found_id {
            Some(id) => Ok(mappings_by_id.remove(&id)),
            None => Ok(None),
        }
    }

    async fn query_mapping_by_id(&self, id: PermissionId) -> Result<Option<PermissionMapping>> {
        let mappings_by_id = self.mappings_by_id.read().await;
        Ok(mappings_by_id.get(&id).cloned())
    }

    async fn query_mapping_by_string(&self, permission: &str) -> Result<Option<PermissionMapping>> {
        let normalized = normalize_permission(permission);
        let mappings_by_id = self.mappings_by_id.read().await;

        Ok(mappings_by_id
            .values()
            .find(|mapping| mapping.normalized_string() == normalized.as_str())
            .cloned())
    }

    async fn list_all_mappings(&self) -> Result<Vec<PermissionMapping>> {
        let mappings_by_id = self.mappings_by_id.read().await;
        Ok(mappings_by_id.values().cloned().collect())
    }
}

/// Normalize a permission name using the repository's lookup semantics.
fn normalize_permission(input: &str) -> String {
    input.trim().to_lowercase()
}

impl PermissionMappingRepositoryBulk for MemoryPermissionMappingRepository {
    async fn store_mappings(
        &self,
        mappings: Vec<PermissionMapping>,
    ) -> Result<Vec<PermissionMapping>> {
        for mapping in &mappings {
            if let Err(error) = mapping.validate() {
                return Err(RepoError::Repositories(
                    RepositoriesError::operation_failed(
                        RepositoryType::PermissionMapping,
                        RepositoryOperation::Insert,
                        format!("Invalid permission mapping in bulk store: {error}"),
                        None,
                        Some("store_mappings".to_string()),
                    ),
                ));
            }
        }

        let mut stored: Vec<PermissionMapping> = Vec::new();
        let mut mappings_by_id = self.mappings_by_id.write().await;

        for mapping in mappings {
            let permission_id = mapping.permission_id();
            let normalized = mapping.normalized_string().to_string();

            if mappings_by_id.contains_key(&permission_id)
                || mappings_by_id
                    .values()
                    .any(|stored_mapping| stored_mapping.normalized_string() == normalized)
            {
                continue;
            }

            mappings_by_id.insert(permission_id, mapping.clone());
            stored.push(mapping);
        }

        Ok(stored)
    }

    async fn remove_mappings_by_ids(
        &self,
        ids: Vec<PermissionId>,
    ) -> Result<Vec<PermissionMapping>> {
        let mut removed: Vec<PermissionMapping> = Vec::new();
        let mut mappings_by_id = self.mappings_by_id.write().await;

        for id in ids {
            if let Some(mapping) = mappings_by_id.remove(&id) {
                removed.push(mapping);
            }
        }

        Ok(removed)
    }

    async fn query_mappings_by_ids(
        &self,
        ids: Vec<PermissionId>,
    ) -> Result<Vec<PermissionMapping>> {
        let mappings_by_id = self.mappings_by_id.read().await;
        let mut mappings: Vec<PermissionMapping> = Vec::new();

        for id in ids {
            if let Some(mapping) = mappings_by_id.get(&id) {
                mappings.push(mapping.clone());
            }
        }

        Ok(mappings)
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryPermissionMappingRepository;
    use crate::permission_mapping_repository::{
        PermissionMappingRepository, PermissionMappingRepositoryBulk,
    };
    use webgates_core::permissions::PermissionMapping;

    #[tokio::test]
    async fn store_mapping_rejects_duplicate_normalized_strings() {
        let repository = MemoryPermissionMappingRepository::default();

        let initial = PermissionMapping::from("read:api");
        let duplicate = PermissionMapping::from("  READ:API  ");

        let stored_initial = match repository.store_mapping(initial.clone()).await {
            Ok(stored) => stored,
            Err(error) => panic!("initial mapping should store: {}", error),
        };
        assert_eq!(stored_initial, Some(initial));

        let stored_duplicate = match repository.store_mapping(duplicate).await {
            Ok(stored) => stored,
            Err(error) => panic!("duplicate insert should succeed as a no-op: {}", error),
        };
        assert!(stored_duplicate.is_none());

        let mappings = match repository.list_all_mappings().await {
            Ok(mappings) => mappings,
            Err(error) => panic!("list should succeed: {}", error),
        };
        assert_eq!(mappings.len(), 1);
    }

    #[tokio::test]
    async fn bulk_store_skips_duplicate_normalized_strings() {
        let repository = MemoryPermissionMappingRepository::default();
        let mappings = vec![
            PermissionMapping::from("read:api"),
            PermissionMapping::from("write:api"),
            PermissionMapping::from(" READ:API "),
        ];

        let stored = match repository.store_mappings(mappings).await {
            Ok(stored) => stored,
            Err(error) => panic!("bulk store should succeed: {}", error),
        };

        assert_eq!(stored.len(), 2);

        let all_mappings = match repository.list_all_mappings().await {
            Ok(mappings) => mappings,
            Err(error) => panic!("list should succeed: {}", error),
        };
        assert_eq!(all_mappings.len(), 2);
    }

    #[tokio::test]
    async fn remove_mapping_by_string_uses_normalized_lookup() {
        let repository = MemoryPermissionMappingRepository::default();
        let mapping = PermissionMapping::from("read:api");

        match repository.store_mapping(mapping.clone()).await {
            Ok(_) => {}
            Err(error) => panic!("store should succeed: {}", error),
        };

        let removed = match repository.remove_mapping_by_string("  READ:API ").await {
            Ok(removed) => removed,
            Err(error) => panic!("remove should succeed: {}", error),
        };

        assert_eq!(removed, Some(mapping));

        let remaining = match repository.list_all_mappings().await {
            Ok(mappings) => mappings,
            Err(error) => panic!("list should succeed: {}", error),
        };
        assert!(remaining.is_empty());
    }
}
