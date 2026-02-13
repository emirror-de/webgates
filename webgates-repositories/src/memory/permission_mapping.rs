use crate::errors::{
    Error as RepoError, RepositoriesError, RepositoryOperation, RepositoryType,
    Result as RepoResult,
};

use webgates::permissions::PermissionId;
use webgates::permissions::mapping::{
    PermissionMapping, PermissionMappingRepository, PermissionMappingRepositoryBulk,
};

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

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
/// This avoids scanning a Vec for common operations and makes bulk insertion,
/// deduplication and lookups O(1) on average.
#[derive(Debug)]
pub struct MemoryPermissionMappingRepository {
    /// Primary store keyed by PermissionId
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
        let mut by_id: HashMap<PermissionId, PermissionMapping> = HashMap::new();

        for mapping in mappings {
            // Validate the mapping before storing
            if let Err(e) = mapping.validate() {
                tracing::warn!("Skipping invalid permission mapping: {}", e);
                continue;
            }

            let id = mapping.permission_id();

            // Skip if id already present
            if by_id.contains_key(&id) {
                continue;
            }

            by_id.insert(id, mapping);
        }

        Self {
            mappings_by_id: Arc::new(RwLock::new(by_id)),
        }
    }
}

impl PermissionMappingRepository for MemoryPermissionMappingRepository {
    async fn store_mapping(
        &self,
        mapping: PermissionMapping,
    ) -> webgates::errors::Result<Option<PermissionMapping>> {
        let res: RepoResult<_> = {
            if let Err(e) = mapping.validate() {
                return Err(RepoError::Repositories(RepositoriesError::operation_failed(
                    RepositoryType::PermissionMapping,
                    RepositoryOperation::Insert,
                    format!("Invalid permission mapping: {}", e),
                    None,
                    Some("store".to_string()),
                ))
                .into());
            }

            let id = mapping.permission_id();

            {
                let read_by_id = self.mappings_by_id.read().await;
                if read_by_id.contains_key(&id) {
                    return Ok(None);
                }
            }

            {
                let mut write_by_id = self.mappings_by_id.write().await;
                if write_by_id.contains_key(&id) {
                    return Ok(None);
                }
                write_by_id.insert(id, mapping.clone());
            }

            Ok(Some(mapping))
        };
        res.map_err(Into::into)
    }

    async fn remove_mapping_by_id(
        &self,
        id: PermissionId,
    ) -> webgates::errors::Result<Option<PermissionMapping>> {
        let res: RepoResult<_> = {
            let mut write_by_id = self.mappings_by_id.write().await;
            Ok(write_by_id.remove(&id))
        };
        res.map_err(Into::into)
    }

    async fn remove_mapping_by_string(
        &self,
        permission: &str,
    ) -> webgates::errors::Result<Option<PermissionMapping>> {
        let res: RepoResult<_> = {
            let normalized = normalize_permission(permission);

            let mut write_by_id = self.mappings_by_id.write().await;
            let mut found_key: Option<PermissionId> = None;
            for (k, v) in write_by_id.iter() {
                if v.normalized_string() == normalized.as_str() {
                    found_key = Some(*k);
                    break;
                }
            }

            if let Some(id) = found_key
                && let Some(removed) = write_by_id.remove(&id)
            {
                return Ok(Some(removed));
            }

            Ok(None)
        };
        res.map_err(Into::into)
    }

    async fn query_mapping_by_id(
        &self,
        id: PermissionId,
    ) -> webgates::errors::Result<Option<PermissionMapping>> {
        let res: RepoResult<_> = {
            let read = self.mappings_by_id.read().await;
            Ok(read.get(&id).cloned())
        };
        res.map_err(Into::into)
    }

    async fn query_mapping_by_string(
        &self,
        permission: &str,
    ) -> webgates::errors::Result<Option<PermissionMapping>> {
        let res: RepoResult<_> = {
            let normalized = normalize_permission(permission);

            let read = self.mappings_by_id.read().await;
            for m in read.values() {
                if m.normalized_string() == normalized.as_str() {
                    return Ok(Some(m.clone()));
                }
            }
            Ok(None)
        };
        res.map_err(Into::into)
    }

    async fn list_all_mappings(&self) -> webgates::errors::Result<Vec<PermissionMapping>> {
        let res: RepoResult<_> = {
            let read = self.mappings_by_id.read().await;
            Ok(read.values().cloned().collect())
        };
        res.map_err(Into::into)
    }
}

/// Normalize a permission name (trim + lowercase).
///
/// This function implements the same normalization logic used in
/// the PermissionId implementation to ensure consistency.
fn normalize_permission(input: &str) -> String {
    input.trim().to_lowercase()
}

impl PermissionMappingRepositoryBulk for MemoryPermissionMappingRepository {
    async fn store_mappings(
        &self,
        mappings: Vec<PermissionMapping>,
    ) -> webgates::errors::Result<Vec<PermissionMapping>> {
        let res: RepoResult<_> = {
            for mapping in &mappings {
                if let Err(e) = mapping.validate() {
                    return Err(RepoError::Repositories(RepositoriesError::operation_failed(
                        RepositoryType::PermissionMapping,
                        RepositoryOperation::Insert,
                        format!("Invalid permission mapping in bulk store: {}", e),
                        None,
                        Some("store_mappings".to_string()),
                    ))
                    .into());
                }
            }

            let mut stored: Vec<PermissionMapping> = Vec::new();
            let mut write_by_id = self.mappings_by_id.write().await;

            for mapping in mappings {
                let id = mapping.permission_id();

                if write_by_id.contains_key(&id) {
                    continue;
                }

                write_by_id.insert(id, mapping.clone());
                stored.push(mapping);
            }

            Ok(stored)
        };
        res.map_err(Into::into)
    }

    async fn remove_mappings_by_ids(
        &self,
        ids: Vec<PermissionId>,
    ) -> webgates::errors::Result<Vec<PermissionMapping>> {
        let res: RepoResult<_> = {
            let mut removed: Vec<PermissionMapping> = Vec::new();

            let mut write_by_id = self.mappings_by_id.write().await;

            for id in ids {
                if let Some(r) = write_by_id.remove(&id) {
                    removed.push(r);
                }
            }

            Ok(removed)
        };
        res.map_err(Into::into)
    }

    async fn query_mappings_by_ids(
        &self,
        ids: Vec<PermissionId>,
    ) -> webgates::errors::Result<Vec<PermissionMapping>> {
        let res: RepoResult<_> = {
            let read_by_id = self.mappings_by_id.read().await;
            let mut out: Vec<PermissionMapping> = Vec::new();

            for id in ids {
                if let Some(found) = read_by_id.get(&id) {
                    out.push(found.clone());
                }
            }

            Ok(out)
        };
        res.map_err(Into::into)
    }
}
