//! SurrealDB-backed permission mapping repository.
//!
//! This module keeps the SurrealDB persistence shape for `PermissionMapping`
//! values at the repository adapter boundary and provides the repository
//! operations used to store, query, and remove permission mappings.

use super::SurrealDbRepository;

use crate::errors::{DatabaseError, DatabaseOperation, Error as RepoError, Result as RepoResult};
use crate::permission_mapping_repository::{
    PermissionMappingRepository, PermissionMappingRepositoryBulk,
};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use surrealdb_types::{RecordId, SurrealValue};

use webgates_core::permissions::mapping::PermissionMapping;
use webgates_core::permissions::permission_id::PermissionId;

/// Adapter for persisting `PermissionMapping` in SurrealDB.
///
/// SurrealDB can deserialize numeric fields as signed 64-bit integers (i64),
/// while our permission IDs are computed 64-bit values that may exceed the
/// positive i63 range. Persisting `permission_id` as a `String` avoids
/// signedness/width pitfalls across different SurrealDB backends and ensures
/// stable round-trips regardless of how numbers are represented internally.
///
/// NOTE: The record key for permission mappings is the `permission_id`
/// (stringified). The `normalized_string` is stored as a regular field and
/// can be queried when reversing from human-readable permission names to ids.
#[derive(Clone, Debug, Serialize, Deserialize, SurrealValue)]
pub struct SurrealPermissionMapping {
    /// Explicit record id allows creating multiple records in a single
    /// CREATE/UPSERT ... CONTENT query by providing per-item record keys.
    id: RecordId,
    normalized_string: String,
    permission_id: String,
}

impl SurrealPermissionMapping {
    /// Build a SurrealPermissionMapping from explicit persisted field values.
    pub fn new(id: RecordId, normalized_string: String, permission_id: String) -> Self {
        Self {
            id,
            normalized_string,
            permission_id,
        }
    }

    /// Build a SurrealPermissionMapping with a concrete RecordId for the given table.
    pub fn with_record_id(table: String, m: &PermissionMapping) -> Self {
        Self {
            id: RecordId::new(table.clone(), m.permission_id().as_u64().to_string()),
            normalized_string: m.normalized_string().to_string(),
            permission_id: m.permission_id().as_u64().to_string(),
        }
    }
}

impl TryFrom<SurrealPermissionMapping> for PermissionMapping {
    type Error = String;

    fn try_from(value: SurrealPermissionMapping) -> std::result::Result<Self, Self::Error> {
        let id_u64 = value.permission_id.parse::<u64>().map_err(|e| {
            format!(
                "invalid permission_id string '{}': {}",
                value.permission_id, e
            )
        })?;
        let id = PermissionId::from_u64(id_u64);
        PermissionMapping::new(value.normalized_string.clone(), id)
            .map_err(|e| format!("failed to construct PermissionMapping: {}", e))
    }
}

impl<S> PermissionMappingRepository for SurrealDbRepository<S>
where
    S: Connection,
{
    type Error = RepoError;

    async fn bootstrap(&self) -> RepoResult<()> {

        self.permission_mapping_schema_initialized
            .get_or_try_init(|| async {
                let table_name = self.scope_settings.permission_mappings.clone();

                let define_table = "DEFINE TABLE IF NOT EXISTS $table SCHEMALESS;";
                self.db
                    .query(define_table)
                    .bind(("table", table_name.clone()))
                    .await
                    .map_err(|e| {
                        RepoError::Database(DatabaseError::bootstrap(
                            format!("Failed to define permission mappings table: {}", e),
                            Some(table_name.clone()),
                        ))
                    })?;

                let define_normalized_field = "DEFINE FIELD IF NOT EXISTS normalized_string ON TABLE type::table($table) TYPE string ASSERT string::len($value) > 0";
                self.db
                    .query(define_normalized_field)
                    .bind(("table", table_name.clone()))
                    .await
                    .map_err(|e| {
                    RepoError::Database(DatabaseError::bootstrap(
                        format!(
                            "Failed to define permission mappings normalized_string field: {}",
                            e
                        ),
                        Some(table_name.clone()),
                    ))
                })?;

                let define_permission_id_field = "DEFINE FIELD IF NOT EXISTS permission_id ON TABLE type::table($table) TYPE string ASSERT string::len($value) > 0";
                self.db
                    .query(define_permission_id_field)
                    .bind(("table", table_name.clone()))
                    .await
                    .map_err(|e| {
                        RepoError::Database(DatabaseError::bootstrap(
                            format!(
                                "Failed to define permission mappings permission_id field: {}",
                                e
                            ),
                            Some(table_name.clone()),
                        ))
                    })?;

                let define_normalized_index = "DEFINE INDEX IF NOT EXISTS permission_mappings_normalized_string_idx ON type::table($table) FIELDS normalized_string UNIQUE";
                self.db
                    .query(define_normalized_index)
                    .bind(("table", table_name.clone()))
                    .await
                    .map_err(|e| {
                    RepoError::Database(DatabaseError::bootstrap(
                        format!(
                            "Failed to define permission mappings normalized_string index: {}",
                            e
                        ),
                        Some(table_name.clone()),
                    ))
                })?;

                let define_permission_id_index = "DEFINE INDEX IF NOT EXISTS permission_mappings_permission_id_idx ON type::table($table) FIELDS permission_id UNIQUE";
                self.db
                    .query(define_permission_id_index)
                    .bind(("table", table_name.clone()))
                    .await
                    .map_err(|e| {
                        RepoError::Database(DatabaseError::bootstrap(
                            format!(
                                "Failed to define permission mappings permission_id index: {}",
                                e
                            ),
                            Some(table_name.clone()),
                        ))
                    })?;

                Ok::<(), RepoError>(())
            })
            .await?;

        Ok(())
    }

    async fn store_mapping(
        &self,
        mapping: PermissionMapping,
    ) -> RepoResult<Option<PermissionMapping>> {
        let res: RepoResult<_> = {
            if let Err(e) = mapping.validate() {
                return Err(RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Insert,
                    format!("Invalid permission mapping: {}", e),
                    Some(self.scope_settings.permission_mappings.clone()),
                    None,
                )));
            }


            let record_id = RecordId::new(
                self.scope_settings.permission_mappings.clone(),
                mapping.permission_id().as_u64().to_string(),
            );

            let spm = SurrealPermissionMapping::with_record_id(
                self.scope_settings.permission_mappings.clone(),
                &mapping,
            );

            let mut response = self
                .db
                .query("UPSERT $record_id CONTENT $record RETURN AFTER")
                .bind(("record_id", record_id))
                .bind(("record", spm))
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Insert,
                        format!("Failed to store permission mapping: {}", e),
                        Some(self.scope_settings.permission_mappings.clone()),
                        None,
                    ))
                })?;
            let upsert_res: Vec<SurrealPermissionMapping> = response.take(0).map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Insert,
                    format!("Failed to extract stored permission mapping: {}", e),
                    Some(self.scope_settings.permission_mappings.clone()),
                    None,
                ))
            })?;

            if !upsert_res.is_empty() {
                Ok(Some(mapping))
            } else {
                Ok(None)
            }
        };
        res
    }

    async fn remove_mapping_by_id(
        &self,
        id: PermissionId,
    ) -> RepoResult<Option<PermissionMapping>> {
        let res: RepoResult<_> = {

            let record_id = RecordId::new(
                self.scope_settings.permission_mappings.clone(),
                id.as_u64().to_string(),
            );
            let mut response = self
                .db
                .query("DELETE $record_id RETURN BEFORE")
                .bind(("record_id", record_id))
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Delete,
                        format!("Failed to delete permission mapping by id: {}", e),
                        Some(self.scope_settings.permission_mappings.clone()),
                        Some(id.as_u64().to_string()),
                    ))
                })?;
            let mut removed: Vec<SurrealPermissionMapping> = response.take(0).map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Delete,
                    format!("Failed to extract deleted permission mapping: {}", e),
                    Some(self.scope_settings.permission_mappings.clone()),
                    Some(id.as_u64().to_string()),
                ))
            })?;

            removed
                .pop()
                .map(|spm| {
                    PermissionMapping::try_from(spm).map_err(|e| {
                        RepoError::Database(DatabaseError::with_context(
                            DatabaseOperation::Delete,
                            format!("Failed to convert deleted permission mapping: {}", e),
                            Some(self.scope_settings.permission_mappings.clone()),
                            Some(id.as_u64().to_string()),
                        ))
                    })
                })
                .transpose()
        };
        res
    }

    async fn remove_mapping_by_string(
        &self,
        permission: &str,
    ) -> RepoResult<Option<PermissionMapping>> {
        let res: RepoResult<_> = {

            let normalized = PermissionMapping::from(permission)
                .normalized_string()
                .to_string();

            let query = "SELECT * FROM type::table($table) WHERE normalized_string = $ns LIMIT 1";
            let mut db_res = self
                .db
                .query(query)
                .bind(("table", self.scope_settings.permission_mappings.clone()))
                .bind(("ns", normalized))
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!(
                            "Failed to query permission mapping by string before delete: {}",
                            e
                        ),
                        Some(self.scope_settings.permission_mappings.clone()),
                        None,
                    ))
                })?;

            let found: Vec<SurrealPermissionMapping> = db_res.take(0).map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Query,
                    format!(
                        "Failed to extract permission mapping by string before delete: {}",
                        e
                    ),
                    Some(self.scope_settings.permission_mappings.clone()),
                    None,
                ))
            })?;

            match found.into_iter().next() {
                Some(spm) => {
                    let mapping = PermissionMapping::try_from(spm).map_err(|e| {
                        RepoError::Database(DatabaseError::with_context(
                            DatabaseOperation::Query,
                            format!(
                                "Failed to convert permission mapping by string before delete: {}",
                                e
                            ),
                            Some(self.scope_settings.permission_mappings.clone()),
                            None,
                        ))
                    })?;

                    let record_id = RecordId::new(
                        self.scope_settings.permission_mappings.clone(),
                        mapping.permission_id().as_u64().to_string(),
                    );

                    let mut response = self
                        .db
                        .query("DELETE $record_id RETURN BEFORE")
                        .bind(("record_id", record_id))
                        .await
                        .map_err(|e| {
                            RepoError::Database(DatabaseError::with_context(
                                DatabaseOperation::Delete,
                                format!("Failed to delete permission mapping by string: {}", e),
                                Some(self.scope_settings.permission_mappings.clone()),
                                None,
                            ))
                        })?;
                    let mut deleted: Vec<SurrealPermissionMapping> =
                        response.take(0).map_err(|e| {
                            RepoError::Database(DatabaseError::with_context(
                                DatabaseOperation::Delete,
                                format!("Failed to extract deleted permission mapping: {}", e),
                                Some(self.scope_settings.permission_mappings.clone()),
                                None,
                            ))
                        })?;

                    deleted
                        .pop()
                        .map(|spm| {
                            PermissionMapping::try_from(spm).map_err(|e| {
                                RepoError::Database(DatabaseError::with_context(
                                    DatabaseOperation::Delete,
                                    format!("Failed to convert deleted permission mapping: {}", e),
                                    Some(self.scope_settings.permission_mappings.clone()),
                                    None,
                                ))
                            })
                        })
                        .transpose()
                }
                None => Ok(None),
            }
        };
        res
    }

    async fn query_mapping_by_id(&self, id: PermissionId) -> RepoResult<Option<PermissionMapping>> {
        let res: RepoResult<_> = {

            let record_id = RecordId::new(
                self.scope_settings.permission_mappings.clone(),
                id.as_u64().to_string(),
            );

            let mut response = self
                .db
                .query("SELECT * FROM $record_id")
                .bind(("record_id", record_id))
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query permission mapping by id: {}", e),
                        Some(self.scope_settings.permission_mappings.clone()),
                        Some(id.as_u64().to_string()),
                    ))
                })?;
            let mut mappings: Vec<SurrealPermissionMapping> = response.take(0).map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Query,
                    format!("Failed to extract permission mapping by id: {}", e),
                    Some(self.scope_settings.permission_mappings.clone()),
                    Some(id.as_u64().to_string()),
                ))
            })?;

            mappings
                .pop()
                .map(|spm| {
                    PermissionMapping::try_from(spm).map_err(|e| {
                        RepoError::Database(DatabaseError::with_context(
                            DatabaseOperation::Query,
                            format!("Failed to convert permission mapping: {}", e),
                            Some(self.scope_settings.permission_mappings.clone()),
                            Some(id.as_u64().to_string()),
                        ))
                    })
                })
                .transpose()
        };
        res
    }

    async fn query_mapping_by_string(
        &self,
        permission: &str,
    ) -> RepoResult<Option<PermissionMapping>> {
        let res: RepoResult<_> = {

            let normalized = PermissionMapping::from(permission)
                .normalized_string()
                .to_string();

            let query = "SELECT * FROM type::table($table) WHERE normalized_string = $ns LIMIT 1";
            let mut db_res = self
                .db
                .query(query)
                .bind(("table", self.scope_settings.permission_mappings.clone()))
                .bind(("ns", normalized.clone()))
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query permission mapping by string: {}", e),
                        Some(self.scope_settings.permission_mappings.clone()),
                        None,
                    ))
                })?;

            let found: Vec<SurrealPermissionMapping> = db_res.take(0).map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Query,
                    format!("Failed to extract permission mapping by string: {}", e),
                    Some(self.scope_settings.permission_mappings.clone()),
                    None,
                ))
            })?;

            found
                .into_iter()
                .next()
                .map(|spm| {
                    PermissionMapping::try_from(spm).map_err(|e| {
                        RepoError::Database(DatabaseError::with_context(
                            DatabaseOperation::Query,
                            format!("Failed to convert permission mapping: {}", e),
                            Some(self.scope_settings.permission_mappings.clone()),
                            None,
                        ))
                    })
                })
                .transpose()
        };
        res
    }

    async fn list_all_mappings(&self) -> RepoResult<Vec<PermissionMapping>> {
        let res: RepoResult<_> = {

            let mut response = self
                .db
                .query("SELECT * FROM type::table($table)")
                .bind(("table", self.scope_settings.permission_mappings.clone()))
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to list permission mappings: {}", e),
                        Some(self.scope_settings.permission_mappings.clone()),
                        None,
                    ))
                })?;
            let all_spm: Vec<SurrealPermissionMapping> = response.take(0).map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Query,
                    format!("Failed to extract permission mappings: {}", e),
                    Some(self.scope_settings.permission_mappings.clone()),
                    None,
                ))
            })?;

            let mut out = Vec::with_capacity(all_spm.len());
            for spm in all_spm {
                let dom = PermissionMapping::try_from(spm).map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to convert permission mapping: {}", e),
                        Some(self.scope_settings.permission_mappings.clone()),
                        None,
                    ))
                })?;
                out.push(dom);
            }
            Ok(out)
        };
        res
    }
}

impl<S> PermissionMappingRepositoryBulk for SurrealDbRepository<S>
where
    S: Connection,
{
    async fn store_mappings(
        &self,
        mappings: Vec<PermissionMapping>,
    ) -> RepoResult<Vec<PermissionMapping>> {
        let res: RepoResult<_> = {

            if mappings.is_empty() {
                return Ok(Vec::new());
            }

            for spm in mappings.iter() {
                if spm.validate().is_err() {
                    return Err(RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Insert,
                        "Invalid permission mapping in bulk insert".to_string(),
                        Some(self.scope_settings.permission_mappings.clone()),
                        None,
                    )));
                }
            }

            for spm in mappings.iter() {
                let record_id = RecordId::new(
                    self.scope_settings.permission_mappings.clone(),
                    spm.permission_id().as_u64().to_string(),
                );

                let spm_record = SurrealPermissionMapping::with_record_id(
                    self.scope_settings.permission_mappings.clone(),
                    spm,
                );

                let mut response = self
                    .db
                    .query("UPSERT $record_id CONTENT $record RETURN AFTER")
                    .bind(("record_id", record_id))
                    .bind(("record", spm_record))
                    .await
                    .map_err(|e| {
                        RepoError::Database(DatabaseError::with_context(
                            DatabaseOperation::Insert,
                            format!("Failed to store permission mapping in bulk: {}", e),
                            Some(self.scope_settings.permission_mappings.clone()),
                            None,
                        ))
                    })?;
                let upsert_res: Vec<SurrealPermissionMapping> = response.take(0).map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Insert,
                        format!("Failed to extract stored permission mapping in bulk: {}", e),
                        Some(self.scope_settings.permission_mappings.clone()),
                        None,
                    ))
                })?;

                if upsert_res.is_empty() {
                    return Err(RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Insert,
                        "Failed to store permission mapping in bulk: no record returned"
                            .to_string(),
                        Some(self.scope_settings.permission_mappings.clone()),
                        None,
                    )));
                }
            }

            Ok(mappings)
        };
        res
    }

    async fn remove_mappings_by_ids(
        &self,
        ids: Vec<PermissionId>,
    ) -> RepoResult<Vec<PermissionMapping>> {
        let res: RepoResult<_> = {

            if ids.is_empty() {
                return Ok(Vec::new());
            }

            let pid_strs: Vec<String> = ids.iter().map(|id| id.as_u64().to_string()).collect();

            let query = "SELECT * FROM type::table($table) WHERE permission_id IN $pids";
            let mut db_res = self
                .db
                .query(query)
                .bind(("table", self.scope_settings.permission_mappings.clone()))
                .bind(("pids", pid_strs))
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!(
                            "Failed to query permission mappings before bulk delete: {}",
                            e
                        ),
                        Some(self.scope_settings.permission_mappings.clone()),
                        None,
                    ))
                })?;

            let found: Vec<SurrealPermissionMapping> = db_res.take(0).map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Query,
                    format!(
                        "Failed to extract permission mappings before bulk delete: {}",
                        e
                    ),
                    Some(self.scope_settings.permission_mappings.clone()),
                    None,
                ))
            })?;

            let mut removed = Vec::with_capacity(found.len());
            for spm in found {
                let mapping = PermissionMapping::try_from(spm).map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!(
                            "Failed to convert permission mapping before bulk delete: {}",
                            e
                        ),
                        Some(self.scope_settings.permission_mappings.clone()),
                        None,
                    ))
                })?;

                let record_id = RecordId::new(
                    self.scope_settings.permission_mappings.clone(),
                    mapping.permission_id().as_u64().to_string(),
                );

                let mut response = self
                    .db
                    .query("DELETE $record_id RETURN BEFORE")
                    .bind(("record_id", record_id))
                    .await
                    .map_err(|e| {
                        RepoError::Database(DatabaseError::with_context(
                            DatabaseOperation::Delete,
                            format!("Failed to delete permission mapping in bulk: {}", e),
                            Some(self.scope_settings.permission_mappings.clone()),
                            None,
                        ))
                    })?;
                let mut deleted: Vec<SurrealPermissionMapping> = response.take(0).map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Delete,
                        format!(
                            "Failed to extract deleted permission mapping in bulk: {}",
                            e
                        ),
                        Some(self.scope_settings.permission_mappings.clone()),
                        None,
                    ))
                })?;

                if let Some(spm) = deleted.pop() {
                    let dom = PermissionMapping::try_from(spm).map_err(|e| {
                        RepoError::Database(DatabaseError::with_context(
                            DatabaseOperation::Delete,
                            format!(
                                "Failed to convert deleted permission mapping in bulk: {}",
                                e
                            ),
                            Some(self.scope_settings.permission_mappings.clone()),
                            None,
                        ))
                    })?;
                    removed.push(dom);
                }
            }

            Ok(removed)
        };
        res
    }

    async fn query_mappings_by_ids(
        &self,
        ids: Vec<PermissionId>,
    ) -> RepoResult<Vec<PermissionMapping>> {
        let res: RepoResult<_> = {

            if ids.is_empty() {
                return Ok(Vec::new());
            }

            let pid_strs: Vec<String> = ids.iter().map(|id| id.as_u64().to_string()).collect();
            let query = "SELECT * FROM type::table($table) WHERE permission_id IN $pids";
            let mut db_res = self
                .db
                .query(query)
                .bind(("table", self.scope_settings.permission_mappings.clone()))
                .bind(("pids", pid_strs.clone()))
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query permission mappings in bulk: {}", e),
                        Some(self.scope_settings.permission_mappings.clone()),
                        None,
                    ))
                })?;

            let found: Vec<SurrealPermissionMapping> = db_res.take(0).map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Query,
                    format!("Failed to extract permission mappings in bulk: {}", e),
                    Some(self.scope_settings.permission_mappings.clone()),
                    None,
                ))
            })?;

            let mut out = Vec::with_capacity(found.len());
            for spm in found {
                let dom = PermissionMapping::try_from(spm).map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to convert permission mapping in bulk query: {}", e),
                        Some(self.scope_settings.permission_mappings.clone()),
                        None,
                    ))
                })?;
                out.push(dom);
            }

            Ok(out)
        };
        res
    }
}
