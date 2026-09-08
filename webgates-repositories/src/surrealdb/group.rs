//! SurrealDB-backed group repository adapter.
//!
//! This module defines the SurrealDB persistence shape for groups and the
//! adapter implementation of `GroupRepository` for `SurrealDbRepository`.

use super::SurrealDbRepository;

use crate::errors::{DatabaseError, DatabaseOperation, Error as RepoError, Result as RepoResult};
use crate::group_repository::GroupRepository;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use surrealdb::Connection;
use surrealdb_types::{RecordId, SurrealValue};
use webgates_core::groups::GroupEntity;

/// SurrealDB persistence record for a stored group.
///
/// This adapter keeps the serialized group payload together with its stable
/// `group_id` record key so other crates can share the same persistence shape
/// when reading from or writing to SurrealDB.
#[derive(Clone, Debug, Serialize, Deserialize, SurrealValue)]
pub struct SurrealGroupRecord {
    group_id: String,
    payload: Value,
}

impl SurrealGroupRecord {
    /// Creates a new SurrealDB group persistence record.
    pub fn new(group_id: String, payload: Value) -> Self {
        Self { group_id, payload }
    }
}

fn group_to_record<T>(group: T, table_name: &str) -> RepoResult<SurrealGroupRecord>
where
    T: Serialize + GroupEntity,
{
    let group_id = group.group_id().to_string();
    let payload = serde_json::to_value(group).map_err(|error| {
        RepoError::Database(DatabaseError::with_context(
            DatabaseOperation::Insert,
            format!("Failed to serialize group payload: {}", error),
            Some(table_name.to_string()),
            Some(group_id.clone()),
        ))
    })?;

    Ok(SurrealGroupRecord::new(group_id, payload))
}

fn record_to_group<T>(record: SurrealGroupRecord, table_name: &str) -> RepoResult<T>
where
    T: DeserializeOwned,
{
    let group_id = record.group_id.clone();

    serde_json::from_value(record.payload).map_err(|error| {
        RepoError::Database(DatabaseError::with_context(
            DatabaseOperation::Query,
            format!("Failed to deserialize group payload: {}", error),
            Some(table_name.to_string()),
            Some(group_id),
        ))
    })
}

impl<S, T> GroupRepository<T> for SurrealDbRepository<S>
where
    S: Connection,
    T: Serialize + DeserializeOwned + GroupEntity + Eq + Clone + Send + Sync + 'static,
{
    type Error = RepoError;

    async fn bootstrap(&self) -> RepoResult<()> {
        self.group_schema_initialized
            .get_or_try_init(|| async {
                let table_name = self.scope_settings.groups.clone();
                let query = "DEFINE TABLE IF NOT EXISTS $table SCHEMALESS;";

                self.db
                    .query(query)
                    .bind(("table", table_name.clone()))
                    .await
                    .map_err(|error| {
                        RepoError::Database(DatabaseError::bootstrap(
                            format!("Failed to bootstrap group table: {}", error),
                            Some(table_name),
                        ))
                    })?;

                Ok::<(), RepoError>(())
            })
            .await?;

        Ok(())
    }

    async fn store_group(&self, group: T) -> RepoResult<bool> {
        let record = group_to_record(group, &self.scope_settings.groups)?;
        let group_id = record.group_id.clone();
        let recid = RecordId::new(self.scope_settings.groups.clone(), group_id.clone());

        let mut existence_response = self
            .db
            .query("SELECT * FROM $record_id")
            .bind(("record_id", recid.clone()))
            .await
            .map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Query,
                    format!("Failed to query group existence: {}", e),
                    Some(self.scope_settings.groups.clone()),
                    Some(group_id.clone()),
                ))
            })?;
        let existing = existence_response
            .take::<Option<SurrealGroupRecord>>(0)
            .map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Query,
                    format!("Failed to extract group existence: {}", e),
                    Some(self.scope_settings.groups.clone()),
                    Some(group_id.clone()),
                ))
            })?;

        if existing.is_some() {
            return Ok(false);
        }

        let mut insert_response = self
            .db
            .query("CREATE $record_id CONTENT $record")
            .bind(("record_id", recid))
            .bind(("record", record))
            .await
            .map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Insert,
                    format!("Failed to insert group: {}", e),
                    Some(self.scope_settings.groups.clone()),
                    Some(group_id.clone()),
                ))
            })?;
        let inserted = insert_response
            .take::<Option<SurrealGroupRecord>>(0)
            .map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Insert,
                    format!("Failed to extract inserted group: {}", e),
                    Some(self.scope_settings.groups.clone()),
                    Some(group_id),
                ))
            })?;

        Ok(inserted.is_some())
    }

    async fn delete_group(&self, id: &str) -> RepoResult<Option<T>> {
        let recid = RecordId::new(self.scope_settings.groups.clone(), id.to_string());
        let mut response = self
            .db
            .query("DELETE $record_id RETURN BEFORE")
            .bind(("record_id", recid))
            .await
            .map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Delete,
                    format!("Failed to delete group: {}", e),
                    Some(self.scope_settings.groups.clone()),
                    Some(id.to_string()),
                ))
            })?;
        let deleted = response
            .take::<Option<SurrealGroupRecord>>(0)
            .map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Delete,
                    format!("Failed to extract deleted group: {}", e),
                    Some(self.scope_settings.groups.clone()),
                    Some(id.to_string()),
                ))
            })?;

        deleted
            .map(|record| record_to_group(record, &self.scope_settings.groups))
            .transpose()
    }

    async fn update_group(&self, group: T) -> RepoResult<Option<T>> {
        let record = group_to_record(group, &self.scope_settings.groups)?;
        let group_id = record.group_id.clone();
        let recid = RecordId::new(self.scope_settings.groups.clone(), group_id.clone());

        let mut response = self
            .db
            .query("UPDATE $record_id CONTENT $record")
            .bind(("record_id", recid))
            .bind(("record", record))
            .await
            .map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Update,
                    format!("Failed to update group: {}", e),
                    Some(self.scope_settings.groups.clone()),
                    Some(group_id.clone()),
                ))
            })?;
        let updated = response
            .take::<Option<SurrealGroupRecord>>(0)
            .map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Update,
                    format!("Failed to extract updated group: {}", e),
                    Some(self.scope_settings.groups.clone()),
                    Some(group_id),
                ))
            })?;

        updated
            .map(|record| record_to_group(record, &self.scope_settings.groups))
            .transpose()
    }

    async fn query_group_by_id(&self, id: &str) -> RepoResult<Option<T>> {
        let recid = RecordId::new(self.scope_settings.groups.clone(), id.to_string());
        let mut response = self
            .db
            .query("SELECT * FROM $record_id")
            .bind(("record_id", recid))
            .await
            .map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Query,
                    format!("Failed to query group by id: {}", e),
                    Some(self.scope_settings.groups.clone()),
                    Some(id.to_string()),
                ))
            })?;
        let found = response
            .take::<Option<SurrealGroupRecord>>(0)
            .map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Query,
                    format!("Failed to extract group by id: {}", e),
                    Some(self.scope_settings.groups.clone()),
                    Some(id.to_string()),
                ))
            })?;

        found
            .map(|record| record_to_group(record, &self.scope_settings.groups))
            .transpose()
    }

    async fn query_all_groups(&self) -> RepoResult<Vec<T>> {
        let mut response = self
            .db
            .query("SELECT * FROM type::table($table)")
            .bind(("table", self.scope_settings.groups.clone()))
            .await
            .map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Query,
                    format!("Failed to query all groups: {}", e),
                    Some(self.scope_settings.groups.clone()),
                    None,
                ))
            })?;
        let groups = response.take::<Vec<SurrealGroupRecord>>(0).map_err(|e| {
            RepoError::Database(DatabaseError::with_context(
                DatabaseOperation::Query,
                format!("Failed to extract groups: {}", e),
                Some(self.scope_settings.groups.clone()),
                None,
            ))
        })?;

        groups
            .into_iter()
            .map(|record| record_to_group(record, &self.scope_settings.groups))
            .collect()
    }
}
