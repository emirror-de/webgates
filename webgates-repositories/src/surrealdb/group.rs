use super::SurrealDbRepository;
use crate::TableName;
use crate::errors::{DatabaseError, DatabaseOperation, Error as RepoError, Result as RepoResult};
use crate::group_repository::GroupRepository;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use surrealdb::Connection;
use surrealdb_types::{RecordId, SurrealValue};
use webgates_core::groups::GroupEntity;

#[derive(Clone, Debug, Serialize, Deserialize, SurrealValue)]
pub struct SurrealGroupRecord {
    group_id: String,
    payload: Value,
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

    Ok(SurrealGroupRecord { group_id, payload })
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
        self.use_ns_db().await?;

        let table_name = TableName::WebgatesGroups.to_string();
        let query = "DEFINE TABLE IF NOT EXISTS $table SCHEMALESS;";

        self.db
            .query(query)
            .bind(("table", table_name.clone()))
            .await
            .map_err(|error| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Insert,
                    format!("Failed to bootstrap group table: {}", error),
                    Some(table_name),
                    None,
                ))
            })?;

        Ok(())
    }

    async fn store_group(&self, group: T) -> RepoResult<bool> {
        self.use_ns_db().await?;

        let record = group_to_record(group, &self.scope_settings.groups)?;
        let group_id = record.group_id.clone();
        let recid = RecordId::new(self.scope_settings.groups.clone(), group_id.clone());

        let existing: Option<SurrealGroupRecord> =
            self.db.select(recid.clone()).await.map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Query,
                    format!("Failed to query group existence: {}", e),
                    Some(self.scope_settings.groups.clone()),
                    Some(group_id.clone()),
                ))
            })?;

        if existing.is_some() {
            return Ok(false);
        }

        let inserted: Option<SurrealGroupRecord> =
            self.db.insert(recid).content(record).await.map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Insert,
                    format!("Failed to insert group: {}", e),
                    Some(self.scope_settings.groups.clone()),
                    Some(group_id.clone()),
                ))
            })?;

        Ok(inserted.is_some())
    }

    async fn delete_group(&self, id: &str) -> RepoResult<Option<T>> {
        self.use_ns_db().await?;

        let recid = RecordId::new(self.scope_settings.groups.clone(), id.to_string());
        let deleted: Option<SurrealGroupRecord> = self.db.delete(recid).await.map_err(|e| {
            RepoError::Database(DatabaseError::with_context(
                DatabaseOperation::Delete,
                format!("Failed to delete group: {}", e),
                Some(self.scope_settings.groups.clone()),
                Some(id.to_string()),
            ))
        })?;

        deleted
            .map(|record| record_to_group(record, &self.scope_settings.groups))
            .transpose()
    }

    async fn update_group(&self, group: T) -> RepoResult<Option<T>> {
        self.use_ns_db().await?;

        let record = group_to_record(group, &self.scope_settings.groups)?;
        let group_id = record.group_id.clone();
        let recid = RecordId::new(self.scope_settings.groups.clone(), group_id.clone());

        let updated: Option<SurrealGroupRecord> =
            self.db.update(&recid).content(record).await.map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Update,
                    format!("Failed to update group: {}", e),
                    Some(self.scope_settings.groups.clone()),
                    Some(group_id.clone()),
                ))
            })?;

        updated
            .map(|record| record_to_group(record, &self.scope_settings.groups))
            .transpose()
    }

    async fn query_group_by_id(&self, id: &str) -> RepoResult<Option<T>> {
        self.use_ns_db().await?;

        let recid = RecordId::new(self.scope_settings.groups.clone(), id.to_string());
        let found: Option<SurrealGroupRecord> = self.db.select(recid).await.map_err(|e| {
            RepoError::Database(DatabaseError::with_context(
                DatabaseOperation::Query,
                format!("Failed to query group by id: {}", e),
                Some(self.scope_settings.groups.clone()),
                Some(id.to_string()),
            ))
        })?;

        found
            .map(|record| record_to_group(record, &self.scope_settings.groups))
            .transpose()
    }

    async fn query_all_groups(&self) -> RepoResult<Vec<T>> {
        self.use_ns_db().await?;

        let groups: Vec<SurrealGroupRecord> = self
            .db
            .select(self.scope_settings.groups.clone())
            .await
            .map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Query,
                    format!("Failed to query all groups: {}", e),
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
