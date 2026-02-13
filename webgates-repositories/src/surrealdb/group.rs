use super::SurrealDbRepository;
use crate::errors::{DatabaseError, DatabaseOperation, Error as RepoError, Result as RepoResult};
use serde::{Serialize, de::DeserializeOwned};
use surrealdb::{Connection, RecordId};
use webgates::errors::Result;
use webgates::groups::{GroupEntity, GroupRepository};

impl<S, T> GroupRepository<T> for SurrealDbRepository<S>
where
    S: Connection,
    T: Serialize + DeserializeOwned + GroupEntity + Eq + Clone + Send + Sync + 'static,
{
    async fn store_group(&self, group: T) -> Result<bool> {
        let res: RepoResult<_> = {
            self.use_ns_db().await?;
            let id_str = group.group_id().to_string();
            let recid = RecordId::from_table_key(self.scope_settings.groups.clone(), &id_str);

            let existing: Option<T> = self.db.select(recid.clone()).await.map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Query,
                    format!("Failed to query group existence: {}", e),
                    Some(self.scope_settings.groups.clone()),
                    Some(id_str.clone()),
                ))
            })?;

            if existing.is_some() {
                return Ok(false);
            }

            let inserted: Option<T> = self.db.insert(recid).content(group).await.map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Insert,
                    format!("Failed to insert group: {}", e),
                    Some(self.scope_settings.groups.clone()),
                    Some(id_str.clone()),
                ))
            })?;
            Ok(inserted.is_some())
        };
        res.map_err(Into::into)
    }

    async fn delete_group(&self, id: &str) -> Result<Option<T>> {
        let res: RepoResult<_> = {
            self.use_ns_db().await?;
            let recid = RecordId::from_table_key(self.scope_settings.groups.clone(), id);
            let deleted: Option<T> = self.db.delete(recid).await.map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Delete,
                    format!("Failed to delete group: {}", e),
                    Some(self.scope_settings.groups.clone()),
                    Some(id.to_string()),
                ))
            })?;
            Ok(deleted)
        };
        res.map_err(Into::into)
    }

    async fn update_group(&self, group: T) -> Result<Option<T>> {
        let res: RepoResult<_> = {
            self.use_ns_db().await?;
            let id_str = group.group_id().to_string();
            let recid = RecordId::from_table_key(self.scope_settings.groups.clone(), &id_str);
            let updated: Option<T> = self.db.update(&recid).content(group).await.map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Update,
                    format!("Failed to update group: {}", e),
                    Some(self.scope_settings.groups.clone()),
                    Some(id_str.clone()),
                ))
            })?;
            Ok(updated)
        };
        res.map_err(Into::into)
    }

    async fn query_group_by_id(&self, id: &str) -> Result<Option<T>> {
        let res: RepoResult<_> = {
            self.use_ns_db().await?;
            let recid = RecordId::from_table_key(self.scope_settings.groups.clone(), id);
            let found: Option<T> = self.db.select(recid).await.map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Query,
                    format!("Failed to query group by id: {}", e),
                    Some(self.scope_settings.groups.clone()),
                    Some(id.to_string()),
                ))
            })?;
            Ok(found)
        };
        res.map_err(Into::into)
    }

    async fn query_all_groups(&self) -> Result<Vec<T>> {
        let res: RepoResult<_> = {
            self.use_ns_db().await?;
            let groups: Vec<T> = self
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
            Ok(groups)
        };
        res.map_err(Into::into)
    }
}
