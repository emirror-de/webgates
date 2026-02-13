use super::SeaOrmRepository;
use crate::TableName;
use crate::errors::{DatabaseError, DatabaseOperation, Error as RepoError, Result};
use crate::sea_orm::models::group as seaorm_group;
use sea_orm::{
    ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder,
    entity::{ActiveModelTrait, ActiveValue},
};
use serde::{Serialize, de::DeserializeOwned};
use webgates::groups::{GroupEntity, GroupRepository as GroupRepositoryTrait};

impl<T> GroupRepositoryTrait<T> for SeaOrmRepository
where
    T: Serialize + DeserializeOwned + GroupEntity + Eq + Clone + Send + Sync + 'static,
{
    type Error = RepoError;

    async fn store_group(&self, group: T) -> Result<bool> {
        let res: Result<_> = {
            let mut model = seaorm_group::ActiveModel::from(group);
            model.id = ActiveValue::NotSet;

            match model.insert(&self.db).await {
                Ok(_) => Ok(true),
                Err(e) => {
                    let msg = e.to_string().to_lowercase();
                    if msg.contains("unique") && msg.contains("constraint") {
                        Ok(false)
                    } else {
                        Err(RepoError::Database(DatabaseError::with_context(
                            DatabaseOperation::Insert,
                            format!("Failed to insert group: {}", e),
                            Some(TableName::AxumGateGroups.to_string()),
                            None,
                        )))
                    }
                }
            }
        };
        res
    }

    async fn delete_group(&self, id: &str) -> Result<Option<T>> {
        let res: Result<_> = {
            let model_opt = seaorm_group::Entity::find()
                .filter(seaorm_group::Column::GroupId.eq(id.to_string()))
                .one(&self.db)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query group for deletion: {}", e),
                        Some(TableName::AxumGateGroups.to_string()),
                        Some(id.to_string()),
                    ))
                })?;

            let model = match model_opt {
                Some(m) => m,
                None => return Ok(None),
            };

            seaorm_group::Entity::delete_by_id(model.id)
                .exec(&self.db)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Delete,
                        format!("Failed to delete group: {}", e),
                        Some(TableName::AxumGateGroups.to_string()),
                        Some(id.to_string()),
                    ))
                })?;

            let dom = model.into_payload().map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Delete,
                    format!("Failed to deserialize deleted group: {}", e),
                    Some(TableName::AxumGateGroups.to_string()),
                    Some(id.to_string()),
                ))
            })?;
            Ok(Some(dom))
        };
        res
    }

    async fn update_group(&self, group: T) -> Result<Option<T>> {
        let res: Result<_> = {
            let gid = group.group_id().to_string();
            let model_opt = seaorm_group::Entity::find()
                .filter(seaorm_group::Column::GroupId.eq(gid.clone()))
                .one(&self.db)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query group for update: {}", e),
                        Some(TableName::AxumGateGroups.to_string()),
                        Some(gid.clone()),
                    ))
                })?;

            let model = match model_opt {
                Some(m) => m,
                None => return Ok(None),
            };

            let mut active = model.into_active_model();
            let new_active = seaorm_group::ActiveModel::from(group);
            active.payload = new_active.payload;

            let updated = active.update(&self.db).await.map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Update,
                    format!("Failed to update group: {}", e),
                    Some(TableName::AxumGateGroups.to_string()),
                    Some(gid.clone()),
                ))
            })?;

            let dom = updated.into_payload().map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Update,
                    format!("Failed to deserialize updated group: {}", e),
                    Some(TableName::AxumGateGroups.to_string()),
                    Some(gid.clone()),
                ))
            })?;
            Ok(Some(dom))
        };
        res
    }

    async fn query_group_by_id(&self, id: &str) -> Result<Option<T>> {
        let res: Result<_> = {
            let model_opt = seaorm_group::Entity::find()
                .filter(seaorm_group::Column::GroupId.eq(id.to_string()))
                .one(&self.db)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query group by id: {}", e),
                        Some(TableName::AxumGateGroups.to_string()),
                        Some(id.to_string()),
                    ))
                })?;

            let model = match model_opt {
                Some(m) => m,
                None => return Ok(None),
            };

            let dom = model.into_payload().map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Query,
                    format!("Failed to deserialize group payload: {}", e),
                    Some(TableName::AxumGateGroups.to_string()),
                    Some(id.to_string()),
                ))
            })?;
            Ok(Some(dom))
        };
        res
    }

    async fn query_all_groups(&self) -> Result<Vec<T>> {
        let res: Result<_> = {
            let models = seaorm_group::Entity::find()
                .order_by_asc(seaorm_group::Column::GroupId)
                .all(&self.db)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query all groups: {}", e),
                        Some(TableName::AxumGateGroups.to_string()),
                        None,
                    ))
                })?;

            let mut out = Vec::with_capacity(models.len());
            for m in models {
                let dom = m.into_payload().map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to deserialize group payload: {}", e),
                        Some(TableName::AxumGateGroups.to_string()),
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
