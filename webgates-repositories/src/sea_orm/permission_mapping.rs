use super::SeaOrmRepository;
use crate::TableName;
use crate::errors::{DatabaseError, DatabaseOperation, Error as RepoError, Result as RepoResult};
use crate::sea_orm::models::permission_mapping as seaorm_permission_mapping;
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ColumnTrait, EntityTrait, QueryFilter, QueryOrder, TransactionTrait, entity::prelude::*,
};

use webgates::permissions::PermissionId;
use webgates::permissions::mapping::{
    PermissionMapping, PermissionMappingRepository, PermissionMappingRepositoryBulk,
};

impl PermissionMappingRepository for SeaOrmRepository {
    type Error = RepoError;

    async fn store_mapping(
        &self,
        mapping: PermissionMapping,
    ) -> RepoResult<Option<PermissionMapping>> {
        let res: RepoResult<_> = {
            if let Err(e) = mapping.validate() {
                return Err(RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Insert,
                    format!("Invalid permission mapping: {}", e),
                    Some(TableName::AxumGatePermissionMappings.to_string()),
                    None,
                ))
                .into());
            }

            let active = seaorm_permission_mapping::ActiveModel::from(mapping.clone());
            seaorm_permission_mapping::Entity::insert(active)
                .on_conflict(
                    OnConflict::column(seaorm_permission_mapping::Column::PermissionId)
                        .do_nothing()
                        .to_owned(),
                )
                .exec(&self.db)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Insert,
                        format!("Failed to execute insert: {}", e),
                        Some(TableName::AxumGatePermissionMappings.to_string()),
                        None,
                    ))
                })?;

            let pid = mapping.permission_id().as_u64().to_string();
            let model_opt = seaorm_permission_mapping::Entity::find()
                .filter(seaorm_permission_mapping::Column::PermissionId.eq(pid.clone()))
                .one(&self.db)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!(
                            "Failed to query permission mapping by id after insert: {}",
                            e
                        ),
                        Some(TableName::AxumGatePermissionMappings.to_string()),
                        Some(pid.clone()),
                    ))
                })?;

            match model_opt {
                Some(model) => {
                    let domain = PermissionMapping::try_from(model).map_err(|e| {
                        RepoError::Database(DatabaseError::with_context(
                            DatabaseOperation::Insert,
                            format!("Failed to convert stored permission mapping: {}", e),
                            Some(TableName::AxumGatePermissionMappings.to_string()),
                            None,
                        ))
                    })?;
                    Ok(Some(domain))
                }
                None => Ok(None),
            }
        };
        res
    }

    async fn remove_mapping_by_id(
        &self,
        id: PermissionId,
    ) -> RepoResult<Option<PermissionMapping>> {
        let res: RepoResult<_> = {
            let id_str = id.as_u64().to_string();
            let txn = self.db.begin().await.map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Connect,
                    format!("Failed to begin transaction for delete: {}", e),
                    Some(TableName::AxumGatePermissionMappings.to_string()),
                    Some(id_str.clone()),
                ))
            })?;

            let model_opt = seaorm_permission_mapping::Entity::find()
                .filter(seaorm_permission_mapping::Column::PermissionId.eq(id_str.clone()))
                .one(&txn)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query permission mapping by id: {}", e),
                        Some(TableName::AxumGatePermissionMappings.to_string()),
                        Some(id_str.clone()),
                    ))
                })?;

            let model = match model_opt {
                Some(m) => m,
                None => {
                    txn.rollback().await.map_err(|e| {
                        RepoError::Database(DatabaseError::with_context(
                            DatabaseOperation::Delete,
                            format!("Failed to rollback transaction: {}", e),
                            Some(TableName::AxumGatePermissionMappings.to_string()),
                            Some(id_str.clone()),
                        ))
                    })?;
                    return Ok(None);
                }
            };

            seaorm_permission_mapping::Entity::delete_by_id(model.id)
                .exec(&txn)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Delete,
                        format!("Failed to delete permission mapping by id: {}", e),
                        Some(TableName::AxumGatePermissionMappings.to_string()),
                        Some(id_str.clone()),
                    ))
                })?;

            txn.commit().await.map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Delete,
                    format!("Failed to commit transaction for delete: {}", e),
                    Some(TableName::AxumGatePermissionMappings.to_string()),
                    Some(id_str.clone()),
                ))
            })?;

            let domain = PermissionMapping::try_from(model).map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Delete,
                    format!("Failed to convert deleted permission mapping: {}", e),
                    Some(TableName::AxumGatePermissionMappings.to_string()),
                    None,
                ))
            })?;
            Ok(Some(domain))
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

            let txn = self.db.begin().await.map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Connect,
                    format!("Failed to begin transaction: {}", e),
                    Some(TableName::AxumGatePermissionMappings.to_string()),
                    None,
                ))
            })?;

            let model_opt = seaorm_permission_mapping::Entity::find()
                .filter(seaorm_permission_mapping::Column::NormalizedString.eq(normalized.clone()))
                .one(&txn)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query permission mapping by string: {}", e),
                        Some(TableName::AxumGatePermissionMappings.to_string()),
                        None,
                    ))
                })?;

            let model = match model_opt {
                Some(m) => m,
                None => {
                    txn.rollback().await.map_err(|e| {
                        RepoError::Database(DatabaseError::with_context(
                            DatabaseOperation::Delete,
                            format!("Failed to rollback transaction: {}", e),
                            Some(TableName::AxumGatePermissionMappings.to_string()),
                            None,
                        ))
                    })?;
                    return Ok(None);
                }
            };

            seaorm_permission_mapping::Entity::delete_by_id(model.id)
                .exec(&txn)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Delete,
                        format!("Failed to delete permission mapping by string: {}", e),
                        Some(TableName::AxumGatePermissionMappings.to_string()),
                        Some(normalized.clone()),
                    ))
                })?;

            txn.commit().await.map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Delete,
                    format!("Failed to commit transaction: {}", e),
                    Some(TableName::AxumGatePermissionMappings.to_string()),
                    Some(normalized.clone()),
                ))
            })?;

            let domain = PermissionMapping::try_from(model).map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Delete,
                    format!("Failed to convert deleted permission mapping: {}", e),
                    Some(TableName::AxumGatePermissionMappings.to_string()),
                    None,
                ))
            })?;
            Ok(Some(domain))
        };
        res
    }

    async fn query_mapping_by_id(&self, id: PermissionId) -> RepoResult<Option<PermissionMapping>> {
        let res: RepoResult<_> = {
            let id_str = id.as_u64().to_string();
            let model = seaorm_permission_mapping::Entity::find()
                .filter(seaorm_permission_mapping::Column::PermissionId.eq(id_str.clone()))
                .one(&self.db)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query permission mapping by id: {}", e),
                        Some(TableName::AxumGatePermissionMappings.to_string()),
                        Some(id_str.clone()),
                    ))
                })?;

            match model {
                Some(m) => {
                    let domain = PermissionMapping::try_from(m).map_err(|e| {
                        RepoError::Database(DatabaseError::with_context(
                            DatabaseOperation::Query,
                            format!("Failed to convert model to permission mapping: {}", e),
                            Some(TableName::AxumGatePermissionMappings.to_string()),
                            Some(id_str.clone()),
                        ))
                    })?;
                    Ok(Some(domain))
                }
                None => Ok(None),
            }
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

            let model = seaorm_permission_mapping::Entity::find()
                .filter(seaorm_permission_mapping::Column::NormalizedString.eq(normalized.clone()))
                .one(&self.db)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query permission mapping by string: {}", e),
                        Some(TableName::AxumGatePermissionMappings.to_string()),
                        None,
                    ))
                })?;

            match model {
                Some(m) => {
                    let domain = PermissionMapping::try_from(m).map_err(|e| {
                        RepoError::Database(DatabaseError::with_context(
                            DatabaseOperation::Query,
                            format!("Failed to convert model to permission mapping: {}", e),
                            Some(TableName::AxumGatePermissionMappings.to_string()),
                            None,
                        ))
                    })?;
                    Ok(Some(domain))
                }
                None => Ok(None),
            }
        };
        res
    }

    async fn list_all_mappings(&self) -> RepoResult<Vec<PermissionMapping>> {
        let res: RepoResult<_> = {
            let models = seaorm_permission_mapping::Entity::find()
                .order_by_asc(seaorm_permission_mapping::Column::PermissionId)
                .all(&self.db)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to list permission mappings: {}", e),
                        Some(TableName::AxumGatePermissionMappings.to_string()),
                        None,
                    ))
                })?;

            let mut out = Vec::with_capacity(models.len());
            for m in models {
                let domain = PermissionMapping::try_from(m).map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to convert model to permission mapping: {}", e),
                        Some(TableName::AxumGatePermissionMappings.to_string()),
                        None,
                    ))
                })?;
                out.push(domain);
            }
            Ok(out)
        };
        res
    }
}

impl PermissionMappingRepositoryBulk for SeaOrmRepository {
    async fn store_mappings(
        &self,
        mappings: Vec<PermissionMapping>,
    ) -> RepoResult<Vec<PermissionMapping>> {
        let res: RepoResult<_> = {
            for mapping in &mappings {
                if let Err(e) = mapping.validate() {
                    return Err(RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Insert,
                        format!("Invalid permission mapping in bulk store: {}", e),
                        Some(TableName::AxumGatePermissionMappings.to_string()),
                        None,
                    ))
                    .into());
                }
            }

            let mut stored = Vec::new();
            let txn = self.db.begin().await.map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Connect,
                    format!("Failed to begin transaction for bulk store: {}", e),
                    Some(TableName::AxumGatePermissionMappings.to_string()),
                    None,
                ))
            })?;

            for mapping in mappings {
                let id_str = mapping.permission_id().as_u64().to_string();

                let exists = seaorm_permission_mapping::Entity::find()
                    .filter(seaorm_permission_mapping::Column::PermissionId.eq(id_str.clone()))
                    .one(&txn)
                    .await
                    .map_err(|e| {
                        RepoError::Database(DatabaseError::with_context(
                            DatabaseOperation::Query,
                            format!("Failed to query permission mapping in bulk store: {}", e),
                            Some(TableName::AxumGatePermissionMappings.to_string()),
                            Some(id_str.clone()),
                        ))
                    })?;

                if exists.is_some() {
                    continue;
                }

                let active = seaorm_permission_mapping::ActiveModel::from(mapping.clone());
                active.insert(&txn).await.map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Insert,
                        format!("Failed to insert permission mapping in bulk store: {}", e),
                        Some(TableName::AxumGatePermissionMappings.to_string()),
                        Some(id_str.clone()),
                    ))
                })?;

                stored.push(mapping);
            }

            txn.commit().await.map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Insert,
                    format!("Failed to commit bulk store transaction: {}", e),
                    Some(TableName::AxumGatePermissionMappings.to_string()),
                    None,
                ))
            })?;

            Ok(stored)
        };
        res
    }

    async fn remove_mappings_by_ids(
        &self,
        ids: Vec<PermissionId>,
    ) -> RepoResult<Vec<PermissionMapping>> {
        let mut removed = Vec::new();

        for id in ids {
            if let Some(pm) = self.remove_mapping_by_id(id).await? {
                removed.push(pm);
            }
        }

        Ok(removed)
    }

    async fn query_mappings_by_ids(
        &self,
        ids: Vec<PermissionId>,
    ) -> RepoResult<Vec<PermissionMapping>> {
        let mut out = Vec::new();
        for id in ids {
            if let Some(pm) = self.query_mapping_by_id(id).await? {
                out.push(pm);
            }
        }
        Ok(out)
    }
}
