use super::SeaOrmRepository;
use crate::TableName;
use crate::account_repository::AccountRepository;
use crate::comma_separated_value::CommaSeparatedValue;
use crate::errors::{DatabaseError, DatabaseOperation, Error as RepoError, Result};
use crate::sea_orm::models::account as seaorm_account;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder,
    Schema,
    entity::{ActiveModelTrait, ActiveValue},
};
use serde::{Serialize, de::DeserializeOwned};
use uuid::Uuid;
use webgates_core::accounts::Account;
use webgates_core::authz::access_hierarchy::AccessHierarchy;

/// Helper to convert a SeaORM model into the domain `Account`.
fn model_to_account<R, G>(model: seaorm_account::Model) -> Result<Account<R, G>>
where
    R: AccessHierarchy + Eq + Clone + Default + Serialize + DeserializeOwned,
    G: Eq + Clone + Serialize + DeserializeOwned,
    Vec<R>: CommaSeparatedValue,
    Vec<G>: CommaSeparatedValue,
{
    let roles = Vec::<R>::from_csv(&model.roles).map_err(|e| {
        RepoError::Database(DatabaseError::with_context(
            DatabaseOperation::Query,
            format!("Failed to parse roles csv: {}", e),
            Some(TableName::WebgatesAccounts.to_string()),
            Some(model.user_id.clone()),
        ))
    })?;
    let groups = Vec::<G>::from_csv(&model.groups).map_err(|e| {
        RepoError::Database(DatabaseError::with_context(
            DatabaseOperation::Query,
            format!("Failed to parse groups csv: {}", e),
            Some(TableName::WebgatesAccounts.to_string()),
            Some(model.user_id.clone()),
        ))
    })?;

    let mut account = Account::new(&model.user_id);
    account.account_id = model.account_id;
    account.roles = roles;
    account.groups = groups;
    Ok(account)
}

impl<R, G> AccountRepository<R, G> for SeaOrmRepository
where
    R: AccessHierarchy
        + Eq
        + Serialize
        + DeserializeOwned
        + std::fmt::Display
        + Clone
        + Send
        + Sync
        + 'static,
    G: Eq + Clone + Serialize + DeserializeOwned + Send + Sync + 'static,
    Vec<R>: CommaSeparatedValue,
    Vec<G>: CommaSeparatedValue,
{
    type Error = RepoError;

    async fn bootstrap(&self) -> Result<()> {
        let builder = self.db.get_database_backend();
        let schema = Schema::new(match builder {
            DbBackend::MySql => DbBackend::MySql,
            DbBackend::Postgres => DbBackend::Postgres,
            DbBackend::Sqlite => DbBackend::Sqlite,
            _ => builder,
        });

        let statement = schema.create_table_from_entity(seaorm_account::Entity);
        self.db.execute(&statement).await.map_err(|error| {
            RepoError::Database(DatabaseError::with_context(
                DatabaseOperation::Insert,
                format!("Failed to bootstrap account table: {}", error),
                Some(TableName::WebgatesAccounts.to_string()),
                None,
            ))
        })?;

        Ok(())
    }

    async fn query_account_by_user_id(&self, user_id: &str) -> Result<Option<Account<R, G>>> {
        let res: Result<_> = {
            let model = seaorm_account::Entity::find()
                .filter(seaorm_account::Column::UserId.eq(user_id))
                .one(&self.db)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query account by user_id: {}", e),
                        Some(TableName::WebgatesAccounts.to_string()),
                        Some(user_id.to_string()),
                    ))
                })?;

            match model {
                Some(m) => Ok(Some(model_to_account(m)?)),
                None => Ok(None),
            }
        };
        res
    }

    async fn query_account_by_id(&self, account_id: &Uuid) -> Result<Option<Account<R, G>>> {
        let res: Result<_> = {
            let model = seaorm_account::Entity::find()
                .filter(seaorm_account::Column::AccountId.eq(*account_id))
                .one(&self.db)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query account by account_id: {}", e),
                        Some(TableName::WebgatesAccounts.to_string()),
                        Some(account_id.to_string()),
                    ))
                })?;

            match model {
                Some(m) => Ok(Some(model_to_account(m)?)),
                None => Ok(None),
            }
        };
        res
    }

    async fn store_account(&self, account: Account<R, G>) -> Result<Option<Account<R, G>>> {
        let res: Result<_> = {
            let account_id = account.account_id;
            let user_id = account.user_id.clone();

            let existing_by_account_id = seaorm_account::Entity::find()
                .filter(seaorm_account::Column::AccountId.eq(account_id))
                .one(&self.db)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to check account_id uniqueness: {}", e),
                        Some(TableName::WebgatesAccounts.to_string()),
                        Some(account_id.to_string()),
                    ))
                })?;

            if existing_by_account_id.is_some() {
                return Ok(None);
            }

            let existing_by_user_id = seaorm_account::Entity::find()
                .filter(seaorm_account::Column::UserId.eq(user_id.clone()))
                .one(&self.db)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to check user_id uniqueness: {}", e),
                        Some(TableName::WebgatesAccounts.to_string()),
                        Some(user_id.clone()),
                    ))
                })?;

            if existing_by_user_id.is_some() {
                return Ok(None);
            }

            let mut model = seaorm_account::ActiveModel::from(account.clone());
            model.id = ActiveValue::NotSet;

            let inserted = model.insert(&self.db).await.map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Insert,
                    format!("Failed to insert account: {}", e),
                    Some(TableName::WebgatesAccounts.to_string()),
                    Some(user_id),
                ))
            })?;

            Ok(Some(model_to_account(inserted)?))
        };
        res
    }

    async fn delete_account(&self, account_id: &Uuid) -> Result<Option<Account<R, G>>> {
        let res: Result<_> = {
            let Some(model) = seaorm_account::Entity::find()
                .filter(seaorm_account::Column::AccountId.eq(*account_id))
                .one(&self.db)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query account for deletion: {}", e),
                        Some(TableName::WebgatesAccounts.to_string()),
                        Some(account_id.to_string()),
                    ))
                })?
            else {
                return Ok(None);
            };

            seaorm_account::Entity::delete_by_id(model.id)
                .exec(&self.db)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Delete,
                        format!("Failed to delete account: {}", e),
                        Some(TableName::WebgatesAccounts.to_string()),
                        Some(account_id.to_string()),
                    ))
                })?;

            Ok(Some(model_to_account(model)?))
        };
        res
    }

    async fn update_account(&self, account: Account<R, G>) -> Result<Option<Account<R, G>>> {
        let res: Result<_> = {
            let account_id = account.account_id;
            let user_id = account.user_id.clone();

            let Some(db_account) = seaorm_account::Entity::find()
                .filter(seaorm_account::Column::AccountId.eq(account_id))
                .one(&self.db)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query account for update: {}", e),
                        Some(TableName::WebgatesAccounts.to_string()),
                        Some(account_id.to_string()),
                    ))
                })?
            else {
                return Ok(None);
            };

            let conflicting_user = seaorm_account::Entity::find()
                .filter(seaorm_account::Column::UserId.eq(user_id.clone()))
                .one(&self.db)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to check user_id uniqueness for update: {}", e),
                        Some(TableName::WebgatesAccounts.to_string()),
                        Some(user_id.clone()),
                    ))
                })?;

            if let Some(conflicting_user) = conflicting_user
                && conflicting_user.account_id != account_id
            {
                return Ok(None);
            }

            let mut db_account = db_account.into_active_model();
            db_account.user_id = ActiveValue::Set(account.user_id);
            db_account.groups = ActiveValue::Set(account.groups.into_csv());
            db_account.roles = ActiveValue::Set(account.roles.into_csv());

            let model = db_account.update(&self.db).await.map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Update,
                    format!("Failed to update account: {}", e),
                    Some(TableName::WebgatesAccounts.to_string()),
                    Some(user_id.clone()),
                ))
            })?;

            Ok(Some(model_to_account(model)?))
        };
        res
    }

    async fn query_all_accounts(&self) -> Result<Vec<Account<R, G>>> {
        let res: Result<_> = {
            let models = seaorm_account::Entity::find()
                .order_by_asc(seaorm_account::Column::UserId)
                .all(&self.db)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query all accounts: {}", e),
                        Some(TableName::WebgatesAccounts.to_string()),
                        None,
                    ))
                })?;

            let mut out = Vec::with_capacity(models.len());
            for model in models {
                out.push(model_to_account(model)?);
            }
            Ok(out)
        };
        res
    }
}
