use super::SurrealDbRepository;
use crate::errors::{DatabaseError, DatabaseOperation, Error as RepoError, Result};
use webgates::accounts::{Account, AccountRepository};
use webgates::authz::AccessHierarchy;

use serde::Serialize;
use serde::de::DeserializeOwned;
use surrealdb::{Connection, RecordId};
use uuid::Uuid;

impl<R, G, S> AccountRepository<R, G> for SurrealDbRepository<S>
where
    R: AccessHierarchy + Eq + DeserializeOwned + Serialize + Send + Sync + 'static,
    G: Serialize + DeserializeOwned + Eq + Clone + Send + Sync + 'static,
    S: Connection,
{
    type Error = RepoError;
    async fn query_account_by_user_id(&self, user_id: &str) -> Result<Option<Account<R, G>>> {
        let res: Result<_> = {
            self.use_ns_db().await?;

            let query = "SELECT * FROM type::table($table) WHERE user_id = $uid LIMIT 1";
            let mut db_res = self
                .db
                .query(query)
                .bind(("table", self.scope_settings.accounts.clone()))
                .bind(("uid", user_id.to_string()))
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query account by user_id: {}", e),
                        Some(self.scope_settings.accounts.clone()),
                        Some(user_id.to_string()),
                    ))
                })?;

            db_res.take::<Option<Account<R, G>>>(0).map_err(|e| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Query,
                    format!("Failed to extract account by user_id: {}", e),
                    Some(self.scope_settings.accounts.clone()),
                    Some(user_id.to_string()),
                ))
            })
        };
        res
    }

    async fn query_account_by_id(&self, account_id: &Uuid) -> Result<Option<Account<R, G>>> {
        let res: Result<_> = {
            self.use_ns_db().await?;

            let db_account: Option<Account<R, G>> = self
                .db
                .select(RecordId::from_table_key(
                    &self.scope_settings.accounts,
                    *account_id,
                ))
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query account by account_id: {}", e),
                        Some(self.scope_settings.accounts.clone()),
                        Some(account_id.to_string()),
                    ))
                })?;
            Ok(db_account)
        };
        res
    }

    async fn store_account(&self, account: Account<R, G>) -> Result<Option<Account<R, G>>> {
        let res: Result<_> = {
            self.use_ns_db().await?;

            let record_id =
                RecordId::from_table_key(self.scope_settings.accounts.clone(), account.account_id);
            let user_id = account.user_id.clone();
            let db_account: Option<Account<R, G>> = self
                .db
                .insert(record_id)
                .content(account)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Insert,
                        format!("Could not insert account: {}", e),
                        Some(self.scope_settings.accounts.clone()),
                        Some(user_id),
                    ))
                })?;
            Ok(db_account)
        };
        res
    }

    async fn delete_account(&self, account_id: &Uuid) -> Result<Option<Account<R, G>>> {
        let res: Result<_> = {
            self.use_ns_db().await?;

            let db_account: Option<Account<R, G>> = self
                .db
                .delete(RecordId::from_table_key(
                    self.scope_settings.accounts.clone(),
                    *account_id,
                ))
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Delete,
                        format!("Failed to delete account: {}", e),
                        Some(self.scope_settings.accounts.clone()),
                        Some(account_id.to_string()),
                    ))
                })?;
            Ok(db_account)
        };
        res
    }

    async fn update_account(&self, account: Account<R, G>) -> Result<Option<Account<R, G>>> {
        let res: Result<_> = {
            self.use_ns_db().await?;

            let record_id =
                RecordId::from_table_key(self.scope_settings.accounts.clone(), account.account_id);
            let db_account: Option<Account<R, G>> = self
                .db
                .update(&record_id)
                .content(account)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Update,
                        format!("Failed to update account: {}", e),
                        Some(self.scope_settings.accounts.clone()),
                        Some(record_id.to_string()),
                    ))
                })?;
            Ok(db_account)
        };
        res
    }

    async fn query_all_accounts(&self) -> Result<Vec<Account<R, G>>> {
        let res: Result<_> = {
            self.use_ns_db().await?;

            let db_accounts: Vec<Account<R, G>> = self
                .db
                .select(self.scope_settings.accounts.clone())
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query all accounts: {}", e),
                        Some(self.scope_settings.accounts.clone()),
                        None,
                    ))
                })?;
            Ok(db_accounts)
        };
        res
    }
}
