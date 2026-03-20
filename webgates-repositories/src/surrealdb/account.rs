use super::SurrealDbRepository;
use crate::TableName;
use crate::account_repository::AccountRepository;
use crate::errors::{DatabaseError, DatabaseOperation, Error as RepoError, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use surrealdb::Connection;
use surrealdb_types::{RecordId, RecordIdKey, SurrealValue, Uuid as SurrealUuid};
use uuid::Uuid;
use webgates_core::accounts::Account;
use webgates_core::authz::AccessHierarchy;
use webgates_core::permissions::{PermissionId, Permissions};

#[derive(Clone, Debug, Serialize, Deserialize, SurrealValue)]
pub struct SurrealAccountRecord {
    account_id: Uuid,
    user_id: String,
    roles: Vec<Value>,
    groups: Vec<Value>,
    permissions: PersistedPermissions,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, SurrealValue)]
pub struct PersistedPermissions {
    permission_ids: Vec<i64>,
}

impl PersistedPermissions {
    fn from_permissions(permissions: &Permissions) -> Self {
        let permission_ids = permissions
            .iter()
            .map(|permission_id| permission_id as i64)
            .collect();

        Self { permission_ids }
    }

    fn into_permissions(self) -> Permissions {
        self.permission_ids.into_iter().fold(
            Permissions::new(),
            |mut permissions, permission_id| {
                permissions.grant(PermissionId::from_u64(permission_id as u64));
                permissions
            },
        )
    }
}

fn serialize_adapter_value<T>(
    value: T,
    field_name: &str,
    table_name: &str,
    record_id: &str,
) -> Result<Value>
where
    T: Serialize,
{
    serde_json::to_value(value).map_err(|error| {
        RepoError::Database(DatabaseError::with_context(
            DatabaseOperation::Insert,
            format!("Failed to serialize account {field_name}: {error}"),
            Some(table_name.to_string()),
            Some(record_id.to_string()),
        ))
    })
}

fn deserialize_adapter_value<T>(
    value: Value,
    field_name: &str,
    table_name: &str,
    record_id: &str,
) -> Result<T>
where
    T: DeserializeOwned,
{
    serde_json::from_value(value).map_err(|error| {
        RepoError::Database(DatabaseError::with_context(
            DatabaseOperation::Query,
            format!("Failed to deserialize account {field_name}: {error}"),
            Some(table_name.to_string()),
            Some(record_id.to_string()),
        ))
    })
}

fn account_to_record<R, G>(account: Account<R, G>, table_name: &str) -> Result<SurrealAccountRecord>
where
    R: AccessHierarchy + Eq + Serialize,
    G: Eq + Clone + Serialize,
{
    let record_id = account.account_id.to_string();
    let roles = account
        .roles
        .into_iter()
        .map(|role| serialize_adapter_value(role, "roles", table_name, &record_id))
        .collect::<Result<Vec<_>>>()?;
    let groups = account
        .groups
        .into_iter()
        .map(|group| serialize_adapter_value(group, "groups", table_name, &record_id))
        .collect::<Result<Vec<_>>>()?;

    Ok(SurrealAccountRecord {
        account_id: account.account_id,
        user_id: account.user_id,
        roles,
        groups,
        permissions: PersistedPermissions::from_permissions(&account.permissions),
    })
}

fn record_to_account<R, G>(record: SurrealAccountRecord, table_name: &str) -> Result<Account<R, G>>
where
    R: AccessHierarchy + Eq + DeserializeOwned,
    G: Eq + Clone + DeserializeOwned,
{
    let record_id = record.account_id.to_string();
    let roles = record
        .roles
        .into_iter()
        .map(|role| deserialize_adapter_value(role, "roles", table_name, &record_id))
        .collect::<Result<Vec<_>>>()?;
    let groups = record
        .groups
        .into_iter()
        .map(|group| deserialize_adapter_value(group, "groups", table_name, &record_id))
        .collect::<Result<Vec<_>>>()?;

    Ok(Account {
        account_id: record.account_id,
        user_id: record.user_id,
        roles,
        groups,
        permissions: record.permissions.into_permissions(),
    })
}

impl<R, G, S> AccountRepository<R, G> for SurrealDbRepository<S>
where
    R: AccessHierarchy + Eq + DeserializeOwned + Serialize + Send + Sync + 'static,
    G: Serialize + DeserializeOwned + Eq + Clone + Send + Sync + 'static,
    S: Connection,
{
    type Error = RepoError;

    async fn bootstrap(&self) -> Result<()> {
        self.use_ns_db().await?;

        let table_name = TableName::WebgatesAccounts.to_string();
        let query = "DEFINE TABLE IF NOT EXISTS $table SCHEMALESS;";

        self.db
            .query(query)
            .bind(("table", table_name.clone()))
            .await
            .map_err(|error| {
                RepoError::Database(DatabaseError::with_context(
                    DatabaseOperation::Insert,
                    format!("Failed to bootstrap account table: {error}"),
                    Some(table_name),
                    None,
                ))
            })?;

        Ok(())
    }

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

            let account = db_res
                .take::<Option<SurrealAccountRecord>>(0)
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to extract account by user_id: {}", e),
                        Some(self.scope_settings.accounts.clone()),
                        Some(user_id.to_string()),
                    ))
                })?;

            match account {
                Some(account) => Ok(Some(record_to_account(
                    account,
                    &self.scope_settings.accounts,
                )?)),
                None => Ok(None),
            }
        };
        res
    }

    async fn query_account_by_id(&self, account_id: &Uuid) -> Result<Option<Account<R, G>>> {
        let res: Result<_> = {
            self.use_ns_db().await?;

            let record_id = account_record_id(&self.scope_settings.accounts, *account_id);
            let db_account: Option<SurrealAccountRecord> =
                self.db.select(record_id).await.map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query account by account_id: {}", e),
                        Some(self.scope_settings.accounts.clone()),
                        Some(account_id.to_string()),
                    ))
                })?;

            match db_account {
                Some(account) => Ok(Some(record_to_account(
                    account,
                    &self.scope_settings.accounts,
                )?)),
                None => Ok(None),
            }
        };
        res
    }

    async fn store_account(&self, account: Account<R, G>) -> Result<Option<Account<R, G>>> {
        let res: Result<_> = {
            self.use_ns_db().await?;

            let record = account_to_record(account, &self.scope_settings.accounts)?;
            let account_id = record.account_id;
            let user_id = record.user_id.clone();

            let existing_by_id = account_record_id(&self.scope_settings.accounts, account_id);
            let existing_account_by_id: Option<SurrealAccountRecord> =
                self.db.select(existing_by_id).await.map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query account by account_id before insert: {}", e),
                        Some(self.scope_settings.accounts.clone()),
                        Some(account_id.to_string()),
                    ))
                })?;

            if existing_account_by_id.is_some() {
                return Ok(None);
            }

            let user_lookup_query =
                "SELECT * FROM type::table($table) WHERE user_id = $uid LIMIT 1";
            let mut existing_by_user_response = self
                .db
                .query(user_lookup_query)
                .bind(("table", self.scope_settings.accounts.clone()))
                .bind(("uid", user_id.clone()))
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query account by user_id before insert: {}", e),
                        Some(self.scope_settings.accounts.clone()),
                        Some(user_id.clone()),
                    ))
                })?;

            let existing_account_by_user = existing_by_user_response
                .take::<Option<SurrealAccountRecord>>(0)
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to extract account by user_id before insert: {}", e),
                        Some(self.scope_settings.accounts.clone()),
                        Some(user_id.clone()),
                    ))
                })?;

            if existing_account_by_user.is_some() {
                return Ok(None);
            }

            let record_id = account_record_id(&self.scope_settings.accounts, account_id);
            let db_account: Option<SurrealAccountRecord> = self
                .db
                .insert(record_id)
                .content(record)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Insert,
                        format!("Could not insert account: {}", e),
                        Some(self.scope_settings.accounts.clone()),
                        Some(user_id),
                    ))
                })?;

            match db_account {
                Some(account) => Ok(Some(record_to_account(
                    account,
                    &self.scope_settings.accounts,
                )?)),
                None => Ok(None),
            }
        };
        res
    }

    async fn delete_account(&self, account_id: &Uuid) -> Result<Option<Account<R, G>>> {
        let res: Result<_> = {
            self.use_ns_db().await?;

            let record_id = account_record_id(&self.scope_settings.accounts, *account_id);
            let db_account: Option<SurrealAccountRecord> =
                self.db.delete(record_id).await.map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Delete,
                        format!("Failed to delete account: {}", e),
                        Some(self.scope_settings.accounts.clone()),
                        Some(account_id.to_string()),
                    ))
                })?;

            match db_account {
                Some(account) => Ok(Some(record_to_account(
                    account,
                    &self.scope_settings.accounts,
                )?)),
                None => Ok(None),
            }
        };
        res
    }

    async fn update_account(&self, account: Account<R, G>) -> Result<Option<Account<R, G>>> {
        let res: Result<_> = {
            self.use_ns_db().await?;

            let record = account_to_record(account, &self.scope_settings.accounts)?;
            let record_account_id = record.account_id;
            let record_id = account_record_id(&self.scope_settings.accounts, record_account_id);
            let db_account: Option<SurrealAccountRecord> = self
                .db
                .update(&record_id)
                .content(record)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Update,
                        format!("Failed to update account: {}", e),
                        Some(self.scope_settings.accounts.clone()),
                        Some(record_account_id.to_string()),
                    ))
                })?;

            match db_account {
                Some(account) => Ok(Some(record_to_account(
                    account,
                    &self.scope_settings.accounts,
                )?)),
                None => Ok(None),
            }
        };
        res
    }

    async fn query_all_accounts(&self) -> Result<Vec<Account<R, G>>> {
        let res: Result<_> = {
            self.use_ns_db().await?;

            let db_accounts: Vec<SurrealAccountRecord> = self
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

            db_accounts
                .into_iter()
                .map(|account| record_to_account(account, &self.scope_settings.accounts))
                .collect::<Result<Vec<_>>>()
        };
        res
    }
}

fn account_record_id(table_name: &str, account_id: Uuid) -> RecordId {
    RecordId::new(
        table_name.to_string(),
        RecordIdKey::from(SurrealUuid::from(account_id)),
    )
}

#[cfg(test)]
mod tests {
    use super::{PersistedPermissions, SurrealAccountRecord, account_to_record, record_to_account};
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use uuid::Uuid;
    use webgates_core::accounts::Account;
    use webgates_core::authz::AccessHierarchy;
    use webgates_core::groups::Group;
    use webgates_core::permissions::{PermissionId, Permissions};
    use webgates_core::roles::Role;

    #[derive(
        Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
    )]
    enum StructuredRole {
        #[default]
        User,
        Admin,
    }

    impl AccessHierarchy for StructuredRole {}

    #[test]
    fn persisted_permissions_round_trip() {
        let permissions = Permissions::new()
            .with("read:account")
            .with("write:account")
            .build();

        let persisted = PersistedPermissions::from_permissions(&permissions);
        let restored = persisted.into_permissions();

        assert!(restored.has("read:account"));
        assert!(restored.has("write:account"));
        assert_eq!(restored, permissions);
    }

    #[test]
    fn persisted_permissions_round_trip_signed_ids() {
        let permissions = Permissions::new()
            .with("read:account")
            .with("write:account")
            .build();

        let persisted = PersistedPermissions {
            permission_ids: permissions
                .iter()
                .map(|permission_id| permission_id as i64)
                .collect(),
        };
        let restored = persisted.into_permissions();

        assert!(restored.has("read:account"));
        assert!(restored.has("write:account"));
        assert_eq!(restored, permissions);
    }

    #[test]
    fn account_record_round_trips_structured_roles_and_groups() {
        let mut account = Account::new(
            "user@example.com".to_string(),
            vec![StructuredRole::Admin],
            vec![Group::new("engineering")],
        );
        account.account_id = Uuid::now_v7();
        account.grant_permission("read:account");
        account.grant_permission("write:account");

        let record = account_to_record(account.clone(), "webgates_accounts").unwrap();
        assert_eq!(record.roles, vec![json!("Admin")]);
        assert_eq!(record.groups, vec![json!("engineering")]);

        let restored =
            record_to_account::<StructuredRole, Group>(record, "webgates_accounts").unwrap();

        assert_eq!(restored, account);
    }

    #[test]
    fn record_to_account_reports_invalid_role_payloads() {
        let record = SurrealAccountRecord {
            account_id: Uuid::now_v7(),
            user_id: "user@example.com".to_string(),
            roles: vec![json!({"unexpected": true})],
            groups: vec![json!("engineering")],
            permissions: PersistedPermissions {
                permission_ids: vec![PermissionId::from("read:account").as_u64() as i64],
            },
        };

        let error = record_to_account::<StructuredRole, Group>(record, "webgates_accounts")
            .expect_err("invalid role payload should fail");

        assert!(
            error
                .to_string()
                .contains("Failed to deserialize account roles"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn record_to_account_round_trips_builtin_role_type() {
        let mut account = Account::new(
            "user@example.com".to_string(),
            vec![Role::User],
            vec![Group::new("engineering")],
        );
        account.account_id = Uuid::now_v7();
        account.grant_permission("read:account");

        let record = account_to_record(account.clone(), "webgates_accounts").unwrap();
        let restored = record_to_account::<Role, Group>(record, "webgates_accounts").unwrap();

        assert_eq!(restored, account);
    }
}
