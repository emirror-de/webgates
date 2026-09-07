//! SurrealDB-backed account repository adapter.
//!
//! This module defines the SurrealDB persistence shapes used for accounts and
//! the conversions between persisted records and the domain-level `Account`
//! type used by the repository boundary.

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
use webgates_core::authz::access_hierarchy::AccessHierarchy;
use webgates_core::permissions::Permissions;
use webgates_core::permissions::permission_id::PermissionId;

/// SurrealDB persistence record for a stored account.
///
/// This type captures the serialized account payload as it is written to and
/// read from the SurrealDB account table.
#[derive(Clone, Debug, Serialize, Deserialize, SurrealValue)]
pub struct SurrealAccountRecord {
    account_id: Uuid,
    user_id: String,
    roles: Vec<Value>,
    groups: Vec<Value>,
    permissions: PersistedPermissions,
}

impl SurrealAccountRecord {
    /// Creates a new SurrealDB account persistence record.
    pub fn new(
        account_id: Uuid,
        user_id: String,
        roles: Vec<Value>,
        groups: Vec<Value>,
        permissions: PersistedPermissions,
    ) -> Self {
        Self {
            account_id,
            user_id,
            roles,
            groups,
            permissions,
        }
    }
}

/// SurrealDB-friendly representation of an account's granted permissions.
///
/// Permission ids are stored as signed 64-bit integers to match the persisted
/// SurrealDB representation used by this repository adapter.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, SurrealValue)]
pub struct PersistedPermissions {
    permission_ids: Vec<i64>,
}

impl From<&Permissions> for PersistedPermissions {
    fn from(permissions: &Permissions) -> Self {
        let permission_ids = permissions
            .iter()
            .map(|permission_id| permission_id as i64)
            .collect();

        Self { permission_ids }
    }
}

impl From<PersistedPermissions> for Permissions {
    fn from(value: PersistedPermissions) -> Self {
        value.permission_ids.into_iter().fold(
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

impl<R, G> TryFrom<Account<R, G>> for SurrealAccountRecord
where
    R: AccessHierarchy + Eq + Serialize,
    G: Eq + Clone + Serialize,
{
    type Error = RepoError;

    fn try_from(account: Account<R, G>) -> Result<Self> {
        let record_id = account.account_id.to_string();
        let roles = account
            .roles
            .into_iter()
            .map(|role| {
                serialize_adapter_value(
                    role,
                    "roles",
                    &TableName::WebgatesAccounts.to_string(),
                    &record_id,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let groups = account
            .groups
            .into_iter()
            .map(|group| {
                serialize_adapter_value(
                    group,
                    "groups",
                    &TableName::WebgatesAccounts.to_string(),
                    &record_id,
                )
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self::new(
            account.account_id,
            account.user_id,
            roles,
            groups,
            PersistedPermissions::from(&account.permissions),
        ))
    }
}

impl<R, G> TryFrom<SurrealAccountRecord> for Account<R, G>
where
    R: AccessHierarchy + Eq + Default + DeserializeOwned,
    G: Eq + Clone + DeserializeOwned,
{
    type Error = RepoError;

    fn try_from(record: SurrealAccountRecord) -> Result<Self> {
        let record_id = record.account_id.to_string();
        let roles = record
            .roles
            .into_iter()
            .map(|role| {
                deserialize_adapter_value(
                    role,
                    "roles",
                    &TableName::WebgatesAccounts.to_string(),
                    &record_id,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let groups = record
            .groups
            .into_iter()
            .map(|group| {
                deserialize_adapter_value(
                    group,
                    "groups",
                    &TableName::WebgatesAccounts.to_string(),
                    &record_id,
                )
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            account_id: record.account_id,
            user_id: record.user_id,
            roles,
            groups,
            permissions: Permissions::from(record.permissions),
        })
    }
}

impl<R, G, S> AccountRepository<R, G> for SurrealDbRepository<S>
where
    R: AccessHierarchy + Eq + Default + DeserializeOwned + Serialize + Send + Sync + 'static,
    G: Serialize + DeserializeOwned + Eq + Clone + Send + Sync + 'static,
    S: Connection,
{
    type Error = RepoError;

    async fn bootstrap(&self) -> Result<()> {
        let repo = self.use_ns_db().await?;

        repo.account_schema_initialized
            .get_or_try_init(|| async {
                let table_name = repo.scope_settings.accounts.clone();
                let query = "DEFINE TABLE IF NOT EXISTS $table SCHEMALESS;";

                repo.db
                    .query(query)
                    .bind(("table", table_name.clone()))
                    .await
                    .map_err(|error| {
                        RepoError::Database(DatabaseError::with_context(
                            DatabaseOperation::Insert,
                            format!("Failed to bootstrap account table: {error}"),
                            Some(table_name.clone()),
                            None,
                        ))
                    })?;

                let define_user_id_index = format!(
                    "DEFINE INDEX IF NOT EXISTS webgates_accounts_user_id_idx ON {} FIELDS user_id UNIQUE",
                    table_name
                );
                repo.db
                    .query(define_user_id_index)
                    .await
                    .map_err(|error| {
                        RepoError::Database(DatabaseError::with_context(
                            DatabaseOperation::Insert,
                            format!("Failed to bootstrap account user_id index: {error}"),
                            Some(table_name),
                            None,
                        ))
                    })?;

                Ok::<(), RepoError>(())
            })
            .await?;

        Ok(())
    }

    async fn query_account_by_user_id(&self, user_id: &str) -> Result<Option<Account<R, G>>> {
        let res: Result<_> = {
            let repo = self.use_ns_db().await?;

            let query = "SELECT * FROM type::table($table) WHERE user_id = $uid LIMIT 1";
            let mut db_res = repo
                .db
                .query(query)
                .bind(("table", repo.scope_settings.accounts.clone()))
                .bind(("uid", user_id.to_string()))
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query account by user_id: {}", e),
                        Some(repo.scope_settings.accounts.clone()),
                        Some(user_id.to_string()),
                    ))
                })?;

            let account = db_res
                .take::<Option<SurrealAccountRecord>>(0)
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to extract account by user_id: {}", e),
                        Some(repo.scope_settings.accounts.clone()),
                        Some(user_id.to_string()),
                    ))
                })?;

            account.map(Account::try_from).transpose()
        };
        res
    }

    async fn query_account_by_id(&self, account_id: &Uuid) -> Result<Option<Account<R, G>>> {
        let res: Result<_> = {
            let repo = self.use_ns_db().await?;

            let record_id = account_record_id(&repo.scope_settings.accounts, *account_id);
            let db_account: Option<SurrealAccountRecord> =
                repo.db.select(record_id).await.map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query account by account_id: {}", e),
                        Some(repo.scope_settings.accounts.clone()),
                        Some(account_id.to_string()),
                    ))
                })?;

            db_account.map(Account::try_from).transpose()
        };
        res
    }

    async fn store_account(&self, account: Account<R, G>) -> Result<Option<Account<R, G>>> {
        let res: Result<_> = {
            let repo = self.use_ns_db().await?;

            let record = SurrealAccountRecord::try_from(account)?;
            let account_id = record.account_id;
            let user_id = record.user_id.clone();

            let existing_by_id = account_record_id(&repo.scope_settings.accounts, account_id);
            let existing_account_by_id: Option<SurrealAccountRecord> =
                repo.db.select(existing_by_id).await.map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query account by account_id before insert: {}", e),
                        Some(repo.scope_settings.accounts.clone()),
                        Some(account_id.to_string()),
                    ))
                })?;

            if existing_account_by_id.is_some() {
                return Ok(None);
            }

            let user_lookup_query =
                "SELECT * FROM type::table($table) WHERE user_id = $uid LIMIT 1";
            let mut existing_by_user_response = repo
                .db
                .query(user_lookup_query)
                .bind(("table", repo.scope_settings.accounts.clone()))
                .bind(("uid", user_id.clone()))
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query account by user_id before insert: {}", e),
                        Some(repo.scope_settings.accounts.clone()),
                        Some(user_id.clone()),
                    ))
                })?;

            let existing_account_by_user = existing_by_user_response
                .take::<Option<SurrealAccountRecord>>(0)
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to extract account by user_id before insert: {}", e),
                        Some(repo.scope_settings.accounts.clone()),
                        Some(user_id.clone()),
                    ))
                })?;

            if existing_account_by_user.is_some() {
                return Ok(None);
            }

            let record_id = account_record_id(&repo.scope_settings.accounts, account_id);
            let db_account: Option<SurrealAccountRecord> = repo
                .db
                .insert(record_id)
                .content(record)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Insert,
                        format!("Could not insert account: {}", e),
                        Some(repo.scope_settings.accounts.clone()),
                        Some(user_id),
                    ))
                })?;

            db_account.map(Account::try_from).transpose()
        };
        res
    }

    async fn delete_account(&self, account_id: &Uuid) -> Result<Option<Account<R, G>>> {
        let res: Result<_> = {
            let repo = self.use_ns_db().await?;

            let record_id = account_record_id(&repo.scope_settings.accounts, *account_id);
            let db_account: Option<SurrealAccountRecord> =
                repo.db.delete(record_id).await.map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Delete,
                        format!("Failed to delete account: {}", e),
                        Some(repo.scope_settings.accounts.clone()),
                        Some(account_id.to_string()),
                    ))
                })?;

            db_account.map(Account::try_from).transpose()
        };
        res
    }

    async fn update_account(&self, account: Account<R, G>) -> Result<Option<Account<R, G>>> {
        let res: Result<_> = {
            let repo = self.use_ns_db().await?;

            let record = SurrealAccountRecord::try_from(account)?;
            let record_account_id = record.account_id;
            let record_id = account_record_id(&repo.scope_settings.accounts, record_account_id);
            let db_account: Option<SurrealAccountRecord> = repo
                .db
                .update(&record_id)
                .content(record)
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Update,
                        format!("Failed to update account: {}", e),
                        Some(repo.scope_settings.accounts.clone()),
                        Some(record_account_id.to_string()),
                    ))
                })?;

            db_account.map(Account::try_from).transpose()
        };
        res
    }

    async fn query_all_accounts(&self) -> Result<Vec<Account<R, G>>> {
        let res: Result<_> = {
            let repo = self.use_ns_db().await?;

            let db_accounts: Vec<SurrealAccountRecord> = repo
                .db
                .select(repo.scope_settings.accounts.clone())
                .await
                .map_err(|e| {
                    RepoError::Database(DatabaseError::with_context(
                        DatabaseOperation::Query,
                        format!("Failed to query all accounts: {}", e),
                        Some(repo.scope_settings.accounts.clone()),
                        None,
                    ))
                })?;

            db_accounts.into_iter().map(Account::try_from).collect()
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
    use super::{PersistedPermissions, SurrealAccountRecord};
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use uuid::Uuid;
    use webgates_core::accounts::Account;
    use webgates_core::authz::access_hierarchy::AccessHierarchy;
    use webgates_core::groups::Group;
    use webgates_core::permissions::Permissions;
    use webgates_core::permissions::permission_id::PermissionId;
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

        let persisted = PersistedPermissions::from(&permissions);
        let restored = Permissions::from(persisted);

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
        let restored = Permissions::from(persisted);

        assert!(restored.has("read:account"));
        assert!(restored.has("write:account"));
        assert_eq!(restored, permissions);
    }

    #[test]
    fn account_record_round_trips_structured_roles_and_groups() {
        let mut account = Account::new("user@example.com");
        account.roles = vec![StructuredRole::Admin];
        account.groups = vec![Group::new("engineering")];
        account.account_id = Uuid::now_v7();
        account.grant_permission("read:account");
        account.grant_permission("write:account");

        let record = match SurrealAccountRecord::try_from(account.clone()) {
            Ok(record) => record,
            Err(error) => panic!("structured account conversion should succeed: {}", error),
        };
        assert_eq!(record.roles, vec![json!("Admin")]);
        assert_eq!(record.groups, vec![json!("engineering")]);

        let restored = match Account::<StructuredRole, Group>::try_from(record) {
            Ok(account) => account,
            Err(error) => panic!("structured account restoration should succeed: {}", error),
        };

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

        let error = match Account::<StructuredRole, Group>::try_from(record) {
            Ok(_) => panic!("invalid role payload should fail"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("Failed to deserialize account roles"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn record_to_account_round_trips_builtin_role_type() {
        let mut account = Account::new("user@example.com");
        account.groups = vec![Group::new("engineering")];
        account.account_id = Uuid::now_v7();
        account.grant_permission("read:account");

        let record = match SurrealAccountRecord::try_from(account.clone()) {
            Ok(record) => record,
            Err(error) => panic!("builtin account conversion should succeed: {}", error),
        };
        let restored = match Account::<Role, Group>::try_from(record) {
            Ok(account) => account,
            Err(error) => panic!("builtin account restoration should succeed: {}", error),
        };

        assert_eq!(restored, account);
    }
}
