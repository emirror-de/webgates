//! SurrealDB-backed repositories.
//!
//! This module provides the SurrealDB-backed repository implementation for
//! accounts, groups, permission mappings, and secrets.
//!
//! It centralizes shared SurrealDB concerns such as:
//! - repository construction
//! - namespace and database selection
//! - stable table-aware error mapping
//! - shared query helpers for consistent list and single-record behavior
//! - dummy-hash setup for constant-time credential verification

use super::TableName;
use crate::errors::{DatabaseError, DatabaseOperation, Error, Result};

use std::default::Default;
use std::sync::Arc;
use surrealdb::{Connection, Surreal};
use tokio::sync::OnceCell;
use webgates_secrets::hashing::{
    argon2::Argon2Hasher,
    errors::{HashingError, HashingOperation},
    hashing_service::HashingService,
};

pub mod account;
pub mod group;
pub mod permission_mapping;
pub mod secret;
#[cfg(feature = "sessions")]
pub mod session;

/// Scope configuration used by [`SurrealDbRepository`].
///
/// Most users can rely on [`DatabaseScope::default()`]. Override fields only if
/// you need custom namespace, database, or table names.
#[derive(Clone, Debug)]
pub struct DatabaseScope {
    /// Accounts table (stores user id, groups, roles).
    pub accounts: String,
    /// Credentials table (stores hashed secrets).
    pub credentials: String,
    /// Permission mappings table (stores normalized string <-> id mapping).
    pub permission_mappings: String,
    /// Groups table (stores persisted group entities).
    pub groups: String,
    /// Namespace where data is stored.
    pub namespace: String,
    /// Database name where data is stored.
    pub database: String,
}

impl Default for DatabaseScope {
    fn default() -> Self {
        Self {
            accounts: TableName::WebgatesAccounts.to_string(),
            credentials: TableName::WebgatesCredentials.to_string(),
            permission_mappings: TableName::WebgatesPermissionMappings.to_string(),
            groups: TableName::WebgatesGroups.to_string(),
            namespace: "webgates".to_string(),
            database: "webgates".to_string(),
        }
    }
}

/// SurrealDB-backed repository offering CRUD for accounts, groups, permission
/// mappings, and secrets plus constant-time credential verification.
///
/// Use `SurrealDbRepository::new(db, DatabaseScope::default()).await` for standard setups.
pub struct SurrealDbRepository<S>
where
    S: Connection,
{
    pub(crate) db: Arc<Surreal<S>>,
    pub(crate) scope_settings: DatabaseScope,
    /// Precomputed dummy Argon2 hash used when a user's secret does not exist.
    /// Ensures the Argon2 verification path is always exercised.
    pub(crate) dummy_hash: String,
    /// Ensures the account schema is bootstrapped once per repository.
    account_schema_initialized: Arc<OnceCell<()>>,
    /// Ensures the credential schema is bootstrapped once per repository.
    credential_schema_initialized: Arc<OnceCell<()>>,
    /// Ensures the group schema is bootstrapped once per repository.
    group_schema_initialized: Arc<OnceCell<()>>,
    /// Ensures the permission-mapping schema is bootstrapped once per repository.
    permission_mapping_schema_initialized: Arc<OnceCell<()>>,
    /// Ensures the session schema is bootstrapped once per repository.
    #[cfg(feature = "sessions")]
    pub(crate) session_schema_initialized: Arc<OnceCell<()>>,
}

impl<S> SurrealDbRepository<S>
where
    S: Connection,
{
    /// Creates a new repository and selects its namespace and database on the owned client.
    pub async fn new(db: Surreal<S>, scope_settings: DatabaseScope) -> Result<Self> {
        let hasher = Argon2Hasher::new_recommended().map_err(|error| {
            Error::Hashing(HashingError::new(
                HashingOperation::Hash,
                format!("Failed to initialize Argon2 hasher: {error}"),
            ))
        })?;
        let dummy_hash = hasher.hash_value("dummy_password").map_err(|error| {
            Error::Hashing(HashingError::new(
                HashingOperation::Hash,
                format!("Failed to generate dummy password hash: {error}"),
            ))
        })?;
        db.use_ns(&scope_settings.namespace)
            .use_db(&scope_settings.database)
            .await
            .map_err(|error| {
                Error::Database(DatabaseError::with_context(
                    DatabaseOperation::Connect,
                    format!("Failed to set namespace/database: {error}"),
                    None,
                    None,
                ))
            })?;

        Ok(Self {
            db: Arc::new(db),
            scope_settings,
            dummy_hash,
            account_schema_initialized: Arc::new(OnceCell::new()),
            credential_schema_initialized: Arc::new(OnceCell::new()),
            group_schema_initialized: Arc::new(OnceCell::new()),
            permission_mapping_schema_initialized: Arc::new(OnceCell::new()),
            #[cfg(feature = "sessions")]
            session_schema_initialized: Arc::new(OnceCell::new()),
        })
    }
}

impl<S> Clone for SurrealDbRepository<S>
where
    S: Connection,
{
    fn clone(&self) -> Self {
        Self {
            db: Arc::clone(&self.db),
            scope_settings: self.scope_settings.clone(),
            dummy_hash: self.dummy_hash.clone(),
            account_schema_initialized: Arc::clone(&self.account_schema_initialized),
            credential_schema_initialized: Arc::clone(&self.credential_schema_initialized),
            group_schema_initialized: Arc::clone(&self.group_schema_initialized),
            permission_mapping_schema_initialized: Arc::clone(
                &self.permission_mapping_schema_initialized,
            ),
            #[cfg(feature = "sessions")]
            session_schema_initialized: Arc::clone(&self.session_schema_initialized),
        }
    }
}

impl<S> SurrealDbRepository<S>
where
    S: Connection,
{
    /// Builds a table-aware database error for SurrealDB adapter operations.
    pub(crate) fn database_error(
        &self,
        operation: DatabaseOperation,
        table_name: impl Into<String>,
        message: impl Into<String>,
        record_id: Option<String>,
    ) -> Error {
        Error::Database(DatabaseError::with_context(
            operation,
            message,
            Some(table_name.into()),
            record_id,
        ))
    }

    /// Builds a scope-aware database error using the configured table string.
    pub(crate) fn scoped_database_error(
        &self,
        operation: DatabaseOperation,
        table_name: &str,
        message: impl Into<String>,
        record_id: Option<String>,
    ) -> Error {
        self.database_error(operation, table_name.to_string(), message, record_id)
    }
}

#[cfg(test)]
mod tests {
    use super::{DatabaseScope, SurrealDbRepository};
    use surrealdb::Surreal;
    use surrealdb::engine::local::Mem;
    use surrealdb_types::{RecordId, SurrealValue};

    #[derive(surrealdb_types::SurrealValue)]
    struct ScopeProbe {
        marker: String,
    }

    #[tokio::test]
    async fn cloned_repositories_share_client_and_independent_sessions_keep_scopes_isolated() {
        let db = match Surreal::new::<Mem>(()).await {
            Ok(db) => db,
            Err(error) => panic!("in-memory SurrealDB setup should succeed: {error}"),
        };
        let other_db = db.clone();
        let repository = match SurrealDbRepository::new(db, DatabaseScope::default()).await {
            Ok(repository) => repository,
            Err(error) => panic!("repository construction should succeed: {error}"),
        };
        // Reconstructing via `Self::new` would generate a new salted hash.
        let original_hash = repository.dummy_hash.clone();

        let scoped = repository.clone();

        assert_eq!(scoped.dummy_hash, original_hash);
        assert!(std::sync::Arc::ptr_eq(&repository.db, &scoped.db));

        let other_scope = DatabaseScope {
            namespace: "other_namespace".to_string(),
            database: "other_database".to_string(),
            ..DatabaseScope::default()
        };
        let other_repository = match SurrealDbRepository::new(other_db, other_scope).await {
            Ok(repository) => repository,
            Err(error) => panic!("alternate repository construction should succeed: {error}"),
        };
        let record_id = RecordId::new("scope_probe", "same_id");
        let (default_write, alternate_write) = tokio::join!(
            scoped
                .db
                .query("CREATE $record_id CONTENT $content")
                .bind(("record_id", record_id.clone()))
                .bind((
                    "content",
                    ScopeProbe {
                        marker: "default".to_string()
                    }
                )),
            other_repository
                .db
                .query("CREATE $record_id CONTENT $content")
                .bind(("record_id", record_id.clone()))
                .bind((
                    "content",
                    ScopeProbe {
                        marker: "alternate".to_string()
                    }
                )),
        );
        match default_write {
            Ok(response) => {
                if let Err(error) = response.check() {
                    panic!("default-scope write should succeed: {error}");
                }
            }
            Err(error) => panic!("default-scope write should succeed: {error}"),
        }
        match alternate_write {
            Ok(response) => {
                if let Err(error) = response.check() {
                    panic!("alternate-scope write should succeed: {error}");
                }
            }
            Err(error) => panic!("alternate-scope write should succeed: {error}"),
        }

        let (default_read, alternate_read) = tokio::join!(
            scoped
                .db
                .query("SELECT * FROM $record_id")
                .bind(("record_id", record_id.clone())),
            other_repository
                .db
                .query("SELECT * FROM $record_id")
                .bind(("record_id", record_id)),
        );
        let mut default_read = match default_read {
            Ok(response) => response,
            Err(error) => panic!("default-scope read should succeed: {error}"),
        };
        let mut alternate_read = match alternate_read {
            Ok(response) => response,
            Err(error) => panic!("alternate-scope read should succeed: {error}"),
        };
        let default_value: Option<ScopeProbe> = match default_read.take(0) {
            Ok(value) => value,
            Err(error) => panic!("default-scope result should deserialize: {error}"),
        };
        let alternate_value: Option<ScopeProbe> = match alternate_read.take(0) {
            Ok(value) => value,
            Err(error) => panic!("alternate-scope result should deserialize: {error}"),
        };

        assert_eq!(
            default_value.map(|value| value.marker).as_deref(),
            Some("default")
        );
        assert_eq!(
            alternate_value.map(|value| value.marker).as_deref(),
            Some("alternate")
        );
    }
}
