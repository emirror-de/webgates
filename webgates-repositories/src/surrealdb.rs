//! SurrealDB-backed repositories for account, group, permission-mapping, and
//! secret persistence with constant-time credential verification.
//!
//! This backend module centralizes shared SurrealDB concerns such as:
//! - repository construction
//! - namespace and database selection
//! - stable table-aware error mapping
//! - shared query helpers for consistent list and single-record behavior
//! - dummy-hash setup for constant-time credential verification

use super::TableName;
use crate::errors::{DatabaseError, DatabaseOperation, Error, Result};
use std::default::Default;
use surrealdb::{Connection, Surreal};
use webgates_secrets::hashing::{
    HashingService,
    argon2::Argon2Hasher,
    errors::{HashingError, HashingOperation},
};

pub mod account;
pub mod group;
pub mod permission_mapping;
pub mod secret;
pub mod session;

/// Scope configuration (namespace, database, table names) used by `SurrealDbRepository`.
///
/// Most users can rely on `DatabaseScope::default()`. Override fields only if you
/// need custom namespace / database names or different table naming.
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
/// Use `SurrealDbRepository::new(db, DatabaseScope::default())` for standard setups.
#[derive(Clone)]
pub struct SurrealDbRepository<S>
where
    S: Connection,
{
    pub(crate) db: Surreal<S>,
    pub(crate) scope_settings: DatabaseScope,
    /// Precomputed dummy Argon2 hash used when a user's secret does not exist.
    /// Ensures the Argon2 verification path is always exercised.
    pub(crate) dummy_hash: String,
}

impl<S> SurrealDbRepository<S>
where
    S: Connection,
{
    /// Creates a new repository that uses the given database connection limited by the given scope.
    pub fn new(db: Surreal<S>, scope_settings: DatabaseScope) -> Result<Self> {
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
        Ok(Self {
            db,
            scope_settings,
            dummy_hash,
        })
    }

    /// Sets the configured namespace and database before each operation.
    pub(crate) async fn use_ns_db(&self) -> Result<()> {
        self.db
            .use_ns(&self.scope_settings.namespace)
            .use_db(&self.scope_settings.database)
            .await
            .map(|_| ())
            .map_err(|error| {
                Error::Database(DatabaseError::with_context(
                    DatabaseOperation::Connect,
                    format!("Failed to set namespace/database: {error}"),
                    None,
                    None,
                ))
            })
    }

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
