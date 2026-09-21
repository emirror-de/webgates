//! SeaORM repository integration.
//!
//! This module provides the SeaORM-backed repository implementation for account,
//! group, permission-mapping, and secret persistence.
//!
//! It centralizes shared SeaORM concerns such as:
//! - repository construction
//! - consistent database error mapping
//! - stable table-aware context for adapter failures
//! - dummy-hash setup for constant-time credential verification

use crate::{
    TableName,
    errors::{DatabaseError, Error, Result},
};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Schema};

use webgates_secrets::hashing::{
    argon2::Argon2Hasher,
    errors::{HashingError, HashingOperation},
    hashing_service::HashingService,
};

/// SeaORM persistence entities (database models) used by `SeaOrmRepository`.
///
/// These are thin schemas mapping relational rows to structures convertible
/// to and from the domain layer.
pub mod models;

mod account;
mod group;
mod permission_mapping;
mod secret;
#[cfg(feature = "sessions")]
pub mod session;

/// Repository implementation for [SeaORM](sea_orm).
///
/// This type owns shared backend concerns for all SeaORM adapters while the
/// individual repository traits are implemented in focused modules.
pub struct SeaOrmRepository {
    pub(crate) db: DatabaseConnection,
    /// Precomputed dummy Argon2 hash used for nonexistent accounts to keep
    /// verification timing consistent.
    pub(crate) dummy_hash: String,
}

impl SeaOrmRepository {
    /// Creates a new repository using the given database connection.
    pub fn new(db: &DatabaseConnection) -> Result<Self> {
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
            db: db.clone(),
            dummy_hash,
        })
    }

    /// Creates all repository tables if they do not exist yet.
    pub async fn bootstrap(&self) -> Result<()> {
        let backend = self.db.get_database_backend();
        let schema = Schema::new(backend);

        self.create_table_if_missing(
            backend,
            schema.create_table_from_entity(models::credentials::Entity),
            TableName::WebgatesCredentials,
        )
        .await?;

        self.create_table_if_missing(
            backend,
            schema.create_table_from_entity(models::account::Entity),
            TableName::WebgatesAccounts,
        )
        .await?;

        self.create_table_if_missing(
            backend,
            schema.create_table_from_entity(models::group::Entity),
            TableName::WebgatesGroups,
        )
        .await?;

        self.create_table_if_missing(
            backend,
            schema.create_table_from_entity(models::permission_mapping::Entity),
            TableName::WebgatesPermissionMappings,
        )
        .await?;

        Ok(())
    }

    async fn create_table_if_missing(
        &self,
        _backend: DbBackend,
        statement: sea_orm::sea_query::TableCreateStatement,
        table_name: TableName,
    ) -> Result<()> {
        self.db
            .execute(&statement)
            .await
            .map(|_| ())
            .map_err(|error| {
                Error::Database(DatabaseError::bootstrap(
                    format!("Failed to create table `{table_name}`: {error}"),
                    Some(table_name.to_string()),
                ))
            })
    }
}
