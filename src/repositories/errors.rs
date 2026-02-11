//! Repository- and database-category native errors.
//!
//! This module defines category-native error types for repositories and databases,
//! used directly in handlers, services, and repositories when dealing with
//! repository or database failures.
//!
//! # Overview
//!
//! - `RepositoriesError`: repository contract/operation failures (by repository type)
//! - `DatabaseError`: database operation failures (by database operation)
//! - `RepositoryType`: identifies the repository domain
//! - `RepositoryOperation`: CRUD-like repository operations
//! - `DatabaseOperation`: common database operations
//!
//! # Examples
//!
//! ```rust
//! use axum_gate::repositories::{RepositoriesError, RepositoryType, RepositoryOperation};
//! use axum_gate::errors::UserFriendlyError;
//!
//! let err = RepositoriesError::operation_failed(
//!     RepositoryType::Account,
//!     RepositoryOperation::Insert,
//!     "unique constraint violation on `user_id`",
//!     Some("user-123".into()),
//!     Some("insert_account".into()),
//! );
//!
//! assert!(err.developer_message().contains("account repository"));
//! assert!(err.support_code().starts_with("REPO-ACCOUNT-INSERT-"));
//! ```
//!
//! ```rust
//! use axum_gate::repositories::{DatabaseError, DatabaseOperation};
//! use axum_gate::errors::UserFriendlyError;
//!
//! let err = DatabaseError::with_context(
//!     DatabaseOperation::Query,
//!     "connection refused",
//!     Some("accounts".into()),
//!     None
//! );
//! assert!(matches!(err.severity(), axum_gate::errors::ErrorSeverity::Error));
//! assert!(err.user_message().contains("data services"));
//! ```

use crate::errors::{ErrorSeverity, UserFriendlyError};
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use thiserror::Error;

/// Repository type identifiers, aligned with this crate's DDD categories.
#[derive(Debug, Clone)]
pub enum RepositoryType {
    /// Account repository
    Account,
    /// Secret repository
    Secret,
    /// Permission mapping repository
    PermissionMapping,
}

impl fmt::Display for RepositoryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RepositoryType::Account => write!(f, "account"),
            RepositoryType::Secret => write!(f, "secret"),
            RepositoryType::PermissionMapping => write!(f, "permission_mapping"),
        }
    }
}

/// Repository operation identifiers for structured reporting.
#[derive(Debug, Clone)]
pub enum RepositoryOperation {
    /// Insert/create operation
    Insert,
    /// Fetch single record by key
    Get,
    /// Update/patch existing record
    Update,
    /// Delete/remove record
    Delete,
}

impl fmt::Display for RepositoryOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RepositoryOperation::Insert => write!(f, "insert"),
            RepositoryOperation::Get => write!(f, "get"),
            RepositoryOperation::Update => write!(f, "update"),
            RepositoryOperation::Delete => write!(f, "delete"),
        }
    }
}

/// Repository-category native errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RepositoriesError {
    /// Repository operation failure (contract or adapter issue).
    #[error("Repository error: {repository} {operation} - {message}")]
    OperationFailed {
        /// Type of repository involved.
        repository: RepositoryType,
        /// Operation that failed.
        operation: RepositoryOperation,
        /// Description of the failure (non-sensitive).
        message: String,
        /// Optional logical key or identifier (sanitized).
        key: Option<String>,
        /// Additional context (non-sensitive).
        context: Option<String>,
    },

    /// A requested entity was not found in the repository.
    #[error("Repository not found: {repository} - {key:?}")]
    NotFound {
        /// Type of repository involved.
        repository: RepositoryType,
        /// Optional logical key or identifier (sanitized).
        key: Option<String>,
    },

    /// A constraint (uniqueness/foreign key) or precondition failed.
    #[error("Repository constraint: {repository} - {message}")]
    Constraint {
        /// Type of repository involved.
        repository: RepositoryType,
        /// Description of the constraint failure (non-sensitive).
        message: String,
        /// Optional logical key or identifier (sanitized).
        key: Option<String>,
    },
}

impl RepositoriesError {
    /// Construct an operation failure.
    pub fn operation_failed(
        repository: RepositoryType,
        operation: RepositoryOperation,
        message: impl Into<String>,
        key: Option<String>,
        context: Option<String>,
    ) -> Self {
        RepositoriesError::OperationFailed {
            repository,
            operation,
            message: message.into(),
            key,
            context,
        }
    }

    /// Construct a not found error.
    pub fn not_found(repository: RepositoryType, key: Option<String>) -> Self {
        RepositoriesError::NotFound { repository, key }
    }

    /// Construct a constraint/precondition failure.
    pub fn constraint(
        repository: RepositoryType,
        message: impl Into<String>,
        key: Option<String>,
    ) -> Self {
        RepositoriesError::Constraint {
            repository,
            message: message.into(),
            key,
        }
    }

    fn support_code_inner(&self) -> String {
        let mut hasher = DefaultHasher::new();
        match self {
            RepositoriesError::OperationFailed {
                repository,
                operation,
                key,
                ..
            } => {
                format!(
                    "REPO-{}-{}-{:X}",
                    repository.to_string().to_uppercase(),
                    operation.to_string().to_uppercase(),
                    {
                        format!("{:?}{:?}", repository, key).hash(&mut hasher);
                        hasher.finish() % 10000
                    }
                )
            }
            RepositoriesError::NotFound { repository, key } => {
                format!(
                    "REPO-{}-NOTFOUND-{:X}",
                    repository.to_string().to_uppercase(),
                    {
                        format!("{:?}{:?}", repository, key).hash(&mut hasher);
                        hasher.finish() % 10000
                    }
                )
            }
            RepositoriesError::Constraint {
                repository, key, ..
            } => {
                format!(
                    "REPO-{}-CONSTRAINT-{:X}",
                    repository.to_string().to_uppercase(),
                    {
                        format!("{:?}{:?}", repository, key).hash(&mut hasher);
                        hasher.finish() % 10000
                    }
                )
            }
        }
    }
}

impl UserFriendlyError for RepositoriesError {
    fn user_message(&self) -> String {
        match self {
            RepositoriesError::OperationFailed { repository, .. } => match repository {
                RepositoryType::Account => "We're having trouble accessing your account information. Please try refreshing the page or signing in again.".to_string(),
                RepositoryType::Secret => "There's an issue with the security system. Please try again or contact support if the problem continues.".to_string(),
                RepositoryType::PermissionMapping => "We're having trouble with the permission system. Your permissions are still active, but some features might not display correctly.".to_string(),
            },
            RepositoriesError::NotFound { repository, .. } => match repository {
                RepositoryType::Account => "We couldn't find an account with the requested identifier.".to_string(),
                RepositoryType::Secret => "We couldn't find the requested security information.".to_string(),
                RepositoryType::PermissionMapping => "We couldn't find the requested permission mapping.".to_string(),
            },
            RepositoriesError::Constraint { repository, .. } => match repository {
                RepositoryType::Account => "We couldn't complete this request due to an account constraint. Please review your input and try again.".to_string(),
                RepositoryType::Secret => "We couldn't complete this request due to a security constraint. Please try again later.".to_string(),
                RepositoryType::PermissionMapping => "We couldn't update the permission mapping due to a constraint. Your permissions remain unchanged.".to_string(),
            },
        }
    }

    fn developer_message(&self) -> String {
        match self {
            RepositoriesError::OperationFailed {
                repository,
                operation,
                message,
                key,
                context,
            } => {
                let key_s = key
                    .as_ref()
                    .map(|k| format!(" [Key: {}]", k))
                    .unwrap_or_default();
                let ctx_s = context
                    .as_ref()
                    .map(|c| format!(" [Context: {}]", c))
                    .unwrap_or_default();
                format!(
                    "Repository operation failed in {} repository ({}): {}{}{}",
                    repository, operation, message, key_s, ctx_s
                )
            }
            RepositoriesError::NotFound { repository, key } => {
                let key_s = key
                    .as_ref()
                    .map(|k| format!(" [Key: {}]", k))
                    .unwrap_or_default();
                format!(
                    "Repository entity not found in {} repository.{}",
                    repository, key_s
                )
            }
            RepositoriesError::Constraint {
                repository,
                message,
                key,
            } => {
                let key_s = key
                    .as_ref()
                    .map(|k| format!(" [Key: {}]", k))
                    .unwrap_or_default();
                format!(
                    "Repository constraint violation in {} repository: {}{}",
                    repository, message, key_s
                )
            }
        }
    }

    fn support_code(&self) -> String {
        self.support_code_inner()
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            RepositoriesError::OperationFailed {
                repository,
                operation,
                ..
            } => match (repository, operation) {
                (RepositoryType::Secret, _) => ErrorSeverity::Critical,
                (RepositoryType::Account, RepositoryOperation::Delete) => ErrorSeverity::Critical,
                _ => ErrorSeverity::Error,
            },
            RepositoriesError::NotFound { repository, .. } => match repository {
                RepositoryType::Account => ErrorSeverity::Warning,
                _ => ErrorSeverity::Info,
            },
            RepositoriesError::Constraint { repository, .. } => match repository {
                RepositoryType::Account | RepositoryType::Secret => ErrorSeverity::Error,
                _ => ErrorSeverity::Warning,
            },
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            RepositoriesError::OperationFailed {
                repository,
                operation,
                ..
            } => match (repository, operation) {
                (RepositoryType::Account, RepositoryOperation::Insert) => vec![
                    "Ensure the account identifier is unique".to_string(),
                    "Verify required fields are provided".to_string(),
                    "Try your request again".to_string(),
                    "Contact support if the problem persists".to_string(),
                ],
                (RepositoryType::Secret, _) => vec![
                    "Do not retry password or secret operations repeatedly".to_string(),
                    "Contact support if security operations continue to fail".to_string(),
                ],
                _ => vec![
                    "Try your request again in a moment".to_string(),
                    "Refresh the page and attempt the operation again".to_string(),
                    "Contact support if issues persist".to_string(),
                ],
            },
            RepositoriesError::NotFound { repository, .. } => match repository {
                RepositoryType::Account => vec![
                    "Verify the account identifier is correct".to_string(),
                    "Ensure you are signed in with the correct account".to_string(),
                    "Contact support if the account should exist".to_string(),
                ],
                _ => vec![
                    "Verify the requested identifier is correct".to_string(),
                    "Refresh the page and try again".to_string(),
                ],
            },
            RepositoriesError::Constraint { repository, .. } => match repository {
                RepositoryType::Account => vec![
                    "Review the input for conflicting or duplicate values".to_string(),
                    "Ensure unique identifiers are not reused".to_string(),
                    "Try again after correcting the input".to_string(),
                ],
                _ => vec![
                    "Review your input for constraint issues".to_string(),
                    "Try your request again in a moment".to_string(),
                    "Contact support if constraints are unclear".to_string(),
                ],
            },
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            RepositoriesError::OperationFailed {
                repository,
                operation,
                ..
            } => {
                match (repository, operation) {
                    (RepositoryType::Secret, _) => false, // avoid repeated security ops
                    _ => true,
                }
            }
            RepositoriesError::NotFound { .. } => false,
            RepositoriesError::Constraint { .. } => false,
        }
    }
}

/// Database operation types.
#[derive(Debug, Clone)]
pub enum DatabaseOperation {
    /// Database connection
    Connect,
    /// Database query
    Query,
    /// Insert row/document
    Insert,
    /// Update row/document
    Update,
    /// Delete row/document
    Delete,
    /// Schema migration
    Migration,
    /// Backup/restore
    Backup,
    /// Transaction block
    Transaction,
}

impl fmt::Display for DatabaseOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DatabaseOperation::Connect => write!(f, "connect"),
            DatabaseOperation::Query => write!(f, "query"),
            DatabaseOperation::Insert => write!(f, "insert"),
            DatabaseOperation::Update => write!(f, "update"),
            DatabaseOperation::Delete => write!(f, "delete"),
            DatabaseOperation::Migration => write!(f, "migration"),
            DatabaseOperation::Backup => write!(f, "backup"),
            DatabaseOperation::Transaction => write!(f, "transaction"),
        }
    }
}

/// Database-category native errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DatabaseError {
    /// Database operation failure (driver/engine-side).
    #[error("Database error: {operation} - {message}")]
    Operation {
        /// The database operation that failed.
        operation: DatabaseOperation,
        /// Description of the failure (non-sensitive).
        message: String,
        /// The table/collection involved (if applicable).
        table: Option<String>,
        /// The record identifier involved (if applicable).
        record_id: Option<String>,
    },
}

impl DatabaseError {
    /// Construct a database error without table/record context.
    pub fn new(operation: DatabaseOperation, message: impl Into<String>) -> Self {
        DatabaseError::Operation {
            operation,
            message: message.into(),
            table: None,
            record_id: None,
        }
    }

    /// Construct a database error with table/record context.
    pub fn with_context(
        operation: DatabaseOperation,
        message: impl Into<String>,
        table: Option<String>,
        record_id: Option<String>,
    ) -> Self {
        DatabaseError::Operation {
            operation,
            message: message.into(),
            table,
            record_id,
        }
    }

    fn support_code_inner(&self) -> String {
        let mut hasher = DefaultHasher::new();
        match self {
            DatabaseError::Operation {
                operation, table, ..
            } => {
                format!("DB-{}-{:X}", operation.to_string().to_uppercase(), {
                    format!("{:?}{:?}", operation, table).hash(&mut hasher);
                    hasher.finish() % 10000
                })
            }
        }
    }
}

impl UserFriendlyError for DatabaseError {
    fn user_message(&self) -> String {
        match self {
            DatabaseError::Operation { operation, .. } => match operation {
                DatabaseOperation::Connect => {
                    "We're having trouble connecting to our database. Please try again in a moment."
                        .to_string()
                }
                DatabaseOperation::Query
                | DatabaseOperation::Insert
                | DatabaseOperation::Update
                | DatabaseOperation::Delete => {
                    "We're experiencing technical difficulties with our data services. Please try again shortly.".to_string()
                }
                DatabaseOperation::Migration | DatabaseOperation::Backup => {
                    "Our system is currently undergoing maintenance. Please try again later."
                        .to_string()
                }
                DatabaseOperation::Transaction => {
                    "We couldn't complete your request due to a technical issue. Please try again."
                        .to_string()
                }
            },
        }
    }

    fn developer_message(&self) -> String {
        match self {
            DatabaseError::Operation {
                operation,
                message,
                table,
                record_id,
            } => {
                let table_context = table
                    .as_ref()
                    .map(|t| format!(" [Table: {}]", t))
                    .unwrap_or_default();
                let record_context = record_id
                    .as_ref()
                    .map(|r| format!(" [Record: {}]", r))
                    .unwrap_or_default();
                format!(
                    "Database {} operation failed: {}{}{}",
                    operation, message, table_context, record_context
                )
            }
        }
    }

    fn support_code(&self) -> String {
        self.support_code_inner()
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            DatabaseError::Operation { operation, .. } => match operation {
                DatabaseOperation::Connect => ErrorSeverity::Critical,
                DatabaseOperation::Migration | DatabaseOperation::Backup => ErrorSeverity::Critical,
                _ => ErrorSeverity::Error,
            },
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            DatabaseError::Operation { operation, .. } => match operation {
                DatabaseOperation::Connect => vec![
                    "Wait a few minutes and try again".to_string(),
                    "Check our status page for any database maintenance notifications".to_string(),
                    "Contact support if the issue persists for more than 15 minutes".to_string(),
                ],
                DatabaseOperation::Query
                | DatabaseOperation::Insert
                | DatabaseOperation::Update
                | DatabaseOperation::Delete => vec![
                    "Try your request again in a moment".to_string(),
                    "Refresh the page and attempt the operation again".to_string(),
                    "Save your work locally if possible and try again later".to_string(),
                    "Contact support if you continue to experience issues".to_string(),
                ],
                DatabaseOperation::Migration | DatabaseOperation::Backup => vec![
                    "This is a system maintenance issue that will be resolved automatically"
                        .to_string(),
                    "Check our status page for maintenance schedules".to_string(),
                    "No action is required from you at this time".to_string(),
                ],
                DatabaseOperation::Transaction => vec![
                    "Try completing your transaction again".to_string(),
                    "Ensure all required information is provided".to_string(),
                    "Contact support if the transaction continues to fail".to_string(),
                ],
            },
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            DatabaseError::Operation { operation, .. } => match operation {
                DatabaseOperation::Connect => true, // connection issues often resolve
                DatabaseOperation::Migration | DatabaseOperation::Backup => false, // maintenance
                _ => true,
            },
        }
    }
}
