use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use thiserror::Error;
use webgates::errors::UserFriendlyError as CoreUserFriendlyError;
use webgates::hashing::{HashingOperation, errors::HashingError};
use webgates::secrets::errors::SecretError;

/// Severity levels for categorizing errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorSeverity {
    /// Actionable operational error.
    Error,
    /// Non-critical warning.
    Warning,
    /// Informational notice.
    Info,
    /// Service-impacting failure.
    Critical,
}

/// Trait for multi-level error messaging without coupling to `webgates` core.
pub trait UserFriendlyError: fmt::Display + fmt::Debug {
    /// Clear, user-safe message (no internals or secrets).
    fn user_message(&self) -> String;
    /// Developer-oriented detail for logs/telemetry.
    fn developer_message(&self) -> String;
    /// Short reference code for support/debugging.
    fn support_code(&self) -> String;
    /// Severity level to guide handling.
    fn severity(&self) -> ErrorSeverity;
    /// Suggested next steps for the caller/user.
    fn suggested_actions(&self) -> Vec<String>;
    /// Whether the operation can be retried safely.
    fn is_retryable(&self) -> bool;
}

/// Repository type identifiers for error context.
#[derive(Debug, Clone)]
pub enum RepositoryType {
    /// Account repository
    Account,
    /// Secret repository
    Secret,
    /// Permission mapping repository
    PermissionMapping,
    /// Group repository
    Group,
}

impl fmt::Display for RepositoryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RepositoryType::Account => write!(f, "account"),
            RepositoryType::Secret => write!(f, "secret"),
            RepositoryType::PermissionMapping => write!(f, "permission_mapping"),
            RepositoryType::Group => write!(f, "group"),
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

/// Repository-category native errors for storage backends.
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
        Self::OperationFailed {
            repository,
            operation,
            message: message.into(),
            key,
            context,
        }
    }

    /// Construct a not found error.
    pub fn not_found(repository: RepositoryType, key: Option<String>) -> Self {
        Self::NotFound { repository, key }
    }

    /// Construct a constraint/precondition failure.
    pub fn constraint(
        repository: RepositoryType,
        message: impl Into<String>,
        key: Option<String>,
    ) -> Self {
        Self::Constraint {
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
            } => format!(
                "REPO-{}-{}-{:X}",
                repository.to_string().to_uppercase(),
                operation.to_string().to_uppercase(),
                {
                    format!("{:?}{:?}", repository, key).hash(&mut hasher);
                    hasher.finish() % 10000
                }
            ),
            RepositoriesError::NotFound { repository, key } => format!(
                "REPO-{}-NOTFOUND-{:X}",
                repository.to_string().to_uppercase(),
                {
                    format!("{:?}{:?}", repository, key).hash(&mut hasher);
                    hasher.finish() % 10000
                }
            ),
            RepositoriesError::Constraint {
                repository, key, ..
            } => format!(
                "REPO-{}-CONSTRAINT-{:X}",
                repository.to_string().to_uppercase(),
                {
                    format!("{:?}{:?}", repository, key).hash(&mut hasher);
                    hasher.finish() % 10000
                }
            ),
        }
    }
}

impl UserFriendlyError for RepositoriesError {
    fn user_message(&self) -> String {
        match self {
            RepositoriesError::OperationFailed { repository, .. } => match repository {
                RepositoryType::Account => {
                    "We’re having trouble accessing account information. Please retry.".to_string()
                }
                RepositoryType::Secret => {
                    "We can’t process this security request right now. Please try again later."
                        .to_string()
                }
                RepositoryType::PermissionMapping => {
                    "We’re having trouble with permission data. Please try again.".to_string()
                }
                RepositoryType::Group => {
                    "We’re having trouble loading group data. Please try again.".to_string()
                }
            },
            RepositoriesError::NotFound { repository, .. } => match repository {
                RepositoryType::Account => {
                    "No account was found for the provided identifier.".to_string()
                }
                RepositoryType::Secret => {
                    "No security data was found for that account.".to_string()
                }
                RepositoryType::PermissionMapping => {
                    "That permission mapping does not exist.".to_string()
                }
                RepositoryType::Group => "That group does not exist.".to_string(),
            },
            RepositoriesError::Constraint { repository, .. } => match repository {
                RepositoryType::Account => {
                    "Account constraints prevented this change. Please review your input."
                        .to_string()
                }
                RepositoryType::Secret => {
                    "Security constraints prevented this change. Please try again later."
                        .to_string()
                }
                RepositoryType::PermissionMapping => {
                    "Permission mapping constraints prevented this change.".to_string()
                }
                RepositoryType::Group => "Group constraints prevented this change.".to_string(),
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
                    "Retry the request".to_string(),
                ],
                (RepositoryType::Secret, _) => vec![
                    "Avoid repeated secret operations".to_string(),
                    "Retry after a short delay".to_string(),
                ],
                _ => vec![
                    "Retry the request".to_string(),
                    "Refresh and attempt again".to_string(),
                ],
            },
            RepositoriesError::NotFound { repository, .. } => match repository {
                RepositoryType::Account => vec![
                    "Verify the account identifier".to_string(),
                    "Ensure you are using the correct account".to_string(),
                ],
                _ => vec!["Verify the requested identifier".to_string()],
            },
            RepositoriesError::Constraint { repository, .. } => match repository {
                RepositoryType::Account => vec![
                    "Check for conflicting or duplicate values".to_string(),
                    "Use unique identifiers".to_string(),
                ],
                _ => vec!["Review input for constraint issues".to_string()],
            },
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            RepositoriesError::OperationFailed {
                repository,
                operation,
                ..
            } => match (repository, operation) {
                (RepositoryType::Secret, _) => false, // avoid repeated security ops
                _ => true,
            },
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
            } => format!("DB-{}-{:X}", operation.to_string().to_uppercase(), {
                format!("{:?}{:?}", operation, table).hash(&mut hasher);
                hasher.finish() % 10000
            }),
        }
    }
}

impl UserFriendlyError for DatabaseError {
    fn user_message(&self) -> String {
        match self {
            DatabaseError::Operation { operation, .. } => match operation {
                DatabaseOperation::Connect => {
                    "We’re having trouble connecting to the database. Please try again shortly."
                        .to_string()
                }
                DatabaseOperation::Query
                | DatabaseOperation::Insert
                | DatabaseOperation::Update
                | DatabaseOperation::Delete => {
                    "Data services are currently unavailable. Please try again shortly.".to_string()
                }
                DatabaseOperation::Migration | DatabaseOperation::Backup => {
                    "Maintenance is in progress. Please try again later.".to_string()
                }
                DatabaseOperation::Transaction => {
                    "We couldn’t complete your request due to a transaction issue. Please retry."
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
                    "Wait briefly and retry".to_string(),
                    "Check database availability".to_string(),
                ],
                DatabaseOperation::Query
                | DatabaseOperation::Insert
                | DatabaseOperation::Update
                | DatabaseOperation::Delete => vec![
                    "Retry the request".to_string(),
                    "If the issue persists, inspect database logs".to_string(),
                ],
                DatabaseOperation::Migration | DatabaseOperation::Backup => {
                    vec!["Wait for maintenance to finish".to_string()]
                }
                DatabaseOperation::Transaction => vec![
                    "Retry the transaction".to_string(),
                    "Verify required inputs are provided".to_string(),
                ],
            },
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            DatabaseError::Operation { operation, .. } => match operation {
                DatabaseOperation::Connect => true,
                DatabaseOperation::Migration | DatabaseOperation::Backup => false,
                _ => true,
            },
        }
    }
}

/// Root error type for repository backends.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Repository-level failures.
    #[error(transparent)]
    Repositories(#[from] RepositoriesError),

    /// Database driver/engine failures.
    #[error(transparent)]
    Database(#[from] DatabaseError),

    /// Hashing failures.
    #[error(transparent)]
    Hashing(#[from] HashingError),
}

impl UserFriendlyError for Error {
    fn user_message(&self) -> String {
        match self {
            Error::Repositories(e) => e.user_message(),
            Error::Database(e) => e.user_message(),
            Error::Hashing(e) => e.user_message(),
        }
    }

    fn developer_message(&self) -> String {
        match self {
            Error::Repositories(e) => e.developer_message(),
            Error::Database(e) => e.developer_message(),
            Error::Hashing(e) => e.developer_message(),
        }
    }

    fn support_code(&self) -> String {
        match self {
            Error::Repositories(e) => e.support_code(),
            Error::Database(e) => e.support_code(),
            Error::Hashing(e) => e.support_code(),
        }
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            Error::Repositories(e) => e.severity(),
            Error::Database(e) => e.severity(),
            Error::Hashing(e) => match e.severity() {
                webgates::errors::ErrorSeverity::Error => ErrorSeverity::Error,
                webgates::errors::ErrorSeverity::Warning => ErrorSeverity::Warning,
                webgates::errors::ErrorSeverity::Info => ErrorSeverity::Info,
                webgates::errors::ErrorSeverity::Critical => ErrorSeverity::Critical,
            },
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            Error::Repositories(e) => e.suggested_actions(),
            Error::Database(e) => e.suggested_actions(),
            Error::Hashing(e) => e.suggested_actions(),
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            Error::Repositories(e) => e.is_retryable(),
            Error::Database(e) => e.is_retryable(),
            Error::Hashing(e) => e.is_retryable(),
        }
    }
}

/// Conversion into the core webgates error type for compatibility.
impl From<Error> for webgates::errors::Error {
    fn from(err: Error) -> Self {
        match err {
            Error::Repositories(e) => {
                webgates::errors::Error::Secrets(SecretError::hashing_with_context(
                    HashingOperation::Verify,
                    format!("repository error: {}", e),
                    None,
                    None,
                ))
            }
            Error::Database(e) => {
                webgates::errors::Error::Secrets(SecretError::hashing_with_context(
                    HashingOperation::Verify,
                    format!("database error: {}", e),
                    None,
                    None,
                ))
            }
            Error::Hashing(e) => webgates::errors::Error::Hashing(e),
        }
    }
}

/// Conversion from the core webgates error type into the repository error domain.
/// Non-hashing categories are mapped to repository-level failures with conservative defaults.
impl From<webgates::errors::Error> for Error {
    fn from(err: webgates::errors::Error) -> Self {
        match err {
            webgates::errors::Error::Hashing(e) => Error::Hashing(e),
            webgates::errors::Error::Secrets(e) => {
                Error::Repositories(RepositoriesError::operation_failed(
                    RepositoryType::Secret,
                    RepositoryOperation::Get,
                    format!("core secrets error: {}", e),
                    None,
                    None,
                ))
            }
            other => Error::Repositories(RepositoriesError::operation_failed(
                RepositoryType::Account,
                RepositoryOperation::Get,
                format!("core error: {}", other),
                None,
                None,
            )),
        }
    }
}

/// Convenience alias for results within this crate.
pub type Result<T> = std::result::Result<T, Error>;
