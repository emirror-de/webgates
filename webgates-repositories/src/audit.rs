//! Audit logging utilities for repository-scoped account workflows.
//!
//! This module contains the subset of audit events needed by
//! `webgates-repositories` so the crate can emit account workflow audit logs
//! without depending on `webgates_core::audit`.
//!
//! Security notes:
//! - Never log secrets, passwords, raw tokens, or JWT contents.
//! - Prefer stable identifiers (`account_id`, `user_id`) and coarse-grained
//!   reason codes.
//! - Keep event fields low-cardinality and safe for logs and metrics.
//!
//! This module only emits events when the `audit-logging` feature is enabled in
//! the containing crate.

use tracing::{Level, event};
use uuid::Uuid;

const TARGET: &str = "webgates_repositories::audit";

/// Records the start of an account deletion workflow.
pub fn account_delete_start(user_id: &str, account_id: &Uuid) {
    event!(
        target: TARGET,
        Level::INFO,
        %user_id,
        account_id = %account_id,
        "account_delete_start"
    );
}

/// Records a successful account deletion.
pub fn account_delete_success(user_id: &str, account_id: &Uuid) {
    event!(
        target: TARGET,
        Level::INFO,
        %user_id,
        account_id = %account_id,
        "account_delete_success"
    );
}

/// Records an account deletion failure and the outcome of any compensating action.
///
/// `secret_restored` indicates whether the corresponding secret was restored
/// after a later workflow step failed:
/// - `Some(true)`: restore succeeded
/// - `Some(false)`: restore was attempted but reported failure
/// - `None`: restore was not attempted or did not complete
pub fn account_delete_failure(
    user_id: &str,
    account_id: &Uuid,
    secret_restored: Option<bool>,
    error_summary: &str,
) {
    match secret_restored {
        Some(true) => event!(
            target: TARGET,
            Level::ERROR,
            %user_id,
            account_id = %account_id,
            error = %error_summary,
            secret_restored = true,
            "account_delete_failure"
        ),
        Some(false) => event!(
            target: TARGET,
            Level::ERROR,
            %user_id,
            account_id = %account_id,
            error = %error_summary,
            secret_restored = false,
            "account_delete_failure"
        ),
        None => event!(
            target: TARGET,
            Level::ERROR,
            %user_id,
            account_id = %account_id,
            error = %error_summary,
            "account_delete_failure"
        ),
    }
}

/// Records a newly created account.
pub fn account_created(user_id: &str, account_id: &Uuid) {
    event!(
        target: TARGET,
        Level::INFO,
        %user_id,
        account_id = %account_id,
        "account_created"
    );
}

/// Records an account insertion failure with a coarse-grained reason code.
///
/// The reason should be a stable, low-cardinality code such as:
/// - `account_repo_none`
/// - `secret_store_false`
/// - `duplicate_user_id`
pub fn account_insert_failure(user_id: &str, reason_code: &str) {
    event!(
        target: TARGET,
        Level::ERROR,
        %user_id,
        reason = %reason_code,
        "account_insert_failure"
    );
}
