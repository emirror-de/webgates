#![cfg(any(feature = "repo-surrealdb", feature = "repo-seaorm"))]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
//! Bulk permission mapping tests gated behind repository features.
//!
//! These tests are only built when a repository backend feature is enabled to
//! avoid unused warnings in feature-off builds. They serve as smoke tests to
//! ensure the workspace compiles and basic permission ID creation works under
//! repository-enabled configurations.

use webgates::permissions::PermissionId;

/// Simple smoke test to ensure permission IDs can be constructed when repository
/// features are enabled.
#[test]
fn permission_id_smoke() {
    let p = PermissionId::from("read:api");
    assert_eq!(p, PermissionId::from("read:api"));
}
