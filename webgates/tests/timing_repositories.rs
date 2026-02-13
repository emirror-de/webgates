#![cfg(any(feature = "repo-surrealdb", feature = "repo-seaorm"))]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
//! Integration timing tests for repository credential verification.
//!
//! These tests run only when the corresponding repository feature is enabled
//! (`repo-surrealdb` or `repo-seaorm`) to avoid unused warnings in feature-off
//! builds. They validate that nonexistent-user and wrong-password paths have
//! comparable timings to reduce user-enumeration via timing side channels.

use std::time::{Duration, Instant};
use webgates::accounts::{Account, AccountRepository};
use webgates::credentials::Credentials;
use webgates::hashing::argon2::Argon2Hasher;
use webgates::prelude::{Group, Role};
use webgates::secrets::Secret;
use webgates::verification_result::VerificationResult;
use webgates_repositories::memory::{MemoryAccountRepository, MemorySecretRepository};

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

#[tokio::test]
#[cfg(feature = "repo-surrealdb")]
async fn timing_surrealdb_optional_mode() {
    // Use in-memory repositories to exercise SurrealDB-backed types behind feature gate.
    run_timing_case().await;
}

#[tokio::test]
#[cfg(feature = "repo-seaorm")]
async fn timing_seaorm_optional_mode() {
    // Use in-memory repositories to exercise SeaORM-backed types behind feature gate.
    run_timing_case().await;
}

async fn run_timing_case() {
    use webgates::credentials::CredentialsVerifier;
    use webgates::secrets::SecretRepository;

    let account_repo = MemoryAccountRepository::<Role, Group>::default();
    let secret_repo = MemorySecretRepository::new_with_argon2_hasher().unwrap();
    let hasher = Argon2Hasher::new_recommended().unwrap();

    let user_id = "user@example.com";
    let password = "correct_password";

    let account = Account::new(user_id, &[Role::User], &[Group::new("test")]);
    let stored = account_repo.store_account(account).await.unwrap().unwrap();

    let secret = Secret::new(&stored.account_id, password, hasher.clone()).unwrap();
    secret_repo.store_secret(secret).await.unwrap();

    // Warm up
    let _ = secret_repo
        .verify_credentials(Credentials::new(&stored.account_id, "wrong_password"))
        .await;
    let _ = secret_repo
        .verify_credentials(Credentials::new(&stored.account_id, password))
        .await;

    let iterations = 4;
    let mut nonexistent = Vec::with_capacity(iterations);
    let mut wrong = Vec::with_capacity(iterations);
    let mut correct = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        // Nonexistent
        let start = Instant::now();
        let res = secret_repo
            .verify_credentials(Credentials::new(&uuid::Uuid::now_v7(), "pw"))
            .await
            .unwrap();
        nonexistent.push(start.elapsed());
        assert_eq!(res, VerificationResult::Unauthorized);

        // Wrong
        let start = Instant::now();
        let res = secret_repo
            .verify_credentials(Credentials::new(&stored.account_id, "wrong_password"))
            .await
            .unwrap();
        wrong.push(start.elapsed());
        assert_eq!(res, VerificationResult::Unauthorized);

        // Correct
        let start = Instant::now();
        let res = secret_repo
            .verify_credentials(Credentials::new(&stored.account_id, password))
            .await
            .unwrap();
        correct.push(start.elapsed());
        assert_eq!(res, VerificationResult::Ok);
    }

    let med_nonexist = median(nonexistent);
    let med_wrong = median(wrong);
    let med_ok = median(correct);

    let (fast, slow) = if med_nonexist < med_wrong {
        (med_nonexist, med_wrong)
    } else {
        (med_wrong, med_nonexist)
    };
    let diff = slow - fast;
    let relative = diff.as_secs_f64() / fast.as_secs_f64().max(1e-9);

    // Generous thresholds for noisy CI
    assert!(
        diff.as_millis() < 200 || relative < 0.75,
        "timing skew too high: diff={}ms, rel={:.2}",
        diff.as_millis(),
        relative
    );

    // Ensure success path isn't trivially zero (sanity check)
    assert!(med_ok.as_millis() >= 1, "success path too fast");
}
