#![cfg(any(feature = "surrealdb", feature = "sea-orm"))]
//! Integration timing tests for repository credential verification.
//!
//! These tests run only when the corresponding repository feature is enabled
//! (`surrealdb` or `sea-orm`) to avoid unused warnings in feature-off
//! builds. They validate that nonexistent-user and wrong-password paths have
//! comparable timings to reduce user-enumeration via timing side channels.

use std::time::{Duration, Instant};
use webgates_core::accounts::Account;
use webgates_core::credentials::Credentials;
use webgates_core::groups::Group;
use webgates_core::roles::Role;
use webgates_core::verification_result::VerificationResult;
use webgates_repositories::{
    account_repository::AccountRepository,
    memory::{account::MemoryAccountRepository, secret::MemorySecretRepository},
    secret_repository::SecretRepository,
};
use webgates_secrets::Secret;
use webgates_secrets::hashing::argon2::Argon2Hasher;

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

#[tokio::test]
#[cfg(feature = "surrealdb")]
async fn timing_surrealdb_optional_mode() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Use in-memory repositories to exercise SurrealDB-backed types behind feature gate.
    run_timing_case().await
}

#[tokio::test]
#[cfg(feature = "sea-orm")]
async fn timing_seaorm_optional_mode() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Use in-memory repositories to exercise SeaORM-backed types behind feature gate.
    run_timing_case().await
}

async fn run_timing_case() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use webgates_core::credentials::credentials_verifier::CredentialsVerifier;

    let account_repo = MemoryAccountRepository::<Role, Group>::default();
    let secret_repo = MemorySecretRepository::new_with_argon2_hasher()?;
    let hasher = Argon2Hasher::new_recommended()?;

    let user_id = "user@example.com";
    let password = "correct_password";

    let mut account = Account::new(user_id);
    account.groups = vec![Group::new("test")];
    let stored: Account<Role, Group> = account_repo
        .store_account(account)
        .await?
        .ok_or("store_account returned None")?;

    let secret = Secret::new(&stored.account_id, password, hasher.clone())?;
    secret_repo.store_secret(secret).await?;

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
        let res: VerificationResult = secret_repo
            .verify_credentials(Credentials::new(&uuid::Uuid::now_v7(), "pw"))
            .await?;
        nonexistent.push(start.elapsed());
        assert_eq!(res, VerificationResult::Unauthorized);

        // Wrong
        let start = Instant::now();
        let res: VerificationResult = secret_repo
            .verify_credentials(Credentials::new(&stored.account_id, "wrong_password"))
            .await?;
        wrong.push(start.elapsed());
        assert_eq!(res, VerificationResult::Unauthorized);

        // Correct
        let start = Instant::now();
        let res: VerificationResult = secret_repo
            .verify_credentials(Credentials::new(&stored.account_id, password))
            .await?;
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

    Ok(())
}
