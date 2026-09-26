//! Integration timing tests for repository credential verification.
//!
//! The backend-specific tests use the production repository implementations so
//! database lookup and credential verification behavior is covered. The memory
//! repository remains covered separately as a low-overhead baseline.

use std::time::{Duration, Instant};

use webgates_core::credentials::Credentials;
use webgates_core::credentials::credentials_verifier::CredentialsVerifier;
use webgates_core::verification_result::VerificationResult;
use webgates_secrets::Secret;
use webgates_secrets::hashing::argon2::Argon2Hasher;

const WARMUP_ITERATIONS: usize = 1;
const MEASURED_ITERATIONS: usize = 2;

fn median(mut values: Vec<Duration>) -> Duration {
    values.sort();
    values[values.len() / 2]
}

#[tokio::test]
async fn timing_memory_repository() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use webgates_core::groups::Group;
    use webgates_core::roles::Role;
    use webgates_repositories::memory::{
        account::MemoryAccountRepository, secret::MemorySecretRepository,
    };

    let account_repo = MemoryAccountRepository::<Role, Group>::default();
    let secret_repo = MemorySecretRepository::new_with_argon2_hasher()?;
    let hasher = Argon2Hasher::new_recommended()?;

    let stored = store_account_and_secret(
        &account_repo,
        &secret_repo,
        hasher,
        "memory-user@example.com",
        "correct_password",
    )
    .await?;

    run_timing_case(&secret_repo, stored.account_id, "correct_password").await
}

#[tokio::test]
#[cfg(feature = "surrealdb")]
async fn timing_surrealdb_repository() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use surrealdb::Surreal;
    use surrealdb::engine::local::Mem;
    use webgates_core::groups::Group;
    use webgates_core::roles::Role;
    use webgates_repositories::account_repository::AccountRepository;
    use webgates_repositories::secret_repository::SecretRepository;
    use webgates_repositories::surrealdb::{DatabaseScope, SurrealDbRepository};

    let db = Surreal::new::<Mem>(()).await?;
    let repository = SurrealDbRepository::new(db, DatabaseScope::default())?;
    AccountRepository::<Role, Group>::bootstrap(&repository).await?;
    SecretRepository::bootstrap(&repository).await?;

    let hasher = Argon2Hasher::new_recommended()?;
    let stored = store_account_and_secret(
        &repository,
        &repository,
        hasher,
        "surrealdb-user@example.com",
        "correct_password",
    )
    .await?;

    run_timing_case(&repository, stored.account_id, "correct_password").await
}

#[tokio::test]
#[cfg(feature = "sea-orm")]
async fn timing_seaorm_repository() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use sea_orm::Database;
    use webgates_repositories::sea_orm::SeaOrmRepository;

    let db = Database::connect("sqlite::memory:").await?;
    let repository = SeaOrmRepository::new(&db)?;
    repository.bootstrap().await?;

    let hasher = Argon2Hasher::new_recommended()?;
    let stored = store_account_and_secret(
        &repository,
        &repository,
        hasher,
        "seaorm-user@example.com",
        "correct_password",
    )
    .await?;

    run_timing_case(&repository, stored.account_id, "correct_password").await
}

async fn store_account_and_secret<A, S>(
    account_repo: &A,
    secret_repo: &S,
    hasher: Argon2Hasher,
    user_id: &str,
    password: &str,
) -> Result<
    webgates_core::accounts::Account<webgates_core::roles::Role, webgates_core::groups::Group>,
    Box<dyn std::error::Error + Send + Sync>,
>
where
    A: webgates_repositories::account_repository::AccountRepository<
            webgates_core::roles::Role,
            webgates_core::groups::Group,
        >,
    S: webgates_repositories::secret_repository::SecretRepository,
{
    use webgates_core::accounts::Account;
    use webgates_core::groups::Group;

    let mut account = Account::new(user_id);
    account.groups = vec![Group::new("test")];
    let stored = account_repo
        .store_account(account)
        .await?
        .ok_or("store_account returned None")?;
    let secret = Secret::new(&stored.account_id, password, hasher)?;
    secret_repo.store_secret(secret).await?;

    Ok(stored)
}

async fn run_timing_case<R>(
    secret_repo: &R,
    account_id: uuid::Uuid,
    password: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    R: CredentialsVerifier + Sync,
{
    for _ in 0..WARMUP_ITERATIONS {
        let _ = secret_repo
            .verify_credentials(Credentials::new(&account_id, "wrong_password"))
            .await?;
        let _ = secret_repo
            .verify_credentials(Credentials::new(&account_id, password))
            .await?;
        let _ = secret_repo
            .verify_credentials(Credentials::new(&uuid::Uuid::now_v7(), "pw"))
            .await?;
    }

    let mut nonexistent = Vec::with_capacity(MEASURED_ITERATIONS);
    let mut wrong = Vec::with_capacity(MEASURED_ITERATIONS);
    let mut correct = Vec::with_capacity(MEASURED_ITERATIONS);

    for _ in 0..MEASURED_ITERATIONS {
        let start = Instant::now();
        let result = secret_repo
            .verify_credentials(Credentials::new(&uuid::Uuid::now_v7(), "pw"))
            .await?;
        nonexistent.push(start.elapsed());
        assert_eq!(result, VerificationResult::Unauthorized);

        let start = Instant::now();
        let result = secret_repo
            .verify_credentials(Credentials::new(&account_id, "wrong_password"))
            .await?;
        wrong.push(start.elapsed());
        assert_eq!(result, VerificationResult::Unauthorized);

        let start = Instant::now();
        let result = secret_repo
            .verify_credentials(Credentials::new(&account_id, password))
            .await?;
        correct.push(start.elapsed());
        assert_eq!(result, VerificationResult::Ok);
    }

    let median_nonexistent = median(nonexistent);
    let median_wrong = median(wrong);
    let median_correct = median(correct);
    let (fast, slow) = if median_nonexistent < median_wrong {
        (median_nonexistent, median_wrong)
    } else {
        (median_wrong, median_nonexistent)
    };
    let difference = slow - fast;
    let relative = difference.as_secs_f64() / fast.as_secs_f64().max(1e-9);

    assert!(
        difference.as_millis() < 250 || relative < 0.90,
        "timing skew too high: diff={}ms, rel={:.2}",
        difference.as_millis(),
        relative
    );
    assert!(median_correct.as_millis() >= 1, "success path too fast");

    Ok(())
}
