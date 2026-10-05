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

// This is an explicitly non-gating diagnostic. Run it in a controlled
// security/performance job with `cargo test -- --ignored --nocapture`.
const WARMUP_ITERATIONS: usize = 8;
const MEASURED_ITERATIONS: usize = 128;
const MAX_MEDIAN_SKEW: f64 = 0.20;
const MAX_ABSOLUTE_SKEW: Duration = Duration::from_millis(50);

fn synthetic_credential() -> String {
    format!("test-credential-{}", uuid::Uuid::now_v7())
}

fn median(mut values: Vec<Duration>) -> Duration {
    values.sort_unstable();
    values[values.len() / 2]
}

fn median_absolute_deviation(values: &[Duration], center: Duration) -> Duration {
    median(values.iter().map(|value| value.abs_diff(center)).collect())
}

fn describe(label: &str, values: &[Duration]) -> String {
    let med = median(values.to_vec());
    let mad = median_absolute_deviation(values, med);
    format!(
        "{label}: n={}, median={}ms, MAD={}ms",
        values.len(),
        med.as_secs_f64() * 1_000.0,
        mad.as_secs_f64() * 1_000.0
    )
}

fn assert_distribution_skew_is_bounded(
    left_label: &str,
    left: &[Duration],
    right_label: &str,
    right: &[Duration],
) {
    let left_median = median(left.to_vec());
    let right_median = median(right.to_vec());
    let (fast, slow) = if left_median <= right_median {
        (left_median, right_median)
    } else {
        (right_median, left_median)
    };
    let difference = slow - fast;
    let relative = difference.as_secs_f64() / slow.as_secs_f64().max(1e-9);

    assert!(
        difference <= MAX_ABSOLUTE_SKEW || relative <= MAX_MEDIAN_SKEW,
        "timing distributions differ beyond the controlled-job tolerance \
         (absolute={}ms, relative={:.2}); {}; {}",
        difference.as_secs_f64() * 1_000.0,
        relative,
        describe(left_label, left),
        describe(right_label, right),
    );
}

#[tokio::test]
#[ignore = "timing diagnostic; run on controlled hardware"]
async fn timing_memory_repository() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use webgates_core::groups::Group;
    use webgates_core::roles::Role;
    use webgates_repositories::memory::{
        account::MemoryAccountRepository, secret::MemorySecretRepository,
    };

    let account_repo = MemoryAccountRepository::<Role, Group>::default();
    let secret_repo = MemorySecretRepository::new_with_argon2_hasher()?;
    let hasher = Argon2Hasher::new_recommended()?;

    let password = synthetic_credential();
    let stored = store_account_and_secret(
        &account_repo,
        &secret_repo,
        hasher,
        "memory-user@example.com",
        &password,
    )
    .await?;

    run_timing_case(&secret_repo, stored.account_id, &password).await
}

#[tokio::test]
#[ignore = "timing diagnostic; run on controlled hardware"]
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
    let repository = SurrealDbRepository::new(db, DatabaseScope::default()).await?;
    AccountRepository::<Role, Group>::bootstrap(&repository).await?;
    SecretRepository::bootstrap(&repository).await?;

    let hasher = Argon2Hasher::new_recommended()?;
    let password = synthetic_credential();
    let stored = store_account_and_secret(
        &repository,
        &repository,
        hasher,
        "surrealdb-user@example.com",
        &password,
    )
    .await?;

    run_timing_case(&repository, stored.account_id, &password).await
}

#[tokio::test]
#[ignore = "timing diagnostic; run on controlled hardware"]
#[cfg(feature = "sea-orm")]
async fn timing_seaorm_repository() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use sea_orm::Database;
    use webgates_repositories::sea_orm::SeaOrmRepository;

    let db = Database::connect("sqlite::memory:").await?;
    let repository = SeaOrmRepository::new(&db)?;
    repository.bootstrap().await?;

    let hasher = Argon2Hasher::new_recommended()?;
    let password = synthetic_credential();
    let stored = store_account_and_secret(
        &repository,
        &repository,
        hasher,
        "seaorm-user@example.com",
        &password,
    )
    .await?;

    run_timing_case(&repository, stored.account_id, &password).await
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
    let wrong_password = synthetic_credential();
    let nonexistent_password = synthetic_credential();

    // Warm each case independently so first-use effects are not included in the
    // measured distributions.
    for _ in 0..WARMUP_ITERATIONS {
        let _ = secret_repo
            .verify_credentials(Credentials::new(&account_id, &wrong_password))
            .await?;
        let _ = secret_repo
            .verify_credentials(Credentials::new(&account_id, password))
            .await?;
        let _ = secret_repo
            .verify_credentials(Credentials::new(
                &uuid::Uuid::now_v7(),
                &nonexistent_password,
            ))
            .await?;
    }

    let mut nonexistent = Vec::with_capacity(MEASURED_ITERATIONS);
    let mut wrong = Vec::with_capacity(MEASURED_ITERATIONS);
    let mut correct = Vec::with_capacity(MEASURED_ITERATIONS);

    // A deterministic shuffle interleaves cases without adding a dependency or
    // making a diagnostic run irreproducible.
    let mut state = 0x9e37_79b9_u64;
    for _ in 0..MEASURED_ITERATIONS {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        for case in [state % 3, (state / 3) % 3, (state / 9) % 3] {
            let start = Instant::now();
            match case {
                0 => {
                    let result = secret_repo
                        .verify_credentials(Credentials::new(
                            &uuid::Uuid::now_v7(),
                            &nonexistent_password,
                        ))
                        .await?;
                    nonexistent.push(start.elapsed());
                    assert_eq!(result, VerificationResult::Unauthorized);
                }
                1 => {
                    let result = secret_repo
                        .verify_credentials(Credentials::new(&account_id, &wrong_password))
                        .await?;
                    wrong.push(start.elapsed());
                    assert_eq!(result, VerificationResult::Unauthorized);
                }
                _ => {
                    let result = secret_repo
                        .verify_credentials(Credentials::new(&account_id, password))
                        .await?;
                    correct.push(start.elapsed());
                    assert_eq!(result, VerificationResult::Ok);
                }
            }
        }
    }

    assert_distribution_skew_is_bounded("nonexistent", &nonexistent, "wrong", &wrong);
    println!("{}", describe("nonexistent", &nonexistent));
    println!("{}", describe("wrong", &wrong));
    println!("{}", describe("correct", &correct));

    Ok(())
}
