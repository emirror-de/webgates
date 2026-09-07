use std::hint::black_box;
use std::time::Instant;

use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use webgates_core::groups::Group;
use webgates_core::roles::Role;
use webgates_repositories::account_repository::AccountRepository;
use webgates_repositories::surrealdb::{DatabaseScope, SurrealDbRepository};

const ITERATIONS: usize = 100;

#[tokio::main]
async fn main() {
    let db = Surreal::new::<Mem>(())
        .await
        .expect("in-memory SurrealDB setup should succeed");
    let repository = SurrealDbRepository::new(db, DatabaseScope::default())
        .expect("repository construction should succeed");

    AccountRepository::<Role, Group>::bootstrap(&repository)
        .await
        .expect("benchmark account schema setup should succeed");

    let account =
        webgates_core::accounts::Account::<Role, Group>::new("benchmark-user@example.invalid");
    AccountRepository::<Role, Group>::store_account(&repository, account)
        .await
        .expect("benchmark account insert should succeed");

    for _ in 0..10 {
        let result = AccountRepository::<Role, Group>::query_account_by_user_id(
            &repository,
            "benchmark-user@example.invalid",
        )
        .await
        .expect("benchmark warmup lookup should succeed");
        black_box(result);
    }

    let started = Instant::now();
    for _ in 0..ITERATIONS {
        let result = AccountRepository::<Role, Group>::query_account_by_user_id(
            &repository,
            "benchmark-user@example.invalid",
        )
        .await
        .expect("benchmark lookup should succeed");
        black_box(result);
    }

    let elapsed = started.elapsed();
    println!(
        "SurrealDB repository lookup: {ITERATIONS} iterations in {elapsed:?} ({:?}/iteration)",
        elapsed / ITERATIONS as u32
    );
}
