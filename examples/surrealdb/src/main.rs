use axum_gate::accounts::AccountInsertService;
use axum_gate::codecs::jwt::RegisteredClaims;
use axum_gate::prelude::*;
use axum_gate::repositories::surrealdb::{DatabaseScope, SurrealDbRepository};

use std::sync::Arc;

use axum::extract::Json;
use axum::routing::{Router, get, post};
use chrono::{TimeDelta, Utc};
use surrealdb::{Surreal, engine::local::Mem};
use tracing::debug;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    dotenvy::dotenv().expect("Could not read .env file.");
    let shared_secret =
        dotenvy::var("AXUM_GATE_SHARED_SECRET").expect("AXUM_GATE_SHARED_SECRET env var not set.");
    let jwt_options = JsonWebTokenOptions {
        enc_key: axum_gate::jsonwebtoken::EncodingKey::from_secret(shared_secret.as_bytes()),
        dec_key: axum_gate::jsonwebtoken::DecodingKey::from_secret(shared_secret.as_bytes()),
        header: Some(axum_gate::jsonwebtoken::Header::default()),
        validation: Some(axum_gate::jsonwebtoken::Validation::default()),
    };
    let jwt_codec =
        Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::new_with_options(jwt_options));

    // Surrealdb memory database connection
    let db = Surreal::new::<Mem>(())
        .await
        .expect("Could not connect to surrealdb memory database.");

    let account_repository =
        Arc::new(SurrealDbRepository::new(db, DatabaseScope::default()).unwrap());
    debug!("Account repository initialized.");
    let secrets_repository = Arc::clone(&account_repository);
    debug!("Secrets repository initialized.");

    AccountInsertService::insert("admin@example.com", "admin_password")
        .with_roles(vec![Role::Admin])
        .with_groups(vec![Group::new("admin")])
        .into_repositories(
            Arc::clone(&account_repository),
            Arc::clone(&secrets_repository),
        )
        .await
        .unwrap();
    debug!("Inserted Admin.");

    AccountInsertService::insert("reporter@example.com", "reporter_password")
        .with_roles(vec![Role::Reporter])
        .with_groups(vec![Group::new("reporter")])
        .into_repositories(
            Arc::clone(&account_repository),
            Arc::clone(&secrets_repository),
        )
        .await
        .unwrap();
    debug!("Inserted Reporter.");

    AccountInsertService::insert("user@example.com", "user_password")
        .with_roles(vec![Role::User])
        .with_groups(vec![Group::new("user")])
        .into_repositories(
            Arc::clone(&account_repository),
            Arc::clone(&secrets_repository),
        )
        .await
        .unwrap();
    debug!("Inserted User.");

    let cookie_template = axum_gate::cookie_template::CookieTemplate::recommended();

    let app = Router::new()
        .route(
            "/login",
            post({
                let registered_claims = RegisteredClaims::new(
                    // same as in distributed example, so you can re-use the consumer_node
                    "auth-node",
                    (Utc::now() + TimeDelta::weeks(1)).timestamp() as u64,
                );
                let secrets_repository = Arc::clone(&secrets_repository);
                let account_repository = Arc::clone(&account_repository);
                let jwt_codec = Arc::clone(&jwt_codec);
                let cookie_template = cookie_template.clone();
                move |cookie_jar, Json(credentials): Json<Credentials<String>>| {
                    axum_gate::route_handlers::login(
                        cookie_jar,
                        credentials,
                        registered_claims,
                        secrets_repository,
                        account_repository,
                        jwt_codec,
                        cookie_template,
                    )
                }
            }),
        )
        .route(
            "/logout",
            get(move |cookie_jar| axum_gate::route_handlers::logout(cookie_jar, cookie_template)),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
