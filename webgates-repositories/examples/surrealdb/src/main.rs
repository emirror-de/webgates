use webgates::accounts::Account;
use webgates::codecs::jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER as JWT_CRYPTO_PROVIDER;
use webgates::codecs::jwt::{JsonWebToken, JwtClaims, RegisteredClaims};
use webgates::cookie_template::CookieTemplate;
use webgates::credentials::Credentials;
use webgates::groups::Group;
use webgates::roles::Role;
use webgates_axum::route_handlers;
use webgates_repositories::services::account_insert::AccountInsertService;
use webgates_repositories::surrealdb::{DatabaseScope, SurrealDbRepository};

use std::fs;
use std::sync::Arc;

use axum::extract::Json;
use axum::routing::{Router, get, post};
use chrono::{TimeDelta, Utc};
use surrealdb::{Surreal, engine::local::Mem};
use tracing::debug;

const EXAMPLE_ES384_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCFT7MfRqWZfNgVX/cH
bxFTlPkBeCKqjsLkZXD/J3ZYHV1EtQksdrKtOzTr2hMs6pmhZANiAASyND9eQ5Qk
7ZteSEPMpExbVJenRWwyobExJMb62mmp3eA7Fszy8uBbLj8HRB16y3QbLcTxCBoo
ldBXfNFzM133OuTV2bBWXq5h34l+A0h4gU/odZ678LfAgnrRYMG4ZjU=
-----END PRIVATE KEY-----
"#;

const EXAMPLE_ES384_PUBLIC_KEY_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEsjQ/XkOUJO2bXkhDzKRMW1SXp0VsMqGx
MSTG+tppqd3gOxbM8vLgWy4/B0Qdest0Gy3E8QgaKJXQV3zRczNd9zrk1dmwVl6u
Yd+JfgNIeIFP6HWeu/C3wIJ60WDBuGY1
-----END PUBLIC KEY-----
"#;

fn load_env_or_file(var_name: &str, path_var_name: &str, fallback: &str) -> String {
    if let Ok(path) = dotenvy::var(path_var_name) {
        return match fs::read_to_string(path) {
            Ok(value) => value,
            Err(error) => panic!("failed to read {path_var_name} file: {error}"),
        };
    }

    dotenvy::var(var_name).unwrap_or_else(|_| fallback.to_string())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let _ = JWT_CRYPTO_PROVIDER.install_default();

    let _ = dotenvy::dotenv();
    let private_key_pem = load_env_or_file(
        "JWT_ES384_PRIVATE_KEY_PEM",
        "JWT_ES384_PRIVATE_KEY_PATH",
        EXAMPLE_ES384_PRIVATE_KEY_PEM,
    );
    let public_key_pem = load_env_or_file(
        "JWT_ES384_PUBLIC_KEY_PEM",
        "JWT_ES384_PUBLIC_KEY_PATH",
        EXAMPLE_ES384_PUBLIC_KEY_PEM,
    );
    let jwt_options = match webgates::codecs::jwt::JsonWebTokenOptions::from_es384_pem(
        private_key_pem.as_bytes(),
        public_key_pem.as_bytes(),
    ) {
        Ok(options) => options,
        Err(error) => panic!("invalid JWT ES384 key pair: {error}"),
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

    AccountInsertService::<Role, Group>::insert("admin@example.com", "admin_password")
        .with_roles(vec![Role::Admin])
        .with_groups(vec![Group::new("admin")])
        .into_repositories(
            Arc::clone(&account_repository),
            Arc::clone(&secrets_repository),
        )
        .await
        .unwrap();
    debug!("Inserted Admin.");

    AccountInsertService::<Role, Group>::insert("reporter@example.com", "reporter_password")
        .with_roles(vec![Role::Reporter])
        .with_groups(vec![Group::new("reporter")])
        .into_repositories(
            Arc::clone(&account_repository),
            Arc::clone(&secrets_repository),
        )
        .await
        .unwrap();
    debug!("Inserted Reporter.");

    AccountInsertService::<Role, Group>::insert("user@example.com", "user_password")
        .with_roles(vec![Role::User])
        .with_groups(vec![Group::new("user")])
        .into_repositories(
            Arc::clone(&account_repository),
            Arc::clone(&secrets_repository),
        )
        .await
        .unwrap();
    debug!("Inserted User.");

    let cookie_template = CookieTemplate::recommended();

    let app = Router::new()
        .route(
            "/login",
            post({
                let registered_claims = RegisteredClaims::new(
                    // same as in distributed example, so you can re-use the consumer_node
                    "auth-node",
                    (Utc::now() + TimeDelta::minutes(15)).timestamp() as u64,
                );
                let secrets_repository = Arc::clone(&secrets_repository);
                let account_repository = Arc::clone(&account_repository);
                let jwt_codec = Arc::clone(&jwt_codec);
                let cookie_template = cookie_template.clone();
                move |cookie_jar, Json(credentials): Json<Credentials<String>>| {
                    route_handlers::login::login(
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
            get(move |cookie_jar| route_handlers::logout::logout(cookie_jar, cookie_template)),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
