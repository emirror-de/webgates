use webgates::accounts::Account;
use webgates::codecs::jwt::{JsonWebToken, JwtClaims, RegisteredClaims};
use webgates::cookie_template::CookieTemplate;
use webgates::credentials::Credentials;
use webgates::groups::Group;
use webgates::roles::Role;
use webgates::secrets::Secret;
use webgates::secrets::hashing::argon2::Argon2Hasher;
use webgates_axum::route_handlers;
use webgates_repositories::account_repository::AccountRepository;
use webgates_repositories::sea_orm::SeaOrmRepository;
use webgates_repositories::secret_repository::SecretRepository;
use webgates_repositories::services::account_insert::AccountInsertService;

use std::fs;
use std::sync::Arc;

use axum::extract::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{Router, get, post};
use chrono::{Duration, Utc};
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Schema};
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

const DATABASE_URL: &str = "sqlite::memory:";
// Use the following if you want to see what is stored
//const DATABASE_URL: &str = "sqlite:auth-node.sqlite3?mode=rwc";

async fn setup_database_schema(db: &DatabaseConnection) {
    let schema = Schema::new(DbBackend::Sqlite);
    let stmt = schema
        .create_table_from_entity(webgates_repositories::sea_orm::models::credentials::Entity);
    // execute the statement using the connection's execute method
    db.execute(&stmt)
        .await
        .expect("Could not create credentials table");

    let stmt =
        schema.create_table_from_entity(webgates_repositories::sea_orm::models::account::Entity);
    db.execute(&stmt)
        .await
        .expect("Could not create account table");
}

#[derive(serde::Deserialize)]
struct PasswordUpdate {
    user_id: String,
    new_password: String,
}

#[derive(serde::Deserialize)]
struct AccountUpdate {
    user_id: String,
    roles: Vec<Role>,
    groups: Vec<String>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

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

    // SQLite memory database connection
    let db: DatabaseConnection = Database::connect(DATABASE_URL)
        .await
        .unwrap_or_else(|_| panic!("Could not connect to {DATABASE_URL} database."));

    setup_database_schema(&db).await;

    let account_repository = Arc::new(SeaOrmRepository::new(&db).unwrap());
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
                    (Utc::now() + Duration::minutes(15)).timestamp() as u64,
                );
                let secrets_repository = Arc::clone(&secrets_repository);
                let account_repository = Arc::clone(&account_repository);
                let jwt_codec = Arc::clone(&jwt_codec);
                let cookie_template = cookie_template.clone();
                move |cookie_jar, Json(credentials): Json<Credentials<String>>| {
                    route_handlers::login::login::<_, _, _, Role, Group>(
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
        )
        .route(
            "/password",
            post({
                let account_repository = Arc::clone(&account_repository);
                let secrets_repository = Arc::clone(&secrets_repository);
                move |Json(body): Json<PasswordUpdate>| async move {
                    let Some(account): std::option::Option<Account<Role, Group>> =
                        account_repository
                            .query_account_by_user_id(&body.user_id)
                            .await
                            .unwrap()
                    else {
                        return (StatusCode::NOT_FOUND, "account not found").into_response();
                    };
                    let hasher = Argon2Hasher::new_recommended().unwrap();
                    let secret =
                        Secret::new(&account.account_id, &body.new_password, hasher).unwrap();
                    secrets_repository.update_secret(secret).await.unwrap();
                    (StatusCode::OK, "password updated").into_response()
                }
            }),
        )
        .route(
            "/account",
            post({
                let account_repository = Arc::clone(&account_repository);
                move |Json(body): Json<AccountUpdate>| async move {
                    let Some(mut account) = account_repository
                        .query_account_by_user_id(&body.user_id)
                        .await
                        .unwrap()
                    else {
                        return (StatusCode::NOT_FOUND, "account not found").into_response();
                    };
                    account.roles = body.roles;
                    account.groups = body.groups.into_iter().map(|g| Group::new(&g)).collect();
                    let _ = account_repository.update_account(account).await.unwrap();
                    (StatusCode::OK, "account updated").into_response()
                }
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
