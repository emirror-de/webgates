use distributed::{ApiPermission, AppPermissions, PermissionHelper};

use webgates::codecs::jsonwebtoken;
use webgates::codecs::jwt::{JsonWebToken, JsonWebTokenOptions, RegisteredClaims};
use webgates::credentials::Credentials;
use webgates::groups::Group;
use webgates::roles::Role;
use webgates_axum::route_handlers;
use webgates_repositories::memory::account::MemoryAccountRepository;
use webgates_repositories::memory::secret::MemorySecretRepository;
use webgates_repositories::services::account_insert::AccountInsertService;

use std::sync::Arc;

use axum::extract::Json;
use axum::routing::{Router, get, post};
use chrono::{TimeDelta, Utc};
use tracing::debug;

const ISSUER: &str = "auth-node";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    debug!("Tracing initialized.");

    dotenvy::dotenv().expect("Could not read .env file.");
    let shared_secret =
        dotenvy::var("webgates_SHARED_SECRET").expect("webgates_SHARED_SECRET env var not set.");
    let jwt_codec = Arc::new(JsonWebToken::new_with_options(JsonWebTokenOptions {
        enc_key: jsonwebtoken::EncodingKey::from_secret(shared_secret.as_bytes()),
        dec_key: jsonwebtoken::DecodingKey::from_secret(shared_secret.as_bytes()),
        header: Some(jsonwebtoken::Header::default()),
        validation: Some(jsonwebtoken::Validation::default()),
    }));
    debug!("JWT codec initialized.");

    let account_repository = Arc::new(MemoryAccountRepository::default());
    debug!("Account repository initialized.");
    let secrets_repository = Arc::new(MemorySecretRepository::new_with_argon2_hasher().unwrap());
    debug!("Secrets repository initialized.");

    // Create admin with all permissions using new zero-sync system
    let mut admin_permissions = roaring::RoaringTreemap::new();
    PermissionHelper::grant_admin_access(&mut admin_permissions);

    AccountInsertService::<Role, Group>::insert("admin@example.com", "admin_password")
        .with_roles(vec![Role::Admin])
        .with_groups(vec![Group::new("admin")])
        .with_permissions(admin_permissions.into())
        .into_repositories(
            Arc::clone(&account_repository),
            Arc::clone(&secrets_repository),
        )
        .await
        .unwrap();
    debug!("Inserted Admin with full permissions.");

    // Create reporter with repository access
    let mut reporter_permissions = roaring::RoaringTreemap::new();
    PermissionHelper::grant_repository_access(&mut reporter_permissions);

    AccountInsertService::<Role, Group>::insert("reporter@example.com", "reporter_password")
        .with_roles(vec![Role::Reporter])
        .with_groups(vec![Group::new("reporter")])
        .with_permissions(reporter_permissions.into())
        .into_repositories(
            Arc::clone(&account_repository),
            Arc::clone(&secrets_repository),
        )
        .await
        .unwrap();
    debug!("Inserted Reporter with repository access.");

    // Create user with API read access only
    let mut user_permissions = roaring::RoaringTreemap::new();
    PermissionHelper::grant_permission(
        &mut user_permissions,
        &AppPermissions::Api(ApiPermission::Read),
    );

    AccountInsertService::<Role, Group>::insert("user@example.com", "user_password")
        .with_roles(vec![Role::User])
        .with_groups(vec![Group::new("user")])
        .with_permissions(user_permissions.into())
        .into_repositories(
            Arc::clone(&account_repository),
            Arc::clone(&secrets_repository),
        )
        .await
        .unwrap();
    debug!("Inserted User with API read access.");

    let cookie_template = webgates::cookie_template::CookieTemplate::recommended();

    let app = Router::new()
        .route(
            "/login",
            post({
                let registered_claims = RegisteredClaims::new(
                    ISSUER,
                    (Utc::now() + TimeDelta::weeks(1)).timestamp() as u64,
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
