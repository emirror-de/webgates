use distributed::{ApiPermission, AppPermissions, PermissionHelper};

use axum_gate::accounts::AccountInsertService;
use axum_gate::codecs::jwt::{JsonWebToken, JsonWebTokenOptions, RegisteredClaims};
use axum_gate::prelude::{Credentials, Group, Role};
use axum_gate::repositories::memory::{MemoryAccountRepository, MemorySecretRepository};

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
        dotenvy::var("AXUM_GATE_SHARED_SECRET").expect("AXUM_GATE_SHARED_SECRET env var not set.");
    let jwt_codec = Arc::new(JsonWebToken::new_with_options(JsonWebTokenOptions {
        enc_key: axum_gate::jsonwebtoken::EncodingKey::from_secret(shared_secret.as_bytes()),
        dec_key: axum_gate::jsonwebtoken::DecodingKey::from_secret(shared_secret.as_bytes()),
        header: Some(axum_gate::jsonwebtoken::Header::default()),
        validation: Some(axum_gate::jsonwebtoken::Validation::default()),
    }));
    debug!("JWT codec initialized.");

    let account_repository = Arc::new(MemoryAccountRepository::default());
    debug!("Account repository initialized.");
    let secrets_repository = Arc::new(MemorySecretRepository::new_with_argon2_hasher().unwrap());
    debug!("Secrets repository initialized.");

    // Create admin with all permissions using new zero-sync system
    let mut admin_permissions = roaring::RoaringTreemap::new();
    PermissionHelper::grant_admin_access(&mut admin_permissions);

    AccountInsertService::insert("admin@example.com", "admin_password")
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

    AccountInsertService::insert("reporter@example.com", "reporter_password")
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

    AccountInsertService::insert("user@example.com", "user_password")
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

    let cookie_template = axum_gate::prelude::CookieTemplate::recommended();

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
