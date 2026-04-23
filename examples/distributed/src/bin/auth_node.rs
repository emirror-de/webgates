use distributed::{ApiPermission, AppPermissions, PermissionHelper};

use axum::extract::Json;
use axum::routing::{Router, get, post};
use webgates::codecs::jwt::RegisteredClaims;
use webgates::credentials::Credentials;
use webgates::groups::Group;
use webgates::roles::Role;
use webgates_axum::route_handlers;
use webgates_codecs::jwt::JwtClaims;
use webgates_codecs::jwt::authority::JwtAuthority;
use webgates_repositories::memory::account::MemoryAccountRepository;
use webgates_repositories::memory::secret::MemorySecretRepository;
use webgates_repositories::services::account_insert::AccountInsertService;

use std::sync::Arc;

use chrono::{TimeDelta, Utc};
use tracing::debug;

use std::fs;

const ISSUER: &str = "auth-node";

const DISTRIBUTED_ES384_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCFT7MfRqWZfNgVX/cH
bxFTlPkBeCKqjsLkZXD/J3ZYHV1EtQksdrKtOzTr2hMs6pmhZANiAASyND9eQ5Qk
7ZteSEPMpExbVJenRWwyobExJMb62mmp3eA7Fszy8uBbLj8HRB16y3QbLcTxCBoo
ldBXfNFzM133OuTV2bBWXq5h34l+A0h4gU/odZ678LfAgnrRYMG4ZjU=
-----END PRIVATE KEY-----
"#;

const DISTRIBUTED_ES384_PUBLIC_KEY_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
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
    debug!("Tracing initialized.");

    let _ = dotenvy::dotenv();
    let private_key_pem = load_env_or_file(
        "JWT_ES384_PRIVATE_KEY_PEM",
        "JWT_ES384_PRIVATE_KEY_PATH",
        DISTRIBUTED_ES384_PRIVATE_KEY_PEM,
    );
    let public_key_pem = load_env_or_file(
        "JWT_ES384_PUBLIC_KEY_PEM",
        "JWT_ES384_PUBLIC_KEY_PATH",
        DISTRIBUTED_ES384_PUBLIC_KEY_PEM,
    );

    // One constructor — codec and JWKS provider are wired automatically with a stable kid.
    let authority = Arc::new(
        JwtAuthority::<JwtClaims<webgates::accounts::Account<Role, Group>>>::from_es384_pem(
            private_key_pem.as_bytes(),
            public_key_pem.as_bytes(),
        )
        .unwrap_or_else(|error| panic!("invalid JWT ES384 key pair: {error}")),
    );
    debug!("JWT authority initialized (kid = {}).", authority.key_id());

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
    let jwt_codec = authority.codec();

    let app = Router::new()
        // JWKS publication — no manual closure needed.
        .route(
            "/.well-known/jwks.json",
            get(route_handlers::jwks::jwks_from_authority::<
                JwtClaims<webgates::accounts::Account<Role, Group>>,
            >),
        )
        .with_state(Arc::clone(&authority))
        .route(
            "/login",
            post({
                let registered_claims = RegisteredClaims::new(
                    ISSUER,
                    (Utc::now() + TimeDelta::minutes(15)).timestamp() as u64,
                );
                let secrets_repository = Arc::clone(&secrets_repository);
                let account_repository = Arc::clone(&account_repository);
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
