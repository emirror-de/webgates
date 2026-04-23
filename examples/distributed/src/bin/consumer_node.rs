use distributed::{ApiPermission, AppPermissions, PermissionHelper, RepositoryPermission};

use webgates::{accounts::Account, authz::access_policy::AccessPolicy, groups::Group, roles::Role};
use webgates_axum::gate::remote_jwks_cookie::RemoteJwksCookieGate;
use webgates_codecs::jwt::{
    JwtClaims,
    remote_verifier::{RemoteJwksVerifier, RemoteJwksVerifierConfig},
};

use std::sync::Arc;

use axum::extract::Extension;
use axum::response::IntoResponse;
use axum::routing::{Router, get};

const ISSUER: &str = "auth-node";

type AppClaims = JwtClaims<Account<Role, Group>>;

async fn index() -> Result<String, ()> {
    Ok("Hello consumer!".to_string())
}

async fn reporter(Extension(user): Extension<Account<Role, Group>>) -> Result<String, ()> {
    Ok(format!(
        "Hello {} and welcome to the consumer node. Your roles are {:?} and you are member of groups {:?}!",
        user.user_id, user.roles, user.groups
    ))
}

async fn user(Extension(user): Extension<Account<Role, Group>>) -> Result<String, ()> {
    Ok(format!(
        "Hello {} and welcome to the consumer node. Your roles are {:?} and you are member of groups {:?}!",
        user.user_id, user.roles, user.groups
    ))
}

async fn permissions(Extension(user): Extension<Account<Role, Group>>) -> impl IntoResponse {
    // Demonstrate zero-sync permission checking
    let has_read_api = PermissionHelper::has_permission(
        user.permissions.as_ref(),
        &AppPermissions::Api(ApiPermission::Read),
    );
    let has_write_api = PermissionHelper::has_permission(
        user.permissions.as_ref(),
        &AppPermissions::Api(ApiPermission::Write),
    );
    let has_read_repo = PermissionHelper::has_permission(
        user.permissions.as_ref(),
        &AppPermissions::Repository(RepositoryPermission::Read),
    );
    let has_write_repo = PermissionHelper::has_permission(
        user.permissions.as_ref(),
        &AppPermissions::Repository(RepositoryPermission::Write),
    );
    let is_admin = PermissionHelper::is_admin(user.permissions.as_ref());

    format!(
        "Hello {} and welcome to the consumer node. Your roles are {:?} and you are member of groups {:?}!\n\
        Zero-Sync Permission Analysis:\n\
        - Read API: {}\n\
        - Write API: {}\n\
        - Read Repository: {}\n\
        - Write Repository: {}\n\
        - Admin Access: {}\n\
        Raw permission bitmap: {:?}",
        user.user_id,
        user.roles,
        user.groups,
        has_read_api,
        has_write_api,
        has_read_repo,
        has_write_repo,
        is_admin,
        user.permissions.iter().collect::<Vec<_>>()
    )
}

async fn admin_group(Extension(user): Extension<Account<Role, Group>>) -> Result<String, ()> {
    Ok(format!(
        "Hi {} and welcome to the secret admin-group site on the consumer node, your roles are {:?} and you are member of groups {:?}!",
        user.user_id, user.roles, user.groups
    ))
}

async fn admin(Extension(user): Extension<Account<Role, Group>>) -> Result<String, ()> {
    Ok(format!(
        "Hello {} and welcome to the consumer node. Your roles are {:?} and you are member of groups {:?}!",
        user.user_id, user.roles, user.groups
    ))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let _ = dotenvy::dotenv();

    // Bootstrap the shared remote JWKS verifier — one constructor from JWKS URL.
    let jwks_url = dotenvy::var("JWKS_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:3000/.well-known/jwks.json".to_string());
    let mut config = RemoteJwksVerifierConfig::from_jwks_url(jwks_url);
    if let Some(ms) = dotenvy::var("JWKS_HTTP_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        config = config.with_http_timeout(std::time::Duration::from_millis(ms));
    }
    if let Some(secs) = dotenvy::var("JWKS_REFRESH_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        config = config.with_refresh_interval(std::time::Duration::from_secs(secs));
    }
    if let Ok(path) = dotenvy::var("JWKS_CACHE_PATH") {
        config = config.with_cache_path(std::path::PathBuf::from(path));
    }

    let verifier = Arc::new(
        RemoteJwksVerifier::<AppClaims>::bootstrap(config)
            .await
            .unwrap_or_else(|error| panic!("failed to bootstrap JWKS verifier: {error}")),
    );
    let _refresh_task = verifier.start_background_refresh();

    // Build per-route gates — one constructor from issuer + shared verifier.
    let admin_gate = RemoteJwksCookieGate::new(ISSUER, Arc::clone(&verifier))
        .with_policy(AccessPolicy::require_role_or_supervisor(Role::Admin));

    let admin_group_gate = RemoteJwksCookieGate::new(ISSUER, Arc::clone(&verifier))
        .with_policy(AccessPolicy::require_group(Group::new("admin")));

    let reporter_gate = RemoteJwksCookieGate::new(ISSUER, Arc::clone(&verifier))
        .with_policy(AccessPolicy::require_role_or_supervisor(Role::Reporter));

    let user_gate = RemoteJwksCookieGate::new(ISSUER, Arc::clone(&verifier))
        .with_policy(AccessPolicy::require_role(Role::User));

    let permissions_gate = RemoteJwksCookieGate::new(ISSUER, Arc::clone(&verifier)).with_policy(
        AccessPolicy::require_permission(&AppPermissions::Api(ApiPermission::Read)),
    );

    let app = Router::new()
        .route("/admin", get(admin).route_layer(admin_gate))
        .route(
            "/secret-admin-group",
            get(admin_group).route_layer(admin_group_gate),
        )
        .route("/reporter", get(reporter).route_layer(reporter_gate))
        .route("/user", get(user).route_layer(user_gate))
        .route(
            "/permissions",
            get(permissions).route_layer(permissions_gate),
        )
        .route("/", get(index));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3001")
        .await
        .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
