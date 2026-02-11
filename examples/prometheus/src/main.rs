//! Prometheus metrics integration example.
//!
//! This example demonstrates how to integrate axum-gate with Prometheus metrics
//! to monitor authentication events, authorization decisions, and other security-related metrics.
//!
//! Run with:
//! ```
//! cargo run --example prometheus
//! ```
//!
//! Then visit:
//! - http://localhost:3000/ - Home page with login form
//! - http://localhost:3000/admin - Admin-only area (requires admin role)
//! - http://localhost:3000/metrics - Prometheus metrics endpoint

use axum_extra::extract::CookieJar;
use axum_gate::{
    accounts::AccountInsertService,
    authz::AccessPolicy,
    codecs::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims, RegisteredClaims},
    cookie_template::CookieTemplate,
    prelude::{Account, Credentials, Gate, Group, Role},
    repositories::memory::{MemoryAccountRepository, MemorySecretRepository},
    route_handlers::{login, logout},
};

use std::sync::Arc;

use axum::{
    Form, Router,
    extract::{Extension, State},
    http::StatusCode,
    response::{Html, Redirect},
    routing::{get, post},
};
use prometheus::{Counter, Histogram, Opts, Registry, TextEncoder};
use serde::Deserialize;

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    // Create Prometheus registry for collecting metrics
    let registry = Registry::new();

    // Create custom application metrics (in addition to axum-gate's built-in metrics)
    let login_attempts = Counter::with_opts(
        Opts::new(
            "axum_gate_example_login_attempts_total",
            "Total number of login attempts",
        )
        .const_label("component", "auth"),
    )
    .unwrap();

    let request_duration = Histogram::with_opts(prometheus::HistogramOpts::new(
        "axum_gate_example_request_duration_seconds",
        "Request duration in seconds",
    ))
    .unwrap();

    registry.register(Box::new(login_attempts.clone())).unwrap();
    registry
        .register(Box::new(request_duration.clone()))
        .unwrap();

    // Set up storage (in-memory for this example)
    let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
    let secret_repo = Arc::new(MemorySecretRepository::new_with_argon2_hasher().unwrap());

    // Create some test users
    create_test_users(Arc::clone(&account_repo), Arc::clone(&secret_repo)).await;

    // Create JWT codec with proper shared secret
    let shared_secret = "my-super-secret-key-for-demo"; // In production, use a proper secret from env
    let jwt_options = JsonWebTokenOptions {
        enc_key: axum_gate::jsonwebtoken::EncodingKey::from_secret(shared_secret.as_bytes()),
        dec_key: axum_gate::jsonwebtoken::DecodingKey::from_secret(shared_secret.as_bytes()),
        header: Some(Default::default()),
        validation: Some(axum_gate::jsonwebtoken::Validation::default()),
    };
    let jwt_codec =
        Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::new_with_options(jwt_options));

    // Create app state
    let app_state = AppState {
        account_repo: Arc::clone(&account_repo),
        secret_repo: Arc::clone(&secret_repo),
        jwt_codec: Arc::clone(&jwt_codec),
        login_attempts,
        registry,
    };

    // Build app with Prometheus metrics enabled
    let app = Router::new()
        .route(
            "/",
            get(home_handler).layer(
                Gate::cookie("prometheus-demo", Arc::clone(&jwt_codec))
                    .allow_anonymous_with_optional_user()
                    .with_prometheus_registry(&app_state.registry) // 🔍 Enable axum-gate Prometheus metrics
                    .configure_cookie_template(|tpl| tpl.name("prometheus-demo"))
                    .unwrap(),
            ),
        )
        .route("/login", post(login_handler))
        .route("/logout", post(logout_handler))
        .route("/metrics", get(metrics_handler))
        // Admin-only area with Prometheus metrics enabled
        .route(
            "/admin",
            get(admin_handler).layer(
                Gate::cookie("prometheus-demo", Arc::clone(&jwt_codec))
                    .with_policy(AccessPolicy::require_role(Role::Admin))
                    .with_prometheus_registry(&app_state.registry) // 🔍 Enable axum-gate Prometheus metrics
                    .configure_cookie_template(|tpl| tpl.name("prometheus-demo"))
                    .unwrap(),
            ),
        )
        // Public area (accessible by authenticated users)
        .route(
            "/dashboard",
            get(dashboard_handler).layer(
                Gate::cookie("prometheus-demo", Arc::clone(&jwt_codec))
                    .with_policy(AccessPolicy::require_role_or_supervisor(Role::Admin))
                    .with_prometheus_registry(&app_state.registry) // 🔍 Enable axum-gate metrics for this route too
                    .configure_cookie_template(|tpl| tpl.name("prometheus-demo"))
                    .unwrap(),
            ),
        )
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    tracing::info!("Server starting on http://localhost:3000");
    tracing::info!("Metrics available at http://localhost:3000/metrics");
    tracing::info!("Test users: admin/admin, user/user");

    axum::serve(listener, app).await.unwrap();
}

#[derive(Clone)]
struct AppState {
    account_repo: Arc<MemoryAccountRepository<Role, Group>>,
    secret_repo: Arc<MemorySecretRepository>,
    jwt_codec: Arc<JsonWebToken<JwtClaims<Account<Role, Group>>>>,
    login_attempts: Counter,
    registry: Registry,
}

async fn home_handler(account: Option<Extension<Account<Role, Group>>>) -> Html<&'static str> {
    if account.is_some() {
        Html(
            r#"
        <!DOCTYPE html>
        <html>
        <head><title>Prometheus Demo - Home</title></head>
        <body>
            <h1>Welcome! You are logged in.</h1>
            <p><a href="/dashboard">Go to Dashboard</a></p>
            <p><a href="/admin">Admin Area</a></p>
            <p><a href="/metrics">View Metrics</a></p>
            <form action="/logout" method="post">
                <button type="submit">Logout</button>
            </form>
        </body>
        </html>
        "#,
        )
    } else {
        Html(
            r#"
        <!DOCTYPE html>
        <html>
        <head><title>Prometheus Demo - Login</title></head>
        <body>
            <h1>Prometheus Integration Demo</h1>
            <p>This example shows how to integrate axum-gate with Prometheus metrics.</p>

            <h2>Login</h2>
            <form action="/login" method="post">
                <div>
                    <label>Username: <input type="text" name="username" required></label>
                </div>
                <div>
                    <label>Password: <input type="password" name="password" required></label>
                </div>
                <button type="submit">Login</button>
            </form>

            <h3>Test Accounts:</h3>
            <ul>
                <li>admin / admin (Admin role)</li>
                <li>user / user (User role)</li>
            </ul>

            <p><a href="/metrics">View Prometheus Metrics</a></p>
        </body>
        </html>
        "#,
        )
    }
}

async fn dashboard_handler(Extension(account): Extension<Account<Role, Group>>) -> Html<String> {
    let content = format!(
        r#"
        <!DOCTYPE html>
        <html>
        <head><title>Dashboard</title></head>
        <body>
            <h1>Dashboard</h1>
            <p>Welcome, {}!</p>
            <p>Roles: {:?}</p>
            <p>Groups: {:?}</p>
            <p>This page demonstrates successful authentication with metrics collection.</p>
            <p><a href="/">Home</a> | <a href="/admin">Admin</a> | <a href="/metrics">Metrics</a></p>
            <form action="/logout" method="post">
                <button type="submit">Logout</button>
            </form>
        </body>
        </html>
        "#,
        account.user_id, account.roles, account.groups
    );
    Html(content)
}

async fn admin_handler(Extension(account): Extension<Account<Role, Group>>) -> Html<String> {
    let content = format!(
        r#"
        <!DOCTYPE html>
        <html>
        <head><title>Admin Panel</title></head>
        <body>
            <h1>Admin Panel</h1>
            <p>Welcome, Administrator {}!</p>
            <p>This page is only accessible to users with Admin role.</p>
            <p>All access attempts to this page are tracked in Prometheus metrics.</p>

            <h2>Security Info</h2>
            <ul>
                <li>Successful authorizations are counted</li>
                <li>Failed authorization attempts are labeled by reason</li>
                <li>JWT validation failures are tracked</li>
                <li>Account operations are audited</li>
            </ul>

            <p><a href="/">Home</a> | <a href="/dashboard">Dashboard</a> | <a href="/metrics">Metrics</a></p>
            <form action="/logout" method="post">
                <button type="submit">Logout</button>
            </form>
        </body>
        </html>
        "#,
        account.user_id
    );
    Html(content)
}

async fn login_handler(
    State(app_state): State<AppState>,
    cookie_jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    // 📊 Increment custom login attempts metric
    app_state.login_attempts.inc();

    let credentials = Credentials::new(&form.username, &form.password);
    let registered_claims = RegisteredClaims::new(
        "prometheus-demo",
        (chrono::Utc::now().timestamp() + 3600) as u64, // 1 hour expiry
    );

    let cookie_template = CookieTemplate::recommended()
        .name("prometheus-demo")
        .secure(false); // Dev only; enable HTTPS + Secure(true) in production

    match login(
        cookie_jar,
        credentials,
        registered_claims,
        Arc::clone(&app_state.secret_repo),
        Arc::clone(&app_state.account_repo),
        Arc::clone(&app_state.jwt_codec),
        cookie_template,
    )
    .await
    {
        Ok(updated_jar) => {
            tracing::info!("User {} logged in successfully", form.username);
            Ok((updated_jar, Redirect::to("/")))
        }
        Err(_) => {
            tracing::warn!("Failed login attempt for user: {}", form.username);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

async fn logout_handler(cookie_jar: CookieJar) -> (CookieJar, Redirect) {
    let cookie_template = CookieTemplate::recommended().name("prometheus-demo");

    let updated_jar = logout(cookie_jar, cookie_template).await;
    tracing::info!("User logged out successfully");
    (updated_jar, Redirect::to("/"))
}

// 📊 Endpoint to expose Prometheus metrics for scraping
async fn metrics_handler(State(app_state): State<AppState>) -> Result<String, StatusCode> {
    let encoder = TextEncoder::new();
    let metric_families = app_state.registry.gather();

    match encoder.encode_to_string(&metric_families) {
        Ok(output) => Ok(output),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn create_test_users(
    account_repo: Arc<MemoryAccountRepository<Role, Group>>,
    secret_repo: Arc<MemorySecretRepository>,
) {
    // Create admin user
    let _ = AccountInsertService::insert("admin", "admin")
        .with_roles(vec![Role::Admin])
        .with_groups(vec![Group::new("leadership")])
        .into_repositories(Arc::clone(&account_repo), Arc::clone(&secret_repo))
        .await;

    // Create regular user
    let _ = AccountInsertService::insert("user", "user")
        .with_roles(vec![Role::User])
        .with_groups(vec![Group::new("customers")])
        .into_repositories(Arc::clone(&account_repo), Arc::clone(&secret_repo))
        .await;

    tracing::info!("Test users created successfully");
}
