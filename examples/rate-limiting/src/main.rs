//! Rate Limiting Example with axum-gate
//!
//! This example demonstrates how to use axum-gate with tower's rate limiting
//! middleware to protect authentication endpoints and authenticated routes.
//!
//! Features demonstrated:
//! - Rate limiting on login endpoints to prevent brute force attacks
//! - Different rate limits for authenticated vs unauthenticated users
//! - Integration with axum-gate's authentication system
//! - Proper error handling for rate limit exceeded

use axum::{
    BoxError, Form, Router,
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};

use axum_extra::extract::CookieJar;
use axum_gate::prelude::*;

use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tokio::net::TcpListener;

use axum::error_handling::HandleErrorLayer;
use tower::{ServiceBuilder, buffer::BufferLayer, limit::RateLimitLayer};
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

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
    let app_state = AppState {};

    // Build the application with rate limiting middleware
    let app = Router::new()
        .route("/", get(home_handler))
        // Login routes with strict rate limiting (5 requests per minute)
        .route("/login", get(login_page_handler).post(login_handler))
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|_: BoxError| async move {
                    StatusCode::TOO_MANY_REQUESTS
                }))
                .layer(BufferLayer::new(1024))
                .layer(RateLimitLayer::new(5, Duration::from_secs(60))),
        )
        .route("/logout", post(logout_handler))
        // Protected dashboard route with moderate rate limiting (30 requests per minute)
        .route(
            "/dashboard",
            get(dashboard_handler).layer(
                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(|_: BoxError| async move {
                        StatusCode::TOO_MANY_REQUESTS
                    }))
                    .layer(BufferLayer::new(1024))
                    .layer(RateLimitLayer::new(30, Duration::from_secs(60)))
                    .layer(
                        Gate::cookie("my-app", Arc::clone(&jwt_codec))
                            .with_policy(
                                AccessPolicy::require_role(Role::User).or_require_role(Role::Admin),
                            )
                            .configure_cookie_template(|tpl| tpl.name("my-app"))?,
                    ),
            ),
        )
        // Admin route with strict rate limiting (10 requests per minute)
        .route(
            "/admin",
            get(admin_handler).layer(
                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(|_: BoxError| async move {
                        StatusCode::TOO_MANY_REQUESTS
                    }))
                    .layer(BufferLayer::new(1024))
                    .layer(RateLimitLayer::new(10, Duration::from_secs(60)))
                    .layer(
                        Gate::cookie("my-app", Arc::clone(&jwt_codec))
                            .with_policy(AccessPolicy::require_role(Role::Admin))
                            .configure_cookie_template(|tpl| tpl.name("my-app"))?,
                    ),
            ),
        )
        // Apply global middleware to all routes
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    let listener = TcpListener::bind("127.0.0.1:3000").await?;
    info!("🚀 Server running on http://127.0.0.1:3000");
    info!("📝 Login with any username/password to test");
    info!("🛡️  Rate limits:");
    info!("   - Login endpoints: 5 requests per minute");
    info!("   - Dashboard: 30 requests per minute");
    info!("   - Admin panel: 10 requests per minute");

    axum::serve(listener, app).await?;

    Ok(())
}

#[derive(Clone)]
struct AppState {}

async fn home_handler() -> Html<&'static str> {
    Html(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Rate Limiting Example</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .container { max-width: 600px; margin: 0 auto; }
                .box { background: #f5f5f5; padding: 20px; margin: 20px 0; border-radius: 5px; }
                form { margin: 20px 0; }
                input, button { padding: 10px; margin: 5px; }
                button { background: #007cba; color: white; border: none; cursor: pointer; }
                button:hover { background: #005a87; }
                .error { color: red; }
                .success { color: green; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🛡️ Rate Limiting Example with axum-gate</h1>

                <div class="box">
                    <h2>Features Demonstrated</h2>
                    <ul>
                        <li><strong>Login rate limiting:</strong> 5 requests per minute (prevents brute force)</li>
                        <li><strong>Dashboard rate limiting:</strong> 30 requests per minute for authenticated users</li>
                        <li><strong>Admin rate limiting:</strong> 10 requests per minute for admin endpoints</li>
                        <li><strong>Global rate limiting:</strong> 100 requests per minute across all endpoints</li>
                        <li>Integration with axum-gate authentication and authorization</li>
                    </ul>
                </div>

                <div class="box">
                    <h2>Test Accounts</h2>
                    <p>Use any non-empty username and password to test the authentication flow.</p>
                </div>

                <div class="box">
                    <h2>Login</h2>
                    <form action="/login" method="post">
                        <div>
                            <input type="text" name="username" placeholder="Username" required>
                        </div>
                        <div>
                            <input type="password" name="password" placeholder="Password" required>
                        </div>
                        <button type="submit">Login</button>
                    </form>
                    <p><em>Try logging in with wrong credentials multiple times to test rate limiting!</em></p>
                </div>

                <div class="box">
                    <h2>Protected Routes</h2>
                    <ul>
                        <li><a href="/dashboard">Dashboard</a> - Requires authentication (30 req/min)</li>
                        <li><a href="/admin">Admin Panel</a> - Requires admin permissions (10 req/min)</li>
                    </ul>
                    <p><em>Rapidly refresh these pages after logging in to test rate limits!</em></p>
                </div>
            </div>
        </body>
        </html>
        "#,
    )
}

async fn login_page_handler() -> Html<&'static str> {
    Html("Login page - use the form on the home page")
}

async fn dashboard_handler(jar: CookieJar) -> Result<Response, StatusCode> {
    // Simple authentication check for demonstration
    if jar.get("my-app").is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard</title>
            <style>body { font-family: Arial, sans-serif; margin: 40px; }</style>
        </head>
        <body>
            <h1>📊 Dashboard</h1>
            <p>Welcome, authenticated user!</p>
            <p><em>This route is protected by rate limiting (30 requests/minute)</em></p>
            <p><strong>Test rate limiting:</strong> Refresh this page rapidly to trigger the rate limit!</p>
            <p><a href="/">← Back to Home</a></p>
            <form action="/logout" method="post">
                <button type="submit">Logout</button>
            </form>
        </body>
        </html>
        "#.to_string();

    Ok(Html(html).into_response())
}

async fn admin_handler(jar: CookieJar) -> Result<Response, StatusCode> {
    // Simple authentication check for demonstration
    if jar.get("my-app").is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Panel</title>
            <style>body { font-family: Arial, sans-serif; margin: 40px; }</style>
        </head>
        <body>
            <h1>⚙️ Admin Panel</h1>
            <p>Welcome, Administrator!</p>
            <p>This is a protected admin route with strict rate limiting.</p>
            <p><em>This route requires admin permissions and is rate limited to 10 requests/minute</em></p>
            <p><strong>Test rate limiting:</strong> Refresh this page rapidly to trigger the admin rate limit!</p>
            <p><a href="/">← Back to Home</a></p>
            <form action="/logout" method="post">
                <button type="submit">Logout</button>
            </form>
        </body>
        </html>
        "#.to_string();

    Ok(Html(html).into_response())
}

async fn login_handler(
    State(_state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Result<Response, StatusCode> {
    info!("Login attempt for user: {}", form.username);

    // For demonstration purposes, accept any non-empty credentials
    let success = !form.username.is_empty() && !form.password.is_empty();

    if success {
        info!("Successful login for user: {}", form.username);

        // Create a simple JWT cookie for demonstration
        let cookie = axum_gate::cookie::Cookie::build(("my-app", "demo-token"))
            .path("/")
            .http_only(true)
            .build();

        let jar = jar.add(cookie);
        Ok((jar, axum::response::Redirect::to("/dashboard")).into_response())
    } else {
        warn!("Invalid credentials provided for user: {}", form.username);
        let html = Html(
            r#"
            <!DOCTYPE html>
            <html>
            <head>
                <title>Login Failed</title>
                <style>body { font-family: Arial, sans-serif; margin: 40px; } .error { color: red; }</style>
            </head>
            <body>
                <h1>❌ Login Failed</h1>
                <p class="error">Invalid username or password.</p>
                <p><em>Note: Try multiple failed login attempts to test the rate limiting (5 attempts per minute)!</em></p>
                <p><a href="/">← Back to Home</a></p>
            </body>
            </html>
            "#,
        );
        Ok(html.into_response())
    }
}

async fn logout_handler(jar: CookieJar) -> Result<Response, StatusCode> {
    // Remove the authentication cookie
    let cookie = axum_gate::cookie::Cookie::build(("my-app", ""))
        .path("/")
        .http_only(true)
        .removal()
        .build();

    let jar = jar.add(cookie);
    info!("User logged out successfully");
    Ok((jar, axum::response::Redirect::to("/")).into_response())
}
