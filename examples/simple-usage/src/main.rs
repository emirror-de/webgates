//! Simple usage example with HTML login form and logout buttons.
//!
//! This example demonstrates basic authentication with a login form
//! on the home page and logout buttons on protected pages.

use axum_extra::extract::CookieJar;
use axum_gate::cookie;
use axum_gate::errors::Result;
use axum_gate::{
    accounts::AccountInsertService,
    codecs::jwt::RegisteredClaims,
    cookie_template::CookieTemplate,
    prelude::*,
    repositories::memory::{MemoryAccountRepository, MemorySecretRepository},
    route_handlers::{login, logout},
};

use std::sync::Arc;

use axum::{
    Form, Router,
    extract::{Extension, State},
    http::StatusCode,
    response::{Html, Json, Redirect},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct DebugInfo {
    account_details: Option<Account<Role, Group>>,
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();

    // Set up storage (in-memory for this example)
    let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
    let secret_repo = Arc::new(MemorySecretRepository::new_with_argon2_hasher()?);

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

    // Build app with different protection levels
    let app = Router::new()
        // Admin-only area
        .route(
            "/admin",
            get(admin_handler).layer(
                Gate::cookie("my-app", Arc::clone(&jwt_codec))
                    .with_policy(AccessPolicy::require_role(Role::Admin))
                    .configure_cookie_template(|tpl| tpl.name("my-app"))?,
            ),
        )
        // Staff area - multiple roles allowed
        .route(
            "/staff",
            get(staff_handler).layer(
                Gate::cookie("my-app", Arc::clone(&jwt_codec))
                    .with_policy(
                        AccessPolicy::require_role(Role::Admin).or_require_role(Role::Moderator),
                    )
                    .configure_cookie_template(|tpl| tpl.name("my-app"))?,
            ),
        )
        // Engineering team area - group-based access
        .route(
            "/engineering",
            get(engineering_handler).layer(
                Gate::cookie("my-app", Arc::clone(&jwt_codec))
                    .with_policy(AccessPolicy::require_group(Group::new("engineering")))
                    .configure_cookie_template(|tpl| tpl.name("my-app"))?,
            ),
        )
        // Any logged-in user
        .route(
            "/profile",
            get(profile_handler).layer(
                Gate::cookie("my-app", Arc::clone(&jwt_codec))
                    .require_login()
                    .configure_cookie_template(|tpl| tpl.name("my-app"))?,
            ),
        )
        // Home page - unprotected, shows login form
        .route("/", get(home_handler))
        // Dashboard - protected, shows dashboard for authenticated users
        .route(
            "/dashboard",
            get(dashboard_handler).layer(
                Gate::cookie("my-app", Arc::clone(&jwt_codec))
                    .require_login()
                    .configure_cookie_template(|tpl| tpl.name("my-app"))?,
            ),
        )
        // Authentication endpoints
        .route("/login", get(login_page_handler).post(login_handler))
        .route("/logout", post(logout_handler))
        // Debug endpoint
        .route("/debug", get(debug_handler))
        // Add repositories and JWT codec to state for handlers
        .with_state(AppState {
            account_repo,
            secret_repo,
            jwt_codec,
        });

    println!("🚀 Server starting on http://localhost:3000");
    println!("📚 Available endpoints:");
    println!("  • GET  / - Home page (login form)");
    println!("  • GET  /dashboard - Dashboard (authenticated users)");
    println!("  • POST /login - Process login");
    println!("  • POST /logout - Logout");
    println!("  • GET  /profile - User profile (authenticated)");
    println!("  • GET  /staff - Staff area (Admin or Moderator)");
    println!("  • GET  /engineering - Engineering area (engineering group)");
    println!("  • GET  /admin - Admin panel (Admin role only)");
    println!();
    println!("🔑 Test accounts:");
    println!("  • admin/admin - Full admin access");
    println!("  • moderator/moderator - Staff access");
    println!("  • engineer/engineer - Engineering access");
    println!("  • user/user - Basic user access");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to bind to address");

    axum::serve(listener, app)
        .await
        .expect("Failed to start server");
    Ok(())
}

#[derive(Clone)]
struct AppState {
    account_repo: Arc<MemoryAccountRepository<Role, Group>>,
    secret_repo: Arc<MemorySecretRepository>,
    jwt_codec: Arc<JsonWebToken<JwtClaims<Account<Role, Group>>>>,
}

// Handler for unauthenticated users
async fn login_page_handler() -> Html<String> {
    // Redirect to home page which now contains the login form
    Html(r#"<script>window.location.href = '/';</script>"#.to_string())
}

// Route handlers

async fn home_handler() -> Html<String> {
    Html(r#"
<!DOCTYPE html>
<html>
<head>
    <title>Axum Gate - Login</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }
        .btn:hover { opacity: 0.8; }
        .info { background: #e7f3ff; padding: 15px; border-radius: 4px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>🔐 Login to Axum Gate Demo</h1>

    <form method="post" action="/login">
        <div class="form-group">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required>
        </div>
        <div class="form-group">
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
        </div>
        <button type="submit" class="btn">Login</button>
    </form>

    <div class="info">
        <h3>📚 Test Accounts</h3>
        <p>Try these test accounts:</p>
        <ul>
            <li><strong>admin/admin</strong> - Full admin access</li>
            <li><strong>moderator/moderator</strong> - Staff access</li>
            <li><strong>engineer/engineer</strong> - Engineering access</li>
            <li><strong>user/user</strong> - Basic user access</li>
        </ul>
    </div>
</body>
</html>
    "#.to_string())
}

async fn dashboard_handler(Extension(user): Extension<Account<Role, Group>>) -> Html<String> {
    Html(format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>Axum Gate - Home</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }}
        .nav a {{ margin-right: 20px; text-decoration: none; color: #007bff; }}
        .content {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .btn {{ background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }}
        .btn-danger {{ background: #dc3545; }}
        .btn:hover {{ opacity: 0.8; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🏠 Welcome, {}!</h1>
        <form method="post" action="/logout" style="display: inline;">
            <button type="submit" class="btn btn-danger">Logout</button>
        </form>
    </div>

    <nav class="nav">
        <a href="/dashboard">Dashboard</a>
        <a href="/profile">Profile</a>
        <a href="/staff">Staff Area</a>
        <a href="/engineering">Engineering</a>
        <a href="/admin">Admin Panel</a>
    </nav>

    <div class="content">
        <h3>👤 Your Account</h3>
        <p><strong>User ID:</strong> {}</p>
        <p><strong>Roles:</strong> {:?}</p>
        <p><strong>Groups:</strong> {:?}</p>
        <p><strong>Permissions:</strong> {} total</p>
    </div>

    <div class="content">
        <h3>🚪 Available Areas</h3>
        <p>Try visiting different protected areas to see role and group-based access control in action!</p>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
            <div style="border: 1px solid #ddd; padding: 15px; border-radius: 5px;">
                <h4>👤 Profile</h4>
                <p>Available to all logged-in users</p>
                <a href="/profile" class="btn">Visit Profile</a>
            </div>
            <div style="border: 1px solid #ddd; padding: 15px; border-radius: 5px;">
                <h4>👥 Staff Area</h4>
                <p>Admin or Moderator roles only</p>
                <a href="/staff" class="btn">Enter Staff Area</a>
            </div>
            <div style="border: 1px solid #ddd; padding: 15px; border-radius: 5px;">
                <h4>⚙️ Engineering</h4>
                <p>Engineering group members only</p>
                <a href="/engineering" class="btn">Enter Engineering</a>
            </div>
            <div style="border: 1px solid #dc3545; padding: 15px; border-radius: 5px;">
                <h4>🔐 Admin Panel</h4>
                <p>Admin role only</p>
                <a href="/admin" class="btn btn-danger">Enter Admin Panel</a>
            </div>
        </div>
    </div>
</body>
</html>
    "#,
        user.user_id,
        user.user_id,
        user.roles,
        user.groups,
        user.permissions.len()
    ))
}

async fn debug_handler(user_ext: Option<Extension<Account<Role, Group>>>) -> Json<DebugInfo> {
    let account_details = if let Some(Extension(user)) = user_ext {
        Some(user)
    } else {
        None
    };

    Json(DebugInfo { account_details })
}

async fn admin_handler(Extension(user): Extension<Account<Role, Group>>) -> Html<String> {
    Html(format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }}
        .nav a {{ margin-right: 20px; text-decoration: none; color: #007bff; }}
        .content {{ background: #fff5f5; border: 2px solid #dc3545; padding: 20px; border-radius: 8px; }}
        .btn {{ background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin-right: 10px; }}
        .btn-danger {{ background: #dc3545; }}
        .btn:hover {{ opacity: 0.8; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 Admin Panel</h1>
        <form method="post" action="/logout" style="display: inline;">
            <button type="submit" class="btn btn-danger">Logout</button>
        </form>
    </div>

    <nav class="nav">
        <a href="/dashboard">Dashboard</a>
        <a href="/profile">Profile</a>
        <a href="/staff">Staff Area</a>
        <a href="/engineering">Engineering</a>
        <a href="/admin">Admin Panel</a>
    </nav>

    <div class="content">
        <h2>Welcome Administrator: {}</h2>
        <p><strong>Your roles:</strong> {:?}</p>
        <p><strong>Your groups:</strong> {:?}</p>

        <h3>⚠️ Administrative Functions</h3>
        <p>You have full administrative access to the system. Use with caution!</p>

        <button class="btn btn-danger">Manage Users</button>
        <button class="btn btn-danger">System Settings</button>
        <button class="btn btn-danger">Security Audit</button>
    </div>
</body>
</html>
    "#,
        user.user_id, user.roles, user.groups
    ))
}

async fn staff_handler(Extension(user): Extension<Account<Role, Group>>) -> Html<String> {
    Html(format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>Staff Area</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }}
        .nav a {{ margin-right: 20px; text-decoration: none; color: #007bff; }}
        .content {{ background: #f0f8ff; padding: 20px; border-radius: 8px; }}
        .btn {{ background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin-right: 10px; }}
        .btn-danger {{ background: #dc3545; }}
        .btn:hover {{ opacity: 0.8; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>👥 Staff Area</h1>
        <form method="post" action="/logout" style="display: inline;">
            <button type="submit" class="btn btn-danger">Logout</button>
        </form>
    </div>

    <nav class="nav">
        <a href="/dashboard">Dashboard</a>
        <a href="/profile">Profile</a>
        <a href="/staff">Staff Area</a>
        <a href="/engineering">Engineering</a>
        <a href="/admin">Admin Panel</a>
    </nav>

    <div class="content">
        <h2>Welcome Staff Member: {}</h2>
        <p><strong>Your roles:</strong> {:?}</p>
        <p><strong>Your groups:</strong> {:?}</p>

        <h3>🛠️ Staff Functions</h3>
        <p>You have elevated permissions as a staff member.</p>

        <button class="btn">User Management</button>
        <button class="btn">Content Moderation</button>
        <button class="btn">Reports</button>
    </div>
</body>
</html>
    "#,
        user.user_id, user.roles, user.groups
    ))
}

async fn engineering_handler(Extension(user): Extension<Account<Role, Group>>) -> Html<String> {
    Html(format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>Engineering Area</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }}
        .nav a {{ margin-right: 20px; text-decoration: none; color: #007bff; }}
        .content {{ background: #f0fff0; padding: 20px; border-radius: 8px; }}
        .btn {{ background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin-right: 10px; }}
        .btn-danger {{ background: #dc3545; }}
        .btn:hover {{ opacity: 0.8; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>⚙️ Engineering Area</h1>
        <form method="post" action="/logout" style="display: inline;">
            <button type="submit" class="btn btn-danger">Logout</button>
        </form>
    </div>

    <nav class="nav">
        <a href="/dashboard">Dashboard</a>
        <a href="/profile">Profile</a>
        <a href="/staff">Staff Area</a>
        <a href="/engineering">Engineering</a>
        <a href="/admin">Admin Panel</a>
    </nav>

    <div class="content">
        <h2>Welcome Engineer: {}</h2>
        <p><strong>Your roles:</strong> {:?}</p>
        <p><strong>Your groups:</strong> {:?}</p>

        <h3>🔧 Engineering Tools</h3>
        <p>Access to technical resources and development tools.</p>

        <button class="btn">Code Repository</button>
        <button class="btn">System Monitoring</button>
        <button class="btn">API Documentation</button>
    </div>
</body>
</html>
    "#,
        user.user_id, user.roles, user.groups
    ))
}

async fn profile_handler(Extension(user): Extension<Account<Role, Group>>) -> Html<String> {
    Html(format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>User Profile</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }}
        .nav a {{ margin-right: 20px; text-decoration: none; color: #007bff; }}
        .content {{ background: #f8f9fa; padding: 20px; border-radius: 8px; }}
        .btn {{ background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin-right: 10px; }}
        .btn-danger {{ background: #dc3545; }}
        .btn:hover {{ opacity: 0.8; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>👤 Your Profile</h1>
        <form method="post" action="/logout" style="display: inline;">
            <button type="submit" class="btn btn-danger">Logout</button>
        </form>
    </div>

    <nav class="nav">
        <a href="/dashboard">Dashboard</a>
        <a href="/profile">Profile</a>
        <a href="/staff">Staff Area</a>
        <a href="/engineering">Engineering</a>
        <a href="/admin">Admin Panel</a>
    </nav>

    <div class="content">
        <h2>Profile Information</h2>
        <p><strong>User ID:</strong> {}</p>
        <p><strong>Roles:</strong> {:?}</p>
        <p><strong>Groups:</strong> {:?}</p>
        <p><strong>Total Permissions:</strong> {}</p>

        <h3>🔑 Your Permissions</h3>
        <div style="background: white; padding: 10px; border-radius: 4px; max-height: 200px; overflow-y: auto;">
            <pre>{:#?}</pre>
        </div>
    </div>
</body>
</html>
    "#,
        user.user_id,
        user.roles,
        user.groups,
        user.permissions.len(),
        user.permissions
    ))
}

// Authentication handlers

async fn login_handler(
    State(state): State<AppState>,
    cookie_jar: CookieJar,
    Form(form_data): Form<LoginForm>,
) -> std::result::Result<(CookieJar, Redirect), (StatusCode, Html<String>)> {
    let credentials = Credentials::new(&form_data.username, &form_data.password);
    let registered_claims = RegisteredClaims::new(
        "my-app",
        (chrono::Utc::now().timestamp() + 3600) as u64, // 1 hour expiry
    );

    let cookie_template = CookieTemplate::recommended()
        .name("my-app")
        .secure(false) // Dev only; enable HTTPS + Secure(true) in production
        .persistent(cookie::time::Duration::hours(24));

    match login(
        cookie_jar,
        credentials,
        registered_claims,
        state.secret_repo,
        state.account_repo,
        state.jwt_codec,
        cookie_template,
    )
    .await
    {
        Ok(updated_jar) => {
            // Login successful, redirect to dashboard
            Ok((updated_jar, Redirect::to("/dashboard")))
        }
        Err(_) => {
            // Login failed, show login form with error
            Err((StatusCode::UNAUTHORIZED, Html(r#"
<!DOCTYPE html>
<html>
<head>
    <title>Axum Gate - Login Error</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }
        .btn:hover { opacity: 0.8; }
        .error { background: #ffebee; border: 1px solid #f44336; color: #d32f2f; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
        .info { background: #e7f3ff; padding: 15px; border-radius: 4px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>🔐 Login to Axum Gate Demo</h1>

    <div class="error">
        <strong>Login Failed!</strong> Invalid username or password.
    </div>

    <form method="post" action="/login">
        <div class="form-group">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required>
        </div>
        <div class="form-group">
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
        </div>
        <button type="submit" class="btn">Login</button>
    </form>

    <div class="info">
        <h3>📚 Test Accounts</h3>
        <p>Try these test accounts:</p>
        <ul>
            <li><strong>admin/admin</strong> - Full admin access</li>
            <li><strong>moderator/moderator</strong> - Staff access</li>
            <li><strong>engineer/engineer</strong> - Engineering access</li>
            <li><strong>user/user</strong> - Basic user access</li>
        </ul>
    </div>
</body>
</html>
            "#.to_string())))
        }
    }
}

async fn logout_handler(cookie_jar: CookieJar) -> (CookieJar, Redirect) {
    let cookie_template = CookieTemplate::recommended().name("my-app");
    let updated_jar = logout(cookie_jar, cookie_template).await;
    (updated_jar, Redirect::to("/"))
}

// Helper function to create test data

async fn create_test_users(
    account_repo: Arc<MemoryAccountRepository<Role, Group>>,
    secret_repo: Arc<MemorySecretRepository>,
) {
    // Admin user
    let _ = AccountInsertService::insert("admin", "admin")
        .with_roles(vec![Role::Admin])
        .with_groups(vec![Group::new("leadership")])
        .into_repositories(Arc::clone(&account_repo), Arc::clone(&secret_repo))
        .await;

    // Moderator user
    let _ = AccountInsertService::insert("moderator", "moderator")
        .with_roles(vec![Role::Moderator])
        .with_groups(vec![Group::new("staff")])
        .into_repositories(Arc::clone(&account_repo), Arc::clone(&secret_repo))
        .await;

    // Engineering user
    let _ = AccountInsertService::insert("engineer", "engineer")
        .with_roles(vec![Role::User])
        .with_groups(vec![Group::new("engineering")])
        .into_repositories(Arc::clone(&account_repo), Arc::clone(&secret_repo))
        .await;

    // Regular user
    let _ = AccountInsertService::insert("user", "user")
        .with_roles(vec![Role::User])
        .with_groups(vec![Group::new("customers")])
        .into_repositories(Arc::clone(&account_repo), Arc::clone(&secret_repo))
        .await;

    println!("✅ Test users created:");
    println!("   • admin/admin (Admin role, leadership group)");
    println!("   • moderator/moderator (Moderator role, staff group)");
    println!("   • engineer/engineer (User role, engineering group)");
    println!("   • user/user (User role, customers group)");
}
