// Example: Custom roles, groups, and access policies
//
// Overview
// - Roles: hierarchical permissions attached to an account (Novice < Experienced < Expert).
// - Groups: coarse-grained memberships (Maintenance, Operations, Administration).
// - AccessHierarchy: marks the role enum as ordered so "supervisors" (higher roles) can satisfy policies.
//
// Routes
// - GET /admin -> requires the Expert role.
// - GET /secret-admin-group -> requires membership in the Maintenance group.
// - GET /reporter -> requires Experienced or any supervisor (i.e., Expert).
// - GET /user -> requires Novice.
// - POST /login -> authenticates JSON credentials and sets a signed, HttpOnly cookie.
// - GET /logout -> clears the session cookie.
//
// Running
// - Ensure AXUM_GATE_SHARED_SECRET is set (a .env is provided in this example).
// - From this example directory, run: cargo run
use axum_gate::accounts::AccountInsertService;
use axum_gate::authz::{AccessHierarchy, AccessPolicy};
use axum_gate::codecs::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims, RegisteredClaims};
use axum_gate::prelude::{Account, Credentials, Gate};
use axum_gate::repositories::memory::{MemoryAccountRepository, MemorySecretRepository};

use std::sync::Arc;

use axum::extract::Json;
use axum::routing::{Router, get, post};
use axum::{Extension, response::Html};
use chrono::{TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use tracing::debug;

pub const ISSUER: &str = "auth-node";

/// A custom role definition.
#[derive(
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Copy,
    Clone,
    Serialize,
    Deserialize,
    Debug,
    strum::Display,
)]
pub enum CustomRoleDefinition {
    #[default]
    Novice,
    Experienced,
    Expert,
}

// Mark the enum as hierarchical so higher roles supervise lower ones.
// With Novice < Experienced < Expert, "require_role_or_supervisor(Experienced)"
// will grant access to both Experienced and Expert users.
impl AccessHierarchy for CustomRoleDefinition {}

/// A custom group definition.
#[derive(Eq, PartialEq, Copy, Clone, Serialize, Deserialize, Debug)]
pub enum CustomGroupDefinition {
    Maintenance,
    Operations,
    Administration,
}

impl CustomGroupDefinition {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Maintenance => "maintenance",
            Self::Operations => "operations",
            Self::Administration => "administration",
        }
    }
}

async fn reporter(
    Extension(user): Extension<Account<CustomRoleDefinition, CustomGroupDefinition>>,
) -> Result<String, ()> {
    Ok(format!(
        "Hello {} and welcome to the consumer node. Your roles are {:?} and you are member of groups {:?}!",
        user.user_id, user.roles, user.groups
    ))
}

async fn user(
    Extension(user): Extension<Account<CustomRoleDefinition, CustomGroupDefinition>>,
) -> Result<String, ()> {
    Ok(format!(
        "Hello {} and welcome to the consumer node. Your roles are {:?} and you are member of groups {:?}!",
        user.user_id, user.roles, user.groups
    ))
}

async fn admin_group(
    Extension(user): Extension<Account<CustomRoleDefinition, CustomGroupDefinition>>,
) -> Result<String, ()> {
    Ok(format!(
        "Hi {} and welcome to the secret admin-group site on the consumer node, your roles are {:?} and you are member of groups {:?}!",
        user.user_id, user.roles, user.groups
    ))
}

async fn admin(
    Extension(user): Extension<Account<CustomRoleDefinition, CustomGroupDefinition>>,
) -> Result<String, ()> {
    Ok(format!(
        "Hello {} and welcome to the consumer node. Your roles are {:?} and you are member of groups {:?}!",
        user.user_id, user.roles, user.groups
    ))
}

async fn index(
    Extension(opt_user): Extension<Option<Account<CustomRoleDefinition, CustomGroupDefinition>>>,
) -> Html<String> {
    let status_html = if opt_user.is_some() {
        r#"<span class="status-badge status-ok">Logged in</span>"#
    } else {
        r#"<span class="status-badge status-err">Not logged in</span>"#
    };

    let prefix = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Axum Gate — Custom Roles Demo</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {
      color-scheme: light;
      --bg: #ffffff;
      --fg: #0b0c10;
      --muted: #475569;
      --accent: #0b57d0;
      --accent-contrast: #ffffff;
      --ok: #166534;
      --err: #b91c1c;
      --card: #ffffff;
      --border: #d1d5db;
      --focus: #0b57d0;
      --shadow: rgba(2, 6, 23, 0.08);
    }
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Arial, "Apple Color Emoji", "Segoe UI Emoji"; margin: 0; padding: 2rem; line-height: 1.5; background: var(--bg); color: var(--fg); }
    .card { max-width: 720px; background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem; box-shadow: 0 2px 8px var(--shadow); }
    h1 { margin: 0 0 0.75rem 0; font-size: 1.4rem; }
    label { display: block; margin-top: 0.75rem; font-weight: 600; }
    input { width: 100%; padding: 0.6rem 0.7rem; border-radius: 8px; border: 1px solid var(--border); background: #ffffff; color: var(--fg); }
    input:focus-visible { outline: 3px solid var(--focus); outline-offset: 2px; border-color: var(--focus); }
    button { margin-top: 1rem; padding: 0.6rem 0.9rem; border-radius: 8px; border: 1px solid var(--border); background: var(--accent); color: var(--accent-contrast); cursor: pointer; }
    button:hover { filter: brightness(0.95); }
    button:focus-visible { outline: 3px solid var(--focus); outline-offset: 2px; }
    .muted { color: var(--muted); font-size: 0.95rem; }
    .row { display: flex; gap: 1rem; flex-wrap: wrap; margin-top: 1rem; }
    .row a { display: inline-block; padding: 0.5rem 0.7rem; border: 1px solid var(--border); border-radius: 8px; color: var(--fg); text-decoration: none; background: #ffffff; }
    .row a:focus-visible { outline: 3px solid var(--focus); outline-offset: 2px; }
    .status-badge { display: inline-block; font-weight: 700; border-radius: 9999px; padding: 0.2rem 0.6rem; border: 1px solid var(--border); }
    .status-badge.status-ok { background: #d1fae5; color: #065f46; border-color: #34d399; }
    .status-badge.status-err { background: #fee2e2; color: #991b1b; border-color: #f87171; }
    .ok { color: var(--ok); }
    .err { color: var(--err); }
    .msg { margin-top: 0.75rem; min-height: 1.25rem; }
    details { margin-top: 0.75rem; }
    code { background: #f1f5f9; border: 1px solid var(--border); padding: 0.15rem 0.35rem; border-radius: 6px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Custom Roles — Demo Login</h1>
    <p id="auth-status" class="muted" role="status" aria-live="polite">"#;

    let suffix = r#"</p>
    <p class="muted">Submit credentials to receive a signed HttpOnly session cookie. Then try the protected routes below.</p>

    <form id="login-form">
      <label for="email">Email</label>
      <input id="email" name="email" type="email" placeholder="admin@example.com" required>

      <label for="password">Password</label>
      <input id="password" name="password" type="password" placeholder="admin_password" required>

      <button type="submit">Log in</button>
      <div id="msg" class="msg muted"></div>
    </form>

    <details>
      <summary>Quick test users</summary>
      <ul>
        <li><code>admin@example.com</code> / <code>admin_password</code> — role: Expert, group: Maintenance</li>
        <li><code>reporter@example.com</code> / <code>reporter_password</code> — role: Experienced, group: Operations</li>
        <li><code>user@example.com</code> / <code>user_password</code> — role: Novice, group: Administration</li>
      </ul>
    </details>

    <div class="row">
      <a href="/user">GET /user (Novice)</a>
      <a href="/reporter">GET /reporter (Experienced or supervisor)</a>
      <a href="/admin">GET /admin (Expert)</a>
      <a href="/secret-admin-group">GET /secret-admin-group (Maintenance group)</a>
      <a href="/logout">GET /logout</a>
    </div>
  </div>

  <script>
    const form = document.getElementById('login-form');
    const msg = document.getElementById('msg');

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      msg.textContent = 'Logging in...';

      const email = document.getElementById('email').value.trim();
      const password = document.getElementById('password').value;

      try {
        const res = await fetch('/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: email, secret: password })
        });

        if (res.ok) {
          // Reload to update server-rendered login status hint
          window.location.href = '/';
        } else {
          const text = await res.text();
          msg.textContent = 'Login failed: ' + (text || res.status);
          msg.className = 'msg err';
        }
      } catch (err) {
        msg.textContent = 'Network error.';
        msg.className = 'msg err';
      }
    });
  </script>
</body>
</html>
"#;

    let mut html = String::with_capacity(prefix.len() + status_html.len() + suffix.len());
    html.push_str(prefix);
    html.push_str(status_html);
    html.push_str(suffix);
    Html(html)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    // Load .env; AXUM_GATE_SHARED_SECRET must be set (and shared between login and verification).
    dotenvy::dotenv().expect("Could not read .env file.");
    let shared_secret =
        dotenvy::var("AXUM_GATE_SHARED_SECRET").expect("AXUM_GATE_SHARED_SECRET env var not set.");
    let jwt_options = JsonWebTokenOptions {
        enc_key: axum_gate::jsonwebtoken::EncodingKey::from_secret(shared_secret.as_bytes()),
        dec_key: axum_gate::jsonwebtoken::DecodingKey::from_secret(shared_secret.as_bytes()),
        header: Some(axum_gate::jsonwebtoken::Header::default()),
        validation: Some(axum_gate::jsonwebtoken::Validation::default()),
    };
    let jwt_codec = Arc::new(JsonWebToken::<
        JwtClaims<Account<CustomRoleDefinition, CustomGroupDefinition>>,
    >::new_with_options(jwt_options));

    let account_repository = Arc::new(MemoryAccountRepository::from(vec![]));
    debug!("Account repository initialized.");
    let secrets_repository = Arc::new(MemorySecretRepository::try_from(vec![]).unwrap());
    debug!("Secrets repository initialized.");

    // Seed: admin has Expert role and belongs to Maintenance group.
    AccountInsertService::insert("admin@example.com", "admin_password")
        .with_roles(vec![CustomRoleDefinition::Expert])
        .with_groups(vec![CustomGroupDefinition::Maintenance])
        .into_repositories(
            Arc::clone(&account_repository),
            Arc::clone(&secrets_repository),
        )
        .await
        .unwrap();
    debug!("Inserted Admin.");

    // Seed: reporter has Experienced role and belongs to Operations group.
    AccountInsertService::insert("reporter@example.com", "reporter_password")
        .with_roles(vec![CustomRoleDefinition::Experienced])
        .with_groups(vec![CustomGroupDefinition::Operations])
        .into_repositories(
            Arc::clone(&account_repository),
            Arc::clone(&secrets_repository),
        )
        .await
        .unwrap();
    debug!("Inserted Reporter.");

    // Seed: user has Novice role and belongs to Administration group.
    AccountInsertService::insert("user@example.com", "user_password")
        .with_roles(vec![CustomRoleDefinition::Novice])
        .with_groups(vec![CustomGroupDefinition::Administration])
        .into_repositories(
            Arc::clone(&account_repository),
            Arc::clone(&secrets_repository),
        )
        .await
        .unwrap();
    debug!("Inserted User.");

    let cookie_template = axum_gate::cookie_template::CookieTemplate::recommended(); // secure defaults for the session cookie

    let app = Router::new()
        .route("/admin", get(admin))
        .layer(
            Gate::cookie(ISSUER, Arc::clone(&jwt_codec))
                .with_cookie_template(cookie_template.clone())
                .with_policy(AccessPolicy::require_role(CustomRoleDefinition::Expert)), // /admin: requires Expert role
        )
        .route(
            "/secret-admin-group",
            get(admin_group).layer(
                Gate::cookie(ISSUER, Arc::clone(&jwt_codec))
                    .with_cookie_template(cookie_template.clone())
                    // /secret-admin-group: requires membership in the Maintenance group
                    .with_policy(AccessPolicy::require_group(
                        CustomGroupDefinition::Maintenance,
                    )),
            ),
        )
        .route(
            "/reporter",
            get(reporter).layer(
                Gate::cookie(ISSUER, Arc::clone(&jwt_codec))
                    .with_cookie_template(cookie_template.clone())
                    // /reporter: allow Experienced OR any supervisor (Expert) via AccessHierarchy
                    .with_policy(AccessPolicy::require_role_or_supervisor(
                        CustomRoleDefinition::Experienced,
                    )),
            ),
        )
        .route(
            "/user",
            get(user).layer(
                Gate::cookie(ISSUER, Arc::clone(&jwt_codec))
                    .with_cookie_template(cookie_template.clone())
                    // /user: requires Novice role
                    .with_policy(AccessPolicy::require_role(CustomRoleDefinition::Novice)),
            ),
        )
        .route(
            "/login", // POST: authenticate credentials and set a signed, HttpOnly cookie
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
            get({
                let cookie_template = cookie_template.clone();
                move |cookie_jar| async move {
                    let jar = axum_gate::route_handlers::logout(cookie_jar, cookie_template).await;
                    (jar, axum::response::Redirect::to("/"))
                }
            }),
        )
        .route(
            "/",
            get(index).layer(
                Gate::cookie(ISSUER, Arc::clone(&jwt_codec))
                    .with_cookie_template(cookie_template.clone())
                    .allow_anonymous_with_optional_user(),
            ),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
