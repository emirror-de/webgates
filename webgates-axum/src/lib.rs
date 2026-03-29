#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
/*!
# webgates-axum

Axum integration layer for the `webgates` core.

This crate exposes the Axum-specific boundary for `webgates`:
- `gate` contains Axum middleware builders for cookie, bearer, and OAuth2 flows
- `route_handlers` contains ready-made login and logout handlers

The core domain types, authentication logic, repositories, codecs, and
framework-agnostic gate configuration live in the sibling `webgates` crate.

## Public API

The intended public entry points are:
- `gate::Gate`
- `gate::cookie`
- `gate::bearer`
- `gate::oauth2`
- `route_handlers`
- `route_handlers::login`
- `route_handlers::logout`

This crate does not provide a convenience prelude and does not re-export Axum.
Use Axum directly from your own dependency list.

## Basic usage

```rust
use axum::{routing::get, Router};
use std::sync::Arc;
use webgates::accounts::Account;
use webgates::authz::AccessPolicy;
use webgates::groups::Group;
use webgates::roles::Role;
use webgates_axum::gate::Gate;
use webgates_codecs::jwt::{JsonWebToken, JwtClaims};

let jwt = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());

let app = Router::<()>::new()
    .route("/admin", get(|| async { "ok" }))
    .layer(
        Gate::cookie("my-app", jwt)
            .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin)),
    );
```
*/

/// Gate builders and middleware for Axum.
pub mod gate;

/// Session middleware for transparent cookie-backed renewal.
pub mod session;

/// Pre-built route handlers for login and logout flows.
///
/// ```rust,ignore
/// use std::sync::Arc;
///
/// use axum::{Json, Router, extract::State, routing::post};
/// use axum_extra::extract::CookieJar;
/// use webgates::accounts::Account;
/// use webgates::codecs::jwt::{JsonWebToken, JwtClaims, RegisteredClaims};
/// use webgates::cookie_template::CookieTemplate;
/// use webgates::credentials::Credentials;
/// use webgates::groups::Group;
/// use webgates::roles::Role;
/// use webgates_axum::route_handlers::{login, logout};
/// use webgates_repositories::memory::account::MemoryAccountRepository;
/// use webgates_repositories::memory::secret::MemorySecretRepository;
///
/// type AppJwtCodec = JsonWebToken<JwtClaims<Account<Role, Group>>>;
///
/// #[derive(Clone)]
/// struct AppState {
///     account_repo: Arc<MemoryAccountRepository<Role, Group>>,
///     secret_repo: Arc<MemorySecretRepository>,
///     jwt_codec: Arc<AppJwtCodec>,
///     cookie_template: CookieTemplate,
/// }
///
/// async fn login_handler(
///     State(state): State<AppState>,
///     cookie_jar: CookieJar,
///     Json(credentials): Json<Credentials<String>>,
/// ) -> Result<CookieJar, axum::http::StatusCode> {
///     let claims = RegisteredClaims::new(
///         "my-app",
///         chrono::Utc::now().timestamp() as u64 + 3600,
///     );
///
///     login(
///         cookie_jar,
///         credentials,
///         claims,
///         Arc::clone(&state.secret_repo),
///         Arc::clone(&state.account_repo),
///         Arc::clone(&state.jwt_codec),
///         state.cookie_template.clone(),
///     )
///     .await
/// }
///
/// async fn logout_handler(
///     State(state): State<AppState>,
///     cookie_jar: CookieJar,
/// ) -> CookieJar {
///     logout(cookie_jar, state.cookie_template.clone()).await
/// }
///
/// let app_state = AppState {
///     account_repo: Arc::new(MemoryAccountRepository::<Role, Group>::default()),
///     secret_repo: Arc::new(MemorySecretRepository::new_with_argon2_hasher().unwrap()),
///     jwt_codec: Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default()),
///     cookie_template: CookieTemplate::recommended().name("auth-token"),
/// };
///
/// let _app: Router<AppState> = Router::new()
///     .route("/login", post(login_handler))
///     .route("/logout", post(logout_handler))
///     .with_state(app_state);
/// ```
pub mod route_handlers;
