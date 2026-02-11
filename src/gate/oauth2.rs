//! OAuth2 login flow with `/login` and `/callback` routes. Cookie templates are validated when building routes to fail fast on insecure combinations.
//!
//! Example: insert account before JWT using a repository (ensures stable `account_id` in cookie)
//!
//! ```rust
//! use axum_gate::prelude::*;
//! use axum_gate::repositories::memory::MemoryAccountRepository;
//! use std::sync::Arc;
//!
//! let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//!
//! // Build an account repository (e.g., in-memory for examples)
//! let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
//!
//! // Configure gate with repository-backed insertion before JWT issuance
//! let gate = Gate::oauth2::<Role, Group>()
//!     .auth_url("https://provider.example.com/oauth2/authorize")
//!     .token_url("https://provider.example.com/oauth2/token")
//!     .client_id("CLIENT_ID")
//!     .client_secret("CLIENT_SECRET")
//!     .redirect_url("http://localhost:3000/auth/callback")
//!     .add_scope("openid")
//!     // Provide JWT codec and TTL as usual
//!     .with_jwt_codec("my-app", jwt_codec, 60 * 60 * 24)
//!     // Persist or load the account before encoding the JWT
//!     .with_account_repository(Arc::clone(&account_repo))
//!     // Map provider tokens to your domain account (e.g., via userinfo)
//!     .with_account_mapper(|_token| {
//!         Box::pin(async move {
//!             Ok(Account::<Role, Group>::new("user@example.com", &[Role::User], &[]))
//!         })
//!     });
//! ```
//!
//!
//! This module provides an OAuth2Gate builder that mounts routes to perform an
//! Authorization Code + PKCE flow. On successful callback, it can:
//! - Map the token response to an `Account<R, G>` via a user-supplied mapper
//! - Mint a first-party JWT via a user-supplied codec (helper provided)
//! - Optionally insert or load the account before issuing the JWT (via `with_account_repository` or `with_account_inserter`) so the cookie includes a stable `account_id`
//! - Set a secure auth cookie using the crate’s cookie template
//! - Optionally redirect to a configured post-login URL
//!
//! Usage (minimal):
//!
//! - Configure the gate (auth url, token url, client credentials, redirect url, scopes)
//! - Provide an account mapper and JWT codec to issue a first-party session
//! - Optionally provide an account inserter or repository to persist/load an account before JWT, ensuring a stable `account_id` in the session cookie
//! - Mount its routes under a base path like `/auth`
//!
//! Example (issuing first-party cookie):
//!
//! ```rust
//! use axum::{Router, routing::get};
//! use axum_gate::prelude::*;
//! use std::sync::Arc;
//!
//! let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//!
//! let gate = Gate::oauth2::<Role, Group>()
//!     .auth_url("https://provider.example.com/oauth2/authorize")
//!     .token_url("https://provider.example.com/oauth2/token")
//!     .client_id("CLIENT_ID")
//!     .client_secret("CLIENT_SECRET") // optional for public clients
//!     .redirect_url("http://localhost:3000/auth/callback")
//!     .add_scope("openid")
//!     .with_post_login_redirect("/")
//!     .with_jwt_codec("my-app", Arc::clone(&jwt_codec), 60 * 60 * 24) // 24h TTL
//!     .with_account_mapper(|_token| {
//!         // Map provider token response to your domain Account<R, G>.
//!         // For plain OAuth2, you might call the provider's userinfo API here.
//!         // Example (pseudo):
//!         // let user = fetch_userinfo(token.access_token())?;
//!         // Ok(Account::new(&user.email, &[Role::User], &[]))
//!         Box::pin(async move {
//!             Ok(Account::<Role, Group>::new("user@example.com", &[Role::User], &[]))
//!         })
//!     });
//!
//! // routes() returns Result<Router<()>, OAuth2Error>; handle or unwrap as needed
//! let auth_router = gate.routes("/auth").expect("valid OAuth2 config");
//! let app = Router::<()>::new().nest("/auth", auth_router);
//! ```
//!
//! Security and cookie configuration:
//! - State and PKCE cookies use secure, short-lived, HttpOnly defaults with SameSite=Lax (good for OAuth redirects).
//! - You can fully customize state/PKCE cookie attributes (name, path, domain, SameSite, Secure, HttpOnly, Max-Age)
//!   via `CookieTemplate` helpers on the builder.
//! - The first-party auth cookie template remains configurable via `with_cookie_template` or `configure_cookie_template`.
//!
//! Example: customize state/PKCE cookies
//! ```rust
//! use axum_gate::prelude::*;
//! use cookie::{SameSite, time::Duration};
//!
//! let gate = Gate::oauth2::<Role, Group>()
//!     // ... provider endpoints and client config ...
//!     // Optional: custom names (multi-provider setups)
//!     .with_cookie_names("my-oauth-state", "my-oauth-pkce")
//!     // Optional: fine-tune state cookie (shorter TTL, SameSite)
//!     .configure_state_cookie_template(|t| {
//!         t.same_site(SameSite::Lax)
//!          .max_age(Duration::minutes(5))
//!     })
//!     .unwrap()
//!     // Optional: fine-tune PKCE cookie similarly
//!     .configure_pkce_cookie_template(|t| {
//!         t.same_site(SameSite::Lax)
//!          .max_age(Duration::minutes(5))
//!     })
//!     .unwrap();
//! ```
//!
//! Note: In production, serve over HTTPS and prefer `Secure=true`. If you set `SameSite=None` you must also set `Secure=true`
//! (browser enforcement); `CookieTemplate::validate()` guards against insecure combinations.

use crate::accounts::{Account, AccountRepository};
use crate::authz::AccessHierarchy;
use crate::codecs::Codec;
use crate::codecs::jwt::{JwtClaims, RegisteredClaims};
use crate::cookie_template::CookieTemplate;
pub mod errors;
use self::errors::{OAuth2CookieKind, OAuth2Error, Result as OAuth2Result};

use axum::{
    Extension, Router,
    extract::Query,
    response::{IntoResponse, Redirect},
    routing::get,
};
use axum_extra::extract::CookieJar;
use chrono::Utc;
use cookie::{SameSite, time::Duration};
use http::StatusCode;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, StandardTokenResponse, TokenResponse,
    TokenUrl, basic::BasicClient, basic::BasicTokenType,
};
use serde::Deserialize;
use std::fmt::Display;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use tracing::{debug, error};

/// Default cookie name for CSRF state during OAuth2 authorization.
const DEFAULT_STATE_COOKIE: &str = "oauth-state";

/// Default cookie name for PKCE verifier during OAuth2 authorization.
const DEFAULT_PKCE_COOKIE: &str = "oauth-pkce";

/// Type alias for an account encoding function.
type AccountEncoderFn<R, G> = Arc<dyn Fn(Account<R, G>) -> OAuth2Result<String> + Send + Sync>;
/// Type alias for an account mapper function.
type AccountMapperFn<R, G> = Arc<
    dyn for<'a> Fn(
            &'a StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
        )
            -> Pin<Box<dyn Future<Output = OAuth2Result<Account<R, G>>> + Send + 'a>>
        + Send
        + Sync,
>;
/// Type alias for an async account persistence function invoked before JWT issuance.
///
/// This closure should persist or load the account (idempotently), and return the account
/// that should be encoded into the first‑party JWT (typically with a stable `account_id`).
type AccountPersistFn<R, G> = Arc<
    dyn Fn(Account<R, G>) -> Pin<Box<dyn Future<Output = OAuth2Result<Account<R, G>>> + Send>>
        + Send
        + Sync,
>;

/// Public builder for configuring OAuth2 routes and session issuance.
#[derive(Clone)]
#[must_use]
pub struct OAuth2Gate<R, G>
where
    R: AccessHierarchy + Eq + Display + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    // OAuth2 endpoints and client config
    auth_url: Option<String>,
    token_url: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    redirect_url: Option<String>,
    scopes: Vec<String>,

    // CSRF/PKCE cookie templates
    state_cookie_template: CookieTemplate,
    pkce_cookie_template: CookieTemplate,

    // First-party session issuance (optional)
    auth_cookie_template: CookieTemplate,
    post_login_redirect: Option<String>,
    mapper: Option<AccountMapperFn<R, G>>,
    account_inserter: Option<AccountPersistFn<R, G>>,
    jwt_encoder: Option<AccountEncoderFn<R, G>>,

    _phantom: PhantomData<(R, G)>,
}

impl<R, G> Default for OAuth2Gate<R, G>
where
    R: AccessHierarchy + Eq + Display + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self {
            auth_url: None,
            token_url: None,
            client_id: None,
            client_secret: None,
            redirect_url: None,
            scopes: Vec::new(),
            state_cookie_template: CookieTemplate::recommended()
                .name(DEFAULT_STATE_COOKIE)
                .same_site(SameSite::Lax)
                .max_age(Duration::minutes(10)),
            pkce_cookie_template: CookieTemplate::recommended()
                .name(DEFAULT_PKCE_COOKIE)
                .same_site(SameSite::Lax)
                .max_age(Duration::minutes(10)),
            auth_cookie_template: CookieTemplate::recommended(),
            post_login_redirect: None,
            mapper: None,
            account_inserter: None,
            jwt_encoder: None,
            _phantom: PhantomData,
        }
    }
}

impl<R, G> OAuth2Gate<R, G>
where
    R: AccessHierarchy + Eq + Display + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    /// Create a new, empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the authorization endpoint URL.
    pub fn auth_url(mut self, url: impl Into<String>) -> Self {
        self.auth_url = Some(url.into());
        self
    }

    /// Set the token endpoint URL.
    pub fn token_url(mut self, url: impl Into<String>) -> Self {
        self.token_url = Some(url.into());
        self
    }

    /// Set the OAuth2 client ID.
    pub fn client_id(mut self, id: impl Into<String>) -> Self {
        self.client_id = Some(id.into());
        self
    }

    /// Set the OAuth2 client secret (optional for public clients).
    pub fn client_secret(mut self, secret: impl Into<String>) -> Self {
        self.client_secret = Some(secret.into());
        self
    }

    /// Set the redirect URL that your provider will call after user authorization.
    pub fn redirect_url(mut self, url: impl Into<String>) -> Self {
        self.redirect_url = Some(url.into());
        self
    }

    /// Add a scope to request from the provider.
    pub fn add_scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    /// Set custom cookie names for state/PKCE (primarily for multi-provider setups).
    ///
    /// This also updates the underlying cookie templates to use the provided names.
    pub fn with_cookie_names(
        mut self,
        state_cookie: impl Into<String>,
        pkce_cookie: impl Into<String>,
    ) -> Self {
        let state_name: String = state_cookie.into();
        let pkce_name: String = pkce_cookie.into();

        self.state_cookie_template = self.state_cookie_template.name(state_name);
        self.pkce_cookie_template = self.pkce_cookie_template.name(pkce_name);
        self
    }

    /// Configure the state cookie template directly.
    pub fn with_state_cookie_template(mut self, template: CookieTemplate) -> Self {
        self.state_cookie_template = template;
        self
    }

    /// Convenience to configure the state cookie template via the high-level builder.
    pub fn configure_state_cookie_template<F>(mut self, f: F) -> OAuth2Result<Self>
    where
        F: FnOnce(CookieTemplate) -> CookieTemplate,
    {
        let template = f(CookieTemplate::recommended());
        template
            .validate()
            .map_err(|e| OAuth2Error::cookie_invalid(OAuth2CookieKind::State, e.to_string()))?;

        self.state_cookie_template = template;
        Ok(self)
    }

    /// Configure the PKCE cookie template directly.
    pub fn with_pkce_cookie_template(mut self, template: CookieTemplate) -> Self {
        self.pkce_cookie_template = template;
        self
    }

    /// Convenience to configure the PKCE cookie template via the high-level builder.
    pub fn configure_pkce_cookie_template<F>(mut self, f: F) -> OAuth2Result<Self>
    where
        F: FnOnce(CookieTemplate) -> CookieTemplate,
    {
        let template = f(CookieTemplate::recommended());
        template
            .validate()
            .map_err(|e| OAuth2Error::cookie_invalid(OAuth2CookieKind::Pkce, e.to_string()))?;

        self.pkce_cookie_template = template;
        Ok(self)
    }

    /// Configure the auth cookie template used to store the first-party JWT.
    pub fn with_cookie_template(mut self, template: CookieTemplate) -> Self {
        self.auth_cookie_template = template;
        self
    }

    /// Convenience to configure the auth cookie template via the high-level builder.
    pub fn configure_cookie_template<F>(mut self, f: F) -> OAuth2Result<Self>
    where
        F: FnOnce(CookieTemplate) -> CookieTemplate,
    {
        let template = f(CookieTemplate::recommended());
        template
            .validate()
            .map_err(|e| OAuth2Error::cookie_invalid(OAuth2CookieKind::Auth, e.to_string()))?;

        self.auth_cookie_template = template;
        Ok(self)
    }

    /// Configure a post-login redirect URL (e.g., "/").
    pub fn with_post_login_redirect(mut self, url: impl Into<String>) -> Self {
        self.post_login_redirect = Some(url.into());
        self
    }

    /// Provide an async account mapper that converts the token response to an Account<R, G>.
    ///
    /// This allows performing async I/O (e.g., calling a provider user info endpoint) without blocking.
    pub fn with_account_mapper<F>(mut self, f: F) -> Self
    where
        F: Send + Sync + 'static,
        for<'a> F: Fn(
            &'a StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
        )
            -> Pin<Box<dyn Future<Output = OAuth2Result<Account<R, G>>> + Send + 'a>>,
    {
        let f = Arc::new(f);
        self.mapper = Some(Arc::new(move |token_resp| (f)(token_resp)));
        self
    }

    /// Provide an async account inserter that persists or loads an account before JWT issuance.
    ///
    /// The closure is called after mapping the provider token to an Account and before encoding the JWT.
    /// It should return the persisted or loaded Account (with a stable account_id).
    pub fn with_account_inserter<F, Fut>(mut self, f: F) -> Self
    where
        F: Fn(Account<R, G>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = OAuth2Result<Account<R, G>>> + Send + 'static,
    {
        self.account_inserter = Some(Arc::new(move |account: Account<R, G>| Box::pin(f(account))));
        self
    }

    /// Convenience: insert into an AccountRepository on first login (idempotent).
    ///
    /// Queries by user_id; if missing, stores the provided account. Returns the existing or stored account.
    pub fn with_account_repository<AccRepo>(mut self, account_repository: Arc<AccRepo>) -> Self
    where
        AccRepo: AccountRepository<R, G> + Send + Sync + 'static,
    {
        self.account_inserter = Some(Arc::new(move |account: Account<R, G>| {
            let repo = Arc::clone(&account_repository);
            Box::pin(async move {
                match repo.query_account_by_user_id(&account.user_id).await {
                    Ok(Some(existing)) => Ok(existing),
                    Ok(None) => match repo.store_account(account).await {
                        Ok(Some(stored)) => Ok(stored),
                        Ok(None) => Err(OAuth2Error::account_persistence(
                            "account repo returned None on store",
                        )),
                        Err(e) => Err(OAuth2Error::account_persistence(e.to_string())),
                    },
                    Err(e) => Err(OAuth2Error::account_persistence(e.to_string())),
                }
            })
        }));
        self
    }

    /// Provide a JWT codec and issuer; sets up a type-erased encoder closure.
    ///
    /// This helper uses your provided codec to mint a first-party session JWT from an Account<R, G>. The `ttl_secs` here sets expiry and overrides `with_jwt_ttl_secs`.
    pub fn with_jwt_codec<C>(mut self, issuer: &str, codec: Arc<C>, ttl_secs: u64) -> Self
    where
        C: Codec<Payload = JwtClaims<Account<R, G>>> + Send + Sync + 'static,
    {
        let issuer = issuer.to_string();
        self.jwt_encoder = Some(Arc::new(move |account: Account<R, G>| {
            let exp = Utc::now().timestamp() as u64 + ttl_secs;
            let registered = RegisteredClaims::new(&issuer, exp);
            let claims = JwtClaims::new(account, registered);
            let bytes = codec
                .encode(&claims)
                .map_err(|e| OAuth2Error::jwt_encoding(e.to_string()))?;
            let token = String::from_utf8(bytes).map_err(|_| OAuth2Error::JwtNotUtf8)?;
            Ok(token)
        }));
        self
    }

    /// Build and return an axum Router with `/login` and `/callback` routes nested under `base_path`.
    ///
    /// Example:
    /// - base_path: "/auth" → routes are "/auth/login" and "/auth/callback"
    pub fn routes(&self, base_path: &str) -> OAuth2Result<Router<()>> {
        // Validate presence of required config and store raw values in handler state
        let auth_url = self
            .auth_url
            .clone()
            .ok_or_else(|| OAuth2Error::missing("auth_url"))?;
        let token_url = self
            .token_url
            .clone()
            .ok_or_else(|| OAuth2Error::missing("token_url"))?;
        let client_id = self
            .client_id
            .clone()
            .ok_or_else(|| OAuth2Error::missing("client_id"))?;
        let redirect_url = self
            .redirect_url
            .clone()
            .ok_or_else(|| OAuth2Error::missing("redirect_url"))?;

        // Validate cookie templates to prevent insecure SameSite=None + Secure=false, etc.
        self.state_cookie_template
            .validate()
            .map_err(|e| OAuth2Error::cookie_invalid(OAuth2CookieKind::State, e.to_string()))?;
        self.pkce_cookie_template
            .validate()
            .map_err(|e| OAuth2Error::cookie_invalid(OAuth2CookieKind::Pkce, e.to_string()))?;
        self.auth_cookie_template
            .validate()
            .map_err(|e| OAuth2Error::cookie_invalid(OAuth2CookieKind::Auth, e.to_string()))?;

        let handler_state = Arc::new(OAuth2HandlerState::<R, G> {
            auth_url,
            token_url,
            client_id,
            client_secret: self.client_secret.clone(),
            redirect_url,
            scopes: self.scopes.clone(),
            state_cookie_template: self.state_cookie_template.clone(),
            pkce_cookie_template: self.pkce_cookie_template.clone(),
            auth_cookie_template: self.auth_cookie_template.clone(),
            post_login_redirect: self.post_login_redirect.clone(),
            mapper: self.mapper.clone(),
            account_inserter: self.account_inserter.clone(),
            jwt_encoder: self.jwt_encoder.clone(),
        });

        let base = base_path.trim_end_matches('/');
        let login_path = format!("{base}/login");
        let callback_path = format!("{base}/callback");

        let router = Router::<()>::new()
            .route(&login_path, get(login_handler::<R, G>))
            .route(&callback_path, get(callback_handler::<R, G>))
            .layer(Extension(handler_state));

        Ok(router)
    }
}

/// Shared handler state injected via `Extension`.
#[derive(Clone)]
struct OAuth2HandlerState<R, G>
where
    R: AccessHierarchy + Eq + Display + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    // Raw OAuth2 config; client is constructed in handlers
    auth_url: String,
    token_url: String,
    client_id: String,
    client_secret: Option<String>,
    redirect_url: String,
    scopes: Vec<String>,

    state_cookie_template: CookieTemplate,
    pkce_cookie_template: CookieTemplate,

    // Session issuance
    auth_cookie_template: CookieTemplate,
    post_login_redirect: Option<String>,
    mapper: Option<AccountMapperFn<R, G>>,
    account_inserter: Option<AccountPersistFn<R, G>>,
    jwt_encoder: Option<AccountEncoderFn<R, G>>,
}

/// Query parameters delivered by the provider to the redirect/callback endpoint.
#[derive(Deserialize, Debug)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// Generates PKCE/state cookies and redirects to the provider's authorization endpoint.
async fn login_handler<R, G>(
    Extension(st): Extension<Arc<OAuth2HandlerState<R, G>>>,
    jar: CookieJar,
) -> impl IntoResponse
where
    R: AccessHierarchy + Eq + Display + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    let auth_url = match AuthUrl::new(st.auth_url.clone()) {
        Ok(u) => u,
        Err(e) => {
            {
                let err = self::errors::OAuth2Error::invalid_url("auth_url", e.to_string());
                error!(
                    "{}",
                    crate::errors::UserFriendlyError::developer_message(&err)
                );
            }
            return (StatusCode::INTERNAL_SERVER_ERROR, "OAuth2 misconfigured").into_response();
        }
    };
    let token_url = match TokenUrl::new(st.token_url.clone()) {
        Ok(u) => u,
        Err(e) => {
            {
                let err = self::errors::OAuth2Error::invalid_url("token_url", e.to_string());
                error!(
                    "{}",
                    crate::errors::UserFriendlyError::developer_message(&err)
                );
            }
            return (StatusCode::INTERNAL_SERVER_ERROR, "OAuth2 misconfigured").into_response();
        }
    };
    let redirect_url = match RedirectUrl::new(st.redirect_url.clone()) {
        Ok(u) => u,
        Err(e) => {
            {
                let err = self::errors::OAuth2Error::invalid_url("redirect_url", e.to_string());
                error!(
                    "{}",
                    crate::errors::UserFriendlyError::developer_message(&err)
                );
            }
            return (StatusCode::INTERNAL_SERVER_ERROR, "OAuth2 misconfigured").into_response();
        }
    };
    let mut client = BasicClient::new(ClientId::new(st.client_id.clone()))
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_redirect_uri(redirect_url);
    if let Some(secret) = &st.client_secret {
        client = client.set_client_secret(ClientSecret::new(secret.clone()));
    }

    // CSRF state
    let csrf = CsrfToken::new_random();
    // PKCE challenge + verifier
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let mut req = client
        .authorize_url(|| csrf.clone())
        .set_pkce_challenge(pkce_challenge);

    for s in &st.scopes {
        req = req.add_scope(Scope::new(s.clone()));
    }

    let (auth_url, csrf_token) = req.url();

    // Prepare cookies using configured templates (short-lived by default)
    let state_cookie = st
        .state_cookie_template
        .build_with_value(csrf_token.secret());

    let pkce_cookie = st
        .pkce_cookie_template
        .build_with_value(pkce_verifier.secret());

    let jar = jar.add(state_cookie).add(pkce_cookie);

    (jar, Redirect::to(auth_url.as_str())).into_response()
}

/// Validates state and PKCE, exchanges code for tokens, optionally mints a first-party JWT,
/// installs auth cookie, clears ephemeral cookies, and redirects (if configured).
async fn callback_handler<R, G>(
    Extension(st): Extension<Arc<OAuth2HandlerState<R, G>>>,
    jar: CookieJar,
    Query(q): Query<CallbackQuery>,
) -> impl IntoResponse
where
    R: AccessHierarchy + Eq + std::fmt::Display + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    // Load state + pkce verifier from cookies
    let state_cookie = jar.get(st.state_cookie_template.cookie_name_ref());
    let pkce_cookie = jar.get(st.pkce_cookie_template.cookie_name_ref());

    let Some(state_cookie) = state_cookie else {
        error!("Missing state cookie");
        let state_removal = st.state_cookie_template.build_removal();
        let pkce_removal = st.pkce_cookie_template.build_removal();
        let jar = jar.add(state_removal).add(pkce_removal);
        return (jar, (StatusCode::BAD_REQUEST, "Missing state")).into_response();
    };

    let Some(pkce_cookie) = pkce_cookie else {
        error!("Missing PKCE cookie");
        let state_removal = st.state_cookie_template.build_removal();
        let pkce_removal = st.pkce_cookie_template.build_removal();
        let jar = jar.add(state_removal).add(pkce_removal);
        return (jar, (StatusCode::BAD_REQUEST, "Missing PKCE")).into_response();
    };

    // If provider returned an error, clear cookies and return a safe error.
    if let Some(err) = q.error.as_deref() {
        let state_removal = st.state_cookie_template.build_removal();
        let pkce_removal = st.pkce_cookie_template.build_removal();
        let jar = jar.add(state_removal).add(pkce_removal);
        error!(
            "OAuth2 provider returned error: {err} {:?}",
            q.error_description.as_deref()
        );
        return (
            jar,
            (StatusCode::BAD_REQUEST, "OAuth2 authorization failed"),
        )
            .into_response();
    }

    // Compare state from query and cookie; require state param
    match q.state.as_deref() {
        Some(state) if state_cookie.value() == state => {}
        _ => {
            error!("State missing or mismatch");
            let state_removal = st.state_cookie_template.build_removal();
            let pkce_removal = st.pkce_cookie_template.build_removal();
            let jar = jar.add(state_removal).add(pkce_removal);
            return (
                jar,
                (StatusCode::BAD_REQUEST, "OAuth2 authorization failed"),
            )
                .into_response();
        }
    }

    let Some(code_str) = q.code.clone() else {
        let state_removal = st.state_cookie_template.build_removal();
        let pkce_removal = st.pkce_cookie_template.build_removal();
        let jar = jar.add(state_removal).add(pkce_removal);
        return (
            jar,
            (StatusCode::BAD_REQUEST, "OAuth2 authorization failed"),
        )
            .into_response();
    };
    let code = AuthorizationCode::new(code_str);
    let pkce_verifier = PkceCodeVerifier::new(pkce_cookie.value().to_string());

    // Exchange code for tokens
    let auth_url = match AuthUrl::new(st.auth_url.clone()) {
        Ok(u) => u,
        Err(e) => {
            {
                let err = self::errors::OAuth2Error::invalid_url("auth_url", e.to_string());
                error!(
                    "{}",
                    crate::errors::UserFriendlyError::developer_message(&err)
                );
            }
            let state_removal = st.state_cookie_template.build_removal();
            let pkce_removal = st.pkce_cookie_template.build_removal();
            let jar = jar.add(state_removal).add(pkce_removal);
            return (
                jar,
                (StatusCode::INTERNAL_SERVER_ERROR, "OAuth2 misconfigured"),
            )
                .into_response();
        }
    };
    let token_url = match TokenUrl::new(st.token_url.clone()) {
        Ok(u) => u,
        Err(e) => {
            {
                let err = self::errors::OAuth2Error::invalid_url("token_url", e.to_string());
                error!(
                    "{}",
                    crate::errors::UserFriendlyError::developer_message(&err)
                );
            }
            let state_removal = st.state_cookie_template.build_removal();
            let pkce_removal = st.pkce_cookie_template.build_removal();
            let jar = jar.add(state_removal).add(pkce_removal);
            return (
                jar,
                (StatusCode::INTERNAL_SERVER_ERROR, "OAuth2 misconfigured"),
            )
                .into_response();
        }
    };
    let redirect_url = match RedirectUrl::new(st.redirect_url.clone()) {
        Ok(u) => u,
        Err(e) => {
            {
                let err = self::errors::OAuth2Error::invalid_url("redirect_url", e.to_string());
                error!(
                    "{}",
                    crate::errors::UserFriendlyError::developer_message(&err)
                );
            }
            let state_removal = st.state_cookie_template.build_removal();
            let pkce_removal = st.pkce_cookie_template.build_removal();
            let jar = jar.add(state_removal).add(pkce_removal);
            return (
                jar,
                (StatusCode::INTERNAL_SERVER_ERROR, "OAuth2 misconfigured"),
            )
                .into_response();
        }
    };
    let mut client = BasicClient::new(ClientId::new(st.client_id.clone()))
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_redirect_uri(redirect_url);
    if let Some(secret) = &st.client_secret {
        client = client.set_client_secret(ClientSecret::new(secret.clone()));
    }

    match client
        .exchange_code(code)
        .set_pkce_verifier(pkce_verifier)
        .request_async(&|req: oauth2::HttpRequest| async move {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()?;
            let url = req.uri().to_string();
            let builder = client.request(req.method().clone(), url);
            let resp = builder
                .headers(req.headers().clone())
                .body(req.body().clone())
                .send()
                .await?;
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = resp.bytes().await?.to_vec();
            let mut resp_out = http::Response::new(body);
            *resp_out.status_mut() = status;
            *resp_out.headers_mut() = headers;
            Ok::<http::Response<Vec<u8>>, reqwest::Error>(resp_out)
        })
        .await
    {
        Ok(token_resp) => {
            debug!(
                "OAuth2 token response received (scopes: {:?})",
                token_resp.scopes()
            );

            // Clear ephemeral cookies (state/pkce) using configured templates
            let state_removal = st.state_cookie_template.build_removal();
            let pkce_removal = st.pkce_cookie_template.build_removal();

            let mut jar = jar.add(state_removal).add(pkce_removal);

            // Try session issuance if configured
            if let (Some(mapper), Some(jwt_encoder)) = (&st.mapper, &st.jwt_encoder) {
                // 1) Map provider tokens -> Account<R, G>
                match (mapper)(&token_resp).await {
                    Ok(mapped_account) => {
                        // 2) Optionally persist/load account before JWT issuance (to get stable account_id)
                        let account_result = if let Some(inserter) = &st.account_inserter {
                            (inserter)(mapped_account).await
                        } else {
                            Ok(mapped_account)
                        };

                        // 3) Encode JWT using the (possibly persisted) account
                        match account_result.and_then(|account| jwt_encoder(account)) {
                            Ok(token) => {
                                // Prepare auth cookie using template flags
                                let auth_cookie = st.auth_cookie_template.build_with_value(&token);

                                jar = jar.add(auth_cookie);

                                if let Some(url) = &st.post_login_redirect {
                                    return (jar, Redirect::to(url)).into_response();
                                } else {
                                    return (jar, (StatusCode::OK, "OAuth2 login OK"))
                                        .into_response();
                                }
                            }
                            Err(e) => {
                                error!(
                                    "OAuth2 session issuance failed [{}]: {}",
                                    crate::errors::UserFriendlyError::support_code(&e),
                                    crate::errors::UserFriendlyError::developer_message(&e),
                                );
                                return (
                                    jar,
                                    (StatusCode::BAD_GATEWAY, "OAuth2 session issuance failed"),
                                )
                                    .into_response();
                            }
                        }
                    }
                    Err(e) => {
                        error!(
                            "OAuth2 account mapping failed [{}]: {}",
                            crate::errors::UserFriendlyError::support_code(&e),
                            crate::errors::UserFriendlyError::developer_message(&e),
                        );
                        return (
                            jar,
                            (StatusCode::BAD_GATEWAY, "OAuth2 account mapping failed"),
                        )
                            .into_response();
                    }
                }
            }

            // If no session issuance configured, return OK
            (jar, (StatusCode::OK, "OAuth2 callback OK")).into_response()
        }
        Err(err) => {
            let oe = self::errors::OAuth2Error::token_exchange(err.to_string());
            error!(
                "OAuth2 token exchange failed [{}]: {}",
                crate::errors::UserFriendlyError::support_code(&oe),
                crate::errors::UserFriendlyError::developer_message(&oe),
            );
            let state_removal = st.state_cookie_template.build_removal();
            let pkce_removal = st.pkce_cookie_template.build_removal();
            let jar = jar.add(state_removal).add(pkce_removal);
            (
                jar,
                (StatusCode::BAD_GATEWAY, "OAuth2 token exchange failed"),
            )
                .into_response()
        }
    }
}

// Debug implementation avoids leaking secrets
impl<R, G> std::fmt::Debug for OAuth2Gate<R, G>
where
    R: AccessHierarchy + Eq + Display + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuth2Gate")
            .field("auth_url", &self.auth_url)
            .field("token_url", &self.token_url)
            .field(
                "client_id",
                &self.client_id.as_ref().map(|_| "<configured>"),
            )
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("redirect_url", &self.redirect_url)
            .field("scopes", &self.scopes)
            .field(
                "state_cookie_name",
                &self.state_cookie_template.cookie_name_ref(),
            )
            .field(
                "pkce_cookie_name",
                &self.pkce_cookie_template.cookie_name_ref(),
            )
            .field(
                "auth_cookie_name",
                &self.auth_cookie_template.cookie_name_ref(),
            )
            .field("post_login_redirect", &self.post_login_redirect)
            .finish()
    }
}

#[cfg(test)]
mod tests {

    use super::OAuth2Gate;
    use crate::cookie_template::CookieTemplate;
    use crate::prelude::{Group, Role};
    #[cfg(debug_assertions)]
    use cookie::SameSite;

    #[test]
    fn cookie_template_recommended_is_valid_in_debug_defaults() {
        // recommended() uses Secure=false, SameSite=Lax in debug builds — should be valid
        let t = CookieTemplate::recommended();
        assert!(t.validate().is_ok());
    }

    #[test]
    #[cfg(debug_assertions)]
    fn cookie_template_insecure_none_is_rejected() {
        // SameSite=None must require Secure=true; validate() should reject this in debug defaults.
        let t = CookieTemplate::recommended().same_site(SameSite::None);
        assert!(t.validate().is_err());
    }

    #[test]
    #[cfg(debug_assertions)]
    fn routes_validation_rejects_invalid_cookie_templates() {
        // Auth cookie using SameSite=None without Secure must be rejected when building routes.
        let gate = OAuth2Gate::<Role, Group>::new()
            .auth_url("https://provider.example.com/oauth2/authorize")
            .token_url("https://provider.example.com/oauth2/token")
            .client_id("id")
            .redirect_url("http://localhost:3000/auth/callback")
            .with_cookie_template(CookieTemplate::recommended().same_site(SameSite::None));
        assert!(gate.routes("/auth").is_err());
    }

    #[test]
    fn debug_redacts_client_secret() {
        let gate = OAuth2Gate::<Role, Group>::new()
            .auth_url("https://provider.example.com/oauth2/authorize")
            .token_url("https://provider.example.com/oauth2/token")
            .client_id("id")
            .client_secret("super-secret")
            .redirect_url("http://localhost:3000/auth/callback");
        let dbg = format!("{:?}", gate);
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("super-secret"));
    }
}
