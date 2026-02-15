//! Axum adapter for the framework-agnostic OAuth2 gate runtime.
//!
//! This layer builds routes for `/login` and `/callback`, delegates all OAuth2
//! logic to the core runtime (`webgates::gate::oauth2`), and maps outcomes to
//! Axum responses. HTTP transport (token exchange) is implemented here via
//! `reqwest` and the `oauth2` crate.
//!
//! Usage mirrors the previous Axum-only API but now forwards to the core runtime:
//!
//! ```ignore
//! use std::sync::Arc;
//! use webgates_axum::gate::Gate;
//! use webgates::prelude::*;
//!
//! let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//!
//! let gate = Gate::oauth2::<Role, Group>()
//!     .auth_url("https://provider.example.com/oauth2/authorize")
//!     .token_url("https://provider.example.com/oauth2/token")
//!     .client_id("CLIENT_ID")
//!     .client_secret("CLIENT_SECRET")
//!     .redirect_url("http://localhost:3000/auth/callback")
//!     .add_scope("openid")
//!     .with_jwt_codec("my-app", Arc::clone(&jwt_codec), 86_400);
//!
//! let router = gate.routes("/auth").expect("valid oauth2 config");
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::{
    Extension, Router,
    extract::Query,
    response::{IntoResponse, Redirect},
    routing::get,
};
use axum_extra::extract::CookieJar;
use http::StatusCode;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, PkceCodeVerifier, RedirectUrl,
    StandardTokenResponse, TokenUrl, basic::BasicClient,
};
use serde::Deserialize;
use tracing::error;
use webgates::accounts::{Account, AccountRepository};
use webgates::authz::AccessHierarchy;
use webgates::codecs::Codec;
use webgates::codecs::jwt::JwtClaims;
use webgates::cookie_template::CookieTemplate;
use webgates::errors::UserFriendlyError;
use webgates::gate::oauth2::errors::OAuth2Error;
use webgates::gate::oauth2::{
    CallbackInput, CallbackOutcome, LoginPreparation, OAuth2Gate as CoreOAuth2Gate, OAuth2Runtime,
    TokenExchanger, TokenRequest,
};

/// Axum-facing OAuth2 gate builder (thin wrapper over the core builder).
#[derive(Clone)]
pub struct OAuth2Gate<R, G>
where
    R: AccessHierarchy + Eq + std::fmt::Display + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    core: CoreOAuth2Gate<R, G>,
    state_cookie_name: String,
    pkce_cookie_name: String,
    auth_cookie_name: String,
    /// Optional token exchanger provided by the integrator. When present this
    /// will be used for the callback token exchange; otherwise the default
    /// `ReqwestTokenExchanger` is used.
    token_exchanger: Option<Arc<dyn TokenExchanger>>,
}

impl<R, G> Default for OAuth2Gate<R, G>
where
    R: AccessHierarchy + Eq + std::fmt::Display + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        let state_default = CookieTemplate::recommended().cookie_name_ref().to_string();
        let pkce_default = CookieTemplate::recommended().cookie_name_ref().to_string();
        let auth_default = CookieTemplate::recommended().cookie_name_ref().to_string();
        Self {
            core: CoreOAuth2Gate::new(),
            state_cookie_name: state_default,
            pkce_cookie_name: pkce_default,
            auth_cookie_name: auth_default,
            token_exchanger: None,
        }
    }
}

impl<R, G> OAuth2Gate<R, G>
where
    R: AccessHierarchy + Eq + std::fmt::Display + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    /// Create a new OAuth2 gate builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the authorization endpoint URL.
    pub fn auth_url(mut self, url: impl Into<String>) -> Self {
        self.core = self.core.auth_url(url);
        self
    }

    /// Set the token endpoint URL.
    pub fn token_url(mut self, url: impl Into<String>) -> Self {
        self.core = self.core.token_url(url);
        self
    }

    /// Set the OAuth2 client ID.
    pub fn client_id(mut self, id: impl Into<String>) -> Self {
        self.core = self.core.client_id(id);
        self
    }

    /// Set the OAuth2 client secret (optional for public clients).
    pub fn client_secret(mut self, secret: impl Into<String>) -> Self {
        self.core = self.core.client_secret(secret);
        self
    }

    /// Set the redirect URL that your provider will call after user authorization.
    pub fn redirect_url(mut self, url: impl Into<String>) -> Self {
        self.core = self.core.redirect_url(url);
        self
    }

    /// Add a scope to request from the provider.
    pub fn add_scope(mut self, scope: impl Into<String>) -> Self {
        self.core = self.core.add_scope(scope);
        self
    }

    /// Set custom cookie names for state/PKCE (primarily for multi-provider setups).
    pub fn with_cookie_names(
        mut self,
        state_cookie: impl Into<String>,
        pkce_cookie: impl Into<String>,
    ) -> Self {
        let state_name = state_cookie.into();
        let pkce_name = pkce_cookie.into();
        self.core = self
            .core
            .with_cookie_names(state_name.clone(), pkce_name.clone());
        self.state_cookie_name = state_name;
        self.pkce_cookie_name = pkce_name;
        self
    }

    /// Configure the state cookie template directly.
    pub fn with_state_cookie_template(mut self, template: CookieTemplate) -> Self {
        self.state_cookie_name = template.cookie_name_ref().to_string();
        self.core = self.core.with_state_cookie_template(template);
        self
    }

    /// Convenience to configure the state cookie template via the high-level builder.
    pub fn configure_state_cookie_template<F>(mut self, f: F) -> Result<Self, OAuth2Error>
    where
        F: FnOnce(CookieTemplate) -> CookieTemplate,
    {
        let template = f(CookieTemplate::recommended());
        self.state_cookie_name = template.cookie_name_ref().to_string();
        self.core = self.core.configure_state_cookie_template(|_| template)?;
        Ok(self)
    }

    /// Configure the PKCE cookie template directly.
    pub fn with_pkce_cookie_template(mut self, template: CookieTemplate) -> Self {
        self.pkce_cookie_name = template.cookie_name_ref().to_string();
        self.core = self.core.with_pkce_cookie_template(template);
        self
    }

    /// Convenience to configure the PKCE cookie template via the high-level builder.
    pub fn configure_pkce_cookie_template<F>(mut self, f: F) -> Result<Self, OAuth2Error>
    where
        F: FnOnce(CookieTemplate) -> CookieTemplate,
    {
        let template = f(CookieTemplate::recommended());
        self.pkce_cookie_name = template.cookie_name_ref().to_string();
        self.core = self.core.configure_pkce_cookie_template(|_| template)?;
        Ok(self)
    }

    /// Configure the auth cookie template used to store the first-party JWT.
    pub fn with_cookie_template(mut self, template: CookieTemplate) -> Self {
        self.auth_cookie_name = template.cookie_name_ref().to_string();
        self.core = self.core.with_cookie_template(template);
        self
    }

    /// Convenience to configure the auth cookie template via the high-level builder.
    pub fn configure_cookie_template<F>(mut self, f: F) -> Result<Self, OAuth2Error>
    where
        F: FnOnce(CookieTemplate) -> CookieTemplate,
    {
        let template = f(CookieTemplate::recommended());
        self.auth_cookie_name = template.cookie_name_ref().to_string();
        self.core = self.core.configure_cookie_template(|_| template)?;
        Ok(self)
    }

    /// Configure a post-login redirect URL (e.g., "/").
    pub fn with_post_login_redirect(mut self, url: impl Into<String>) -> Self {
        self.core = self.core.with_post_login_redirect(url);
        self
    }

    /// Provide an async account mapper that converts the token response to an Account<R, G>.
    pub fn with_account_mapper<F>(mut self, f: F) -> Self
    where
        F: Send + Sync + 'static,
        for<'a> F: Fn(
            &'a StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>,
        ) -> Pin<
            Box<dyn Future<Output = Result<Account<R, G>, OAuth2Error>> + Send + 'a>,
        >,
    {
        self.core = self.core.with_account_mapper(f);
        self
    }

    /// Provide an async account inserter that persists or loads an account before JWT issuance.
    pub fn with_account_inserter<F, Fut>(mut self, f: F) -> Self
    where
        F: Fn(Account<R, G>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Account<R, G>, OAuth2Error>> + Send + 'static,
    {
        self.core = self.core.with_account_inserter(f);
        self
    }

    /// Convenience: insert into an AccountRepository on first login (idempotent).
    pub fn with_account_repository<AccRepo>(mut self, repo: Arc<AccRepo>) -> Self
    where
        AccRepo: AccountRepository<R, G> + Send + Sync + 'static,
    {
        self.core = self.core.with_account_repository(repo);
        self
    }

    /// Provide a JWT codec and issuer; sets up a type-erased encoder closure.
    pub fn with_jwt_codec<C>(mut self, issuer: &str, codec: Arc<C>, ttl_secs: u64) -> Self
    where
        C: Codec<Payload = JwtClaims<Account<R, G>>> + Send + Sync + 'static,
    {
        self.core = self.core.with_jwt_codec(issuer, codec, ttl_secs);
        self
    }

    /// Configure a custom `TokenExchanger` for this wrapper.
    ///
    /// This allows integrators to inject a test or custom exchanger that will be
    /// used by the callback handler during token exchange. The method consumes and
    /// returns the wrapper for ergonomic builder-style usage.
    pub fn with_token_exchanger(mut self, exchanger: impl TokenExchanger + 'static) -> Self {
        self.token_exchanger = Some(Arc::new(exchanger));
        self
    }

    /// Build and return an Axum Router with `/login` and `/callback` routes nested under `base_path`.
    ///
    /// This method consumes the current wrapper configuration and produces a ready-to-mount
    /// `Router`. The configured `token_exchanger` (if any) is injected into the handler
    /// state; otherwise the default `ReqwestTokenExchanger` will be used.
    pub fn into_router(&self, base_path: &str) -> Result<Router<()>, OAuth2Error> {
        let runtime = self.core.clone().build()?;

        // Determine which exchanger to use: the configured one or the default.
        let exchanger: Arc<dyn TokenExchanger> = match &self.token_exchanger {
            Some(e) => Arc::clone(e),
            None => Arc::new(ReqwestTokenExchanger),
        };

        let state = Arc::new(HandlerState::<R, G> {
            runtime,
            state_cookie_name: self.state_cookie_name.clone(),
            pkce_cookie_name: self.pkce_cookie_name.clone(),
            exchanger,
        });

        let base = base_path.trim_end_matches('/');
        let login_path = format!("{base}/login");
        let callback_path = format!("{base}/callback");

        let router = Router::<()>::new()
            .route(&login_path, get(login_handler::<R, G>))
            .route(&callback_path, get(callback_handler::<R, G>))
            .layer(Extension(state));

        Ok(router)
    }
}

/// State shared across handlers.
#[derive(Clone)]
struct HandlerState<R, G>
where
    R: AccessHierarchy + Eq + std::fmt::Display + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    runtime: OAuth2Runtime<R, G>,
    state_cookie_name: String,
    pkce_cookie_name: String,
    /// Token exchanger used by callback handler (injected from the wrapper).
    exchanger: Arc<dyn TokenExchanger>,
}

#[derive(Deserialize, Debug)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// Prepares state/pkce cookies and redirects to the provider.
async fn login_handler<R, G>(
    Extension(st): Extension<Arc<HandlerState<R, G>>>,
    jar: CookieJar,
) -> impl IntoResponse
where
    R: AccessHierarchy + Eq + std::fmt::Display + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    match st.runtime.prepare_login() {
        Ok(LoginPreparation {
            redirect_url,
            state_cookie,
            pkce_cookie,
        }) => {
            let jar = jar.add(state_cookie).add(pkce_cookie);
            (jar, Redirect::to(&redirect_url)).into_response()
        }
        Err(e) => {
            error!(
                "OAuth2 login prepare failed [{}]: {}",
                e.support_code(),
                e.developer_message()
            );
            (StatusCode::INTERNAL_SERVER_ERROR, "OAuth2 misconfigured").into_response()
        }
    }
}

/// Validates state/pkce, exchanges code, issues session (if configured), and responds.
async fn callback_handler<R, G>(
    Extension(st): Extension<Arc<HandlerState<R, G>>>,
    jar: CookieJar,
    Query(q): Query<CallbackQuery>,
) -> impl IntoResponse
where
    R: AccessHierarchy + Eq + std::fmt::Display + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    let state_cookie = jar.get(&st.state_cookie_name).cloned();
    let pkce_cookie = jar.get(&st.pkce_cookie_name).cloned();

    let input = CallbackInput {
        code: q.code.clone(),
        state: q.state.clone(),
        error: q.error.clone(),
        error_description: q.error_description.clone(),
        state_cookie,
        pkce_cookie,
    };

    let exchanger_ref: &dyn TokenExchanger = st.exchanger.as_ref();

    match st.runtime.evaluate_callback(input, exchanger_ref).await {
        CallbackOutcome::Success {
            cookies,
            redirect_to,
            message,
        } => {
            let jar = cookies.into_iter().fold(jar, |acc, c| acc.add(c));
            if let Some(loc) = redirect_to {
                (jar, Redirect::to(&loc)).into_response()
            } else {
                (
                    jar,
                    (StatusCode::OK, message.unwrap_or_else(|| "OK".to_string())),
                )
                    .into_response()
            }
        }
        CallbackOutcome::Failure { cookies, error } => {
            let jar = cookies.into_iter().fold(jar, |acc, c| acc.add(c));
            error!(
                "OAuth2 callback failed [{}]: {}",
                error.support_code(),
                error.developer_message()
            );
            let status = match error {
                OAuth2Error::MissingStateCookie
                | OAuth2Error::MissingPkceCookie
                | OAuth2Error::StateMismatch
                | OAuth2Error::MissingAuthorizationCode
                | OAuth2Error::ProviderReturnedError { .. } => StatusCode::BAD_REQUEST,
                _ => StatusCode::BAD_GATEWAY,
            };
            (jar, (status, error.user_message())).into_response()
        }
    }
}

/// Reqwest-based token exchanger implementing the core `TokenExchanger` trait.
#[derive(Default)]
struct ReqwestTokenExchanger;

impl TokenExchanger for ReqwestTokenExchanger {
    fn exchange_code(
        &self,
        request: TokenRequest,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        StandardTokenResponse<
                            oauth2::EmptyExtraTokenFields,
                            oauth2::basic::BasicTokenType,
                        >,
                        OAuth2Error,
                    >,
                > + Send,
        >,
    > {
        Box::pin(async move {
            let token_url = TokenUrl::new(request.token_url.clone())
                .map_err(|e| OAuth2Error::invalid_url("token_url", e.to_string()))?;
            // Auth URL is required by BasicClient; reusing token_url satisfies the type without affecting token exchange.
            let auth_url = AuthUrl::new(request.token_url.clone())
                .map_err(|e| OAuth2Error::invalid_url("auth_url", e.to_string()))?;
            let mut client = BasicClient::new(ClientId::new(request.client_id.clone()))
                .set_auth_uri(auth_url)
                .set_token_uri(token_url);
            if let Some(secret) = request.client_secret.as_ref() {
                client = client.set_client_secret(ClientSecret::new(secret.clone()));
            }
            let redirect_url = RedirectUrl::new(request.redirect_url.clone())
                .map_err(|e| OAuth2Error::invalid_url("redirect_url", e.to_string()))?;
            client = client.set_redirect_uri(redirect_url);

            let auth_code = AuthorizationCode::new(request.code.clone());
            let pkce_verifier = PkceCodeVerifier::new(request.pkce_verifier.clone());

            client
                .exchange_code(auth_code)
                .set_pkce_verifier(pkce_verifier)
                .request_async(&|req: oauth2::HttpRequest| async move {
                    let http_client = reqwest::Client::builder()
                        .timeout(std::time::Duration::from_secs(10))
                        .build()?;
                    let url = req.uri().to_string();
                    let builder = http_client.request(req.method().clone(), url);
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
                .map_err(|e| OAuth2Error::token_exchange(e.to_string()))
        })
    }
}
