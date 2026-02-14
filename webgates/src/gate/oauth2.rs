#![allow(dead_code)]
//! OAuth2 gate configuration and runtime.
//!
//! This module implements the OAuth2 Authorization Code + PKCE flow builder
//! and the runtime that performs login preparation and callback evaluation.
//! It is intentionally framework-agnostic: adapters or integration crates map
//! the runtime outcomes into transport-specific responses (HTTP redirects,
//! cookies to set/clear, JSON bodies, etc.).
//!
//! # Example — in-crate OAuth2 wiring and adapter sketch
//!
//! The core crate exposes `OAuth2Gate` (builder) and `OAuth2Runtime` (evaluator).
//! Integration code can prepare login redirects and evaluate callbacks using
//! these types without coupling the core to any HTTP framework. The example
//! below remains inside the crate boundaries and demonstrates:
//! - building a gate and converting it into a runtime, and
//! - a minimal `TokenExchanger` implementation sketch that could be used by a
//!   runtime during callback evaluation.
//!
//! ```rust
//! use std::sync::Arc;
//! use std::future::Future;
//! use std::pin::Pin;
//! use webgates::prelude::{Account, Group, Role, JsonWebToken, JwtClaims};
//! use webgates::gate::oauth2::{OAuth2Gate, OAuth2Runtime, TokenRequest, TokenExchanger, CallbackInput};
//! use webgates::cookie_template::CookieTemplate;
//!
//! // A trivial TokenExchanger that would call the provider's token endpoint.
//! // Integration code should implement this abstraction with an HTTP client.
//! struct DummyExchanger;
//! impl TokenExchanger for DummyExchanger {
//!     fn exchange_code(
//!         &self,
//!         _request: TokenRequest,
//!     ) -> Pin<Box<dyn Future<Output = Result<oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>, webgates::gate::oauth2::errors::OAuth2Error>> + Send>> {
//!         // Placeholder: real implementation would perform an HTTP POST to the
//!         // provider's token endpoint and return the parsed token response.
//!         Box::pin(async move {
//!             Err(webgates::gate::oauth2::errors::OAuth2Error::provider_error(
//!                 "dummy exchanger".to_string(),
//!                 None,
//!             ))
//!         })
//!     }
//! }
//!
//! async fn example() {
//!     // Configure cookie templates used for state/pkce/auth cookies.
//!     let state_tpl = CookieTemplate::recommended();
//!     let pkce_tpl = CookieTemplate::recommended();
//!     let auth_tpl = CookieTemplate::recommended();
//!
//!     // Build a minimal gate; real usage must set auth/token URLs and client creds.
//!     let gate = OAuth2Gate::<Role, Group>::default()
//!         .with_cookie_template(auth_tpl)
//!         .with_pkce_cookie_template(pkce_tpl)
//!         .with_state_cookie_template(state_tpl)
//!         .with_post_login_redirect("/".to_string());
//!
//!     // Convert builder into a runtime (validates configured templates and required fields).
//!     let runtime = match gate.build() {
//!         Ok(rt) => rt,
//!         Err(e) => {
//!             // handle misconfiguration
//!             tracing::error!(error = %e, "oauth2 gate misconfigured");
//!             return;
//!         }
//!     };
//!
//!     // Prepare a login: get redirect URL and cookies to set (state/pkce)
//!     let login = match runtime.prepare_login() {
//!         Ok(p) => p,
//!         Err(e) => {
//!             tracing::error!(error = %e, "prepare_login failed");
//!             return;
//!         }
//!     };
//!
//!     // In a real adapter: set `login.state_cookie` and `login.pkce_cookie` and
//!     // redirect the user to `login.redirect_url`.
//!
//!     // Later, in the callback handler the adapter should construct a
//!     // `CallbackInput` (including cookies received) and call `evaluate_callback`
//!     // with an implementation of `TokenExchanger` to perform the provider token
//!     // exchange. The returned `CallbackOutcome` is then mapped into framework
//!     // responses (redirect + set/clear cookies, error pages, etc.).
//! }
//! ```
//!
//! ## JWT validation
//!
//! `OAuth2Runtime::evaluate_callback` performs the provider token
//! exchange and constructs a first-party JWT using the configured encoder.
//! The jwt encoder uses the configured codec in this crate (typically backed
//! by the `jsonwebtoken` crate). Adapters should not re-validate signatures or
//! re-implement cryptographic checks; they should rely on the runtime's
//! outcome and map results to transport-specific responses.

use std::fmt::Display;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;

use crate::accounts::{Account, AccountRepository};
use crate::authz::AccessHierarchy;
use crate::codecs::Codec;
use crate::codecs::jwt::{JwtClaims, RegisteredClaims};
use crate::cookie_template::CookieTemplate;
use chrono::Utc;
use cookie::Cookie;
use oauth2::{
    AuthUrl, ClientId, ClientSecret, EmptyExtraTokenFields, RedirectUrl, Scope,
    StandardTokenResponse, TokenUrl, basic::BasicTokenType,
};
use serde::{Deserialize, Serialize};

pub mod errors;
use errors::{OAuth2CookieKind, OAuth2Error, Result as OAuth2Result};

/// Alias for the resulting token exchange future.
type OAuth2TokenExchangeFuture = Pin<
    Box<
        dyn Future<
                Output = OAuth2Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>>,
            > + Send,
    >,
>;

/// Type alias for an async account mapper function.
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

/// Type alias for an account encoding function.
type AccountEncoderFn<R, G> = Arc<dyn Fn(Account<R, G>) -> OAuth2Result<String> + Send + Sync>;

/// Minimal token request data passed to the exchanger.
#[derive(Clone, Debug)]
pub struct TokenRequest {
    /// Authorization code returned by the provider.
    pub code: String,
    /// PKCE verifier bound to the original authorization request.
    pub pkce_verifier: String,
    /// OAuth2 token endpoint.
    pub token_url: String,
    /// OAuth2 client id.
    pub client_id: String,
    /// Optional OAuth2 client secret.
    pub client_secret: Option<String>,
    /// Redirect URL used in the original authorization request.
    pub redirect_url: String,
}

/// Trait abstracting token exchange to keep the core free of HTTP clients.
pub trait TokenExchanger: Send + Sync {
    /// Exchange an authorization code for a token response.
    fn exchange_code(&self, request: TokenRequest) -> OAuth2TokenExchangeFuture;
}

/// Prepared login data: redirect target and cookies to set.
#[derive(Debug, Clone)]
pub struct LoginPreparation {
    /// Provider authorization URL to redirect the user to.
    pub redirect_url: String,
    /// CSRF state cookie to set before redirect.
    pub state_cookie: Cookie<'static>,
    /// PKCE verifier cookie to set before redirect.
    pub pkce_cookie: Cookie<'static>,
}

/// Callback input received from the transport adapter.
#[derive(Debug, Clone)]
pub struct CallbackInput {
    /// Authorization code from provider (if any).
    pub code: Option<String>,
    /// State parameter from provider (if any).
    pub state: Option<String>,
    /// Error parameter from provider (if any).
    pub error: Option<String>,
    /// Error description from provider (if any).
    pub error_description: Option<String>,
    /// CSRF state cookie value from the original login request.
    pub state_cookie: Option<Cookie<'static>>,
    /// PKCE verifier cookie value from the original login request.
    pub pkce_cookie: Option<Cookie<'static>>,
}

/// Callback evaluation outcome for adapters to map into HTTP responses.
#[derive(Debug, Clone)]
pub enum CallbackOutcome {
    /// Success with optional JWT cookie and optional redirect.
    Success {
        /// Cookies to set (state/pkce removals plus optional auth cookie).
        cookies: Vec<Cookie<'static>>,
        /// Optional redirect target (e.g., post-login URL).
        redirect_to: Option<String>,
        /// Optional message body for non-redirect responses.
        message: Option<String>,
    },
    /// Failure with cookies to clear and an error for logging/telemetry.
    Failure {
        /// Cookies to set (typically removals).
        cookies: Vec<Cookie<'static>>,
        /// Error describing the failure.
        error: OAuth2Error,
    },
}

/// Public builder for configuring OAuth2 routes and session issuance (framework-agnostic).
#[derive(Clone)]
#[must_use]
pub struct OAuth2Gate<R, G>
where
    R: AccessHierarchy + Eq + Display + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    auth_url: Option<String>,
    token_url: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    redirect_url: Option<String>,
    scopes: Vec<String>,

    state_cookie_template: CookieTemplate,
    pkce_cookie_template: CookieTemplate,
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
            state_cookie_template: CookieTemplate::recommended(),
            pkce_cookie_template: CookieTemplate::recommended(),
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
    pub fn with_account_inserter<F, Fut>(mut self, f: F) -> Self
    where
        F: Fn(Account<R, G>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = OAuth2Result<Account<R, G>>> + Send + 'static,
    {
        self.account_inserter = Some(Arc::new(move |account: Account<R, G>| Box::pin(f(account))));
        self
    }

    /// Convenience: insert into an AccountRepository on first login (idempotent).
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

    /// Build a runtime evaluator from the configured builder.
    pub fn build(self) -> OAuth2Result<OAuth2Runtime<R, G>> {
        let auth_url = self
            .auth_url
            .ok_or_else(|| OAuth2Error::missing("auth_url"))?;
        let token_url = self
            .token_url
            .ok_or_else(|| OAuth2Error::missing("token_url"))?;
        let client_id = self
            .client_id
            .ok_or_else(|| OAuth2Error::missing("client_id"))?;
        let redirect_url = self
            .redirect_url
            .ok_or_else(|| OAuth2Error::missing("redirect_url"))?;

        self.state_cookie_template
            .validate()
            .map_err(|e| OAuth2Error::cookie_invalid(OAuth2CookieKind::State, e.to_string()))?;
        self.pkce_cookie_template
            .validate()
            .map_err(|e| OAuth2Error::cookie_invalid(OAuth2CookieKind::Pkce, e.to_string()))?;
        self.auth_cookie_template
            .validate()
            .map_err(|e| OAuth2Error::cookie_invalid(OAuth2CookieKind::Auth, e.to_string()))?;

        Ok(OAuth2Runtime {
            auth_url,
            token_url,
            client_id,
            client_secret: self.client_secret,
            redirect_url,
            scopes: self.scopes,
            state_cookie_template: self.state_cookie_template,
            pkce_cookie_template: self.pkce_cookie_template,
            auth_cookie_template: self.auth_cookie_template,
            post_login_redirect: self.post_login_redirect,
            mapper: self.mapper,
            account_inserter: self.account_inserter,
            jwt_encoder: self.jwt_encoder,
            _phantom: PhantomData,
        })
    }
}

/// Runtime evaluator for OAuth2 login + callback (framework-agnostic).
#[derive(Clone)]
pub struct OAuth2Runtime<R, G>
where
    R: AccessHierarchy + Eq + Display + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    auth_url: String,
    token_url: String,
    client_id: String,
    client_secret: Option<String>,
    redirect_url: String,
    scopes: Vec<String>,

    state_cookie_template: CookieTemplate,
    pkce_cookie_template: CookieTemplate,
    auth_cookie_template: CookieTemplate,
    post_login_redirect: Option<String>,

    mapper: Option<AccountMapperFn<R, G>>,
    account_inserter: Option<AccountPersistFn<R, G>>,
    jwt_encoder: Option<AccountEncoderFn<R, G>>,

    _phantom: PhantomData<(R, G)>,
}

impl<R, G> OAuth2Runtime<R, G>
where
    R: AccessHierarchy + Eq + Display + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    /// Prepare login: build state/pkce cookies and provider authorization URL.
    pub fn prepare_login(&self) -> OAuth2Result<LoginPreparation> {
        let auth_url = AuthUrl::new(self.auth_url.clone())
            .map_err(|e| OAuth2Error::invalid_url("auth_url", e.to_string()))?;
        let token_url = TokenUrl::new(self.token_url.clone())
            .map_err(|e| OAuth2Error::invalid_url("token_url", e.to_string()))?;
        let redirect_url = RedirectUrl::new(self.redirect_url.clone())
            .map_err(|e| OAuth2Error::invalid_url("redirect_url", e.to_string()))?;

        let mut client = oauth2::basic::BasicClient::new(ClientId::new(self.client_id.clone()))
            .set_auth_uri(auth_url)
            .set_token_uri(token_url)
            .set_redirect_uri(redirect_url);

        if let Some(secret) = &self.client_secret {
            client = client.set_client_secret(ClientSecret::new(secret.clone()));
        }

        // CSRF state + PKCE
        let csrf = oauth2::CsrfToken::new_random();
        let (pkce_challenge, pkce_verifier) = oauth2::PkceCodeChallenge::new_random_sha256();

        let mut req = client
            .authorize_url(|| csrf.clone())
            .set_pkce_challenge(pkce_challenge);
        for s in &self.scopes {
            req = req.add_scope(Scope::new(s.clone()));
        }
        let (auth_url, csrf_token) = req.url();

        let state_cookie = self
            .state_cookie_template
            .build_with_value(csrf_token.secret());
        let pkce_cookie = self
            .pkce_cookie_template
            .build_with_value(pkce_verifier.secret());

        let prep = LoginPreparation {
            redirect_url: auth_url.to_string(),
            state_cookie,
            pkce_cookie,
        };

        Ok(prep)
    }

    /// Evaluate callback with provided input and token exchanger.
    pub async fn evaluate_callback<E>(&self, input: CallbackInput, exchanger: &E) -> CallbackOutcome
    where
        E: TokenExchanger,
    {
        // prepare removal cookies
        let mut cookies: Vec<Cookie<'static>> = Vec::new();
        cookies.push(self.state_cookie_template.build_removal());
        cookies.push(self.pkce_cookie_template.build_removal());

        // Provider returned error?
        if let Some(err) = input.error.as_ref() {
            let oe = OAuth2Error::provider_error(err.clone(), input.error_description.clone());
            return CallbackOutcome::Failure { cookies, error: oe };
        }

        // Validate state cookie presence
        let state_cookie = match input.state_cookie {
            Some(c) => c,
            None => {
                return CallbackOutcome::Failure {
                    cookies,
                    error: OAuth2Error::MissingStateCookie,
                };
            }
        };
        let pkce_cookie = match input.pkce_cookie {
            Some(c) => c,
            None => {
                return CallbackOutcome::Failure {
                    cookies,
                    error: OAuth2Error::MissingPkceCookie,
                };
            }
        };

        // State must match and be present
        match input.state.as_deref() {
            Some(state) if state_cookie.value() == state => {}
            _ => {
                return CallbackOutcome::Failure {
                    cookies,
                    error: OAuth2Error::StateMismatch,
                };
            }
        }

        // Authorization code must be present
        let code_str = match input.code {
            Some(c) => c,
            None => {
                return CallbackOutcome::Failure {
                    cookies,
                    error: OAuth2Error::MissingAuthorizationCode,
                };
            }
        };

        // Build token request
        let token_req = TokenRequest {
            code: code_str,
            pkce_verifier: pkce_cookie.value().to_string(),
            token_url: self.token_url.clone(),
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            redirect_url: self.redirect_url.clone(),
        };

        // Exchange code
        let token_resp = match exchanger.exchange_code(token_req).await {
            Ok(resp) => resp,
            Err(e) => {
                return CallbackOutcome::Failure {
                    cookies,
                    error: OAuth2Error::token_exchange(e.to_string()),
                };
            }
        };

        // Map account if configured
        let mapped_account = if let Some(mapper) = &self.mapper {
            match (mapper)(&token_resp).await {
                Ok(acc) => Some(acc),
                Err(e) => {
                    return CallbackOutcome::Failure { cookies, error: e };
                }
            }
        } else {
            None
        };

        // Persist if configured
        let persisted_account = if let Some(account) = mapped_account {
            if let Some(inserter) = &self.account_inserter {
                match (inserter)(account).await {
                    Ok(acc) => Some(acc),
                    Err(e) => {
                        return CallbackOutcome::Failure { cookies, error: e };
                    }
                }
            } else {
                Some(account)
            }
        } else {
            None
        };

        // Encode JWT if configured
        if let (Some(account), Some(encoder)) = (persisted_account, &self.jwt_encoder) {
            match encoder(account) {
                Ok(token) => {
                    let auth_cookie = self.auth_cookie_template.build_with_value(&token);
                    cookies.push(auth_cookie);
                }
                Err(e) => {
                    return CallbackOutcome::Failure { cookies, error: e };
                }
            }
        }

        CallbackOutcome::Success {
            cookies,
            redirect_to: self.post_login_redirect.clone(),
            message: Some("OAuth2 callback OK".into()),
        }
    }
}

/// Internal representation of provider tokens used by some adapters.
/// This mirrors `oauth2` crate types for serialization if needed.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProviderTokenResponse {
    /// Access token string.
    pub access_token: String,
    /// Optional refresh token.
    pub refresh_token: Option<String>,
    /// Optional id token (for OpenID Connect providers).
    pub id_token: Option<String>,
    /// Scopes granted.
    pub scopes: Option<Vec<String>>,
}
