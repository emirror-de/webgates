use std::fmt::Debug;
use std::sync::Arc;

use tower::Layer;
use webgates::accounts::Account;
use webgates::authz::AccessHierarchy;
use webgates::codecs::Codec;
use webgates::codecs::jwt::JwtClaims;
use webgates::cookie_template::CookieTemplate;
use webgates::sessions::config::SessionConfig;
use webgates::sessions::tokens::AuthTokenIssuer;

use super::cookie_session_service::CookieSessionService;

/// Builder layer for transparent cookie-backed session renewal.
///
/// Apply this as the outer layer and the regular cookie gate as the inner layer:
///
/// - outer: [`CookieSessionLayer`]
/// - inner: `webgates_axum::gate::Gate::cookie(...)`
///
/// This layer is responsible for:
/// - reading auth and refresh cookies
/// - deciding whether renewal should be attempted
/// - requiring successful renewal when the auth token is expired
/// - mutating request/response cookies when renewal succeeds
///
/// The inner cookie gate remains responsible for:
/// - auth-token validation
/// - issuer checks
/// - authorization policy enforcement
#[derive(Clone)]
pub struct CookieSessionLayer<C, R, G, Repo>
where
    C: Codec<Payload = JwtClaims<Account<R, G>>>
        + AuthTokenIssuer<webgates::sessions::session::Session>
        + Clone,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq + Clone,
    Repo: webgates::sessions::repository::SessionRepository + Clone,
{
    codec: Arc<C>,
    auth_cookie_template: CookieTemplate,
    refresh_cookie_template: CookieTemplate,
    session_config: SessionConfig,
    session_repository: Repo,
    _phantom: std::marker::PhantomData<(R, G)>,
}

impl<C, R, G, Repo> Debug for CookieSessionLayer<C, R, G, Repo>
where
    C: Codec<Payload = JwtClaims<Account<R, G>>>
        + AuthTokenIssuer<webgates::sessions::session::Session>
        + Clone,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq + Clone,
    Repo: webgates::sessions::repository::SessionRepository + Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CookieSessionLayer")
            .field("auth_cookie_template", &self.auth_cookie_template)
            .field("refresh_cookie_template", &self.refresh_cookie_template)
            .field("session_config", &self.session_config)
            .finish_non_exhaustive()
    }
}

impl<C, R, G, Repo> CookieSessionLayer<C, R, G, Repo>
where
    C: Codec<Payload = JwtClaims<Account<R, G>>>
        + AuthTokenIssuer<webgates::sessions::session::Session>
        + Clone,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq + Clone,
    Repo: webgates::sessions::repository::SessionRepository + Clone,
{
    /// Creates a new cookie-session layer from the required renewal dependencies.
    #[must_use]
    pub fn new(
        codec: Arc<C>,
        session_repository: Repo,
        session_config: SessionConfig,
        auth_cookie_template: CookieTemplate,
        refresh_cookie_template: CookieTemplate,
    ) -> Self {
        Self {
            codec,
            auth_cookie_template,
            refresh_cookie_template,
            session_config,
            session_repository,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Returns the configured auth-cookie template.
    #[must_use]
    pub fn auth_cookie_template(&self) -> &CookieTemplate {
        &self.auth_cookie_template
    }

    /// Returns the configured refresh-cookie template.
    #[must_use]
    pub fn refresh_cookie_template(&self) -> &CookieTemplate {
        &self.refresh_cookie_template
    }

    /// Returns the configured session settings.
    #[must_use]
    pub fn session_config(&self) -> &SessionConfig {
        &self.session_config
    }

    /// Returns the configured session repository.
    #[must_use]
    pub fn session_repository(&self) -> &Repo {
        &self.session_repository
    }

    /// Returns the codec used to validate and reissue auth tokens.
    #[must_use]
    pub fn codec(&self) -> &Arc<C> {
        &self.codec
    }

    /// Replaces the auth-cookie template.
    #[must_use]
    pub fn with_auth_cookie_template(mut self, auth_cookie_template: CookieTemplate) -> Self {
        self.auth_cookie_template = auth_cookie_template;
        self
    }

    /// Replaces the refresh-cookie template.
    #[must_use]
    pub fn with_refresh_cookie_template(mut self, refresh_cookie_template: CookieTemplate) -> Self {
        self.refresh_cookie_template = refresh_cookie_template;
        self
    }

    /// Replaces the session configuration.
    #[must_use]
    pub fn with_session_config(mut self, session_config: SessionConfig) -> Self {
        self.session_config = session_config;
        self
    }

    /// Replaces the session repository.
    #[must_use]
    pub fn with_session_repository(mut self, session_repository: Repo) -> Self {
        self.session_repository = session_repository;
        self
    }
}

impl<S, C, R, G, Repo> Layer<S> for CookieSessionLayer<C, R, G, Repo>
where
    C: Codec<Payload = JwtClaims<Account<R, G>>>
        + AuthTokenIssuer<webgates::sessions::session::Session>
        + Clone
        + Send
        + Sync
        + 'static,
    <C as AuthTokenIssuer<webgates::sessions::session::Session>>::Error: std::fmt::Display,
    R: AccessHierarchy + Eq + std::fmt::Display + Clone + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
    Repo: webgates::sessions::repository::SessionRepository + Clone + Send + Sync + 'static,
{
    type Service = CookieSessionService<S, C, R, G, Repo>;

    fn layer(&self, inner: S) -> Self::Service {
        CookieSessionService::new(
            inner,
            Arc::clone(&self.codec),
            self.session_repository.clone(),
            self.session_config.clone(),
            self.auth_cookie_template.clone(),
            self.refresh_cookie_template.clone(),
        )
    }
}
