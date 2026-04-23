use std::fmt::Debug;
use std::sync::Arc;

use tower::Layer;
use webgates::accounts::Account;
use webgates::authz::access_hierarchy::AccessHierarchy;
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
///
/// # Examples
///
/// The codec type must implement both [`webgates::codecs::Codec`] and
/// [`webgates::sessions::tokens::AuthTokenIssuer`]. The example below uses
/// [`webgates_repositories::memory::session::MemorySessionRepository`] for
/// the session store, which is suitable for tests and local development.
///
/// ```rust
/// use std::sync::Arc;
///
/// use axum::{Router, routing::get};
/// use webgates::accounts::Account;
/// use webgates::authz::access_policy::AccessPolicy;
/// use webgates::codecs::Codec;
/// use webgates::codecs::jwt::{JwtClaims, RegisteredClaims};
/// use webgates::cookie_template::CookieTemplate;
/// use webgates::groups::Group;
/// use webgates::roles::Role;
/// use webgates::sessions::config::SessionConfig;
/// use webgates::sessions::errors::TokenError;
/// use webgates::sessions::session::Session;
/// use webgates::sessions::tokens::{AuthToken, AuthTokenIssuer};
/// use webgates_axum::gate::Gate;
/// use webgates_axum::session::cookie_session_layer::CookieSessionLayer;
/// use webgates_codecs::jwt::{JsonWebToken, JsonWebTokenOptions};
/// use webgates_repositories::memory::session::MemorySessionRepository;
///
/// // A codec that satisfies both the JWT encoding contract and the session
/// // auth-token issuance contract. In production this wraps your app's JWT
/// // configuration; here it uses the default options.
/// #[derive(Clone)]
/// struct AppCodec {
///     jwt: JsonWebToken<JwtClaims<Account<Role, Group>>>,
/// }
///
/// impl AppCodec {
///     fn new() -> Self {
///         Self {
///             jwt: JsonWebToken::new_with_options(JsonWebTokenOptions::default()),
///         }
///     }
/// }
///
/// impl Codec for AppCodec {
///     type Payload = JwtClaims<Account<Role, Group>>;
///
///     fn encode(&self, payload: &Self::Payload) -> webgates::codecs::Result<Vec<u8>> {
///         self.jwt.encode(payload)
///     }
///
///     fn decode(&self, encoded: &[u8]) -> webgates::codecs::Result<Self::Payload> {
///         self.jwt.decode(encoded)
///     }
/// }
///
/// impl AuthTokenIssuer<Session> for AppCodec {
///     type Error = TokenError;
///
///     fn issue_auth_token(
///         &self,
///         session: &Session,
///     ) -> impl std::future::Future<Output = Result<AuthToken, TokenError>> + Send {
///         let account = Account::<Role, Group>::new(&session.subject_id);
///         // Set a 15-minute expiry; replace with your own claims builder.
///         let exp = std::time::SystemTime::now()
///             .duration_since(std::time::UNIX_EPOCH)
///             .unwrap_or_default()
///             .as_secs()
///             + 900;
///         let claims = JwtClaims::new(
///             account,
///             RegisteredClaims::new("my-app", exp)
///                 .with_session_id(session.session_id.into_uuid().to_string()),
///         );
///         let result = self
///             .jwt
///             .encode(&claims)
///             .map_err(|_| TokenError::AuthIssuanceFailed)
///             .and_then(|encoded| {
///                 String::from_utf8(encoded).map_err(|_| TokenError::AuthIssuanceFailed)
///             })
///             .and_then(AuthToken::new);
///         std::future::ready(result)
///     }
/// }
///
/// let codec = Arc::new(AppCodec::new());
/// let session_repo = MemorySessionRepository::new();
/// let session_config = SessionConfig::default();
/// let auth_cookie = CookieTemplate::recommended().name("auth-token");
/// let refresh_cookie = CookieTemplate::recommended().name("refresh-token");
///
/// // Compose the session layer (outer) around the cookie gate (inner).
/// let session_layer = CookieSessionLayer::<_, Role, Group, _>::new(
///     Arc::clone(&codec),
///     session_repo,
///     session_config,
///     auth_cookie.clone(),
///     refresh_cookie,
/// );
/// let gate = Gate::cookie("my-app", Arc::clone(&codec))
///     .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin));
///
/// let _app: Router = Router::new()
///     .route("/protected", get(|| async { "ok" }))
///     .layer(session_layer)
///     .layer(gate);
/// ```
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
