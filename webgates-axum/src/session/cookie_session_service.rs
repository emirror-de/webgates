use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{body::Body, extract::Request, http::Response};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use http::{HeaderValue, StatusCode, header::SET_COOKIE};
use tower::Service;
use webgates::accounts::Account;
use webgates::authz::AccessHierarchy;
use webgates::codecs::Codec;
use webgates::codecs::jwt::{JwtClaims, RegisteredClaims};
use webgates::cookie_template::CookieTemplate;
use webgates::sessions::config::SessionConfig;
use webgates::sessions::renewal::{AuthTokenState, RenewalOutcome, RenewalRequirement};
use webgates::sessions::repository::SessionRepository;
use webgates::sessions::services::SessionRenewer;
use webgates::sessions::tokens::{
    AuthTokenIssuer, OpaqueRefreshTokenGenerator, RefreshTokenPlaintext, Sha256RefreshTokenHasher,
    TokenPairIssuer,
};

/// Outer middleware service that performs transparent cookie-backed session
/// renewal before the inner auth cookie gate runs.
///
/// The intended composition is:
/// - outer: `CookieSessionLayer` / `CookieSessionService`
/// - inner: `webgates_axum::gate::Gate::cookie(...)`
///
/// This service implements the following behavior:
/// - valid auth token outside the proactive renewal window: pass through
/// - near-expiry auth token: try renewal opportunistically, continue on failure
/// - expired auth token: require successful renewal before continuing
/// - invalid auth token: reject immediately without trying renewal
///
/// On successful renewal, the service:
/// - rewrites the incoming auth cookie so the inner cookie gate sees the new JWT
/// - appends `Set-Cookie` headers for the renewed auth and refresh cookies on
///   the outgoing response
#[derive(Clone)]
pub struct CookieSessionService<S, C, R, G, Repo>
where
    C: Codec<Payload = JwtClaims<Account<R, G>>>
        + AuthTokenIssuer<webgates::sessions::session::Session>
        + Clone,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq + Clone,
    Repo: SessionRepository + Clone,
{
    inner: S,
    codec: Arc<C>,
    session_repository: Repo,
    session_config: SessionConfig,
    auth_cookie_template: CookieTemplate,
    refresh_cookie_template: CookieTemplate,
    _phantom: std::marker::PhantomData<(R, G)>,
}

impl<S, C, R, G, Repo> std::fmt::Debug for CookieSessionService<S, C, R, G, Repo>
where
    C: Codec<Payload = JwtClaims<Account<R, G>>>
        + AuthTokenIssuer<webgates::sessions::session::Session>
        + Clone,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq + Clone,
    Repo: SessionRepository + Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CookieSessionService")
            .field("session_config", &self.session_config)
            .field("auth_cookie_template", &self.auth_cookie_template)
            .field("refresh_cookie_template", &self.refresh_cookie_template)
            .finish_non_exhaustive()
    }
}

impl<S, C, R, G, Repo> CookieSessionService<S, C, R, G, Repo>
where
    C: Codec<Payload = JwtClaims<Account<R, G>>>
        + AuthTokenIssuer<webgates::sessions::session::Session>
        + Clone,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq + Clone,
    Repo: SessionRepository + Clone,
{
    /// Creates a new cookie-session service.
    #[must_use]
    pub fn new(
        inner: S,
        codec: Arc<C>,
        session_repository: Repo,
        session_config: SessionConfig,
        auth_cookie_template: CookieTemplate,
        refresh_cookie_template: CookieTemplate,
    ) -> Self {
        Self {
            inner,
            codec,
            session_repository,
            session_config,
            auth_cookie_template,
            refresh_cookie_template,
            _phantom: std::marker::PhantomData,
        }
    }

    fn auth_cookie<'a>(&self, req: &'a Request<Body>) -> Option<Cookie<'a>> {
        let cookie_jar = CookieJar::from_headers(req.headers());
        cookie_jar
            .get(self.auth_cookie_template.cookie_name_ref())
            .cloned()
    }

    fn refresh_cookie<'a>(&self, req: &'a Request<Body>) -> Option<Cookie<'a>> {
        let cookie_jar = CookieJar::from_headers(req.headers());
        cookie_jar
            .get(self.refresh_cookie_template.cookie_name_ref())
            .cloned()
    }

    fn auth_token_state(
        &self,
        registered_claims: &RegisteredClaims,
        now: SystemTime,
    ) -> AuthTokenState {
        let expiration_time = UNIX_EPOCH + Duration::from_secs(registered_claims.expiration_time);

        if expiration_time <= now {
            let expired_for = now
                .duration_since(expiration_time)
                .unwrap_or(Duration::ZERO);
            return AuthTokenState::Expired { expired_for };
        }

        let expires_in = expiration_time
            .duration_since(now)
            .unwrap_or(Duration::ZERO);

        if expires_in <= self.session_config.proactive_renewal_window {
            AuthTokenState::NearExpiry { expires_in }
        } else {
            AuthTokenState::Valid { expires_in }
        }
    }

    fn rewrite_request_auth_cookie(
        req: &mut Request<Body>,
        auth_cookie_template: &CookieTemplate,
        auth_token: &str,
    ) {
        let auth_name = auth_cookie_template.cookie_name_ref();
        let new_pair = format!("{}={}", auth_name, auth_token);

        // Parse the existing Cookie header and update only the auth cookie entry
        // so that all other cookies (e.g., CSRF tokens, feature flags) reach the
        // inner handler unchanged.  Using HeaderMap::insert with only the auth
        // cookie would silently drop every other cookie on the request.
        let updated = if let Some(existing) = req.headers().get(http::header::COOKIE) {
            let existing_str = existing.to_str().unwrap_or("");
            let mut replaced = false;
            let mut parts: Vec<String> = existing_str
                .split(';')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|pair| {
                    let name = pair.split('=').next().unwrap_or("").trim();
                    if name == auth_name {
                        replaced = true;
                        new_pair.clone()
                    } else {
                        pair.to_owned()
                    }
                })
                .collect();
            if !replaced {
                parts.push(new_pair);
            }
            parts.join("; ")
        } else {
            new_pair
        };

        let header_value = match HeaderValue::from_str(&updated) {
            Ok(value) => value,
            Err(_) => return,
        };

        req.headers_mut().insert(http::header::COOKIE, header_value);
    }

    fn append_set_cookie(response: &mut Response<Body>, cookie: Cookie<'static>) -> bool {
        let serialized = cookie.to_string();
        let header_value = match HeaderValue::from_str(&serialized) {
            Ok(value) => value,
            Err(_) => return false,
        };

        response.headers_mut().append(SET_COOKIE, header_value);
        true
    }

    fn apply_renewal_cookies(
        response: &mut Response<Body>,
        auth_cookie_template: &CookieTemplate,
        refresh_cookie_template: &CookieTemplate,
        auth_token: &str,
        refresh_token: &str,
    ) -> bool {
        let auth_cookie = auth_cookie_template.build_with_value(auth_token);
        let refresh_cookie = refresh_cookie_template.build_with_value(refresh_token);

        Self::append_set_cookie(response, auth_cookie)
            && Self::append_set_cookie(response, refresh_cookie)
    }

    #[allow(clippy::unwrap_used)]
    fn unauthorized() -> Response<Body> {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::from("Unauthorized"))
            .unwrap()
    }
}

impl<S, C, R, G, Repo> Service<Request<Body>> for CookieSessionService<S, C, R, G, Repo>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    Account<R, G>: Clone,
    C: Codec<Payload = JwtClaims<Account<R, G>>>
        + AuthTokenIssuer<webgates::sessions::session::Session>
        + Clone
        + Send
        + Sync
        + 'static,
    <C as AuthTokenIssuer<webgates::sessions::session::Session>>::Error: std::fmt::Display,
    R: AccessHierarchy + Eq + std::fmt::Display + Clone + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
    Repo: SessionRepository + Clone + Send + Sync + 'static,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let auth_cookie = self.auth_cookie(&req);
        let refresh_cookie = self.refresh_cookie(&req);

        let Some(auth_cookie) = auth_cookie else {
            let inner = self.inner.call(req);
            return Box::pin(inner);
        };

        let auth_token = auth_cookie.value_trimmed().to_owned();
        let decoded = match self.codec.decode(auth_token.as_bytes()) {
            Ok(claims) => claims,
            Err(_) => return Box::pin(async move { Ok(Self::unauthorized()) }),
        };

        let now = SystemTime::now();
        let auth_token_state = self.auth_token_state(&decoded.registered_claims, now);

        let requirement = match auth_token_state {
            AuthTokenState::Valid { .. } => {
                let inner = self.inner.call(req);
                return Box::pin(inner);
            }
            AuthTokenState::NearExpiry { .. } => RenewalRequirement::Proactive,
            AuthTokenState::Expired { .. } => RenewalRequirement::Required,
            AuthTokenState::Invalid => return Box::pin(async move { Ok(Self::unauthorized()) }),
        };

        let Some(refresh_cookie) = refresh_cookie else {
            if matches!(requirement, RenewalRequirement::Required) {
                return Box::pin(async move { Ok(Self::unauthorized()) });
            }
            let inner = self.inner.call(req);
            return Box::pin(inner);
        };

        let refresh_token =
            match RefreshTokenPlaintext::new(refresh_cookie.value_trimmed().to_owned()) {
                Ok(token) => token,
                Err(_) => {
                    if matches!(requirement, RenewalRequirement::Required) {
                        return Box::pin(async move { Ok(Self::unauthorized()) });
                    }
                    let inner = self.inner.call(req);
                    return Box::pin(inner);
                }
            };

        let token_pair_issuer = TokenPairIssuer::new(
            self.codec.as_ref().clone(),
            OpaqueRefreshTokenGenerator::default(),
            Sha256RefreshTokenHasher,
        );

        let renewer = match SessionRenewer::new(
            self.session_config.clone(),
            self.session_repository.clone(),
            token_pair_issuer,
        ) {
            Ok(renewer) => renewer,
            Err(_) => {
                if matches!(requirement, RenewalRequirement::Required) {
                    return Box::pin(async move { Ok(Self::unauthorized()) });
                }
                let inner = self.inner.call(req);
                return Box::pin(inner);
            }
        };

        // Clone the inner service so ownership can be moved into the async
        // future below. This avoids blocking the executor thread with a nested
        // synchronous runtime (which would deadlock or panic under Tokio).
        let mut inner = self.inner.clone();
        let auth_cookie_template = self.auth_cookie_template.clone();
        let refresh_cookie_template = self.refresh_cookie_template.clone();

        Box::pin(async move {
            let renewal_outcome = match renewer
                .renew_session(auth_token_state, requirement, &refresh_token, now)
                .await
            {
                Ok(outcome) => outcome,
                Err(_) => {
                    if matches!(requirement, RenewalRequirement::Required) {
                        return Ok(Self::unauthorized());
                    }
                    return inner.call(req).await;
                }
            };

            match renewal_outcome {
                RenewalOutcome::Renewed { tokens, .. } => {
                    Self::rewrite_request_auth_cookie(
                        &mut req,
                        &auth_cookie_template,
                        tokens.auth_token.as_str(),
                    );

                    let auth_token = tokens.auth_token.into_inner();
                    let refresh_token = tokens.refresh_token.into_inner();
                    let mut response = inner.call(req).await?;
                    let _ = Self::apply_renewal_cookies(
                        &mut response,
                        &auth_cookie_template,
                        &refresh_cookie_template,
                        &auth_token,
                        &refresh_token,
                    );
                    Ok(response)
                }
                RenewalOutcome::NotNeeded | RenewalOutcome::LeaseUnavailable { .. } => {
                    inner.call(req).await
                }
                RenewalOutcome::Rejected | RenewalOutcome::ReplayDetected { .. } => {
                    if matches!(requirement, RenewalRequirement::Required) {
                        Ok(Self::unauthorized())
                    } else {
                        inner.call(req).await
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    use webgates::codecs::jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER as JWT_CRYPTO_PROVIDER;
    use webgates::groups::Group;
    use webgates::roles::Role;
    use webgates::sessions::lease::{LeaseAcquisition, LeaseId, LeaseTtl, RenewalLease};
    use webgates::sessions::repository::{
        CreateSession, RepositoryResult, RevokeSessionScope, RotateRefreshToken,
        RotateRefreshTokenOutcome,
    };
    use webgates::sessions::session::{
        Session, SessionFamilyId, SessionFamilyRecord, SessionLookup, SessionRecord,
        SessionRefreshRecord, SessionTouch,
    };
    use webgates::sessions::tokens::{AuthToken, RefreshTokenHashRef};
    use webgates_codecs::jwt::{JsonWebToken, JsonWebTokenOptions};

    #[derive(Clone)]
    struct RecordingSessionRepository {
        state: Arc<Mutex<RepositoryState>>,
    }

    struct RepositoryState {
        lookup: Option<SessionLookup>,
        lease_result: Option<LeaseAcquisition>,
        rotate_outcome: RotateRefreshTokenOutcome,
        revoke_family_calls: usize,
    }

    impl Default for RepositoryState {
        fn default() -> Self {
            Self {
                lookup: None,
                lease_result: None,
                rotate_outcome: RotateRefreshTokenOutcome::Rotated,
                revoke_family_calls: 0,
            }
        }
    }

    impl Default for RecordingSessionRepository {
        fn default() -> Self {
            Self {
                state: Arc::new(Mutex::new(RepositoryState {
                    lookup: None,
                    lease_result: None,
                    rotate_outcome: RotateRefreshTokenOutcome::Rotated,
                    revoke_family_calls: 0,
                })),
            }
        }
    }

    impl SessionRepository for RecordingSessionRepository {
        async fn create_session(&self, _input: CreateSession) -> RepositoryResult<()> {
            Ok(())
        }

        async fn find_session_by_refresh_token_hash<'a>(
            &'a self,
            _refresh_token_hash: RefreshTokenHashRef<'a>,
        ) -> RepositoryResult<Option<SessionLookup>> {
            match self.state.lock() {
                Ok(state) => Ok(state.lookup.clone()),
                Err(error) => panic!("repository state lock should not be poisoned: {}", error),
            }
        }

        async fn find_session(
            &self,
            _session_id: webgates::sessions::session::SessionId,
        ) -> RepositoryResult<Option<SessionRecord>> {
            Ok(None)
        }

        async fn find_family(
            &self,
            _family_id: SessionFamilyId,
        ) -> RepositoryResult<Option<SessionFamilyRecord>> {
            Ok(None)
        }

        async fn find_refresh_record(
            &self,
            _session_id: webgates::sessions::session::SessionId,
        ) -> RepositoryResult<Option<SessionRefreshRecord>> {
            Ok(None)
        }

        async fn try_acquire_renewal_lease(
            &self,
            _session_id: webgates::sessions::session::SessionId,
            lease: RenewalLease,
        ) -> RepositoryResult<LeaseAcquisition> {
            match self.state.lock() {
                Ok(state) => Ok(state
                    .lease_result
                    .unwrap_or(LeaseAcquisition::Acquired(lease))),
                Err(error) => panic!("repository state lock should not be poisoned: {}", error),
            }
        }

        async fn rotate_refresh_token(
            &self,
            _input: RotateRefreshToken,
        ) -> RepositoryResult<RotateRefreshTokenOutcome> {
            match self.state.lock() {
                Ok(state) => Ok(state.rotate_outcome),
                Err(error) => panic!("repository state lock should not be poisoned: {}", error),
            }
        }

        async fn revoke_session(
            &self,
            _session_id: webgates::sessions::session::SessionId,
            _scope: RevokeSessionScope,
        ) -> RepositoryResult<()> {
            Ok(())
        }

        async fn revoke_family(&self, _family_id: SessionFamilyId) -> RepositoryResult<()> {
            match self.state.lock() {
                Ok(mut state) => {
                    state.revoke_family_calls += 1;
                    Ok(())
                }
                Err(error) => panic!("repository state lock should not be poisoned: {}", error),
            }
        }

        async fn touch_session(&self, _touch: SessionTouch) -> RepositoryResult<()> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct SessionCodec {
        jwt: JsonWebToken<JwtClaims<Account<Role, Group>>>,
    }

    impl SessionCodec {
        fn new() -> Self {
            Self {
                jwt: JsonWebToken::new_with_options(JsonWebTokenOptions::default()),
            }
        }
    }

    impl Codec for SessionCodec {
        type Payload = JwtClaims<Account<Role, Group>>;

        fn encode(&self, payload: &Self::Payload) -> webgates::codecs::Result<Vec<u8>> {
            self.jwt.encode(payload)
        }

        fn decode(&self, encoded_value: &[u8]) -> webgates::codecs::Result<Self::Payload> {
            self.jwt.decode(encoded_value)
        }
    }

    impl AuthTokenIssuer<webgates::sessions::session::Session> for SessionCodec {
        type Error = webgates::sessions::errors::TokenError;

        fn issue_auth_token(
            &self,
            session: &webgates::sessions::session::Session,
        ) -> impl std::future::Future<Output = Result<AuthToken, Self::Error>> + Send {
            let mut account = Account::new(&session.subject_id);
            account.groups = vec![Group::new("staff")];
            let claims = JwtClaims::new(
                account,
                RegisteredClaims::new(
                    "issuer",
                    unix_seconds(SystemTime::now() + Duration::from_secs(900)),
                ),
            );
            let result = self
                .jwt
                .encode(&claims)
                .map_err(|_| webgates::sessions::errors::TokenError::AuthIssuanceFailed)
                .and_then(|encoded| {
                    String::from_utf8(encoded)
                        .map_err(|_| webgates::sessions::errors::TokenError::AuthIssuanceFailed)
                })
                .and_then(AuthToken::new);

            std::future::ready(result)
        }
    }

    fn unix_seconds(time: SystemTime) -> u64 {
        match time.duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(error) => panic!("system time should be after UNIX_EPOCH: {}", error),
        }
    }

    fn install_jwt_crypto_provider() {
        let _ = JWT_CRYPTO_PROVIDER.install_default();
    }

    fn auth_cookie_template() -> CookieTemplate {
        CookieTemplate::recommended().name("auth-token")
    }

    fn refresh_cookie_template() -> CookieTemplate {
        CookieTemplate::recommended().name("refresh-token")
    }

    fn request_with_cookies(
        auth_value: Option<&str>,
        refresh_value: Option<&str>,
    ) -> Request<Body> {
        let mut cookies = Vec::new();

        if let Some(auth_value) = auth_value {
            cookies.push(format!("auth-token={auth_value}"));
        }
        if let Some(refresh_value) = refresh_value {
            cookies.push(format!("refresh-token={refresh_value}"));
        }

        let mut builder = Request::builder().uri("/protected");
        if !cookies.is_empty() {
            builder = builder.header(http::header::COOKIE, cookies.join("; "));
        }

        match builder.body(Body::empty()) {
            Ok(request) => request,
            Err(error) => panic!("request construction should succeed: {}", error),
        }
    }

    fn sample_lookup(now: SystemTime) -> SessionLookup {
        let session = Session::new(
            SessionFamilyId::new(),
            "user@example.com",
            now - Duration::from_secs(60),
            now + Duration::from_secs(3600),
        );
        let family = SessionFamilyRecord::new(
            session.family_id,
            session.subject_id.clone(),
            now - Duration::from_secs(60),
        );
        let refresh = SessionRefreshRecord::new(
            session.session_id,
            session.family_id,
            now + Duration::from_secs(3600),
        );

        SessionLookup::new(session, family, refresh)
    }

    fn make_auth_token(codec: &SessionCodec, expiration_time: u64) -> String {
        let mut account = Account::new("user@example.com");
        account.groups = vec![Group::new("staff")];
        let claims = JwtClaims::new(account, RegisteredClaims::new("issuer", expiration_time));
        let encoded = match codec.encode(&claims) {
            Ok(encoded) => encoded,
            Err(error) => panic!("auth token encoding should succeed: {}", error),
        };
        match String::from_utf8(encoded) {
            Ok(token) => token,
            Err(error) => panic!("auth token should be valid UTF-8: {}", error),
        }
    }

    #[tokio::test]
    async fn valid_token_outside_window_passes_through_without_set_cookie() {
        install_jwt_crypto_provider();
        let codec = Arc::new(SessionCodec::new());
        let repository = RecordingSessionRepository::default();
        let service = CookieSessionService::<_, _, Role, Group, _>::new(
            tower::service_fn(|_req| async {
                Ok::<_, Infallible>(
                    match Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::empty())
                    {
                        Ok(response) => response,
                        Err(error) => panic!("response construction should succeed: {}", error),
                    },
                )
            }),
            Arc::clone(&codec),
            repository,
            SessionConfig::default(),
            auth_cookie_template(),
            refresh_cookie_template(),
        );

        let auth_token = make_auth_token(
            &codec,
            unix_seconds(SystemTime::now() + Duration::from_secs(900)),
        );
        let response = service
            .oneshot(request_with_cookies(
                Some(&auth_token),
                Some("refresh-token"),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key(SET_COOKIE));
    }

    #[tokio::test]
    async fn near_expiry_token_renews_and_sets_response_cookies() {
        install_jwt_crypto_provider();
        let codec = Arc::new(SessionCodec::new());
        let repository = RecordingSessionRepository::default();
        {
            let mut state = match repository.state.lock() {
                Ok(state) => state,
                Err(error) => panic!("repository state lock should not be poisoned: {}", error),
            };
            let now = SystemTime::now();
            state.lookup = Some(sample_lookup(now));
            let session_id = match state.lookup.as_ref() {
                Some(lookup) => lookup.session.session_id,
                None => panic!("sample lookup should be present"),
            };
            state.lease_result = Some(LeaseAcquisition::Acquired(RenewalLease::from_ttl(
                session_id,
                LeaseId::new(),
                now,
                LeaseTtl::new(Duration::from_secs(30)),
            )));
            state.rotate_outcome = RotateRefreshTokenOutcome::Rotated;
        }

        let service = CookieSessionService::<_, _, Role, Group, _>::new(
            tower::service_fn(|req: Request<Body>| async move {
                let cookie_header = req
                    .headers()
                    .get(http::header::COOKIE)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_string();

                Ok::<_, Infallible>(
                    match Response::builder()
                        .status(StatusCode::OK)
                        .header("x-cookie-seen", cookie_header)
                        .body(Body::empty())
                    {
                        Ok(response) => response,
                        Err(error) => panic!("response construction should succeed: {}", error),
                    },
                )
            }),
            Arc::clone(&codec),
            repository,
            SessionConfig::default(),
            auth_cookie_template(),
            refresh_cookie_template(),
        );

        let auth_token = make_auth_token(
            &codec,
            unix_seconds(SystemTime::now() + Duration::from_secs(30)),
        );
        let response = service
            .oneshot(request_with_cookies(
                Some(&auth_token),
                Some("refresh-token"),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get_all(SET_COOKIE).iter().count() >= 2);
        let seen_cookie = response
            .headers()
            .get("x-cookie-seen")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert!(seen_cookie.contains("auth-token="));
    }

    #[tokio::test]
    async fn expired_token_requires_successful_renewal() {
        install_jwt_crypto_provider();
        let codec = Arc::new(SessionCodec::new());
        let repository = RecordingSessionRepository::default();
        {
            let mut state = match repository.state.lock() {
                Ok(state) => state,
                Err(error) => panic!("repository state lock should not be poisoned: {}", error),
            };
            state.lookup = None;
            state.rotate_outcome = RotateRefreshTokenOutcome::SessionMissing;
        }

        let service = CookieSessionService::<_, _, Role, Group, _>::new(
            tower::service_fn(|_req| async {
                Ok::<_, Infallible>(
                    match Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::empty())
                    {
                        Ok(response) => response,
                        Err(error) => panic!("response construction should succeed: {}", error),
                    },
                )
            }),
            Arc::clone(&codec),
            repository,
            SessionConfig::default(),
            auth_cookie_template(),
            refresh_cookie_template(),
        );

        let auth_token = make_auth_token(
            &codec,
            unix_seconds(SystemTime::now() - Duration::from_secs(1)),
        );
        let response = service
            .oneshot(request_with_cookies(
                Some(&auth_token),
                Some("refresh-token"),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn invalid_auth_token_is_rejected_without_renewal_attempt() {
        install_jwt_crypto_provider();
        let codec = Arc::new(SessionCodec::new());
        let repository = RecordingSessionRepository::default();

        let service = CookieSessionService::<_, _, Role, Group, _>::new(
            tower::service_fn(|_req| async {
                Ok::<_, Infallible>(
                    match Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::empty())
                    {
                        Ok(response) => response,
                        Err(error) => panic!("response construction should succeed: {}", error),
                    },
                )
            }),
            codec,
            repository,
            SessionConfig::default(),
            auth_cookie_template(),
            refresh_cookie_template(),
        );

        let response = service
            .oneshot(request_with_cookies(
                Some("not-a-jwt"),
                Some("refresh-token"),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn lease_unavailable_for_near_expiry_token_passes_through_without_cookie_updates() {
        install_jwt_crypto_provider();
        let codec = Arc::new(SessionCodec::new());
        let repository = RecordingSessionRepository::default();
        let now = SystemTime::now();

        {
            let mut state = match repository.state.lock() {
                Ok(state) => state,
                Err(error) => panic!("repository state lock should not be poisoned: {}", error),
            };
            state.lookup = Some(sample_lookup(now));
            let session_id = match state.lookup.as_ref() {
                Some(lookup) => lookup.session.session_id,
                None => panic!("sample lookup should be present"),
            };
            let active_lease = RenewalLease::from_ttl(
                session_id,
                LeaseId::new(),
                now,
                LeaseTtl::new(Duration::from_secs(30)),
            );
            state.lease_result = Some(LeaseAcquisition::HeldByOther { active_lease });
        }

        let service = CookieSessionService::<_, _, Role, Group, _>::new(
            tower::service_fn(|req: Request<Body>| async move {
                let cookie_header = req
                    .headers()
                    .get(http::header::COOKIE)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_string();

                Ok::<_, Infallible>(
                    match Response::builder()
                        .status(StatusCode::OK)
                        .header("x-cookie-seen", cookie_header)
                        .body(Body::empty())
                    {
                        Ok(response) => response,
                        Err(error) => panic!("response construction should succeed: {}", error),
                    },
                )
            }),
            Arc::clone(&codec),
            repository,
            SessionConfig::default(),
            auth_cookie_template(),
            refresh_cookie_template(),
        );

        let auth_token = make_auth_token(
            &codec,
            unix_seconds(SystemTime::now() + Duration::from_secs(30)),
        );
        let response = service
            .oneshot(request_with_cookies(
                Some(&auth_token),
                Some("refresh-token"),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key(SET_COOKIE));
        let seen_cookie = response
            .headers()
            .get("x-cookie-seen")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert!(seen_cookie.contains(&format!("auth-token={auth_token}")));
    }

    #[tokio::test]
    async fn replay_detected_for_expired_token_is_rejected_and_revokes_family() {
        install_jwt_crypto_provider();
        let codec = Arc::new(SessionCodec::new());
        let repository = RecordingSessionRepository::default();
        let now = SystemTime::now();

        {
            let mut state = match repository.state.lock() {
                Ok(state) => state,
                Err(error) => panic!("repository state lock should not be poisoned: {}", error),
            };
            state.lookup = Some(sample_lookup(now));
            let session_id = match state.lookup.as_ref() {
                Some(lookup) => lookup.session.session_id,
                None => panic!("sample lookup should be present"),
            };
            state.lease_result = Some(LeaseAcquisition::Acquired(RenewalLease::from_ttl(
                session_id,
                LeaseId::new(),
                now,
                LeaseTtl::new(Duration::from_secs(30)),
            )));
            state.rotate_outcome = RotateRefreshTokenOutcome::RefreshTokenMismatch;
        }

        let service = CookieSessionService::<_, _, Role, Group, _>::new(
            tower::service_fn(|_req| async {
                Ok::<_, Infallible>(
                    match Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::empty())
                    {
                        Ok(response) => response,
                        Err(error) => panic!("response construction should succeed: {}", error),
                    },
                )
            }),
            Arc::clone(&codec),
            repository.clone(),
            SessionConfig::default(),
            auth_cookie_template(),
            refresh_cookie_template(),
        );

        let auth_token = make_auth_token(
            &codec,
            unix_seconds(SystemTime::now() - Duration::from_secs(1)),
        );
        let response = service
            .oneshot(request_with_cookies(
                Some(&auth_token),
                Some("refresh-token"),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let state = match repository.state.lock() {
            Ok(state) => state,
            Err(error) => panic!("repository state lock should not be poisoned: {}", error),
        };
        assert_eq!(state.revoke_family_calls, 1);
    }

    #[tokio::test]
    async fn replay_detected_for_near_expiry_token_passes_through_without_cookie_updates() {
        install_jwt_crypto_provider();
        let codec = Arc::new(SessionCodec::new());
        let repository = RecordingSessionRepository::default();
        let now = SystemTime::now();

        {
            let mut state = match repository.state.lock() {
                Ok(state) => state,
                Err(error) => panic!("repository state lock should not be poisoned: {}", error),
            };
            state.lookup = Some(sample_lookup(now));
            let session_id = match state.lookup.as_ref() {
                Some(lookup) => lookup.session.session_id,
                None => panic!("sample lookup should be present"),
            };
            state.lease_result = Some(LeaseAcquisition::Acquired(RenewalLease::from_ttl(
                session_id,
                LeaseId::new(),
                now,
                LeaseTtl::new(Duration::from_secs(30)),
            )));
            state.rotate_outcome = RotateRefreshTokenOutcome::RefreshTokenMismatch;
        }

        let service = CookieSessionService::<_, _, Role, Group, _>::new(
            tower::service_fn(|req: Request<Body>| async move {
                let cookie_header = req
                    .headers()
                    .get(http::header::COOKIE)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_string();

                Ok::<_, Infallible>(
                    match Response::builder()
                        .status(StatusCode::OK)
                        .header("x-cookie-seen", cookie_header)
                        .body(Body::empty())
                    {
                        Ok(response) => response,
                        Err(error) => panic!("response construction should succeed: {}", error),
                    },
                )
            }),
            Arc::clone(&codec),
            repository.clone(),
            SessionConfig::default(),
            auth_cookie_template(),
            refresh_cookie_template(),
        );

        let auth_token = make_auth_token(
            &codec,
            unix_seconds(SystemTime::now() + Duration::from_secs(30)),
        );
        let response = service
            .oneshot(request_with_cookies(
                Some(&auth_token),
                Some("refresh-token"),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key(SET_COOKIE));
        let seen_cookie = response
            .headers()
            .get("x-cookie-seen")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert!(seen_cookie.contains(&format!("auth-token={auth_token}")));
        let state = match repository.state.lock() {
            Ok(state) => state,
            Err(error) => panic!("repository state lock should not be poisoned: {}", error),
        };
        assert_eq!(state.revoke_family_calls, 1);
    }

    /// Verifies that cookies unrelated to the auth token (e.g., CSRF tokens,
    /// feature flags) are still present on the request received by the inner
    /// handler after a near-expiry renewal rewrites the auth cookie.
    ///
    /// Previously `rewrite_request_auth_cookie` used `HeaderMap::insert` which
    /// replaced the entire Cookie header, silently dropping every other cookie.
    #[tokio::test]
    async fn non_auth_cookies_survive_renewal_cookie_rewrite() {
        install_jwt_crypto_provider();
        let codec = Arc::new(SessionCodec::new());
        let repository = RecordingSessionRepository::default();
        let now = SystemTime::now();

        {
            let mut state = match repository.state.lock() {
                Ok(state) => state,
                Err(error) => panic!("repository state lock should not be poisoned: {}", error),
            };
            state.lookup = Some(sample_lookup(now));
            let session_id = match state.lookup.as_ref() {
                Some(lookup) => lookup.session.session_id,
                None => panic!("sample lookup should be present"),
            };
            state.lease_result = Some(LeaseAcquisition::Acquired(RenewalLease::from_ttl(
                session_id,
                LeaseId::new(),
                now,
                LeaseTtl::new(Duration::from_secs(30)),
            )));
            state.rotate_outcome = RotateRefreshTokenOutcome::Rotated;
        }

        let service = CookieSessionService::<_, _, Role, Group, _>::new(
            tower::service_fn(|req: Request<Body>| async move {
                // Echo the raw Cookie header back so the test can inspect it.
                let cookie_header = req
                    .headers()
                    .get(http::header::COOKIE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();

                Ok::<_, Infallible>(
                    match Response::builder()
                        .status(StatusCode::OK)
                        .header("x-cookie-seen", cookie_header)
                        .body(Body::empty())
                    {
                        Ok(response) => response,
                        Err(error) => panic!("response construction should succeed: {}", error),
                    },
                )
            }),
            Arc::clone(&codec),
            repository,
            SessionConfig::default(),
            auth_cookie_template(),
            refresh_cookie_template(),
        );

        // Near-expiry auth token so the service triggers renewal.
        let auth_token = make_auth_token(
            &codec,
            unix_seconds(SystemTime::now() + Duration::from_secs(30)),
        );

        // Request carries an auth cookie, a refresh cookie, AND an extra csrf-token.
        let req = match Request::builder()
            .uri("/protected")
            .header(
                http::header::COOKIE,
                format!(
                    "auth-token={}; csrf-token=abc123; refresh-token=r1",
                    auth_token
                ),
            )
            .body(Body::empty())
        {
            Ok(req) => req,
            Err(error) => panic!("request construction should succeed: {}", error),
        };

        let response = service.oneshot(req).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let seen_cookie = response
            .headers()
            .get("x-cookie-seen")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();

        // The csrf-token must still be visible to the inner handler.
        assert!(
            seen_cookie.contains("csrf-token=abc123"),
            "csrf-token was dropped from the Cookie header after renewal rewrite; \
             actual Cookie header seen by inner service: {seen_cookie:?}"
        );

        // The auth-token entry must have been updated (new JWT issued on renewal).
        assert!(
            seen_cookie.contains("auth-token="),
            "auth-token cookie missing from rewritten Cookie header: {seen_cookie:?}"
        );
        assert!(
            !seen_cookie.contains(&format!("auth-token={auth_token}")),
            "auth-token was not updated to the renewed token; \
             Cookie header seen by inner service: {seen_cookie:?}"
        );

        // Renewal must have issued Set-Cookie headers on the response.
        assert!(
            response.headers().get_all(SET_COOKIE).iter().count() >= 2,
            "expected at least 2 Set-Cookie headers on a renewed response"
        );
    }
}
