//! Bearer gate implementation for tonic services.
//!
//! This module provides the compile-time-typed [`BearerGate`] builder and the
//! tower [`Layer`] implementations that the builder produces. Two compile-time
//! modes are available:
//!
//! - **JWT mode** (`BearerGate<C, R, G, JwtConfig<R, G>>`): validates
//!   `Authorization: Bearer <jwt>` metadata, decodes the token, enforces an
//!   [`AccessPolicy`], and inserts auth context into request extensions.
//!
//! - **Static token mode** (`BearerGate<C, R, G, StaticTokenConfig>`): performs
//!   a constant-time comparison of the bearer token against the configured
//!   secret and inserts a [`StaticTokenAuthorized`] marker into request
//!   extensions.
//!
//! # Mode transitions
//!
//! Start with `Gate::bearer(issuer, codec)` which returns a JWT-mode gate.
//! Call `.with_static_token(token)` to transition to static token mode at
//! compile time. JWT policy methods are not available in static token mode.
//!
//! # Extension types
//!
//! | Mode | Extension inserted |
//! |---|---|
//! | JWT strict | [`JwtAuthContext<R, G>`] |
//! | JWT optional | [`OptionalJwtAuthContext<R, G>`] |
//! | Static strict | [`StaticTokenAuthorized`] (`true`) |
//! | Static optional | [`StaticTokenAuthorized`] (`true` or `false`) |
//!
//! # Usage in a tonic service
//!
//! Wrap your tonic server with the layer produced by this gate:
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use webgates::accounts::Account;
//! use webgates::authz::AccessPolicy;
//! use webgates::roles::Role;
//! use webgates::groups::Group;
//! use webgates_codecs::jwt::{JsonWebToken, JwtClaims};
//! use webgates_tonic::gate::Gate;
//!
//! let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! let layer = Gate::bearer("my-svc", codec)
//!     .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin));
//!
//! // Wrap a tonic server with `.layer(layer)` before adding to a Router.
//! ```

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use http::{Request, Response};
use subtle::ConstantTimeEq as _;
use tonic::Status;
use tonic::body::Body as TonicBody;
use tower::{Layer, Service};
use tracing::warn;

use webgates::accounts::Account;
use webgates::authz::access_hierarchy::AccessHierarchy;
use webgates::authz::access_policy::AccessPolicy;
use webgates::codecs::Codec;
use webgates::codecs::jwt::JwtClaims;

use crate::context::{JwtAuthContext, OptionalJwtAuthContext, StaticTokenAuthorized};
use crate::errors::AuthError;

/// JWT mode configuration (compile-time type parameter for [`BearerGate`]).
///
/// This type is not directly constructible by users; it is produced as the
/// mode parameter by [`Gate::bearer`] and consumed by the builder methods on
/// [`BearerGate`].
#[derive(Clone)]
pub struct JwtConfig<R, G>
where
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq,
{
    policy: AccessPolicy<R, G>,
    optional: bool,
}

impl<R, G> std::fmt::Debug for JwtConfig<R, G>
where
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtConfig")
            .field("optional", &self.optional)
            .finish_non_exhaustive()
    }
}

/// Static token mode configuration (compile-time type parameter for [`BearerGate`]).
///
/// This type is not directly constructible by users; it is produced by
/// [`BearerGate::with_static_token`] as a compile-time mode transition.
#[derive(Clone)]
pub struct StaticTokenConfig {
    token: String,
    optional: bool,
}

impl std::fmt::Debug for StaticTokenConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticTokenConfig")
            .field("token", &"<redacted>")
            .field("optional", &self.optional)
            .finish_non_exhaustive()
    }
}

/// Tonic bearer gate with a compile-time mode parameter.
///
/// Constructed via [`crate::gate::Gate::bearer`]. Use the builder methods to
/// configure the gate before calling `.layer(inner_service)` to produce a
/// tower [`Layer`].
#[derive(Clone)]
pub struct BearerGate<C, R, G, M>
where
    C: Codec,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq,
{
    issuer: String,
    codec: Arc<C>,
    mode: M,
    _phantom: std::marker::PhantomData<(R, G)>,
}

impl<C, R, G> std::fmt::Debug for BearerGate<C, R, G, JwtConfig<R, G>>
where
    C: Codec,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BearerGate")
            .field("issuer", &self.issuer)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl<C, R, G> std::fmt::Debug for BearerGate<C, R, G, StaticTokenConfig>
where
    C: Codec,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BearerGate")
            .field("issuer", &self.issuer)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl<C, R, G> BearerGate<C, R, G, JwtConfig<R, G>>
where
    C: Codec,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq + Clone,
{
    /// Internal constructor used by [`crate::gate::Gate::bearer`].
    pub(crate) fn new_with_codec(issuer: &str, codec: Arc<C>) -> Self {
        Self {
            issuer: issuer.to_owned(),
            codec,
            mode: JwtConfig {
                policy: AccessPolicy::deny_all(),
                optional: false,
            },
            _phantom: std::marker::PhantomData,
        }
    }

    /// Set the access policy (OR semantics between policy requirements).
    pub fn with_policy(mut self, policy: AccessPolicy<R, G>) -> Self {
        self.mode.policy = policy;
        self
    }

    /// Allow any authenticated user (baseline role plus all supervisors).
    ///
    /// Equivalent to `with_policy(AccessPolicy::require_role_or_supervisor(R::default()))`.
    /// Requires `R: Default`.
    pub fn require_login(mut self) -> Self
    where
        R: Default,
    {
        let baseline = R::default();
        self.mode.policy = AccessPolicy::require_role_or_supervisor(baseline);
        self
    }

    /// Allow unauthenticated requests; insert [`OptionalJwtAuthContext`] for every request.
    ///
    /// The gate does not enforce the access policy in optional mode. Handlers
    /// must perform any required authorization checks themselves.
    pub fn allow_anonymous_with_optional_user(mut self) -> Self {
        self.mode.optional = true;
        self
    }

    /// Transition to static token mode at compile time.
    ///
    /// All previously configured JWT policies are dropped in favor of exact
    /// bearer-token matching. The returned gate is in static token mode and
    /// only supports [`allow_anonymous_with_optional_user`](BearerGate::allow_anonymous_with_optional_user).
    pub fn with_static_token(
        self,
        token: impl Into<String>,
    ) -> BearerGate<C, R, G, StaticTokenConfig> {
        BearerGate {
            issuer: self.issuer,
            codec: self.codec,
            mode: StaticTokenConfig {
                token: token.into(),
                optional: false,
            },
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<C, R, G> BearerGate<C, R, G, StaticTokenConfig>
where
    C: Codec,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq + Clone,
{
    /// Allow unauthenticated requests; insert [`StaticTokenAuthorized`] for every request.
    ///
    /// In optional mode the gate always forwards the request. The inserted
    /// [`StaticTokenAuthorized`] marker reports whether the provided token matched.
    pub fn allow_anonymous_with_optional_user(mut self) -> Self {
        self.mode.optional = true;
        self
    }
}

// ===================== LAYER IMPLEMENTATIONS ======================

impl<S, C, R, G> Layer<S> for BearerGate<C, R, G, JwtConfig<R, G>>
where
    C: Codec<Payload = JwtClaims<Account<R, G>>> + Send + Sync + 'static,
    R: AccessHierarchy + Eq + std::fmt::Display + Clone + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    type Service = JwtBearerService<C, R, G, S>;

    fn layer(&self, inner: S) -> Self::Service {
        if self.mode.optional {
            JwtBearerService::new_optional(
                inner,
                &self.issuer,
                self.mode.policy.clone(),
                Arc::clone(&self.codec),
            )
        } else {
            JwtBearerService::new(
                inner,
                &self.issuer,
                self.mode.policy.clone(),
                Arc::clone(&self.codec),
            )
        }
    }
}

impl<S, C, R, G> Layer<S> for BearerGate<C, R, G, StaticTokenConfig>
where
    C: Codec,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq + Clone,
{
    type Service = StaticTokenService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        if self.mode.optional {
            StaticTokenService::new_optional(inner, self.mode.token.clone())
        } else {
            StaticTokenService::new(inner, self.mode.token.clone())
        }
    }
}

// ===================== JWT SERVICE ======================

/// Tower service for JWT bearer authentication and authorization on tonic servers.
///
/// Validates the `authorization` gRPC metadata key, decodes the JWT, enforces
/// the configured [`AccessPolicy`], and inserts typed auth context into request
/// extensions before forwarding the request.
#[derive(Clone)]
pub struct JwtBearerService<C, R, G, S>
where
    C: Codec<Payload = JwtClaims<Account<R, G>>>,
    R: AccessHierarchy + Eq + std::fmt::Display + Clone,
    G: Eq + Clone,
{
    inner: S,
    runtime: webgates::gate::bearer::JwtBearerRuntime<C, R, G>,
}

impl<C, R, G, S> JwtBearerService<C, R, G, S>
where
    C: Codec<Payload = JwtClaims<Account<R, G>>>,
    R: AccessHierarchy + Eq + std::fmt::Display + Clone,
    G: Eq + Clone,
{
    fn new(inner: S, issuer: &str, policy: AccessPolicy<R, G>, codec: Arc<C>) -> Self {
        Self {
            inner,
            runtime: webgates::gate::bearer::JwtBearerRuntime::new(issuer, policy, codec, false),
        }
    }

    fn new_optional(inner: S, issuer: &str, policy: AccessPolicy<R, G>, codec: Arc<C>) -> Self {
        Self {
            inner,
            runtime: webgates::gate::bearer::JwtBearerRuntime::new(issuer, policy, codec, true),
        }
    }

    /// Extract the bearer token from the `authorization` header of an HTTP
    /// request that wraps a tonic gRPC call.
    ///
    /// Returns `Err` if the header is missing or the value is not a valid
    /// ASCII `Bearer <token>` pair.
    fn extract_bearer_token(req: &Request<TonicBody>) -> Result<Option<&str>, AuthError> {
        let Some(value) = req.headers().get(http::header::AUTHORIZATION) else {
            return Ok(None);
        };
        let text: &str = value
            .to_str()
            .map_err(|_| AuthError::MalformedAuthorizationMetadata)?
            .trim();
        let mut parts = text.split_whitespace();
        let scheme = parts
            .next()
            .ok_or(AuthError::MalformedAuthorizationMetadata)?;
        if !scheme.eq_ignore_ascii_case("Bearer") {
            return Err(AuthError::MalformedAuthorizationMetadata);
        }
        let token = parts
            .next()
            .ok_or(AuthError::MalformedAuthorizationMetadata)?;
        Ok(Some(token))
    }
}

impl<C, R, G, S> Service<Request<TonicBody>> for JwtBearerService<C, R, G, S>
where
    S: Service<Request<TonicBody>, Response = Response<TonicBody>, Error = Infallible>
        + Send
        + 'static,
    S::Future: Send + 'static,
    C: Codec<Payload = JwtClaims<Account<R, G>>> + Send + Sync + 'static,
    R: AccessHierarchy + Eq + std::fmt::Display + Clone + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    type Response = Response<TonicBody>;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<TonicBody>) -> Self::Future {
        #[cfg(feature = "audit-logging")]
        use webgates::audit;

        #[cfg(feature = "audit-logging")]
        let _span = audit::request_span(req.method().as_str(), req.uri().path(), None);

        let token_result = Self::extract_bearer_token(&req);

        let token = match token_result {
            Ok(t) => t,
            Err(err) => {
                let status = err.into_status();
                return Box::pin(async move { Ok(status_to_response(status)) });
            }
        };

        let eval = self.runtime.evaluate(token);

        match eval {
            webgates::gate::bearer::BearerEvaluation::JwtOptionalAnonymous => {
                req.extensions_mut()
                    .insert(OptionalJwtAuthContext::<R, G>::anonymous());
                let fut = self.inner.call(req);
                Box::pin(fut)
            }
            webgates::gate::bearer::BearerEvaluation::JwtOptionalAuthorized {
                account,
                registered_claims,
            } => {
                req.extensions_mut()
                    .insert(OptionalJwtAuthContext::<R, G>::authenticated(
                        account,
                        registered_claims,
                    ));
                let fut = self.inner.call(req);
                Box::pin(fut)
            }
            webgates::gate::bearer::BearerEvaluation::JwtDenyAllPolicy => {
                #[cfg(feature = "audit-logging")]
                audit::denied(None, "policy_denies_all");
                let status = AuthError::PolicyDeniesAll.into_status();
                Box::pin(async move { Ok(status_to_response(status)) })
            }
            webgates::gate::bearer::BearerEvaluation::JwtMissingToken => {
                #[cfg(feature = "audit-logging")]
                audit::denied(None, "missing_authorization_header");
                let status = AuthError::MissingAuthorizationMetadata.into_status();
                Box::pin(async move { Ok(status_to_response(status)) })
            }
            webgates::gate::bearer::BearerEvaluation::JwtInvalidToken => {
                #[cfg(feature = "audit-logging")]
                audit::jwt_invalid_token("validation_failed");
                let status = AuthError::InvalidToken.into_status();
                Box::pin(async move { Ok(status_to_response(status)) })
            }
            webgates::gate::bearer::BearerEvaluation::JwtInvalidIssuer { expected, actual } => {
                #[cfg(feature = "audit-logging")]
                audit::jwt_invalid_issuer(&expected, &actual);
                warn!(
                    "JWT issuer mismatch. Expected='{}', Actual='{}'",
                    expected, actual
                );
                let status = AuthError::InvalidIssuer.into_status();
                Box::pin(async move { Ok(status_to_response(status)) })
            }
            webgates::gate::bearer::BearerEvaluation::JwtPolicyDenied { account_id } => {
                #[cfg(not(feature = "audit-logging"))]
                let _ = account_id;
                #[cfg(feature = "audit-logging")]
                audit::denied(Some(&account_id), "policy_denied");
                let status = AuthError::PolicyDenied.into_status();
                Box::pin(async move { Ok(status_to_response(status)) })
            }
            webgates::gate::bearer::BearerEvaluation::JwtAuthorized {
                account,
                registered_claims,
            } => {
                #[cfg(feature = "audit-logging")]
                audit::authorized(&account.account_id, None);
                req.extensions_mut()
                    .insert(JwtAuthContext::new(account, registered_claims));
                let fut = self.inner.call(req);
                Box::pin(fut)
            }
            // Static token evaluation variants are not handled by the JWT service.
            _ => {
                let status = AuthError::Internal.into_status();
                Box::pin(async move { Ok(status_to_response(status)) })
            }
        }
    }
}

// ===================== STATIC TOKEN SERVICE ======================

/// Tower service for static bearer token authorization on tonic servers.
///
/// Performs a constant-time comparison of the `authorization` bearer token
/// against the configured static secret and inserts a [`StaticTokenAuthorized`]
/// marker into request extensions.
#[derive(Clone)]
pub struct StaticTokenService<S> {
    inner: S,
    token: String,
    optional: bool,
}

impl<S> StaticTokenService<S> {
    fn new(inner: S, token: String) -> Self {
        Self {
            inner,
            token,
            optional: false,
        }
    }

    fn new_optional(inner: S, token: String) -> Self {
        Self {
            inner,
            token,
            optional: true,
        }
    }

    /// Extract the bearer token from the HTTP `authorization` header.
    fn extract_bearer_token(req: &Request<TonicBody>) -> Option<&str> {
        let value = req.headers().get(http::header::AUTHORIZATION)?;
        let text: &str = value.to_str().ok()?.trim();
        let mut parts = text.split_whitespace();
        let scheme = parts.next()?;
        if !scheme.eq_ignore_ascii_case("Bearer") {
            return None;
        }
        parts.next()
    }
}

impl<S> Service<Request<TonicBody>> for StaticTokenService<S>
where
    S: Service<Request<TonicBody>, Response = Response<TonicBody>, Error = Infallible>
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<TonicBody>;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<TonicBody>) -> Self::Future {
        #[cfg(feature = "audit-logging")]
        use webgates::audit;

        #[cfg(feature = "audit-logging")]
        let _span = audit::request_span(req.method().as_str(), req.uri().path(), None);

        if self.optional {
            let provided = Self::extract_bearer_token(&req);
            let authorized =
                provided.is_some_and(|t| bool::from(t.as_bytes().ct_eq(self.token.as_bytes())));
            req.extensions_mut()
                .insert(StaticTokenAuthorized::new(authorized));
            let fut = self.inner.call(req);
            return Box::pin(fut);
        }

        // Strict mode: require matching bearer token.
        let Some(provided) = Self::extract_bearer_token(&req) else {
            #[cfg(feature = "audit-logging")]
            audit::denied(None, "missing_authorization_header");
            let status = AuthError::MissingAuthorizationMetadata.into_status();
            return Box::pin(async move { Ok(status_to_response(status)) });
        };

        if !bool::from(provided.as_bytes().ct_eq(self.token.as_bytes())) {
            #[cfg(feature = "audit-logging")]
            audit::denied(None, "static_token_mismatch");
            let status = AuthError::PolicyDenied.into_status();
            return Box::pin(async move { Ok(status_to_response(status)) });
        }

        req.extensions_mut()
            .insert(StaticTokenAuthorized::new(true));
        let fut = self.inner.call(req);
        Box::pin(fut)
    }
}

/// Convert a [`tonic::Status`] into an HTTP response with a gRPC trailer.
fn status_to_response(status: Status) -> Response<TonicBody> {
    status.into_http::<TonicBody>()
}

// ===================== TESTS ======================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use http::Request;
    use tower::{Layer, ServiceExt};

    use chrono::Utc;
    use webgates::accounts::Account;
    use webgates::authz::access_policy::AccessPolicy;
    use webgates::codecs::Codec as _;
    use webgates::codecs::jwt::{JsonWebToken, JwtClaims, RegisteredClaims};
    use webgates::groups::Group;
    use webgates::roles::Role;

    use super::*;
    use crate::context::{JwtAuthContext, OptionalJwtAuthContext, StaticTokenAuthorized};

    type TestBearerGateJwt = BearerGate<
        JsonWebToken<JwtClaims<Account<Role, Group>>>,
        Role,
        Group,
        JwtConfig<Role, Group>,
    >;

    fn install_jwt_crypto_provider() {
        use webgates::codecs::jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER as JWT_CRYPTO_PROVIDER;
        let _ = JWT_CRYPTO_PROVIDER.install_default();
    }

    fn make_request_no_auth() -> Request<TonicBody> {
        Request::builder()
            .uri("/test.Service/Method")
            .body(TonicBody::empty())
            .expect("request construction should succeed")
    }

    fn make_request_with_bearer(token: &str) -> Request<TonicBody> {
        Request::builder()
            .uri("/test.Service/Method")
            .header(http::header::AUTHORIZATION, format!("Bearer {token}"))
            .body(TonicBody::empty())
            .expect("request construction should succeed")
    }

    fn echo_service() -> impl Service<
        Request<TonicBody>,
        Response = Response<TonicBody>,
        Error = Infallible,
        Future = impl Future<Output = Result<Response<TonicBody>, Infallible>> + Send + 'static,
    > + Clone {
        tower::service_fn(|_req: Request<TonicBody>| async {
            Ok::<_, Infallible>(Response::new(TonicBody::empty()))
        })
    }

    /// JWT gate denies when no authorization header is present.
    #[tokio::test]
    async fn strict_jwt_missing_token() {
        install_jwt_crypto_provider();
        let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let gate: TestBearerGateJwt = BearerGate::new_with_codec("issuer", codec)
            .with_policy(AccessPolicy::require_role(Role::Admin));

        let svc = gate.layer(echo_service());
        let resp = svc.oneshot(make_request_no_auth()).await.expect("no error");
        assert_eq!(
            resp.status(),
            http::StatusCode::OK,
            "tonic uses 200 for gRPC status errors"
        );
        // gRPC status is conveyed in the grpc-status trailer.
        let trailers = resp
            .headers()
            .get("grpc-status")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok());
        // UNAUTHENTICATED = 16
        assert_eq!(trailers, Some(16), "expected UNAUTHENTICATED grpc-status");
    }

    /// JWT gate denies with a malformed (non-Bearer) authorization header.
    #[tokio::test]
    async fn strict_jwt_malformed_token() {
        install_jwt_crypto_provider();
        let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let gate: TestBearerGateJwt = BearerGate::new_with_codec("issuer", codec)
            .with_policy(AccessPolicy::require_role(Role::Admin));

        let svc = gate.layer(echo_service());
        let req = Request::builder()
            .uri("/test.Service/Method")
            .header(http::header::AUTHORIZATION, "Basic dXNlcjpwYXNz")
            .body(TonicBody::empty())
            .expect("request construction should succeed");
        let resp = svc.oneshot(req).await.expect("no error");
        let trailers = resp
            .headers()
            .get("grpc-status")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok());
        // UNAUTHENTICATED = 16
        assert_eq!(trailers, Some(16));
    }

    /// JWT gate denies when the deny-all policy is configured.
    #[tokio::test]
    async fn strict_jwt_deny_all_policy() {
        install_jwt_crypto_provider();
        let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        // No policy set — defaults to deny_all.
        let gate: TestBearerGateJwt = BearerGate::new_with_codec("issuer", codec);

        let svc = gate.layer(echo_service());
        let resp = svc
            .oneshot(make_request_with_bearer("any-token"))
            .await
            .expect("no error");
        let trailers = resp
            .headers()
            .get("grpc-status")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok());
        // UNAUTHENTICATED = 16
        assert_eq!(trailers, Some(16));
    }

    /// JWT gate authorizes when a valid token is presented.
    #[tokio::test]
    async fn strict_jwt_authorized() {
        install_jwt_crypto_provider();
        let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let account = Account::<Role, Group>::new("user");
        let exp = Utc::now().timestamp() as u64 + 60;
        let claims = JwtClaims::new(account.clone(), RegisteredClaims::new("issuer", exp));
        let encoded = codec.encode(&claims).expect("encode jwt");
        let token = String::from_utf8(encoded).expect("utf-8");

        let gate: TestBearerGateJwt =
            BearerGate::new_with_codec("issuer", Arc::clone(&codec)).require_login();

        let svc = gate.layer(tower::service_fn(move |req: Request<TonicBody>| {
            let ctx = req
                .extensions()
                .get::<JwtAuthContext<Role, Group>>()
                .cloned();
            async move {
                // Context must be present on success.
                assert!(ctx.is_some(), "JwtAuthContext must be inserted on success");
                Ok::<_, Infallible>(Response::new(TonicBody::empty()))
            }
        }));

        let resp = svc
            .oneshot(make_request_with_bearer(&token))
            .await
            .expect("no error");
        // Successful path: inner service returns 200 with grpc-status 0.
        let trailers = resp
            .headers()
            .get("grpc-status")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok());
        // OK = 0 (or not set when inner service returns a plain 200 body)
        assert!(trailers.is_none() || trailers == Some(0));
    }

    /// Optional JWT gate inserts anonymous context when no token is present.
    #[tokio::test]
    async fn optional_jwt_no_token() {
        install_jwt_crypto_provider();
        let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let gate: TestBearerGateJwt =
            BearerGate::new_with_codec("issuer", codec).allow_anonymous_with_optional_user();

        let svc = gate.layer(tower::service_fn(|req: Request<TonicBody>| async move {
            let ctx = req
                .extensions()
                .get::<OptionalJwtAuthContext<Role, Group>>()
                .cloned();
            assert!(
                ctx.is_some(),
                "OptionalJwtAuthContext must always be inserted"
            );
            assert!(
                !ctx.unwrap().is_authenticated(),
                "must be anonymous when no token"
            );
            Ok::<_, Infallible>(Response::new(TonicBody::empty()))
        }));

        svc.oneshot(make_request_no_auth()).await.expect("no error");
    }

    /// Optional JWT gate inserts authenticated context for a valid token.
    #[tokio::test]
    async fn optional_jwt_with_valid_token() {
        install_jwt_crypto_provider();
        let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let account = Account::<Role, Group>::new("user");
        let exp = Utc::now().timestamp() as u64 + 60;
        let claims = JwtClaims::new(account.clone(), RegisteredClaims::new("issuer", exp));
        let encoded = codec.encode(&claims).expect("encode jwt");
        let token = String::from_utf8(encoded).expect("utf-8");

        let gate: TestBearerGateJwt = BearerGate::new_with_codec("issuer", Arc::clone(&codec))
            .allow_anonymous_with_optional_user();

        let svc = gate.layer(tower::service_fn(
            move |req: Request<TonicBody>| async move {
                let ctx = req
                    .extensions()
                    .get::<OptionalJwtAuthContext<Role, Group>>()
                    .cloned();
                assert!(ctx.is_some(), "OptionalJwtAuthContext must be present");
                assert!(ctx.unwrap().is_authenticated(), "must be authenticated");
                Ok::<_, Infallible>(Response::new(TonicBody::empty()))
            },
        ));

        svc.oneshot(make_request_with_bearer(&token))
            .await
            .expect("no error");
    }

    /// Optional JWT gate inserts anonymous context for an invalid token without blocking the request.
    #[tokio::test]
    async fn optional_jwt_with_invalid_token() {
        install_jwt_crypto_provider();
        let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let gate: TestBearerGateJwt =
            BearerGate::new_with_codec("issuer", codec).allow_anonymous_with_optional_user();

        let svc = gate.layer(tower::service_fn(|req: Request<TonicBody>| async move {
            let ctx = req
                .extensions()
                .get::<OptionalJwtAuthContext<Role, Group>>()
                .cloned();
            assert!(ctx.is_some(), "OptionalJwtAuthContext must be present");
            assert!(
                !ctx.unwrap().is_authenticated(),
                "invalid token must result in anonymous context"
            );
            Ok::<_, Infallible>(Response::new(TonicBody::empty()))
        }));

        svc.oneshot(make_request_with_bearer("invalid-token-value"))
            .await
            .expect("no error");
    }

    /// Strict static token gate rejects a missing bearer token.
    #[tokio::test]
    async fn static_token_strict_missing() {
        install_jwt_crypto_provider();
        let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let gate: BearerGate<_, Role, Group, StaticTokenConfig> =
            BearerGate::new_with_codec("issuer", codec).with_static_token("secret");

        let svc = gate.layer(echo_service());
        let resp = svc.oneshot(make_request_no_auth()).await.expect("no error");
        let trailers = resp
            .headers()
            .get("grpc-status")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok());
        // UNAUTHENTICATED = 16
        assert_eq!(trailers, Some(16));
    }

    /// Strict static token gate rejects a wrong bearer token.
    #[tokio::test]
    async fn static_token_strict_wrong_token() {
        install_jwt_crypto_provider();
        let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let gate: BearerGate<_, Role, Group, StaticTokenConfig> =
            BearerGate::new_with_codec("issuer", codec).with_static_token("correct-secret");

        let svc = gate.layer(echo_service());
        let resp = svc
            .oneshot(make_request_with_bearer("wrong-secret"))
            .await
            .expect("no error");
        let trailers = resp
            .headers()
            .get("grpc-status")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok());
        // PERMISSION_DENIED = 7
        assert_eq!(trailers, Some(7));
    }

    /// Strict static token gate authorizes when the correct token is presented.
    #[tokio::test]
    async fn static_token_strict_success() {
        install_jwt_crypto_provider();
        let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let gate: BearerGate<_, Role, Group, StaticTokenConfig> =
            BearerGate::new_with_codec("issuer", codec).with_static_token("my-secret");

        let svc = gate.layer(tower::service_fn(|req: Request<TonicBody>| async move {
            let auth = req.extensions().get::<StaticTokenAuthorized>().copied();
            assert!(auth.is_some(), "StaticTokenAuthorized must be inserted");
            assert!(auth.unwrap().is_authorized(), "must be authorized");
            Ok::<_, Infallible>(Response::new(TonicBody::empty()))
        }));

        svc.oneshot(make_request_with_bearer("my-secret"))
            .await
            .expect("no error");
    }

    /// Optional static token gate inserts authorized=true when the token matches.
    #[tokio::test]
    async fn static_token_optional_success() {
        install_jwt_crypto_provider();
        let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let gate: BearerGate<_, Role, Group, StaticTokenConfig> =
            BearerGate::new_with_codec("issuer", codec)
                .with_static_token("my-secret")
                .allow_anonymous_with_optional_user();

        let svc = gate.layer(tower::service_fn(|req: Request<TonicBody>| async move {
            let auth = req.extensions().get::<StaticTokenAuthorized>().copied();
            assert!(auth.is_some());
            assert!(auth.unwrap().is_authorized());
            Ok::<_, Infallible>(Response::new(TonicBody::empty()))
        }));

        svc.oneshot(make_request_with_bearer("my-secret"))
            .await
            .expect("no error");
    }

    /// Optional static token gate inserts authorized=false for an unauthenticated request.
    #[tokio::test]
    async fn static_token_optional_anonymous() {
        install_jwt_crypto_provider();
        let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let gate: BearerGate<_, Role, Group, StaticTokenConfig> =
            BearerGate::new_with_codec("issuer", codec)
                .with_static_token("my-secret")
                .allow_anonymous_with_optional_user();

        let svc = gate.layer(tower::service_fn(|req: Request<TonicBody>| async move {
            let auth = req.extensions().get::<StaticTokenAuthorized>().copied();
            assert!(auth.is_some());
            assert!(!auth.unwrap().is_authorized());
            Ok::<_, Infallible>(Response::new(TonicBody::empty()))
        }));

        svc.oneshot(make_request_no_auth()).await.expect("no error");
    }
}
