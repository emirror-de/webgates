//! Bearer gate implementation supporting two compile-time distinct modes:
//! - JWT bearer authentication & authorization (policy-based)
//! - Static bearer token (boolean authorization)
//!
//! Each mode exposes only the relevant builder methods at compile time:
//!
//! JWT Mode (BearerGate<_, _, _, JwtConfig<_, _>>):
//!   - with_policy(...)
//!   - require_login()            (requires R: Default; baseline role + supervisors)
//!   - allow_anonymous_with_optional_user()
//!   - with_static_token(token)   (transitions to static token mode)
//!
//! Static Token Mode (BearerGate<_, _, _, StaticTokenConfig>):
//!   - allow_anonymous_with_optional_user()
//!
//! Optional Mode Semantics:
//!   - JWT optional: always forwards; inserts:
//!       * `Option<Account<R,G>>`
//!       * `Option<RegisteredClaims>`
//!   - Static token optional: always forwards; inserts:
//!       * StaticTokenAuthorized(bool)
//!
//! Strict Mode Semantics:
//!   - JWT strict: validates Authorization: Bearer `<jwt>`, enforces AccessPolicy;
//!     inserts `Account<R,G>` and `RegisteredClaims` on success, 401 otherwise
//!   - Static token strict: requires `Authorization: Bearer <exact_token>`;
//!     inserts `StaticTokenAuthorized(true)` on success, 401 otherwise
//!
//! Example (JWT strict):
//! ```rust,ignore
//! use std::sync::Arc;
//! use axum::Router;
//! use webgates::accounts::Account;
//! use webgates::authz::AccessPolicy;
//! use webgates::groups::Group;
//! use webgates::roles::Role;
//! use webgates_codecs::jwt::{JwtClaims, JsonWebToken};
//! use webgates_axum::gate::Gate;
//! let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//!
//! let router = Router::<()>::new();
//! let gate = Gate::bearer::<JsonWebToken::<JwtClaims<Account<Role, Group>>>, Role, Group>("my-app", codec)
//!     .with_policy(AccessPolicy::require_role(Role::Admin));
//! router.layer(gate);
//! ```
//!
//! Example (JWT optional):
//! ```rust,ignore
//! use std::sync::Arc;
//! use webgates::accounts::Account;
//! use webgates::groups::Group;
//! use webgates::roles::Role;
//! use webgates_codecs::jwt::{JwtClaims, JsonWebToken};
//! use webgates_axum::gate::Gate;
//! let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//!
//! let gate = Gate::bearer::<JsonWebToken::<JwtClaims<Account<Role, Group>>>, Role, Group>("my-app", codec)
//!     .allow_anonymous_with_optional_user(); // Option<Account>, Option<RegisteredClaims>
//! ```
//!
//! Transition to static token mode (compile-time change of available methods):
//! ```rust,ignore
//! use std::sync::Arc;
//! use webgates::accounts::Account;
//! use webgates::groups::Group;
//! use webgates::roles::Role;
//! use webgates_codecs::jwt::{JwtClaims, JsonWebToken};
//! use webgates_axum::gate::Gate;
//! let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//!
//! let gate = Gate::bearer::<JsonWebToken::<JwtClaims<Account<Role, Group>>>, Role, Group>("svc-a", codec)
//!     .with_static_token("internal-static-token"); // now static token mode (no with_policy)
//! ```
//!
//! Static token optional:
//! ```rust,ignore
//! use std::sync::Arc;
//! use webgates::accounts::Account;
//! use webgates::groups::Group;
//! use webgates::roles::Role;
//! use webgates_codecs::jwt::{JwtClaims, JsonWebToken};
//! use webgates_axum::gate::Gate;
//! let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//!
//! let gate = Gate::bearer::<JsonWebToken::<JwtClaims<Account<Role, Group>>>, Role, Group>("svc-a", codec)
//!     .with_static_token("internal-static-token")
//!     .allow_anonymous_with_optional_user(); // installs StaticTokenAuthorized(bool)
//! ```
//!
//! Handler extraction (static token optional):
//! ```rust
//! use webgates::accounts::Account;
//! use webgates::groups::Group;
//! use webgates::roles::Role;
//! use webgates_codecs::jwt::{JwtClaims, JsonWebToken};
//! use webgates_axum::gate::bearer::static_token_authorized::StaticTokenAuthorized;
//!
//! async fn handler(
//!     axum::Extension(token_auth): axum::Extension<StaticTokenAuthorized>
//! ) {
//!     if token_auth.is_authorized() { /* privileged */ } else { /* public */ }
//! }
//! ```

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::{body::Body, extract::Request, http::Response};
use http::StatusCode;
use tower::{Layer, Service};
use tracing::warn;

pub mod static_token_authorized;

use static_token_authorized::StaticTokenAuthorized;
use webgates::accounts::Account;
use webgates::authz::access_hierarchy::AccessHierarchy;
use webgates::authz::access_policy::AccessPolicy;
use webgates::codecs::Codec;
use webgates::codecs::jwt::{JwtClaims, RegisteredClaims};

/// JWT mode configuration (compile-time).
#[derive(Clone)]
pub(crate) struct JwtConfig<R, G>
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

/// Static token mode configuration (compile-time).
#[derive(Clone)]
pub(crate) struct StaticTokenConfig {
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

/// Generic bearer gate with compile-time mode parameter.
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

impl<C, R, G> BearerGate<C, R, G, JwtConfig<R, G>>
where
    C: Codec,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq + Clone,
{
    /// Internal constructor (used by `Gate::bearer`).
    pub(crate) fn new_with_codec(issuer: &str, codec: Arc<C>) -> Self {
        Self {
            issuer: issuer.to_string(),
            codec,
            mode: JwtConfig {
                policy: AccessPolicy::deny_all(),
                optional: false,
            },
            _phantom: std::marker::PhantomData,
        }
    }

    /// Set access policy (OR semantics between requirements).
    pub fn with_policy(mut self, policy: AccessPolicy<R, G>) -> Self {
        self.mode.policy = policy;
        self
    }

    /// Turn on optional mode (install `Option<Account>`, `Option<RegisteredClaims>`).
    pub fn allow_anonymous_with_optional_user(mut self) -> Self {
        self.mode.optional = true;
        self
    }

    /// Configure the gate to allow any authenticated user: the baseline role (least
    /// privileged) from `Default::default()` and all supervisor roles as defined by
    /// your `AccessHierarchy`.
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

    /// Enables Prometheus metrics for audit logging (JWT bearer mode).
    ///
    /// No-op unless both `audit-logging` and `prometheus` features are enabled.
    /// Safe to call multiple times; registration is idempotent.
    #[cfg(feature = "prometheus")]
    pub fn with_prometheus_metrics(self) -> Self {
        let _ = webgates::audit::prometheus_metrics::install_prometheus_metrics();
        self
    }

    /// Installs Prometheus metrics into the provided registry (JWT bearer mode).
    ///
    /// No-op if metrics already installed. Returns `self` for builder chaining.
    #[cfg(feature = "prometheus")]
    pub fn with_prometheus_registry(self, registry: &prometheus::Registry) -> Self {
        let _ =
            webgates::audit::prometheus_metrics::install_prometheus_metrics_with_registry(registry);
        self
    }

    /// Transition to static token mode: policies are discarded.
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

// (require_login specialization for crate::auth::Role/Group temporarily removed to resolve generic issues)

impl<C, R, G> BearerGate<C, R, G, StaticTokenConfig>
where
    C: Codec,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq + Clone,
{
    /// Enable optional mode (install StaticTokenAuthorized(bool)).
    pub fn allow_anonymous_with_optional_user(mut self) -> Self {
        self.mode.optional = true;
        self
    }
}

// ===================== LAYER IMPLEMENTATIONS ======================

impl<S, C, R, G> Layer<S> for BearerGate<C, R, G, JwtConfig<R, G>>
where
    C: Codec<Payload = JwtClaims<Account<R, G>>>,
    R: AccessHierarchy + Eq + std::fmt::Display + Sync + Send + 'static,
    G: Eq + Clone + Sync + Send + 'static,
{
    type Service = JwtBearerService<C, R, G, S>;

    fn layer(&self, inner: S) -> Self::Service {
        if self.mode.optional {
            JwtBearerService::new_optional(
                inner,
                &self.issuer,
                self.mode.policy.clone(), // policy unused in optional mode but cloned for uniform struct
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

#[derive(Clone)]
/// JWT bearer token authentication service.
///
/// This service handles JWT bearer token authentication for protected routes,
/// validating tokens from the `Authorization: Bearer <token>` header.
pub(crate) struct JwtBearerService<C, R, G, S>
where
    C: Codec<Payload = JwtClaims<Account<R, G>>>,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq + Clone,
{
    inner: S,
    runtime: webgates::gate::bearer::JwtBearerRuntime<C, R, G>,
}

impl<C, R, G, S> JwtBearerService<C, R, G, S>
where
    C: Codec<Payload = JwtClaims<Account<R, G>>>,
    R: AccessHierarchy + Eq + std::fmt::Display,
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

    fn unauthorized() -> Response<Body> {
        let mut resp = Response::new(Body::from("Unauthorized"));
        *resp.status_mut() = StatusCode::UNAUTHORIZED;
        resp.headers_mut().insert(
            http::header::WWW_AUTHENTICATE,
            http::HeaderValue::from_static("Bearer"),
        );
        resp
    }

    fn bearer_token(req: &Request<Body>) -> Option<&str> {
        let value = req.headers().get(http::header::AUTHORIZATION)?;
        let value = value.to_str().ok()?.trim();
        let mut parts = value.split_whitespace();
        let scheme = parts.next()?;
        if !scheme.eq_ignore_ascii_case("Bearer") {
            return None;
        }
        parts.next()
    }
}

impl<C, R, G, S> Service<Request<Body>> for JwtBearerService<C, R, G, S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible> + Send + 'static,
    S::Future: Send + 'static,
    Account<R, G>: Clone,
    C: Codec<Payload = JwtClaims<Account<R, G>>>,
    R: AccessHierarchy + Eq + std::fmt::Display + Sync + Send + 'static,
    G: Eq + Clone + Sync + Send + 'static,
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
        #[cfg(feature = "audit-logging")]
        use webgates::audit;

        let unauthorized_future = Box::pin(async move { Ok(Self::unauthorized()) });

        #[cfg(feature = "audit-logging")]
        let _span = audit::request_span(req.method().as_str(), req.uri().path(), None);

        let eval = self.runtime.evaluate(Self::bearer_token(&req));

        match eval {
            webgates::gate::bearer::BearerEvaluation::JwtOptionalAnonymous => {
                req.extensions_mut().insert(Option::<Account<R, G>>::None);
                req.extensions_mut()
                    .insert(Option::<RegisteredClaims>::None);
                let fut = self.inner.call(req);
                Box::pin(fut)
            }
            webgates::gate::bearer::BearerEvaluation::JwtOptionalAuthorized {
                account,
                registered_claims,
            } => {
                req.extensions_mut().insert(Some(account));
                req.extensions_mut().insert(Some(registered_claims));
                let fut = self.inner.call(req);
                Box::pin(fut)
            }
            webgates::gate::bearer::BearerEvaluation::JwtDenyAllPolicy => {
                #[cfg(feature = "audit-logging")]
                audit::denied(None, "policy_denies_all");
                unauthorized_future
            }
            webgates::gate::bearer::BearerEvaluation::JwtMissingToken => {
                #[cfg(feature = "audit-logging")]
                audit::denied(None, "missing_authorization_header");
                unauthorized_future
            }
            webgates::gate::bearer::BearerEvaluation::JwtInvalidToken => {
                #[cfg(feature = "audit-logging")]
                audit::jwt_invalid_token("validation_failed");
                unauthorized_future
            }
            webgates::gate::bearer::BearerEvaluation::JwtInvalidIssuer { expected, actual } => {
                #[cfg(feature = "audit-logging")]
                audit::jwt_invalid_issuer(&expected, &actual);
                warn!("JWT issuer mismatch. Expected='{expected}', Actual='{actual}'");
                unauthorized_future
            }
            webgates::gate::bearer::BearerEvaluation::JwtPolicyDenied { account_id } => {
                #[cfg(not(feature = "audit-logging"))]
                let _ = account_id;
                #[cfg(feature = "audit-logging")]
                audit::denied(Some(&account_id), "policy_denied");
                unauthorized_future
            }
            webgates::gate::bearer::BearerEvaluation::JwtAuthorized {
                account,
                registered_claims,
            } => {
                #[cfg(feature = "audit-logging")]
                audit::authorized(&account.account_id, None);
                req.extensions_mut().insert(account);
                req.extensions_mut().insert(registered_claims);
                let fut = self.inner.call(req);
                Box::pin(fut)
            }
            // Static token evaluation is not handled here; JWT runtime only.
            _ => unauthorized_future,
        }
    }
}

// ===================== STATIC TOKEN SERVICE ======================

#[derive(Clone)]
/// Static bearer token authentication service.
///
/// This service handles authentication using pre-configured static tokens
/// from the `Authorization: Bearer <token>` header.
pub(crate) struct StaticTokenService<S> {
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

    fn unauthorized() -> Response<Body> {
        let mut resp = Response::new(Body::from("Unauthorized"));
        *resp.status_mut() = StatusCode::UNAUTHORIZED;
        resp.headers_mut().insert(
            http::header::WWW_AUTHENTICATE,
            http::HeaderValue::from_static("Bearer"),
        );
        resp
    }

    fn bearer_token(req: &Request<Body>) -> Option<&str> {
        let value = req.headers().get(http::header::AUTHORIZATION)?;
        let value = value.to_str().ok()?.trim();
        let mut parts = value.split_whitespace();
        let scheme = parts.next()?;
        if !scheme.eq_ignore_ascii_case("Bearer") {
            return None;
        }
        parts.next()
    }
}

impl<S> Service<Request<Body>> for StaticTokenService<S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible> + Send + 'static,
    S::Future: Send + 'static,
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
        #[cfg(feature = "audit-logging")]
        use webgates::audit;

        #[cfg(feature = "audit-logging")]
        let _span = audit::request_span(req.method().as_str(), req.uri().path(), None);

        if self.optional {
            let provided = Self::bearer_token(&req);
            let authorized = provided.map(|v| v == self.token).unwrap_or(false);
            req.extensions_mut()
                .insert(StaticTokenAuthorized::new(authorized));
            let fut = self.inner.call(req);
            return Box::pin(fut);
        }

        let Some(provided) = Self::bearer_token(&req) else {
            #[cfg(feature = "audit-logging")]
            audit::denied(None, "missing_authorization_header");
            return Box::pin(async move { Ok(Self::unauthorized()) });
        };

        if provided != self.token {
            #[cfg(feature = "audit-logging")]
            audit::denied(None, "static_token_mismatch");
            return Box::pin(async move { Ok(Self::unauthorized()) });
        }

        // Strict static token success: insert positive indicator
        req.extensions_mut()
            .insert(StaticTokenAuthorized::new(true));

        let fut = self.inner.call(req);
        Box::pin(fut)
    }
}

// ===================== TESTS ======================

#[cfg(test)]
mod tests {
    use super::*;
    use webgates::accounts::Account;
    use webgates::codecs::jwt::{JsonWebToken, JwtClaims};
    use webgates::groups::Group;
    use webgates::roles::Role;

    type BearerGateJsonwebtoken = BearerGate<
        JsonWebToken<JwtClaims<Account<Role, Group>>>,
        Role,
        Group,
        JwtConfig<Role, Group>,
    >;

    #[test]
    fn jwt_gate_initial_deny_all() {
        let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let gate: BearerGateJsonwebtoken = BearerGate::new_with_codec("issuer", codec);
        assert!(gate.mode.policy.denies_all());
        assert!(!gate.mode.optional);
    }

    #[test]
    fn jwt_gate_policy_set() {
        let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let gate =
            BearerGate::new_with_codec("issuer", codec)
                .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin));
        assert!(!gate.mode.policy.denies_all());
    }

    #[test]
    fn transition_to_static_mode() {
        let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let static_gate: BearerGate<_, Role, Group, StaticTokenConfig> =
            BearerGate::new_with_codec("issuer", codec).with_static_token("secret");
        assert_eq!(static_gate.mode.token, "secret");
        assert!(!static_gate.mode.optional);
    }

    #[test]
    fn static_optional_mode() {
        let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let static_gate: BearerGate<_, Role, Group, StaticTokenConfig> =
            BearerGate::new_with_codec("issuer", codec)
                .with_static_token("secret")
                .allow_anonymous_with_optional_user();
        assert!(static_gate.mode.optional);
    }

    #[test]
    fn jwt_unauthorized_has_www_authenticate() {
        tokio_test::block_on(async {
            use axum::{body::Body, extract::Request, http::Response};
            use std::convert::Infallible;
            use tower::ServiceExt;

            let codec =
                std::sync::Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
            let gate: BearerGateJsonwebtoken = BearerGate::new_with_codec("issuer", codec)
                .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin));

            let svc = gate.layer(tower::service_fn(|_req: Request<Body>| async {
                Ok::<_, Infallible>(Response::new(Body::from("ok")))
            }));

            let req = Request::new(Body::empty());
            let resp = svc.oneshot(req).await.unwrap();

            assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
            let hdr = resp
                .headers()
                .get(http::header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok());
            assert_eq!(hdr, Some("Bearer"));
        });
    }

    #[test]
    fn static_token_unauthorized_has_www_authenticate() {
        tokio_test::block_on(async {
            use axum::{body::Body, extract::Request, http::Response};
            use std::convert::Infallible;
            use tower::ServiceExt;

            let codec =
                std::sync::Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
            let gate: BearerGate<_, Role, Group, StaticTokenConfig> =
                BearerGate::new_with_codec("issuer", codec).with_static_token("secret");

            let svc = gate.layer(tower::service_fn(|_req: Request<Body>| async {
                Ok::<_, Infallible>(Response::new(Body::from("ok")))
            }));

            let req = Request::new(Body::empty());
            let resp = svc.oneshot(req).await.unwrap();

            assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
            let hdr = resp
                .headers()
                .get(http::header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok());
            assert_eq!(hdr, Some("Bearer"));
        });
    }
}
