use webgates::accounts::Account;
use webgates::authz::{AccessHierarchy, AccessPolicy};
use webgates::codecs::Codec;
use webgates::codecs::jwt::{JwtClaims, RegisteredClaims};
use webgates::gate::Gate as CoreGate;
use webgates::gate::cookie::{CookieEvaluation, CookieGateRuntime};

use std::convert::Infallible;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::{body::Body, extract::Request, http::Response};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use http::StatusCode;
use tower::Service;
use tracing::{trace, warn};
#[cfg(feature = "audit-logging")]
use webgates::audit;
use webgates::cookie_template::CookieTemplate;

/// Cookie-backed JWT gate service.
///
/// Behavior:
/// - Strict mode (default): validates the JWT from the configured cookie,
///   enforces the configured `AccessPolicy`, and on success inserts
///   `Account<R, G>` and `RegisteredClaims` into request extensions. On failure,
///   responds with 401 Unauthorized.
/// - Optional mode (`allow_anonymous_with_optional_user()` from the builder):
///   never blocks. It inserts only:
///
///   - `Option<Account<R, G>>`
///   - `Option<RegisteredClaims>`
///
///   They are `Some(..)` when a valid JWT cookie is present and `None` otherwise.
///   No concrete types are inserted in this mode. Authorization policy is not
///   evaluated; handlers must enforce any required checks explicitly.
///
/// The cookie name and attributes are derived from the provided `CookieBuilder`.
/// The issuer and JWT validation are configured via the builder that constructs
/// this service.
#[derive(Debug, Clone)]
pub struct CookieGateService<C, R, G, S>
where
    C: Codec<Payload = JwtClaims<Account<R, G>>>,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq + Clone,
{
    /// Downstream service invoked after gate processing.
    inner: S,
    /// Framework-agnostic runtime that performs JWT validation and policy checks.
    runtime: CookieGateRuntime<C, R, G>,
    /// Template defining how the authentication cookie is read and interpreted.
    cookie_template: CookieTemplate,
}

impl<C, R, G, S> CookieGateService<C, R, G, S>
where
    C: Codec<Payload = JwtClaims<Account<R, G>>>,
    R: AccessHierarchy + Eq + std::fmt::Display + Default,
    G: Eq + Clone,
{
    /// Creates a new instance of a cookie gate service (strict mode).
    pub fn new(
        inner: S,
        issuer: &str,
        policy: AccessPolicy<R, G>,
        codec: Arc<C>,
        cookie_template: CookieTemplate,
    ) -> Self {
        let gate = CoreGate::cookie::<C, R, G>(issuer, Arc::clone(&codec))
            .with_policy(policy)
            .with_cookie_template(cookie_template.clone());
        Self {
            inner,
            runtime: gate.runtime(),
            cookie_template,
        }
    }

    /// Creates a new instance in "optional extensions" mode.
    ///
    /// Public for advanced usage; normally constructed by the `Gate` builder when
    /// `with_optional_extensions()` is used.
    pub fn new_with_optional_extensions(
        inner: S,
        issuer: &str,
        codec: Arc<C>,
        cookie_template: CookieTemplate,
    ) -> Self {
        let gate = CoreGate::cookie::<C, R, G>(issuer, Arc::clone(&codec))
            .allow_anonymous_with_optional_user()
            .with_cookie_template(cookie_template.clone());
        Self {
            inner,
            runtime: gate.runtime(),
            cookie_template,
        }
    }
}

impl<C, R, G, S> CookieGateService<C, R, G, S>
where
    C: Codec<Payload = JwtClaims<Account<R, G>>>,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq + Clone,
{
    /// Queries the webgates auth cookie from the request.
    pub fn auth_cookie(&self, req: &Request<Body>) -> Option<Cookie<'_>> {
        let cookie_jar = CookieJar::from_headers(req.headers());
        cookie_jar
            .get(self.cookie_template.cookie_name_ref())
            .cloned()
    }

    /// Used to return the unauthorized response.
    #[allow(clippy::unwrap_used)]
    fn unauthorized() -> Response<Body> {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::from("Unauthorized"))
            .unwrap()
    }
}

impl<C, R, G, S> Service<Request<Body>> for CookieGateService<C, R, G, S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible> + Send + 'static,
    S::Future: Send + 'static,
    Account<R, G>: Clone,
    C: Codec<Payload = JwtClaims<Account<R, G>>>,
    R: AccessHierarchy + Eq + std::fmt::Display + Default + Sync + Send + 'static,
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
        let unauthorized_future = Box::pin(async move { Ok(Self::unauthorized()) });

        #[cfg(feature = "audit-logging")]
        let _audit_request_span =
            audit::request_span(req.method().as_str(), req.uri().path(), None);
        #[cfg(feature = "audit-logging")]
        let _audit_request_enter = _audit_request_span.enter();

        let auth_cookie = self.auth_cookie(&req);
        if let Some(ref cookie) = auth_cookie {
            trace!("webgates cookie: {cookie:#?}");
        } else {
            trace!("webgates: no auth cookie present");
        }
        let token = auth_cookie.as_ref().map(|c| c.value_trimmed().to_owned());
        let eval = self.runtime.evaluate(token.as_deref());

        match eval {
            CookieEvaluation::OptionalAnonymous => {
                req.extensions_mut().insert(Option::<Account<R, G>>::None);
                req.extensions_mut()
                    .insert(Option::<RegisteredClaims>::None);
                let inner = self.inner.call(req);
                Box::pin(inner)
            }
            CookieEvaluation::OptionalAuthorized {
                account,
                registered_claims,
            } => {
                req.extensions_mut().insert(Some(account));
                req.extensions_mut().insert(Some(registered_claims));
                let inner = self.inner.call(req);
                Box::pin(inner)
            }
            CookieEvaluation::Authorized {
                account,
                registered_claims,
            } => {
                #[cfg(feature = "audit-logging")]
                {
                    audit::authorized(&account.account_id, None);
                }
                req.extensions_mut().insert(account);
                req.extensions_mut().insert(registered_claims);
                let inner = self.inner.call(req);
                Box::pin(inner)
            }
            CookieEvaluation::DenyAllPolicy => {
                #[cfg(feature = "audit-logging")]
                {
                    audit::denied(None, "policy_denies_all");
                }
                unauthorized_future
            }
            CookieEvaluation::MissingToken => {
                #[cfg(feature = "audit-logging")]
                {
                    audit::denied(None, "missing_cookie");
                }
                unauthorized_future
            }
            CookieEvaluation::InvalidToken => {
                #[cfg(feature = "audit-logging")]
                {
                    audit::jwt_invalid_token("validation_failed");
                }
                unauthorized_future
            }
            CookieEvaluation::InvalidIssuer { expected, actual } => {
                #[cfg(feature = "audit-logging")]
                {
                    audit::jwt_invalid_issuer(&expected, &actual);
                }
                warn!(
                    "JWT issuer validation failed. Expected: '{}', Actual: '{}'",
                    expected, actual
                );
                unauthorized_future
            }
            CookieEvaluation::PolicyDenied { account_id } => {
                #[cfg(not(feature = "audit-logging"))]
                let _ = account_id;
                #[cfg(feature = "audit-logging")]
                {
                    audit::denied(Some(&account_id), "policy_denied");
                }
                unauthorized_future
            }
        }
    }
}
