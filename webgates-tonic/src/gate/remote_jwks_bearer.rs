//! Remote JWKS-backed bearer gate for Tonic gRPC consumer services.
//!
//! [`RemoteJwksBearerGate`] wraps a [`RemoteJwksVerifier`] into a tonic-compatible
//! tower [`Layer`] that authenticates gRPC requests via the `Authorization: Bearer`
//! metadata header and enforces an [`AccessPolicy`].
//!
//! # Typical usage
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use webgates::authz::access_policy::AccessPolicy;
//! use webgates::roles::Role;
//! use webgates::groups::Group;
//! use webgates::accounts::Account;
//! use webgates_codecs::jwt::{JwtClaims, remote_verifier::{RemoteJwksVerifier, RemoteJwksVerifierConfig}};
//! use webgates_tonic::gate::remote_jwks_bearer::RemoteJwksBearerGate;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! type AppClaims = JwtClaims<Account<Role, Group>>;
//!
//! let config = RemoteJwksVerifierConfig::from_jwks_url(
//!     "https://auth.example.com/.well-known/jwks.json",
//! );
//! let verifier = Arc::new(RemoteJwksVerifier::<AppClaims>::bootstrap(config).await?);
//! let _refresh = verifier.start_background_refresh();
//!
//! let layer = RemoteJwksBearerGate::new("auth-node", Arc::clone(&verifier))
//!     .with_policy(AccessPolicy::require_role(Role::Admin));
//!
//! // Wrap a tonic server with `.layer(layer)` before adding to a Router.
//! # Ok(())
//! # }
//! ```

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use http::{Request, Response};
use serde::{Serialize, de::DeserializeOwned};
use tonic::Status;
use tonic::body::Body as TonicBody;
use tower::{Layer, Service};

use webgates::accounts::Account;
use webgates::authz::access_hierarchy::AccessHierarchy;
use webgates::authz::access_policy::AccessPolicy;
use webgates::authz::authorization_service::AuthorizationService;
use webgates::codecs::jwt::JwtClaims;
use webgates_codecs::jwt::remote_verifier::RemoteJwksVerifier;

use crate::context::JwtAuthContext;
use crate::errors::AuthError;

/// Tonic layer that authenticates gRPC requests via a remote JWKS-backed bearer token.
#[derive(Clone)]
pub struct RemoteJwksBearerGate<R, G>
where
    R: AccessHierarchy
        + Eq
        + std::fmt::Display
        + Clone
        + Serialize
        + DeserializeOwned
        + Send
        + Sync
        + 'static,
    G: Eq + Clone + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    issuer: String,
    verifier: Arc<RemoteJwksVerifier<JwtClaims<Account<R, G>>>>,
    policy: AccessPolicy<R, G>,
}

impl<R, G> RemoteJwksBearerGate<R, G>
where
    R: AccessHierarchy
        + Eq
        + std::fmt::Display
        + Clone
        + Default
        + Serialize
        + DeserializeOwned
        + Send
        + Sync
        + 'static,
    G: Eq + Clone + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    /// Build a gate from an issuer string and a shared remote JWKS verifier.
    ///
    /// The gate starts with a `deny_all` policy; call [`with_policy`](Self::with_policy)
    /// to configure access rules.
    pub fn new(
        issuer: impl Into<String>,
        verifier: Arc<RemoteJwksVerifier<JwtClaims<Account<R, G>>>>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            verifier,
            policy: AccessPolicy::deny_all(),
        }
    }

    /// Set the access policy.
    #[must_use]
    pub fn with_policy(mut self, policy: AccessPolicy<R, G>) -> Self {
        self.policy = policy;
        self
    }

    /// Allow any authenticated user (baseline role plus all supervisors).
    #[must_use]
    pub fn require_login(mut self) -> Self
    where
        R: Default,
    {
        let baseline = R::default();
        self.policy = AccessPolicy::require_role_or_supervisor(baseline);
        self
    }
}

impl<S, R, G> Layer<S> for RemoteJwksBearerGate<R, G>
where
    R: AccessHierarchy
        + Eq
        + std::fmt::Display
        + Clone
        + Default
        + Serialize
        + DeserializeOwned
        + Send
        + Sync
        + 'static,
    G: Eq + Clone + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    type Service = RemoteJwksBearerService<S, R, G>;

    fn layer(&self, inner: S) -> Self::Service {
        RemoteJwksBearerService {
            inner,
            issuer: self.issuer.clone(),
            verifier: Arc::clone(&self.verifier),
            authorization: AuthorizationService::new(self.policy.clone()),
        }
    }
}

/// Tower service produced by [`RemoteJwksBearerGate`].
#[derive(Clone)]
pub struct RemoteJwksBearerService<S, R, G>
where
    R: AccessHierarchy
        + Eq
        + std::fmt::Display
        + Clone
        + Serialize
        + DeserializeOwned
        + Send
        + Sync
        + 'static,
    G: Eq + Clone + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    inner: S,
    issuer: String,
    verifier: Arc<RemoteJwksVerifier<JwtClaims<Account<R, G>>>>,
    authorization: AuthorizationService<R, G>,
}

impl<S, R, G> Service<Request<TonicBody>> for RemoteJwksBearerService<S, R, G>
where
    S: Service<Request<TonicBody>, Response = Response<TonicBody>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    R: AccessHierarchy
        + Eq
        + std::fmt::Display
        + Clone
        + Serialize
        + DeserializeOwned
        + Send
        + Sync
        + 'static,
    G: Eq + Clone + Serialize + DeserializeOwned + Send + Sync + 'static,
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
        let issuer = self.issuer.clone();
        let verifier = Arc::clone(&self.verifier);
        let authorization = self.authorization.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Extract bearer token from Authorization header.
            let token = match extract_bearer_token(&req) {
                Ok(Some(t)) => t.to_owned(),
                Ok(None) => {
                    let status = AuthError::MissingAuthorizationMetadata.into_status();
                    return Ok(status_to_response(status));
                }
                Err(err) => {
                    let status = err.into_status();
                    return Ok(status_to_response(status));
                }
            };

            // Verify the token against the remote JWKS key set (local, no network I/O).
            let claims = match verifier.verify_token(&token).await {
                Ok(claims) => claims,
                Err(error) => {
                    tracing::warn!(error = %error, "remote JWKS bearer token verification failed");
                    let status = AuthError::InvalidToken.into_status();
                    return Ok(status_to_response(status));
                }
            };

            // Validate issuer.
            if claims.registered_claims.issuer != issuer {
                tracing::warn!(
                    expected = %issuer,
                    actual = %claims.registered_claims.issuer,
                    "JWT issuer mismatch"
                );
                let status = AuthError::InvalidIssuer.into_status();
                return Ok(status_to_response(status));
            }

            // Enforce access policy.
            if !authorization.is_authorized(&claims.custom_claims) {
                let status = AuthError::PolicyDenied.into_status();
                return Ok(status_to_response(status));
            }

            // Inject auth context into request extensions.
            req.extensions_mut().insert(JwtAuthContext::new(
                claims.custom_claims,
                claims.registered_claims,
            ));

            inner.call(req).await
        })
    }
}

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

fn status_to_response(status: Status) -> Response<TonicBody> {
    status.into_http::<TonicBody>()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use http::Request;
    use tower::ServiceExt as _;
    use webgates::accounts::Account;
    use webgates::codecs::jwt::JwtClaims;
    use webgates::groups::Group;
    use webgates::roles::Role;
    use webgates_codecs::jwt::remote_verifier::{RemoteJwksVerifier, RemoteJwksVerifierConfig};

    type AppClaims = JwtClaims<Account<Role, Group>>;

    async fn make_verifier() -> Arc<RemoteJwksVerifier<AppClaims>> {
        use axum::Router;
        use axum::routing::get;
        use webgates_codecs::jwt::jwks::{EcP384Jwk, JwksDocument};

        const PUBLIC_PEM: &[u8] = br#"-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEsjQ/XkOUJO2bXkhDzKRMW1SXp0VsMqGx
MSTG+tppqd3gOxbM8vLgWy4/B0Qdest0Gy3E8QgaKJXQV3zRczNd9zrk1dmwVl6u
Yd+JfgNIeIFP6HWeu/C3wIJ60WDBuGY1
-----END PUBLIC KEY-----
"#;

        let key = EcP384Jwk::from_public_key_pem("dev-kid", PUBLIC_PEM).unwrap();
        let doc = JwksDocument { keys: vec![key] };
        let doc_json = serde_json::to_string(&doc).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let doc_json_clone = doc_json.clone();
        tokio::spawn(async move {
            let app = Router::new().route(
                "/.well-known/jwks.json",
                get(move || {
                    let body = doc_json_clone.clone();
                    async move {
                        axum::response::Response::builder()
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(body))
                            .unwrap()
                    }
                }),
            );
            axum::serve(listener, app).await.unwrap();
        });

        let url = format!("http://{addr}/.well-known/jwks.json");
        let config = RemoteJwksVerifierConfig::from_jwks_url(url);
        let verifier = RemoteJwksVerifier::<AppClaims>::bootstrap(config)
            .await
            .expect("bootstrap should succeed");
        Arc::new(verifier)
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

    fn make_request_no_auth() -> Request<TonicBody> {
        Request::builder()
            .uri("/test.Service/Method")
            .body(TonicBody::empty())
            .unwrap()
    }

    fn make_request_with_bearer(token: &str) -> Request<TonicBody> {
        Request::builder()
            .uri("/test.Service/Method")
            .header(http::header::AUTHORIZATION, format!("Bearer {token}"))
            .body(TonicBody::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn gate_rejects_missing_token() {
        let verifier = make_verifier().await;
        let gate = RemoteJwksBearerGate::new("auth-node", verifier).require_login();

        let svc = gate.layer(echo_service());
        let resp = svc.oneshot(make_request_no_auth()).await.unwrap();
        let grpc_status = resp
            .headers()
            .get("grpc-status")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok());
        // UNAUTHENTICATED = 16
        assert_eq!(grpc_status, Some(16));
    }

    #[tokio::test]
    async fn gate_rejects_invalid_token() {
        let verifier = make_verifier().await;
        let gate = RemoteJwksBearerGate::new("auth-node", verifier).require_login();

        let svc = gate.layer(echo_service());
        let resp = svc
            .oneshot(make_request_with_bearer("not-a-valid-jwt"))
            .await
            .unwrap();
        let grpc_status = resp
            .headers()
            .get("grpc-status")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok());
        // UNAUTHENTICATED = 16
        assert_eq!(grpc_status, Some(16));
    }

    #[tokio::test]
    async fn gate_rejects_deny_all_policy() {
        let verifier = make_verifier().await;
        // No policy set — defaults to deny_all.
        let gate: RemoteJwksBearerGate<Role, Group> =
            RemoteJwksBearerGate::new("auth-node", verifier);

        let svc = gate.layer(echo_service());
        let resp = svc
            .oneshot(make_request_with_bearer("any-token"))
            .await
            .unwrap();
        let grpc_status = resp
            .headers()
            .get("grpc-status")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok());
        // UNAUTHENTICATED = 16 (token is invalid, fails before policy check)
        assert_eq!(grpc_status, Some(16));
    }
}
