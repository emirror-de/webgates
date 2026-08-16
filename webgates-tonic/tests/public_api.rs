// Integration tests: canonical public-API regression coverage for webgates-tonic.
//
// These tests prove that downstream users can construct and use the intended
// tonic integration through canonical public module paths only. Internal
// module paths (`gate::bearer::JwtBearerService`, etc.) are intentionally
// NOT imported here; only the published surface is exercised.
//
// Coverage:
// - `webgates_tonic::gate::Gate::bearer` entry point
// - `BearerGate` builder methods: `with_policy`, `require_login`,
//   `allow_anonymous_with_optional_user`, `with_static_token`
// - All four auth context types via their public module paths
// - End-to-end request dispatch through the tower layer boundary
// - gRPC status codes in response headers (UNAUTHENTICATED = 16,
//   PERMISSION_DENIED = 7)

use std::convert::Infallible;
use std::sync::Arc;

use chrono::Utc;
use http::{Request, Response};
use tonic::body::Body as TonicBody;
use tower::{Layer as _, ServiceExt as _};

use webgates::accounts::Account;
use webgates::authz::access_policy::AccessPolicy;
use webgates::codecs::Codec as _;
use webgates::codecs::jwt::{JsonWebToken, JwtClaims, RegisteredClaims};
use webgates::groups::Group;
use webgates::roles::Role;

// Canonical public paths — these must remain stable for downstream users.
use webgates_tonic::context::JwtAuthContext;
use webgates_tonic::context::OptionalJwtAuthContext;
use webgates_tonic::context::StaticTokenAuthorized;
use webgates_tonic::gate::Gate;

type Claims = JwtClaims<Account<Role, Group>>;

// ── helpers ──────────────────────────────────────────────────────────────────

fn install_crypto_provider() {
    use webgates::codecs::jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER;
    let _ = DEFAULT_PROVIDER.install_default();
}

fn empty_request() -> Request<TonicBody> {
    Request::builder()
        .uri("/pkg.Service/Method")
        .body(TonicBody::empty())
        .expect("valid request")
}

fn bearer_request(token: &str) -> Request<TonicBody> {
    Request::builder()
        .uri("/pkg.Service/Method")
        .header(http::header::AUTHORIZATION, format!("Bearer {token}"))
        .body(TonicBody::empty())
        .expect("valid request")
}

fn echo_svc() -> impl tower::Service<
    Request<TonicBody>,
    Response = Response<TonicBody>,
    Error = Infallible,
    Future = impl std::future::Future<Output = Result<Response<TonicBody>, Infallible>> + Send + 'static,
> + Clone {
    tower::service_fn(|_req: Request<TonicBody>| async {
        Ok::<_, Infallible>(Response::new(TonicBody::empty()))
    })
}

fn grpc_status(resp: &Response<TonicBody>) -> Option<u32> {
    resp.headers()
        .get("grpc-status")
        .and_then(|v: &http::HeaderValue| v.to_str().ok())
        .and_then(|v: &str| v.parse::<u32>().ok())
}

fn test_codec() -> Arc<JsonWebToken<Claims>> {
    Arc::new(JsonWebToken::<Claims>::new_with_options(
        webgates::codecs::jwt::JsonWebTokenOptions::generate_for_testing()
            .expect("generating ephemeral ES384 key pair should not fail"),
    ))
}

fn make_valid_token(codec: &JsonWebToken<Claims>, issuer: &str) -> String {
    let account = Account::<Role, Group>::new("user");
    let exp = Utc::now().timestamp() as u64 + 60;
    let claims = Claims::new(account, RegisteredClaims::new(issuer, exp));
    let encoded = codec.encode(&claims).expect("encode jwt");
    String::from_utf8(encoded).expect("utf-8")
}

// ── Gate::bearer — public API entry point ────────────────────────────────────

/// `Gate::bearer` constructs a layer that can be applied to a service.
#[tokio::test]
async fn gate_bearer_constructs_layer() {
    install_crypto_provider();
    let codec = test_codec();

    // Should compile and run without panic — proves the canonical path works.
    let layer = Gate::bearer("svc", Arc::clone(&codec))
        .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin));

    let svc = layer.layer(echo_svc());
    let resp: Response<TonicBody> = svc.oneshot(empty_request()).await.expect("infallible");
    // Missing token → UNAUTHENTICATED (16).
    assert_eq!(grpc_status(&resp), Some(16));
}

// ── require_login ─────────────────────────────────────────────────────────────

/// `require_login` allows any user with the baseline role (Role::default()).
#[tokio::test]
async fn require_login_denies_missing_token() {
    install_crypto_provider();
    let codec = test_codec();
    let layer = Gate::bearer("svc", Arc::clone(&codec)).require_login();
    let svc = layer.layer(echo_svc());

    let resp: Response<TonicBody> = svc.oneshot(empty_request()).await.expect("infallible");
    assert_eq!(grpc_status(&resp), Some(16));
}

#[tokio::test]
async fn require_login_allows_valid_token() {
    install_crypto_provider();
    let codec = test_codec();
    let token = make_valid_token(&codec, "svc");

    let layer = Gate::bearer("svc", Arc::clone(&codec)).require_login();
    let svc = layer.layer(tower::service_fn(|req: Request<TonicBody>| async move {
        let ctx = req
            .extensions()
            .get::<JwtAuthContext<Role, Group>>()
            .cloned();
        assert!(ctx.is_some(), "JwtAuthContext must be present on success");
        Ok::<_, Infallible>(Response::new(TonicBody::empty()))
    }));

    let resp: Response<TonicBody> = svc
        .oneshot(bearer_request(&token))
        .await
        .expect("infallible");
    // Inner service returned plain 200; grpc-status may be absent or 0.
    assert!(grpc_status(&resp).is_none() || grpc_status(&resp) == Some(0));
}

// ── allow_anonymous_with_optional_user ───────────────────────────────────────

/// Optional mode forwards requests without a token and inserts an anonymous context.
#[tokio::test]
async fn optional_mode_forwards_unauthenticated_request() {
    install_crypto_provider();
    let codec = test_codec();
    let layer = Gate::bearer("svc", Arc::clone(&codec)).allow_anonymous_with_optional_user();

    let svc = layer.layer(tower::service_fn(|req: Request<TonicBody>| async move {
        let ctx = req
            .extensions()
            .get::<OptionalJwtAuthContext<Role, Group>>()
            .cloned();
        assert!(
            ctx.is_some(),
            "OptionalJwtAuthContext must always be present"
        );
        assert!(!ctx.unwrap().is_authenticated(), "anonymous when no token");
        Ok::<_, Infallible>(Response::new(TonicBody::empty()))
    }));

    svc.oneshot(empty_request()).await.expect("infallible");
}

/// Optional mode inserts an authenticated context when a valid token is present.
#[tokio::test]
async fn optional_mode_inserts_authenticated_context_for_valid_token() {
    install_crypto_provider();
    let codec = test_codec();
    let token = make_valid_token(&codec, "svc");
    let layer = Gate::bearer("svc", Arc::clone(&codec)).allow_anonymous_with_optional_user();

    let svc = layer.layer(tower::service_fn(|req: Request<TonicBody>| async move {
        let ctx = req
            .extensions()
            .get::<OptionalJwtAuthContext<Role, Group>>()
            .cloned();
        assert!(ctx.is_some());
        assert!(ctx.unwrap().is_authenticated(), "must be authenticated");
        Ok::<_, Infallible>(Response::new(TonicBody::empty()))
    }));

    svc.oneshot(bearer_request(&token))
        .await
        .expect("infallible");
}

/// Optional mode inserts an anonymous context for an invalid token.
#[tokio::test]
async fn optional_mode_is_anonymous_for_invalid_token() {
    install_crypto_provider();
    let codec = test_codec();
    let layer = Gate::bearer("svc", Arc::clone(&codec)).allow_anonymous_with_optional_user();

    let svc = layer.layer(tower::service_fn(|req: Request<TonicBody>| async move {
        let ctx = req
            .extensions()
            .get::<OptionalJwtAuthContext<Role, Group>>()
            .cloned();
        assert!(ctx.is_some());
        assert!(
            !ctx.unwrap().is_authenticated(),
            "invalid token must be anonymous"
        );
        Ok::<_, Infallible>(Response::new(TonicBody::empty()))
    }));

    svc.oneshot(bearer_request("not-a-real-jwt"))
        .await
        .expect("infallible");
}

// ── with_static_token ─────────────────────────────────────────────────────────

/// Strict static-token gate rejects a missing token with UNAUTHENTICATED.
#[tokio::test]
async fn static_token_strict_rejects_missing_token() {
    install_crypto_provider();
    let codec = test_codec();
    let layer = Gate::bearer("svc", codec).with_static_token("correct");

    let svc = layer.layer(echo_svc());
    let resp: Response<TonicBody> = svc.oneshot(empty_request()).await.expect("infallible");
    assert_eq!(grpc_status(&resp), Some(16), "UNAUTHENTICATED expected");
}

/// Strict static-token gate rejects a wrong token with PERMISSION_DENIED.
#[tokio::test]
async fn static_token_strict_rejects_wrong_token() {
    install_crypto_provider();
    let codec = test_codec();
    let layer = Gate::bearer("svc", codec).with_static_token("correct");

    let svc = layer.layer(echo_svc());
    let resp: Response<TonicBody> = svc
        .oneshot(bearer_request("wrong"))
        .await
        .expect("infallible");
    assert_eq!(grpc_status(&resp), Some(7), "PERMISSION_DENIED expected");
}

/// Strict static-token gate forwards requests with the correct token and inserts the marker.
#[tokio::test]
async fn static_token_strict_authorizes_correct_token() {
    install_crypto_provider();
    let codec = test_codec();
    let layer = Gate::bearer("svc", codec).with_static_token("secret");

    let svc = layer.layer(tower::service_fn(|req: Request<TonicBody>| async move {
        let auth = req.extensions().get::<StaticTokenAuthorized>().copied();
        assert!(auth.is_some(), "StaticTokenAuthorized must be present");
        assert!(auth.unwrap().is_authorized(), "must be authorized");
        Ok::<_, Infallible>(Response::new(TonicBody::empty()))
    }));

    svc.oneshot(bearer_request("secret"))
        .await
        .expect("infallible");
}

/// Optional static-token gate inserts authorized=false for an anonymous request.
#[tokio::test]
async fn static_token_optional_anonymous_request() {
    install_crypto_provider();
    let codec = test_codec();
    let layer = Gate::bearer("svc", codec)
        .with_static_token("secret")
        .allow_anonymous_with_optional_user();

    let svc = layer.layer(tower::service_fn(|req: Request<TonicBody>| async move {
        let auth = req.extensions().get::<StaticTokenAuthorized>().copied();
        assert!(auth.is_some());
        assert!(!auth.unwrap().is_authorized(), "must be unauthorized");
        Ok::<_, Infallible>(Response::new(TonicBody::empty()))
    }));

    svc.oneshot(empty_request()).await.expect("infallible");
}

/// Optional static-token gate inserts authorized=true when the token matches.
#[tokio::test]
async fn static_token_optional_authorized_request() {
    install_crypto_provider();
    let codec = test_codec();
    let layer = Gate::bearer("svc", codec)
        .with_static_token("secret")
        .allow_anonymous_with_optional_user();

    let svc = layer.layer(tower::service_fn(|req: Request<TonicBody>| async move {
        let auth = req.extensions().get::<StaticTokenAuthorized>().copied();
        assert!(auth.is_some());
        assert!(auth.unwrap().is_authorized(), "must be authorized");
        Ok::<_, Infallible>(Response::new(TonicBody::empty()))
    }));

    svc.oneshot(bearer_request("secret"))
        .await
        .expect("infallible");
}

// ── issuer mismatch ───────────────────────────────────────────────────────────

/// A JWT with a mismatched issuer is rejected with UNAUTHENTICATED.
#[tokio::test]
async fn strict_jwt_issuer_mismatch_is_unauthenticated() {
    install_crypto_provider();
    let codec = test_codec();
    // Token minted with issuer "other-svc", gate expects "svc".
    let token = make_valid_token(&codec, "other-svc");

    let layer = Gate::bearer("svc", Arc::clone(&codec)).require_login();
    let svc = layer.layer(echo_svc());

    let resp: Response<TonicBody> = svc
        .oneshot(bearer_request(&token))
        .await
        .expect("infallible");
    assert_eq!(
        grpc_status(&resp),
        Some(16),
        "issuer mismatch must be UNAUTHENTICATED"
    );
}

// ── context accessors ─────────────────────────────────────────────────────────

/// `JwtAuthContext` accessors return the expected account and claims.
#[tokio::test]
async fn jwt_auth_context_accessors_end_to_end() {
    install_crypto_provider();
    let codec = test_codec();

    let account = Account::<Role, Group>::new("alice");
    let exp = Utc::now().timestamp() as u64 + 60;
    let claims = Claims::new(account.clone(), RegisteredClaims::new("svc", exp));
    let encoded = codec.encode(&claims).expect("encode");
    let token = String::from_utf8(encoded).expect("utf-8");

    let layer = Gate::bearer("svc", Arc::clone(&codec)).require_login();

    let svc = layer.layer(tower::service_fn(move |req: Request<TonicBody>| {
        let expected_user_id = account.user_id.clone();
        async move {
            let ctx = req
                .extensions()
                .get::<JwtAuthContext<Role, Group>>()
                .cloned()
                .expect("context must be present");
            assert_eq!(ctx.account().user_id, expected_user_id);
            assert_eq!(ctx.registered_claims().issuer, "svc");
            Ok::<_, Infallible>(Response::new(TonicBody::empty()))
        }
    }));

    svc.oneshot(bearer_request(&token))
        .await
        .expect("infallible");
}
