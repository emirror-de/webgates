//! Bearer gate example for tonic services.
//!
//! This example demonstrates how to construct and apply `webgates-tonic`
//! bearer gate middleware to a tower service that proxies tonic gRPC
//! requests. It exercises:
//!
//! - Strict JWT bearer gate with an explicit `AccessPolicy`
//! - Optional JWT bearer gate (`allow_anonymous_with_optional_user`)
//! - Static-token gate (strict and optional)
//!
//! The example uses a simple tower `service_fn` echo service instead of a
//! full tonic-generated server so that the example can be verified with
//! `cargo check --examples` without a `.proto` file.

use std::convert::Infallible;
use std::sync::Arc;

use http::{Request, Response};
use tonic::body::Body as TonicBody;
use tower::{Layer as _, ServiceExt as _};
use webgates::accounts::Account;
use webgates::authz::access_policy::AccessPolicy;
use webgates::codecs::jwt::{JsonWebToken, JwtClaims};
use webgates::groups::Group;
use webgates::roles::Role;
use webgates_tonic::context::{JwtAuthContext, OptionalJwtAuthContext, StaticTokenAuthorized};
use webgates_tonic::gate::Gate;

type Claims = JwtClaims<Account<Role, Group>>;

/// A minimal echo service used to represent an inner tonic server.
fn echo_service() -> impl tower::Service<
    Request<TonicBody>,
    Response = Response<TonicBody>,
    Error = Infallible,
    Future = impl std::future::Future<Output = Result<Response<TonicBody>, Infallible>> + Send + 'static,
> + Clone {
    tower::service_fn(|_req: Request<TonicBody>| async {
        Ok::<_, Infallible>(Response::new(TonicBody::empty()))
    })
}

#[tokio::main]
async fn main() {
    // ── 1. Strict JWT bearer gate ────────────────────────────────────────────
    // Only requests bearing a valid JWT that satisfies the configured policy
    // will be forwarded. All others receive UNAUTHENTICATED or PERMISSION_DENIED.

    let codec = Arc::new(JsonWebToken::<Claims>::default());

    let _strict_jwt_layer = Gate::bearer("example-svc", Arc::clone(&codec))
        .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin));

    // In a real tonic application:
    //
    //   Server::builder()
    //       .layer(_strict_jwt_layer)
    //       .add_service(MyServiceServer::new(my_impl))
    //       .serve(addr)
    //       .await?;

    // ── 2. Optional JWT bearer gate ──────────────────────────────────────────
    // All requests are forwarded. The `OptionalJwtAuthContext` extension is
    // inserted so handlers can inspect whether the caller is authenticated.

    let optional_jwt_layer =
        Gate::bearer("example-svc", Arc::clone(&codec)).allow_anonymous_with_optional_user();

    // Demonstrate using the layer with a service_fn echo service.
    let svc = optional_jwt_layer.layer(tower::service_fn(|req: Request<TonicBody>| async move {
        let ctx = req
            .extensions()
            .get::<OptionalJwtAuthContext<Role, Group>>()
            .cloned();
        if let Some(ctx) = ctx {
            if ctx.is_authenticated() {
                println!(
                    "authenticated: {}",
                    ctx.account().map(|a| a.user_id.as_str()).unwrap_or("?")
                );
            } else {
                println!("anonymous request");
            }
        }
        Ok::<_, Infallible>(Response::new(TonicBody::empty()))
    }));

    let req = Request::builder()
        .uri("/example.Service/Call")
        .body(TonicBody::empty())
        .expect("valid request");
    let _ = svc.oneshot(req).await;

    // ── 3. Strict static-token gate ──────────────────────────────────────────
    // Only requests that present the exact matching bearer token are forwarded.
    // The comparison is constant-time.

    let _strict_static =
        Gate::bearer("example-svc", Arc::clone(&codec)).with_static_token("my-shared-secret");

    // ── 4. Optional static-token gate ────────────────────────────────────────
    // All requests are forwarded. Handlers read `StaticTokenAuthorized` to
    // decide whether to perform privileged operations.

    let optional_static = Gate::bearer("example-svc", Arc::clone(&codec))
        .with_static_token("my-shared-secret")
        .allow_anonymous_with_optional_user();

    let svc = optional_static.layer(tower::service_fn(|req: Request<TonicBody>| async move {
        let authorized = req
            .extensions()
            .get::<StaticTokenAuthorized>()
            .copied()
            .map(|a| a.is_authorized())
            .unwrap_or(false);
        println!("static token authorized: {authorized}");
        Ok::<_, Infallible>(Response::new(TonicBody::empty()))
    }));

    let req = Request::builder()
        .uri("/example.Service/Call")
        .header(http::header::AUTHORIZATION, "Bearer my-shared-secret")
        .body(TonicBody::empty())
        .expect("valid request");
    let _ = svc.oneshot(req).await;

    // ── 5. Strict JWT gate — reading JwtAuthContext in a handler ────────────
    // The auth context is only inserted when the token is valid and the policy
    // is satisfied. Handlers can retrieve it from request extensions.

    let strict_jwt_layer = Gate::bearer("example-svc", Arc::clone(&codec)).require_login();

    let svc = strict_jwt_layer.layer(tower::service_fn(|req: Request<TonicBody>| async move {
        // In a real handler, retrieve the context and use it:
        if let Some(_ctx) = req.extensions().get::<JwtAuthContext<Role, Group>>() {
            // ctx.account().user_id, ctx.registered_claims().issuer, …
        }
        Ok::<_, Infallible>(Response::new(TonicBody::empty()))
    }));

    // A request without a token will receive UNAUTHENTICATED (grpc-status 16).
    let req = Request::builder()
        .uri("/example.Service/Call")
        .body(TonicBody::empty())
        .expect("valid request");
    let resp: Response<TonicBody> = svc.oneshot(req).await.expect("infallible");
    let grpc_status = resp
        .headers()
        .get("grpc-status")
        .and_then(|v: &http::HeaderValue| v.to_str().ok())
        .and_then(|v: &str| v.parse::<u32>().ok());
    println!("grpc-status for unauthenticated request: {grpc_status:?}");

    // Use the echo_service helper (prevents dead-code warning).
    let _ = echo_service();
}
