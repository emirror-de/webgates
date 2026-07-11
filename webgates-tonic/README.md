# webgates-tonic

User-focused tonic server-side integration for the `webgates` stack.

`webgates-tonic` is the tonic-facing transport adapter for `webgates`. It lets you apply bearer-token authentication and authorization to gRPC services running on tonic while keeping the core auth and policy logic in the framework-agnostic `webgates` crate.

This crate is **server-side only**. It does not provide cookie transport, browser-based OAuth2 flows, or tonic client utilities.

## Who this crate is for

Use `webgates-tonic` when you want to:

- protect tonic gRPC services with bearer-token authentication
- enforce `webgates` authorization policies in server middleware
- read typed authentication context inside tonic handlers
- use optional JWT auth context for mixed public/authenticated gRPC methods
- support static-token service-to-service authentication
- keep transport concerns separate from the core `webgates` domain and auth logic

You still depend on `webgates` for domain types, codecs, policies, claims, and repository contracts.

## What this crate helps you build

Use this crate when you want one or more of these tonic-facing workflows:

- bearer-token authentication for tonic services
- authorization enforcement in tonic middleware
- typed auth context extraction inside handlers
- optional authenticated-or-public gRPC methods
- static-token service-to-service protection

## Install

Most applications should depend on both crates explicitly.

```toml
[dependencies]
tonic = "0.14"
webgates = "1.0.0"
webgates-tonic = "1.0.0"
```

Minimum supported Rust version: `1.94`.

## The mental model

The easiest way to understand `webgates-tonic` is:

1. define auth and authorization rules in `webgates`
2. adapt them into tonic middleware with `webgates_tonic::gate::Gate`
3. let middleware validate bearer metadata and enforce policy
4. read typed auth context from request extensions inside your gRPC handlers

This keeps responsibilities separate:

- `webgates` owns policies, account claims, and token validation building blocks
- `webgates-tonic` owns tonic-layer request interception and status mapping

## Quick start

### Strict JWT bearer gate

Applies the configured `AccessPolicy` to every request. Returns `UNAUTHENTICATED` or `PERMISSION_DENIED` on failure and inserts `JwtAuthContext` on success.

```rust,ignore
use std::sync::Arc;

use webgates::accounts::Account;
use webgates::authz::access_policy::AccessPolicy;
use webgates::codecs::jwt::{JsonWebToken, JwtClaims};
use webgates::groups::Group;
use webgates::roles::Role;
use webgates_tonic::gate::Gate;

type Claims = JwtClaims<Account<Role, Group>>;

let codec = Arc::new(JsonWebToken::<Claims>::default());

let layer = Gate::bearer("my-svc", codec)
    .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin));
```

### Require any authenticated user

```rust,ignore
let layer = Gate::bearer("my-svc", codec).require_login();
```

### Optional authentication

Optional mode forwards all requests and inserts `OptionalJwtAuthContext`.
Handlers decide what to do with authenticated vs anonymous requests.

```rust,ignore
use webgates_tonic::context::OptionalJwtAuthContext;
use webgates::roles::Role;
use webgates::groups::Group;

let layer = Gate::bearer("my-svc", codec).allow_anonymous_with_optional_user();

// In the handler:
// let ctx = req.extensions().get::<OptionalJwtAuthContext<Role, Group>>();
// if ctx.map(|c| c.is_authenticated()).unwrap_or(false) { ... }
```

### Static-token gate

Static-token mode performs constant-time bearer token matching and inserts `StaticTokenAuthorized`.

```rust,ignore
use webgates_tonic::context::StaticTokenAuthorized;

let layer = Gate::bearer("my-svc", codec).with_static_token("internal-static-token");

let optional_layer = Gate::bearer("my-svc", codec)
    .with_static_token("internal-static-token")
    .allow_anonymous_with_optional_user();
```

## Reading auth context in a handler

```rust,ignore
use tonic::{Request, Response, Status};
use webgates_tonic::context::JwtAuthContext;
use webgates::groups::Group;
use webgates::roles::Role;

async fn my_handler(
    req: Request<MyRequest>,
) -> Result<Response<MyResponse>, Status> {
    let ctx = req
        .extensions()
        .get::<JwtAuthContext<Role, Group>>()
        .ok_or_else(|| Status::unauthenticated("missing auth context"))?;

    let account = ctx.account();
    let claims = ctx.registered_claims();
    let _ = (account, claims);
    todo!()
}
```

## Core concepts

### 1. `Gate` is the main integration entry point

Use `webgates_tonic::gate::Gate` to build tonic bearer-token middleware.

The main entry point is:

- `Gate::bearer(issuer, codec)`

From there you can configure:

- `.with_policy(policy)`
- `.require_login()`
- `.allow_anonymous_with_optional_user()`
- `.with_static_token(token)`

### 2. Context types are how handlers read auth state

The middleware inserts typed values into request extensions so handlers can read authentication state without manually decoding metadata.

Main types are:

- `JwtAuthContext`
- `OptionalJwtAuthContext`
- `StaticTokenAuthorized`

### 3. `AuthError` defines status mapping

`AuthError` is the typed error model used by the middleware for auth failures.
It maps failures to appropriate `tonic::Status` values such as:

- `UNAUTHENTICATED`
- `PERMISSION_DENIED`
- `INTERNAL`

## Transport mechanism

`webgates-tonic` uses tower `Layer` and `Service` wrappers that operate directly on `http::Request<tonic::body::Body>`.

That gives the middleware access to the full HTTP header set, including `Authorization: Bearer <token>`, before the tonic request type is constructed. The layer can then insert typed extensions that handlers later read through `request.extensions()`.

## Non-goals

- client-side tonic authentication
- cookie-based authentication
- browser-redirect or OAuth2 authorization code flows
- any feature not required for server-side bearer token validation

## Features

- `default = []`
- `audit-logging`: enables audit logging integration from `webgates`
- `prometheus`: installs Prometheus metrics integration for auth events; depends on `audit-logging`

## Security checklist

- keep the issuer identical between token minting and gate validation
- use persistent signing keys in production and rotate them deliberately
- prefer short-lived JWTs and explicit observability
- avoid logging secrets, raw tokens, or sensitive payloads
- for static-token mode, the comparison is constant-time but the token is still held in memory as a plain string; protect the process environment accordingly

## Recommended onboarding path

If you are new to this crate, I recommend this order:

1. `gate::Gate`
2. `context`
3. `errors`
4. `gate::bearer`
5. `gate::remote_jwks_bearer` if you need remote JWKS-backed verification

## Which crate should you use?

- use `webgates-tonic` when you want tonic server-side bearer-token integration
- use `webgates` when you want the higher-level application-facing auth stack
- use `webgates-axum` when you want HTTP/Axum integration instead of gRPC
- use `webgates-codecs` when you need codec or JWT support directly

## License

MIT
