# webgates-tonic

Tonic server-side integration for the `webgates` core.

This crate is the tonic-facing adapter layer for `webgates`. It exposes a small public API:

- `webgates_tonic::gate::Gate` as the canonical entry point for bearer token authentication and authorization on tonic gRPC servers
- `webgates_tonic::context::JwtAuthContext` for reading the authenticated account and claims in strict JWT mode
- `webgates_tonic::context::OptionalJwtAuthContext` for reading optional auth context in optional JWT mode
- `webgates_tonic::context::StaticTokenAuthorized` for reading the static-token authorization marker in static-token mode
- `webgates_tonic::errors::AuthError` for explicit tonic status mapping of authentication and authorization failures

This crate is **server-side only**. It does not provide cookie transport, browser-redirect OAuth2 flows, or any client-side tonic utilities.

It does not replace `webgates`. You still depend on `webgates` for domain types, codecs, policies, claims, and repository contracts.

## Install

Most applications should depend on both crates explicitly.

```toml
[dependencies]
tonic = "0.14"
webgates = "0.1"
webgates-tonic = "0.1"
```

MSRV: 1.91

## Public API

The canonical public API of this crate is intentionally small.

### Gate entry point

Use `webgates_tonic::gate::Gate` to build middleware:

- `Gate::bearer(issuer, codec)` — create a JWT bearer gate (strict mode by default)

The builder supports:

- `.with_policy(policy)` — configure an explicit `AccessPolicy`
- `.require_login()` — allow any authenticated user with the baseline role or a supervisor role
- `.allow_anonymous_with_optional_user()` — forward all requests and insert optional auth context
- `.with_static_token(token)` — transition to constant-time static-token matching mode

### What to import directly

Prefer direct imports from stable module paths:

```rust
use webgates_tonic::gate::Gate;
use webgates_tonic::context::JwtAuthContext;
use webgates_tonic::context::OptionalJwtAuthContext;
use webgates_tonic::context::StaticTokenAuthorized;
use webgates_tonic::errors::AuthError;
```

Do not rely on convenience prelude-style imports. Prefer the explicit paths above.

## Quick start

### Strict JWT bearer gate

Applies the configured `AccessPolicy` to every request. Returns `UNAUTHENTICATED` or `PERMISSION_DENIED` on failure; inserts `JwtAuthContext` on success.

```rust,ignore
use std::sync::Arc;

use webgates::accounts::Account;
use webgates::authz::AccessPolicy;
use webgates::codecs::jwt::{JsonWebToken, JwtClaims};
use webgates::roles::Role;
use webgates::groups::Group;
use webgates_tonic::gate::Gate;

type Claims = JwtClaims<Account<Role, Group>>;

let codec = Arc::new(JsonWebToken::<Claims>::default());

// Wrap a tonic server builder with this layer before adding to a Router.
let layer = Gate::bearer("my-svc", codec)
    .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin));
```

### Require any authenticated user

```rust,ignore
let layer = Gate::bearer("my-svc", codec).require_login();
```

### Optional authentication

Forwards all requests. Inserts `OptionalJwtAuthContext` with the authenticated account when a valid token is present, or an anonymous context otherwise. Handlers must perform any required access checks themselves.

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

Performs constant-time bearer token matching. Inserts `StaticTokenAuthorized` into request extensions.

```rust,ignore
use webgates_tonic::context::StaticTokenAuthorized;

// Strict: rejects requests with a missing or wrong token.
let layer = Gate::bearer("my-svc", codec).with_static_token("internal-static-token");

// Optional: forwards all requests; the marker reports whether the token matched.
let layer = Gate::bearer("my-svc", codec)
    .with_static_token("internal-static-token")
    .allow_anonymous_with_optional_user();

// In the handler:
// let auth = req.extensions().get::<StaticTokenAuthorized>().copied();
// if auth.map(|a| a.is_authorized()).unwrap_or(false) { ... }
```

### Reading auth context in a handler

```rust,ignore
use tonic::{Request, Response, Status};
use webgates_tonic::context::JwtAuthContext;
use webgates::roles::Role;
use webgates::groups::Group;

async fn my_handler(
    req: Request<MyRequest>,
) -> Result<Response<MyResponse>, Status> {
    let ctx = req
        .extensions()
        .get::<JwtAuthContext<Role, Group>>()
        .ok_or_else(|| Status::unauthenticated("missing auth context"))?;

    let account = ctx.account();
    let claims  = ctx.registered_claims();
    // ... perform handler logic
    todo!()
}
```

## Transport mechanism

`webgates-tonic` uses tower `Layer`/`Service` wrappers that operate directly on `http::Request<tonic::body::Body>`. This gives access to the full HTTP header set (including `Authorization: Bearer <token>`) before the tonic request type is constructed, and allows inserting typed extensions into `http::Extensions` so that tonic handlers can retrieve them via `request.extensions()`.

## Non-goals

- Client-side tonic authentication (token injection for outgoing calls).
- Cookie-based authentication.
- Browser-redirect or OAuth2 authorization code flows.
- Any feature that is not required for server-side bearer token validation.

## Features

- `default = []`
- `audit-logging`: enables audit logging integration from `webgates`
- `prometheus`: installs Prometheus metrics integration for auth events; depends on `audit-logging`

## Security checklist

- Keep the issuer identical between token minting and gate validation.
- Use persistent signing keys in production and rotate them deliberately.
- Prefer short-lived JWTs and explicit observability.
- Avoid logging secrets, raw tokens, or sensitive payloads.
- For static-token mode, the comparison is constant-time but the token is held in memory as a plain string — protect the process environment accordingly.

## License

MIT
