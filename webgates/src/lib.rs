#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
/*!
# webgates

User-focused composition crate for building a practical `webgates` application stack.

`webgates` builds on `webgates-core` and adds optional higher-level capabilities
such as authentication workflows, framework-agnostic gate builders, cookie
configuration, JWT support, sessions, secrets, OAuth2, and observability.

Most application developers should start here rather than wiring multiple
workspace crates together manually.

## When to use this crate

Use `webgates` when you want:

- one crate as the main dependency for application code
- the core domain model plus higher-level authentication and authorization tools
- framework-agnostic gate configuration for cookies, bearer tokens, or OAuth2
- optional login/logout orchestration
- optional session-backed authentication and renewal
- optional audit logging and metrics hooks

If you only need the domain model and authorization primitives, use
`webgates-core` directly.

## What this crate adds

Compared with `webgates-core`, this crate adds optional modules for:

- authentication workflows via [`authn`]
- cookie configuration via [`cookie_template`]
- framework-agnostic gate builders via [`gate`]
- audit logging via [`audit`] when the `audit-logging` feature is enabled

Additional sibling crates are re-exported behind features:

- `codecs` enables `webgates-codecs`
- `secrets` enables `webgates-secrets`
- `sessions` enables `webgates-sessions`

Framework adapters remain in sibling crates such as `webgates-axum`.
Persistence backends remain in `webgates-repositories`.

## Quick mental model

A common application flow looks like this:

1. use the re-exported core domain model such as [`accounts::Account`] and
   [`authz::access_policy::AccessPolicy`]
2. define protected access with a [`gate::Gate`]
3. translate the gate into framework behavior using an adapter crate such as
   `webgates-axum`
4. optionally add login/logout, cookies, sessions, secrets, and observability
   through feature flags

## Quick start

The canonical domain types come from the same paths as in `webgates-core`:

```rust
use webgates::accounts::Account;
use webgates::authz::access_policy::AccessPolicy;
use webgates::groups::Group;
use webgates::roles::Role;
```

A minimal codec-only setup looks like this:

```rust
#[cfg(feature = "codecs")]
# {
use std::sync::Arc;
use webgates::accounts::Account;
use webgates::codecs::jwt::{JsonWebToken, JwtClaims};
use webgates::groups::Group;
use webgates::roles::Role;

type AppClaims = JwtClaims<Account<Role, Group>>;
let codec = Arc::new(JsonWebToken::<AppClaims>::new_with_options(
    webgates::codecs::jwt::JsonWebTokenOptions::generate_for_testing()
        .expect("generating ephemeral ES384 key pair should not fail"),
));
let _ = codec;
# }
```

When the `cookies` feature is enabled, you can build a cookie-based gate:

```rust
#[cfg(feature = "cookies")]
# {
use std::sync::Arc;
use webgates::accounts::Account;
use webgates::authz::access_policy::AccessPolicy;
use webgates::codecs::jwt::{JsonWebToken, JwtClaims};
use webgates::gate::Gate;
use webgates::groups::Group;
use webgates::roles::Role;

type AppClaims = JwtClaims<Account<Role, Group>>;
let codec = Arc::new(JsonWebToken::<AppClaims>::new_with_options(
    webgates::codecs::jwt::JsonWebTokenOptions::generate_for_testing()
        .expect("generating ephemeral ES384 key pair should not fail"),
));

let gate = Gate::cookie::<_, Role, Group>("my-app", Arc::clone(&codec))
    .require_login()
    .with_policy(AccessPolicy::<Role, Group>::require_permission("admin:read"));

let _ = gate;
# }
```

## Session-backed deployment model

When you enable session-backed authentication, the canonical deployment model is:

- an **auth authority** that verifies credentials, issues auth and refresh
  tokens, owns session persistence, and performs refresh-token rotation and
  revocation
- one or more **resource services** that validate short-lived access tokens
  locally and enforce authorization policy
- an optional **single-node deployment** that runs both roles together while
  preserving the same token and revocation semantics

In that model, refresh-token and session mutation logic stay on the authority,
while resource services validate access tokens locally without per-request
introspection calls. Revocation consistency across resource nodes is therefore
bounded by the short access-token TTL.

## Feature model

This crate enables no optional features by default.

Main features:

- `authn` — authentication services; depends on `codecs`, `repositories`, and `secrets`
- `codecs` — re-export `webgates-codecs`
- `cookies` — cookie templates and cookie-dependent gate helpers
- `oauth2` — OAuth2 gate support; depends on `codecs`, `cookies`, and `repositories`
- `secrets` — re-export `webgates-secrets`
- `sessions` — framework-agnostic session lifecycle and renewal primitives
- `repositories` — repository contracts used by higher-level workflows
- `audit-logging` — structured audit events
- `prometheus` — Prometheus metrics for audit logging
- `full` — the standard composed stack

## Getting started on docs.rs

If you are reading this crate on docs.rs, this is a good order to follow:

1. Start with the re-exported core model in [`accounts`], [`roles`], [`groups`],
   and [`permissions`].
2. Read [`gate`] to understand the main higher-level abstraction.
3. Read [`cookie_template`] if you use browser cookies.
4. Read [`authn`] if you are implementing login/logout workflows.
5. Explore feature-gated re-exports such as `codecs`, `secrets`, and `sessions`
   based on your application needs.

## Design notes

- `webgates-core` owns the core domain and authorization API.
- `webgates` extends that API with optional higher-level functionality.
- `webgates-axum` owns Axum-specific integration.
- `webgates-repositories` owns persistence backends and repository modules.
*/

pub use webgates_core::validate_permissions;
pub use webgates_core::{
    accounts, authz, credentials, errors_core, groups, permissions, roles, verification_result,
};

#[cfg(feature = "audit-logging")]
pub mod audit;
#[cfg(feature = "authn")]
pub mod authn;
#[cfg(feature = "cookies")]
pub use cookie;
#[cfg(feature = "codecs")]
pub use webgates_codecs as codecs;
#[cfg(feature = "cookies")]
pub mod cookie_template;
#[cfg(any(
    feature = "authn",
    feature = "codecs",
    feature = "cookies",
    feature = "secrets"
))]
pub mod errors;
#[cfg(any(feature = "codecs", feature = "cookies"))]
pub(crate) mod errors_integration;
#[cfg(any(feature = "codecs", feature = "cookies", feature = "oauth2"))]
pub mod gate;
#[cfg(feature = "secrets")]
pub use webgates_secrets as secrets;
#[cfg(feature = "sessions")]
pub use webgates_sessions as sessions;
