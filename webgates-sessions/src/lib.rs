#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
/*!
# webgates-sessions

Framework-agnostic session lifecycle building blocks for `webgates` applications.

This crate defines the core types and contracts needed to issue, renew, rotate,
and revoke session-backed authentication without depending on HTTP adapters,
cookies, or any specific web framework.

## When to use this crate

Use `webgates-sessions` when you want:

- framework-agnostic session issuance and renewal
- refresh-token rotation and replay handling
- repository contracts for persisted session state
- lease coordination for concurrent renewal attempts
- transport-independent session services

## Key modules

The crate is split by responsibility so you can learn it in layers:

- [`session`] and [`tokens`] define the core domain and token types
- [`config`] and [`context`] define issuance and renewal inputs
- [`renewal`], [`lease`], and [`logout`] define lifecycle transitions and coordination rules
- [`repository`] defines the persistence contract
- [`services`] wires the pieces together into issue, renew, and revoke workflows
- [`errors`] defines the session-layer failure model

These modules keep transport concerns in adapter crates such as
`webgates-axum`.

## Distributed deployment model

The same session lifecycle works for both single-node and distributed
applications.

Canonical responsibilities are:

- **Auth authority**: verifies credentials, issues auth and refresh tokens,
  persists session state, rotates refresh tokens, revokes sessions or session
  families, and owns signing keys.
- **Resource service**: validates short-lived access tokens locally,
  enforces authorization policy, never rotates refresh tokens, and never owns
  session persistence.
- **Single-node deployment**: runs both roles in one process while keeping the
  same token and revocation semantics.

This separation keeps refresh-token and session mutation logic in one place
while preserving fast local authorization on resource requests.

## Trust boundaries and token model

In the canonical distributed setup:

- private signing keys stay on the auth authority only
- resource services receive public verification keys only
- refresh tokens are handled only by authority-owned login, renewal, and logout flows
- access tokens are validated on every protected resource request

Helper-minted session-backed access tokens use a short-lived JWT plus a
long-lived refresh-token session. The `jti` claim supports audit correlation
and token lineage, while the `sid` claim binds a session-backed access token to
one server-side session identifier.

Revocation consistency across resource nodes is intentionally bounded by the
short access-token TTL. That trade-off avoids per-request introspection network
calls while keeping refresh-token rotation and replay-aware revocation in the
session layer.

## Getting started

A good first path is to read [`session`], [`tokens`], and [`services`] together.
That gives you the main domain model, token model, and workflow layer in order.
*/

/// Typed session configuration.
pub mod config;
/// Request and session context inputs.
pub mod context;
/// Session-layer error types.
pub mod errors;
/// Renewal lease coordination types.
pub mod lease;
/// Logout and revocation intent types.
pub mod logout;
/// Renewal flow inputs and outcomes.
pub mod renewal;
/// Persistence contracts for session storage.
pub mod repository;
/// Session issuance, renewal, and revocation workflows.
pub mod services;
/// Session and session-family domain types.
pub mod session;
/// Auth and refresh token primitives.
pub mod tokens;
