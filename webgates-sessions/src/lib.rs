#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
/*!
# webgates-sessions

User-focused session lifecycle building blocks for the `webgates` ecosystem.

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

## How the crate is organized

The crate is split by responsibility so you can learn it in layers:

- [`session`] and [`tokens`] define the core domain and token types
- [`config`] and [`context`] define issuance and renewal inputs
- [`renewal`], [`lease`], and [`logout`] define lifecycle transitions and coordination rules
- [`repository`] defines the persistence contract
- [`services`] wires the pieces together into issue, renew, and revoke workflows
- [`errors`] defines the session-layer failure model

These modules keep transport concerns in adapter crates such as
`webgates-axum`.

## Quick start

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
