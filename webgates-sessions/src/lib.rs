#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
/*!
# webgates-sessions

Framework-agnostic session lifecycle building blocks for the `webgates`
ecosystem.

This crate defines the core types and contracts needed to issue, renew, and
revoke session-backed authentication without depending on HTTP adapters,
cookies, or any specific web framework.

## Public API

The crate is organized around explicit domain modules:

- [`config`] - typed session configuration
- [`context`] - request and session context inputs
- [`errors`] - session-layer error types
- [`lease`] - renewal lease coordination types
- [`logout`] - logout and revocation intent types
- [`renewal`] - renewal flow inputs and outcomes
- [`repository`] - persistence contracts for session storage
- [`services`] - session issuance, renewal, and revocation workflows
- [`session`] - session and session-family domain types
- [`tokens`] - auth and refresh token primitives

These modules keep transport concerns in adapter crates such as
`webgates-axum`.
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
/// In-memory session repository for tests and local composition.
pub mod memory;
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
