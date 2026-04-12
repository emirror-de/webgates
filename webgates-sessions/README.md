# webgates-sessions

Framework-agnostic session lifecycle and JWT auto-renewal primitives for the `webgates` ecosystem.

This crate provides the transport-independent building blocks for issuing, renewing, and revoking session-backed authentication. It keeps session state, refresh-token rotation, replay handling, renewal leases, and revocation rules in a core crate, while HTTP adapters such as `webgates-axum` remain responsible for cookie extraction and response mutation.

## What this crate provides

`webgates-sessions` is designed for applications that want:

- short-lived auth tokens
- long-lived refresh-token-backed sessions
- framework-agnostic session issuance and renewal
- replay-aware refresh-token rotation
- explicit repository contracts for persistent session storage
- deterministic in-memory session storage for tests and local development

## Core concepts

### Session-backed authentication

A successful login can issue:

- an auth token for request authorization
- an opaque refresh token for session continuity

The auth token is intended to be short-lived. The refresh token is intended to be stored only as a hash on the server side and rotated whenever renewal succeeds.

### Renewal coordination

Concurrent renewal attempts are coordinated through short-lived renewal leases:

- one request acquires the lease and performs rotation
- parallel requests can detect lease contention
- near-expiry requests may continue when the current auth token is still valid
- expired-auth requests require successful renewal before proceeding

### Replay handling

Refresh-token reuse after rotation is treated as a compromise signal. Session implementations built on this crate can revoke the affected session family when replay is detected.

## Public API

The crate is organized around explicit domain modules:

- `config`: typed session configuration
- `context`: renewal and request context inputs
- `errors`: session-layer errors
- `lease`: renewal lease coordination types
- `logout`: logout and revocation intent types
- `renewal`: renewal flow requests, decisions, and outcomes
- `repository`: session persistence contracts
- `services`: session issuance, renewal, and revocation workflows
- `session`: session and session-family domain models
- `tokens`: auth and refresh-token primitives

## Install

Add the crate directly if you want the session layer by itself:

```toml
[dependencies]
webgates-sessions = "0.1"
```

Or use it through the user-facing `webgates` composition crate:

```toml
[dependencies]
webgates = { version = "0.1", default-features = false, features = ["authn", "codecs", "repositories", "secrets", "sessions"] }
```

MSRV: 1.91

## Typical responsibilities

This crate owns:

- session and session-family identifiers and records
- auth and refresh-token issuance primitives
- refresh-token hashing helpers
- renewal decision types and lease state
- repository traits for session creation, lookup, rotation, touch, and revocation
- service-layer workflows for issue, renew, and revoke operations

This crate does not own:

- HTTP cookie extraction
- HTTP response cookie writing
- framework middleware wiring
- route parsing or status-code mapping

Those concerns belong in adapter crates such as `webgates-axum`.

## Repository model

Applications provide a `SessionRepository` implementation to persist session state.

The repository contract covers:

- session creation
- session lookup by refresh-token hash
- session and family lookup
- refresh-record lookup
- renewal lease acquisition
- atomic refresh-token rotation
- current-session revocation
- family revocation
- session touch updates

For local development and tests, use the in-memory repository.

For persistent storage, use a backend adapter such as the session repository support in `webgates-repositories`.

## Services

The crate exposes three primary service types:

- `SessionIssuer`
- `SessionRenewer`
- `SessionRevoker`

These services are intended to remain transport-agnostic so they can be composed from HTTP adapters, CLI flows, or other integration layers without embedding framework-specific behavior.

### Minimal session lifecycle (conceptual)

The three services map to the three lifecycle transitions a session-backed auth flow needs:

```rust,ignore
use std::time::SystemTime;
use webgates_sessions::config::SessionConfig;
use webgates_sessions::logout::LogoutRequest;
use webgates_sessions::services::{SessionIssuer, SessionRenewer, SessionRevoker};

// Issue: called on successful login — returns an auth token and an opaque refresh token.
let issued = session_issuer.issue_session("user@example.com", SystemTime::now()).await?;
// issued.tokens.auth_token    — short-lived JWT for request authorization
// issued.tokens.refresh_token — opaque high-entropy token for renewal; store only its hash

// Renew: called when the client presents a refresh token (e.g. via CookieSessionLayer in Axum).
// Rotates the refresh token, extends the session, and issues a fresh auth token.
let renewed = session_renewer.renew_session(renewal_context).await?;

// Revoke: called on logout — removes the session (or the full family) from the repository.
let outcome = session_revoker.revoke_session(LogoutRequest::current_session(session_id)).await?;
```

For a complete working composition in Axum, see the `webgates-axum` crate and the `simple-usage` or `distributed` examples.

## Integration with Axum

For Axum applications, keep this crate in the core layer and use `webgates-axum` for the HTTP boundary.

Typical Axum composition includes:

- `webgates::authn::SessionLoginService` for session-backed login
- `webgates::authn::SessionLogoutService` for session-backed logout
- `webgates_axum::route_handlers::login_with_sessions`
- `webgates_axum::route_handlers::logout_with_sessions`
- `webgates_axum::session::CookieSessionLayer`

This keeps cookie extraction and `Set-Cookie` mutation in the Axum adapter while renewal rules and revocation semantics remain here.

## Security notes

- Use persistent signing keys in production.
- Keep auth tokens short-lived.
- Treat refresh tokens as opaque high-entropy secrets.
- Store refresh tokens only as hashes on the server side.
- Rotate refresh tokens on successful renewal.
- Revoke the affected session family when replay is detected.
- Avoid logging raw auth tokens, refresh tokens, or secret material.
- Keep adapter cookies `HttpOnly`, `Secure`, and narrowly scoped where possible.

## Validation

Typical validation commands for this crate:

- `cargo test -p webgates-sessions`
- `cargo test --doc -p webgates-sessions`

## Related crates

- `webgates`: user-facing composition crate
- `webgates-axum`: Axum adapter layer
- `webgates-repositories`: repository implementations and storage backends
- `webgates-codecs`: auth-token codecs
- `webgates-secrets`: hashing and secret primitives

## License

MIT
