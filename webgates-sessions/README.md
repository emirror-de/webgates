# webgates-sessions

User-focused session lifecycle and renewal primitives for the `webgates` ecosystem.

`webgates-sessions` is the session layer of the workspace. It provides the framework-agnostic types, repository contracts, and service workflows needed to issue, renew, rotate, and revoke session-backed authentication.

This crate intentionally keeps HTTP and cookie behavior out of scope. That lets session rules live in one place while adapters such as `webgates-axum` remain responsible for request parsing, cookie extraction, and response mutation.

## Who this crate is for

Use `webgates-sessions` when you want to:

- issue short-lived auth tokens backed by longer-lived refresh-token sessions
- model refresh-token rotation and replay handling
- coordinate renewal attempts with short-lived leases
- implement framework-agnostic session issuance, renewal, and revocation
- define or implement repository contracts for persisted session state
- build custom integrations outside HTTP frameworks

If you want the higher-level application composition, use `webgates`.
If you want Axum transport integration, use `webgates-axum`.
If you want repository implementations, use `webgates-repositories`.

## What this crate provides

`webgates-sessions` is designed for applications that want:

- short-lived auth tokens
- long-lived refresh-token-backed sessions
- framework-agnostic session issuance and renewal
- replay-aware refresh-token rotation
- explicit repository contracts for persistent session storage
- deterministic in-memory-friendly semantics for tests and local development

## Install

Add the crate directly if you want the session layer by itself:

```toml
[dependencies]
webgates-sessions = "1.0.0"
```

Or use it through the user-facing `webgates` composition crate:

```toml
[dependencies]
webgates = { version = "1.0.0", default-features = false, features = ["authn", "codecs", "repositories", "secrets", "sessions"] }
```

Minimum supported Rust version: `1.91`.

## The mental model

The easiest way to understand this crate is:

1. a successful login issues an auth token plus a refresh token
2. the auth token is short-lived and used for request authorization
3. the refresh token is long-lived, opaque, and stored only as a hash on the server side
4. renewal rotates the refresh token and usually issues a fresh auth token
5. replay or logout can revoke one session or an entire session family

## Core concepts

### 1. Session-backed authentication

A successful login can issue:

- an auth token for request authorization
- an opaque refresh token for session continuity

The auth token is intended to be short-lived. The refresh token is intended to be stored only as a hash on the server side and rotated whenever renewal succeeds.

### 2. Renewal coordination

Concurrent renewal attempts are coordinated through short-lived renewal leases:

- one request acquires the lease and performs rotation
- parallel requests can detect lease contention
- near-expiry requests may continue when the current auth token is still valid
- expired-auth requests require successful renewal before proceeding

### 3. Replay handling

Refresh-token reuse after rotation is treated as a compromise signal. Session implementations built on this crate can revoke the affected session family when replay is detected.

## How the crate is organized

The crate is split by responsibility so you can learn it in layers:

- `session` and `tokens` define the core session and token domain types
- `config` and `context` define the inputs that shape issuance and renewal behavior
- `renewal`, `lease`, and `logout` define the lifecycle transitions and coordination rules
- `repository` defines the persistence contract
- `services` wires those pieces into issue, renew, and revoke workflows
- `errors` defines the session-layer failure model

## Services

The crate exposes three primary service types:

- `SessionIssuer`
- `SessionRenewer`
- `SessionRevoker`

These services stay transport-agnostic so they can be called from HTTP adapters, CLI tools, workers, or other integration layers.

### Minimal session lifecycle

The three services map to the three lifecycle transitions a session-backed auth flow needs:

```rust,ignore
use std::time::SystemTime;
use webgates_sessions::config::SessionConfig;
use webgates_sessions::logout::LogoutRequest;
use webgates_sessions::services::{SessionIssuer, SessionRenewer, SessionRevoker};

// Issue: called on successful login.
let issued = session_issuer.issue_session("user@example.com", SystemTime::now()).await?;

// Renew: called when the client presents a refresh token.
let renewed = session_renewer.renew_session(renewal_context).await?;

// Revoke: called on logout.
let outcome = session_revoker.revoke_session(LogoutRequest::current_session(session_id)).await?;
```

For a complete working HTTP composition, see `webgates-axum`.

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

For local development and tests, use the in-memory repository from `webgates-repositories`.
For persistent storage, use backend adapters such as the session repository support in `webgates-repositories`.

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

## Integration with Axum

For Axum applications, keep this crate in the core layer and use `webgates-axum` for the HTTP boundary.

Typical Axum composition includes:

- `webgates::authn::SessionLoginService` for session-backed login
- `webgates::authn::SessionLogoutService` for session-backed logout
- `webgates_axum::route_handlers::login_with_sessions`
- `webgates_axum::route_handlers::logout_with_sessions`
- `webgates_axum::session::CookieSessionLayer`

This keeps cookie extraction and `Set-Cookie` mutation in the Axum adapter while renewal rules and revocation semantics remain here.

## Distributed deployment model

Use the same lifecycle for both single-node and distributed deployments:

- **Auth authority**: owns login, refresh-token session state, renewal, logout, and access-token minting
- **Resource services**: validate short-lived access tokens locally and enforce authorization
- **Single-node deployment**: runs both roles in one process

This keeps the public behavior identical across deployment modes while limiting cross-node coupling. Revocation consistency is bounded by the short access-token TTL.

## Security notes

- use persistent signing keys in production
- keep auth tokens short-lived
- treat refresh tokens as opaque high-entropy secrets
- store refresh tokens only as hashes on the server side
- rotate refresh tokens on successful renewal
- revoke the affected session family when replay is detected
- avoid logging raw auth tokens, refresh tokens, or secret material
- keep adapter cookies `HttpOnly`, `Secure`, and narrowly scoped where possible

## Recommended onboarding path

If you are new to this crate, I recommend this order:

1. `session`
2. `tokens`
3. `config`
4. `renewal`
5. `repository`
6. `services`
7. `logout` and `lease`

## Validation

Typical validation commands for this crate:

- `cargo test -p webgates-sessions`
- `cargo test --doc -p webgates-sessions`

## Which crate should you use?

- use `webgates-sessions` when you need the session lifecycle and renewal layer directly
- use `webgates` when you want the higher-level application-facing composition crate
- use `webgates-axum` when you want Axum transport integration for session-backed flows
- use `webgates-repositories` when you need repository implementations for session persistence

## Related crates

- `webgates` - user-facing composition crate
- `webgates-axum` - Axum adapter layer
- `webgates-repositories` - repository implementations and storage backends
- `webgates-codecs` - auth-token codecs
- `webgates-secrets` - hashing and secret primitives

## License

MIT

For the distributed deployment operations guide, see `docs/distributed-sessions.md` in the repository root.
