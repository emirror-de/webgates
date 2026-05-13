# webgates

[![Crates.io](https://img.shields.io/crates/v/webgates.svg)](https://crates.io/crates/webgates)
[![Documentation](https://docs.rs/webgates/badge.svg)](https://docs.rs/webgates)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Build Status](https://github.com/emirror-de/webgates/workflows/CI/badge.svg)](https://github.com/emirror-de/webgates/actions)

`webgates` is a Rust workspace for authentication, authorization, session-backed login flows, and transport adapters.

This repository is organized as a set of focused crates so you can either start from the main application-facing crate or adopt narrower layers directly.

## Workspace crates

The repository is organized into focused crates with clear boundaries:

- `webgates` — main application-facing composition crate for gates, authentication workflows, optional cookies, OAuth2, sessions, and observability
- `webgates-core` — foundational domain types and authorization primitives with no HTTP, codec, or session dependencies
- `webgates-codecs` — JWT codecs, validation helpers, ES384 key handling, and JWKS support
- `webgates-secrets` — secret value and password-hashing primitives for safe server-side credential handling
- `webgates-sessions` — framework-agnostic session issuance, renewal, refresh-token rotation, leases, and revocation primitives
- `webgates-repositories` — repository traits, in-memory implementations, repository-scoped services, and optional SeaORM / SurrealDB backends
- `webgates-axum` — Axum transport adapter for gates, login/logout handlers, JWKS publication, and transparent cookie-backed session renewal
- `webgates-tonic` — tonic server-side transport adapter for bearer-token authentication and authorization in gRPC services

## How to choose a crate

Typical usage patterns:

- start with `webgates` when you want the main application-facing composition layer
- use `webgates-core` directly for domain-only authorization logic
- use `webgates-codecs` when you need JWT handling without the higher-level stack
- use `webgates-secrets` when you need hashing and secret handling directly
- use `webgates-sessions` when you need the session lifecycle layer directly
- use `webgates-repositories` when you need repository contracts or storage backends directly
- add `webgates-axum` or `webgates-tonic` when you want transport integration

## Getting started

For most applications, start with the main composition crate:

```toml
[dependencies]
webgates = "1.0.0"
```

Common Axum setup with session-backed authentication:

```toml
[dependencies]
webgates = { version = "1.0.0", default-features = false, features = ["authn", "codecs", "cookies", "repositories", "secrets", "sessions"] }
webgates-axum = "1.0.0"
```

Use `webgates-repositories` for persistence backends such as in-memory, SeaORM, or SurrealDB. Backend support is feature-gated in that crate.

Minimum supported Rust version: `1.91`.

## How the workspace fits together

A typical application stack looks like this:

1. `webgates-core` defines accounts, roles, groups, permissions, and authorization primitives
2. `webgates` composes the core model with higher-level auth flows and optional features
3. `webgates-codecs`, `webgates-secrets`, `webgates-sessions`, and `webgates-repositories` provide narrower building blocks behind those higher-level flows
4. `webgates-axum` or `webgates-tonic` adapts the model to HTTP or gRPC transports

This keeps domain rules, token handling, secret handling, session lifecycle, persistence, and transport concerns in distinct layers.

## Workspace capabilities

Feature highlights available across the workspace include:

- cookie and bearer authentication
- explicit authorization policies
- session-backed authentication with refresh-token rotation
- repository contracts plus in-memory and database-backed implementations
- JWKS-based distributed verification
- Axum and tonic transport adapters
- optional audit logging and Prometheus integration

## Session-backed deployment model

When you enable session-backed authentication, the canonical deployment model is:

- an **auth authority** that verifies credentials, issues auth and refresh tokens, owns session persistence, and performs refresh-token rotation and revocation
- one or more **resource services** that validate short-lived access tokens locally and enforce authorization policy
- an optional **single-node deployment** that runs both roles together while preserving the same token and revocation semantics

In that model, refresh-token and session mutation logic stay on the authority, while resource services validate access tokens locally without per-request introspection calls. Revocation consistency across resource nodes is therefore bounded by the short access-token TTL.

For the distributed authority/resource operations guide, including key management and rollout guidance, see `docs/distributed-sessions.md`.

## Crate docs

- `webgates`: https://docs.rs/webgates
- `webgates-core`: https://docs.rs/webgates-core
- `webgates-codecs`: https://docs.rs/webgates-codecs
- `webgates-secrets`: https://docs.rs/webgates-secrets
- `webgates-sessions`: https://docs.rs/webgates-sessions
- `webgates-repositories`: https://docs.rs/webgates-repositories
- `webgates-axum`: https://docs.rs/webgates-axum
- `webgates-tonic`: https://docs.rs/webgates-tonic

## Repository docs and examples

- `docs/distributed-sessions.md` — distributed deployment operations guide
- `examples/distributed/README.md` — JWKS-first distributed setup example
- `examples/oauth2-github` — OAuth2 login flow example
- `examples/prometheus` — metrics integration example
- `examples/permission-validation` and `examples/permission-registry` — permission modeling examples
- `webgates-repositories/examples/sea-orm` and `webgates-repositories/examples/surrealdb` — backend examples
- `TROUBLESHOOTING.md` — common integration and debugging guidance

## Security and licensing notes

- keep signing keys persistent and out of source control in production
- avoid logging raw tokens, secrets, or cookies
- align issuer strings, cookie names, and cookie templates across the layers that mint, validate, write, and clear auth state
- enable only the features and crates you actually need
- review the `surrealdb` feature in `webgates-repositories` carefully before production use

SurrealDB is distributed under the Business Source License 1.1 (BUSL). If you enable the optional SurrealDB backend for development, CI, or distribution, review its license terms and comply with any obligations.

## Development

- run the full workspace test suite with `cargo test --workspace --all-features`
- run workspace checks with `cargo check --workspace --all-features`
- see crate-specific READMEs for focused API guidance
- see `docs/distributed-sessions.md` for deployment and rotation procedures
- see `CONTRIBUTING.md` for contributor setup, CI workflow, and local validation commands

## License

MIT
