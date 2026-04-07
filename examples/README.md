Examples

This directory contains curated examples demonstrating common setups.

- simple-usage: Minimal Axum application demonstrating cookie-based auth, login/logout handlers, roles and groups. Run with:

  cargo run -p examples --example simple-usage --manifest-path examples/simple-usage/Cargo.toml

- oauth2-github: OAuth2 Authorization Code + PKCE flow example (requires GitHub OAuth app credentials).
- prometheus: Shows Prometheus integration and metrics.
- permission-validation / permission-registry: Examples for permission registry validation.

Start with `simple-usage` for a development-focused demo that exercises webgates-axum features.
