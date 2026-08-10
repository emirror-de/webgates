# Troubleshooting

Common issues and quick resolutions when working with this workspace.

## Build failures due to missing items or unresolved imports

**Symptom**: `error[E0433]: failed to resolve` or `error[E0425]: cannot find function/type/value`.

**Cause**: Crates in this workspace ship with `default = []`. Modules and types that live behind a feature flag are not compiled unless you enable that flag.

**Fix**: Enable the relevant feature in your `Cargo.toml`. Common examples:

- Need `Gate`, `codecs::jwt`, or cookie helpers?
  ```toml
  webgates = { version = "1.1.0", features = ["codecs", "cookies", "authn"] }
  ```
- Need session-backed login/logout?
  ```toml
  webgates = { version = "1.1.0", features = ["sessions"] }
  ```
- Need Prometheus metrics?
  ```toml
  webgates = { version = "1.1.0", features = ["prometheus"] }
    webgates-axum = { version = "1.1.0", features = ["prometheus"] }
  ```
- Need the SurrealDB repository backend?
  ```toml
  webgates-repositories = { version = "1.1.0", features = ["surrealdb"] }
  ```
- Need the SeaORM repository backend?
  ```toml
  webgates-repositories = { version = "1.1.0", features = ["sea-orm"] }
  ```
- Need the in-memory session repository for tests or local dev?
  ```toml
  webgates-repositories = { version = "1.1.0", features = ["sessions"] }
  ```

Refer to `FEATURE_MATRIX.md` for the full list of available features and their dependencies.

## Feature matrix check fails

**Symptom**: The documented feature combinations or validation commands no longer match the actual workspace manifests.

**Fix**: Update `FEATURE_MATRIX.md` to match the `[features]` sections in the relevant `Cargo.toml` files, then re-run the Nix-shell validation commands documented there.

## Outdated API documentation

Regenerate docs locally:

```bash
nix develop -c cargo doc --workspace --no-deps
```

Then open `target/doc/webgates/index.html` in your browser.

## SurrealDB / SeaORM compilation errors

**Symptom**: Build fails when `surrealdb` or `sea-orm` feature is enabled.

**Cause**: These are optional backend features that pull in large transitive dependencies. They may also require system libraries (e.g., `libssl`).

**Fix**:
- Only enable the backend feature when you actually need it.
- For local development without a database, use the in-memory backends (no extra feature needed for accounts; use the `sessions` feature for the in-memory session repository).
- If you are on a system missing OpenSSL headers, install `libssl-dev` (Debian/Ubuntu) or `openssl-devel` (Fedora/RHEL) or rely on the `rustls` TLS backend by checking the upstream crate docs.

## Tests that depend on external services

**Symptom**: Integration tests or examples panic at startup because no database is reachable.

**Fix**: Some examples (e.g., `examples/distributed`, `webgates-repositories/examples/surrealdb`) start embedded databases. These do not require external setup. Other tests that connect to a real PostgreSQL or remote SurrealDB instance will need those services running. Check the test file doc comments or the example `README.md` for specific setup instructions.

## `cargo run -p <package>` not found

**Symptom**: `error: package ID specification ... did not match any packages`.

**Cause**: The package name in `Cargo.toml` may differ from the directory name.

**Fix**: Use the exact `name` from the relevant `Cargo.toml`. Workspace package names:

| Directory | Package name |
|-----------|-------------|
| `examples/simple-usage` | `simple-usage-example` |
| `examples/custom-roles` | `custom-roles-example` |
| `examples/permission-validation` | `permission-validation-example` |
| `examples/permission-registry` | `permission-registry-example` |
| `examples/prometheus` | `prometheus-example` |
| `examples/rate-limiting` | `rate-limiting-example` |
| `examples/distributed` | `distributed` |
| `examples/oauth2-github` | `oauth2-github` |

## OAuth2 example: "State mismatch" or missing callback cookie

**Symptom**: GitHub OAuth callback returns a state-mismatch error.

**Fix**:
- Ensure the `GITHUB_REDIRECT_URL` env var matches the callback URL configured in your GitHub OAuth app exactly, including scheme, host, and port.
- Clear your browser cookies and retry.
- Confirm `APP_ADDR` and the redirect URL use the same host/port.

## Login returns 401 immediately after successful OAuth2 callback

**Symptom**: Protected routes return 401 even though the OAuth2 login completed.

**Fix**: Verify that the cookie name and issuer are consistent between the OAuth2 callback (which sets the cookie) and the `Gate::cookie(...)` configuration (which reads it). A name or issuer mismatch causes silent validation failure.

## Clippy or format errors in CI

**Fix**: Run locally before pushing:

```bash
nix develop -c cargo fmt --all
nix develop -c cargo clippy --workspace --all-targets -- -D warnings
```

## Still stuck?

Open an issue with:
- Steps to reproduce
- Rust version (`rustc --version`)
- Output of the failing command (`cargo test`, `cargo check`, etc.)
- Which features you have enabled
