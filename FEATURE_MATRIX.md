# Feature Matrix

This document defines the canonical feature set for all webgates workspace crates and the minimal feature combinations that must compile.

## Purpose

This matrix serves as the authoritative source for:
- Feature definitions across all workspace crates
- Minimal feature combinations that must compile successfully
- CI validation requirements
- README documentation accuracy

## Core Principles

1. **No default features**: All crates ship with `default = []` to minimize dependencies
2. **Minimal feature combinations**: Each feature should be independently compilable when possible
3. **Clear dependency chains**: Features that require other features should declare dependencies explicitly
4. **Consistent naming**: Feature names should be consistent across crates where applicable

## Workspace Feature Matrix

### webgates

**Features:**
- `default = []`
- `wasm = ["uuid/js"]` - WASM compatibility
- `codecs = ["dep:chrono", "dep:serde_json", "dep:serde_with", "dep:webgates-codecs"]` - JWT/token encoding
- `secrets = ["dep:rand", "dep:webgates-secrets"]` - Secret handling and hashing
- `repositories = ["dep:webgates-repositories"]` - Repository contracts
- `sessions = ["codecs", "repositories", "secrets", "dep:webgates-sessions"]` - Session management
- `cookies = ["codecs", "dep:cookie"]` - Cookie template support
- `oauth2 = ["codecs", "cookies", "repositories", "dep:oauth2"]` - OAuth2 flows
- `authn = ["codecs", "repositories", "secrets", "tokio/rt-multi-thread", "dep:tracing"]` - Authentication services
- `audit-logging = ["dep:tracing"]` - Structured audit events
- `prometheus = ["audit-logging", "dep:prometheus"]` - Prometheus metrics
- `full = ["authn", "audit-logging", "codecs", "cookies", "oauth2", "prometheus", "repositories", "secrets", "sessions"]`

**Minimal combinations that must compile:**
- `--no-default-features --features codecs`
- `--no-default-features --features cookies`
- `--no-default-features --features oauth2`
- `--no-default-features --features authn`
- `--features wasm`
- `--features full`

### webgates-core

**Features:**
- `default = []`

**Minimal combinations that must compile:**
- (default only)

### webgates-axum

**Features:**
- `default = []`
- `audit-logging = ["webgates/audit-logging"]`
- `prometheus = ["audit-logging", "dep:prometheus", "webgates/prometheus"]`

**Minimal combinations that must compile:**
- (default only)
- `--all-features`

### webgates-repositories

**Features:**
- `default = []`
- `audit-logging = []`
- `sessions = ["dep:webgates-sessions"]`
- `surrealdb = ["dep:serde_json", "dep:surrealdb", "dep:surrealdb-types"]`
- `sea-orm = ["dep:sea-orm", "dep:sea-query", "dep:serde_json"]`

**Minimal combinations that must compile:**
- (default only)
- `--features surrealdb`
- `--features sea-orm`
- `--all-features`

### webgates-sessions

**Features:**
- `default = []`

**Minimal combinations that must compile:**
- (default only)

### webgates-codecs

**Features:**
- `default = []`

**Minimal combinations that must compile:**
- (default only)

### webgates-secrets

**Features:**
- `default = []`

**Minimal combinations that must compile:**
- (default only)

### webgates-tonic

**Features:**
- `default = []`
- `audit-logging = ["webgates/audit-logging"]`
- `prometheus = ["audit-logging", "webgates/prometheus", "dep:prometheus"]`

**Minimal combinations that must compile:**
- (default only)
- `--all-features`

## CI Requirements

The following commands must pass for the feature matrix to be considered valid:

```bash
# Core validation commands
nix develop -c cargo fmt --all --check
nix develop -c cargo clippy --workspace --all-targets -- -D warnings
nix develop -c cargo test --workspace --all-targets
nix develop -c cargo test --workspace --doc

# Minimal feature combination tests (webgates)
nix develop -c cargo test -p webgates --no-default-features --features codecs
nix develop -c cargo test -p webgates --no-default-features --features cookies
nix develop -c cargo test -p webgates --no-default-features --features oauth2
nix develop -c cargo test -p webgates --no-default-features --features authn
nix develop -c cargo test -p webgates --features wasm
nix develop -c cargo test -p webgates --features full

# Repository backend tests
nix develop -c cargo test -p webgates-repositories --features surrealdb
nix develop -c cargo test -p webgates-repositories --features sea-orm
nix develop -c cargo test -p webgates-repositories --all-features

# All other crates with default features
nix develop -c cargo test -p webgates-core
nix develop -c cargo test -p webgates-axum --all-features
nix develop -c cargo test -p webgates-sessions
nix develop -c cargo test -p webgates-codecs
nix develop -c cargo test -p webgates-secrets
nix develop -c cargo test -p webgates-tonic --all-features
```

## Maintenance

When adding, removing, or modifying features:

1. Update this document first
2. Update the relevant `Cargo.toml` files
3. Update README documentation
4. Verify all documented features and commands stay aligned with the corresponding `Cargo.toml` files
5. Run the relevant Nix-shell validation commands from this document
6. Update CI workflow if new minimal combinations are required

## Validation

Use the Nix-shell validation commands above to validate that:
- All documented features exist in the actual `Cargo.toml` files
- No undocumented features exist in `Cargo.toml` files
- All minimal feature combinations compile successfully
- Feature dependencies are correctly declared
