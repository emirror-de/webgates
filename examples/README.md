# Examples

This directory contains curated examples demonstrating common setups for the `webgates` workspace.

Start with `simple-usage` for a self-contained Axum server that exercises cookie-based login, logout, roles, groups, and permission guards — no external services required.

## Available examples

| Directory | Package name | What it demonstrates |
|-----------|-------------|----------------------|
| `simple-usage` | `simple-usage-example` | Minimal Axum server with cookie auth, login/logout handlers, role and group guards |
| `custom-roles` | `custom-roles-example` | Defining and using application-specific role hierarchies |
| `permission-validation` | `permission-validation-example` | Test-time permission collision validation with `validate_permissions!` |
| `permission-registry` | `permission-registry-example` | Optional permission mapping registry for reverse lookup and audit logging |
| `rate-limiting` | `rate-limiting-example` | Combining `webgates-axum` gates with `tower` rate limiting middleware |
| `prometheus` | `prometheus-example` | Prometheus metrics integration for auth and authorization events |
| `distributed` | `distributed` | Canonical authority/resource deployment with ES384-signed JWTs and public-key verification |
| `oauth2-github` | `oauth2-github` | GitHub OAuth2 Authorization Code + PKCE flow with first-party JWT cookie issuance |

Backend-specific examples also live under the `webgates-repositories` crate:

- `webgates-repositories/examples/sea-orm` — SeaORM account and session repository setup
- `webgates-repositories/examples/surrealdb` — SurrealDB account and session repository setup

## Running examples

All commands are run from the **workspace root** unless noted otherwise.

### simple-usage

No prerequisites — uses in-memory repositories and a generated JWT key.

```bash
cargo run -p simple-usage-example
```

### custom-roles

No prerequisites.

```bash
cargo run -p custom-roles-example
```

### permission-validation

Runs as a test (the macro generates a `#[test]` function).

```bash
cargo test -p permission-validation-example
```

### permission-registry

No prerequisites — uses in-memory repositories.

```bash
cargo run -p permission-registry-example
```

### rate-limiting

No prerequisites.

```bash
cargo run -p rate-limiting-example
```

### prometheus

No prerequisites — uses in-memory repositories and a generated JWT key.

```bash
cargo run -p prometheus-example
```

Then visit:
- http://localhost:3000/ — home page with login form
- http://localhost:3000/admin — admin-only area (admin/admin)
- http://localhost:3000/metrics — Prometheus metrics endpoint

### distributed

Requires an `.env` file in `examples/distributed/`. Copy the provided `.env.example` and point it to ES384 PEM key files (or inline PEM values):

```bash
cp examples/distributed/.env.example examples/distributed/.env
# Edit .env and set JWT_ES384_* key variables
```

Start both nodes (each in a separate terminal from the workspace root):

```bash
cargo run -p distributed --bin auth_node
cargo run -p distributed --bin consumer_node
```

The auth node listens on http://127.0.0.1:3000 and the consumer node on http://127.0.0.1:3001. See `examples/distributed/README.md` for endpoint details.

### oauth2-github

Requires a GitHub OAuth application and an `.env` file. See `examples/oauth2-github/README.md` for the full setup guide.

```bash
cargo run -p oauth2-github
```

## Compile-checking all examples

```bash
cargo check -p simple-usage-example
cargo check -p custom-roles-example
cargo check -p permission-validation-example
cargo check -p permission-registry-example
cargo check -p rate-limiting-example
cargo check -p prometheus-example
cargo check -p distributed
cargo check -p oauth2-github
```
