# `webgates` Distributed System Example with Nested Enum Permissions

This example demonstrates the canonical distributed `webgates` model with one
auth authority and one resource consumer node. The auth authority signs
short-lived access JWTs with an ES384 private key. Consumer nodes validate those
JWTs locally using keys fetched from the authority JWKS endpoint.

## Features

- **Authority/resource split**: only the auth node mints JWTs and handles login/logout
- **JWKS discovery**: auth node publishes `/.well-known/jwks.json` and consumer uses `JWKS_URL`
- **Public-key verification on consumers**: consumer nodes validate locally without signing keys
- **Short-lived access tokens**: 15-minute access-token TTL by default
- **Zero-Sync Permissions**: No per-request node-to-node coordination required for authorization
- **Type-Safe Nested Enums**: Organized permission structure with compile-time safety
- **Strum Integration**: Automatic serialization/deserialization support
- **Performance Optimized**: High-performance permission checking with roaring bitmaps (64-bit `RoaringTreemap`)
- **Collision Resistant**: SHA-256 based deterministic permission IDs

## Architecture

The example consists of two nodes:

1. **Auth Node** (`auth_node.rs`) - verifies credentials and issues JWT auth cookies
2. **Consumer Node** (`consumer_node.rs`) - validates JWTs and enforces policies

## How to Run and Test with Insomnia/Postman

This example is intended to be exercised using an external HTTP client such as Insomnia, Postman, or curl.

1) Prerequisites
- Rust toolchain installed
- Copy `.env.example` to `.env` in this directory and configure ES384 keys:

```bash
cp examples/distributed/.env.example examples/distributed/.env
# Then either point *_PATH to PEM files or set inline *_PEM values.
```

The `.env` file is listed in the repository's `.gitignore` and must not be committed.

You can generate a local ES384 keypair with OpenSSL:

```bash
mkdir -p examples/distributed/keys
openssl ecparam -name secp384r1 -genkey -noout -out examples/distributed/keys/auth-es384-private.pem
openssl ec -in examples/distributed/keys/auth-es384-private.pem -pubout -out examples/distributed/keys/auth-es384-public.pem
```

2) Start the Auth Node

```bash
cargo run --bin auth_node
```

The auth node listens on http://127.0.0.1:3000.

It also publishes JWKS at:

- http://127.0.0.1:3000/.well-known/jwks.json

3) Start the Consumer Node (in a separate shell)

```bash
JWKS_URL=http://127.0.0.1:3000/.well-known/jwks.json cargo run --bin consumer_node
```

The consumer node listens on http://127.0.0.1:3001.

4) Obtain a Session Cookie (POST /login on Auth Node)

- URL: http://127.0.0.1:3000/login
- Method: POST
- Headers: Content-Type: application/json
- Body (choose one of the pre-configured users):

```json
{ "id": "admin@example.com", "secret": "admin_password" }
```

```json
{ "id": "reporter@example.com", "secret": "reporter_password" }
```

```json
{ "id": "user@example.com", "secret": "user_password" }
```

- On success, the response sets an HttpOnly authentication cookie. Configure your client to preserve cookies between requests.

5) Call Consumer Endpoints with the Cookie

Use the same client session (cookies preserved) to call:

- http://127.0.0.1:3001/               (public)
- http://127.0.0.1:3001/permissions    (requires API read permission)
- http://127.0.0.1:3001/user           (User role)
- http://127.0.0.1:3001/reporter       (Reporter role)
- http://127.0.0.1:3001/admin          (Admin role)
- http://127.0.0.1:3001/secret-admin-group (group "admin")

6) Logout (optional)

- URL: http://127.0.0.1:3000/logout
- Method: GET
- Clears the authentication cookie.

Notes
- The JWT is stored in a secure HttpOnly cookie using `CookieTemplateBuilder::recommended()` defaults.
- Access is enforced via `Gate::cookie(...).with_policy(AccessPolicy::...)` on the consumer node.
- Permissions use 64-bit deterministic IDs and can be passed to `require_permission(...)` as strings or enums that implement `AsPermissionName`.
- The consumer node cannot mint tokens and performs verification using fetched JWKS keys.
- Startup behavior is fail-closed when no live JWKS and no cache are available.
- Optional cache hardening:
  - `JWKS_CACHE_PATH=examples/distributed/.cache/jwks.json`
  - `JWKS_REFRESH_SECS=60`
  - `JWKS_HTTP_TIMEOUT_MS=3000`
- In this example, login and logout stay on the auth authority; consumer routes only validate and authorize.

For broader deployment, key rotation, and incident-response guidance, see
`docs/distributed-sessions.md`.
