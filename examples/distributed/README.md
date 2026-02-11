# `axum-gate` Distributed System Example with Nested Enum Permissions

This example demonstrates how to use `axum-gate` within a distributed system where all nodes share the same secret for encryption, featuring a type-safe nested enum permission system with strum serialization.

## Features

- **Zero-Sync Permissions**: No coordination required between distributed nodes
- **Type-Safe Nested Enums**: Organized permission structure with compile-time safety
- **Strum Integration**: Automatic serialization/deserialization support
- **Performance Optimized**: High-performance permission checking with roaring bitmaps (64-bit `RoaringTreemap`)
- **Collision Resistant**: SHA-256 based deterministic permission IDs

## Architecture

The example consists of two nodes:

1. **Auth Node** (`auth_node.rs`) - Issues JWT tokens with permission bitmaps
2. **Consumer Node** (`consumer_node.rs`) - Validates permissions without coordination

## How to Run and Test with Insomnia/Postman

This example is intended to be exercised using an external HTTP client such as Insomnia, Postman, or curl.

1) Prerequisites
- Rust toolchain installed
- Create an `.env` file in this directory with a strong shared secret:

```env
AXUM_GATE_SHARED_SECRET=your-super-secret-key-here-make-it-long-and-random
```

2) Start the Auth Node

```bash
cargo run --bin auth_node
```

The auth node listens on http://127.0.0.1:3000.

3) Start the Consumer Node (in a separate shell)

```bash
cargo run --bin consumer_node
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
