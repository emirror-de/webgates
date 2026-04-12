# Custom Roles Example

This example demonstrates how to define application-specific role hierarchies, groups, and access policies in `webgates`.

## What it demonstrates

- Defining a custom role enum with an ordered hierarchy (`Novice < Experienced < Expert`)
- Defining custom groups (`Maintenance`, `Operations`, `Administration`)
- Using `AccessHierarchy` so higher roles satisfy lower-role policies
- Protecting Axum routes with role, group, and permission guards
- Cookie-based login/logout handlers

## Routes

- `POST /login` — authenticate with JSON credentials and receive a session cookie
- `GET /logout` — clear the session cookie
- `GET /admin` — requires the `Expert` role
- `GET /reporter` — requires `Experienced` or any supervisor (i.e., `Expert`)
- `GET /user` — requires `Novice`
- `GET /secret-admin-group` — requires the `Maintenance` group

## Setup

Copy `.env.example` to `.env` and set a strong random secret:

```bash
cp examples/custom-roles/.env.example examples/custom-roles/.env
# Edit .env and set a strong random value for webgates_SHARED_SECRET
```

The `.env` file is listed in `.gitignore` and must not be committed.

## Run

From the workspace root:

```bash
cargo run -p custom-roles-example
```

The server listens on http://127.0.0.1:3000.
