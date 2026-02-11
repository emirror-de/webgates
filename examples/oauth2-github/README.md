# OAuth2 with GitHub example

This example shows how to plug GitHub as an OAuth2 provider into `axum-gate` using the built-in `Gate::oauth2()` flow. After a successful Authorization Code + PKCE round-trip with GitHub, the example mints a first‑party JWT and sets it as a secure HTTP‑only cookie to authenticate against your app (so you can continue to use the familiar `CookieGate` for protected routes).

Important: This example is for local development. Always review the Security notes at the bottom before deploying to production.

## What you’ll get

- A small Axum server on http://localhost:3000
- Routes:
  - GET `/auth/login` → redirects to GitHub OAuth consent
  - GET `/auth/callback` → handles GitHub redirect, issues first‑party session cookie
  - GET `/protected` → sample protected route (using CookieGate)
  - GET `/` → homepage with “Login with GitHub” link

## Prerequisites

- Rust (stable)
- A GitHub OAuth application (Client ID + Client Secret)
- A browser that can visit http://localhost:3000

## Create a GitHub OAuth App

1) Go to https://github.com/settings/developers → “OAuth Apps” → “New OAuth App”.
2) Fill in:
   - Application name: any friendly name
   - Homepage URL: http://localhost:3000
   - Authorization callback URL: http://localhost:3000/auth/callback
3) After creating the app, copy:
   - Client ID
   - Client Secret

Note: The callback URL must match exactly what you configure in this example.

## Environment variables

Create a `.env` file in your current working directory (see Run section) or export these in your shell:

- GitHub OAuth settings:
  - GITHUB_CLIENT_ID=…          (required)
  - GITHUB_CLIENT_SECRET=…      (required)
  - GITHUB_REDIRECT_URL=http://localhost:3000/auth/callback

- First‑party JWT/session settings:
  - JWT_SECRET=dev-very-secret-key           (required; use a strong secret in prod)
  - JWT_ISSUER=my-app                        (optional; default example value)
  - AUTH_COOKIE_NAME=auth-token              (optional; default example value)
  - JWT_TTL_SECS=86400                       (optional; token lifetime in seconds; default 86400)
  - POST_LOGIN_REDIRECT=/                    (optional; where to send the user after login)

- Server:
  - APP_ADDR=127.0.0.1:3000                  (optional; bind address, default 127.0.0.1:3000)

Example `.env`:

```
GITHUB_CLIENT_ID=iv1.abc123xyz
GITHUB_CLIENT_SECRET=shhh_its_a_secret
GITHUB_REDIRECT_URL=http://localhost:3000/auth/callback
JWT_SECRET=local-dev-secret-change-me
JWT_ISSUER=my-app
AUTH_COOKIE_NAME=auth-token
JWT_TTL_SECS=86400
POST_LOGIN_REDIRECT=/
APP_ADDR=127.0.0.1:3000
```

## Run

From the repository root:

- From the workspace root:
  - cargo run -p oauth2-github
  - Place your .env at the workspace root for this command
- Or change to the example directory and run:
  - cd examples/oauth2-github
  - cargo run
  - Place your .env inside examples/oauth2-github for this command

Then open http://localhost:3000 and click “Login with GitHub”.

## How it works (high level)

- GET `/auth/login`:
  - Generates a CSRF `state` and a PKCE verifier.
  - Stores both in short‑lived HTTP‑only cookies (SameSite=Lax).
  - Redirects to `https://github.com/login/oauth/authorize` with your configured scopes (e.g. `read:user user:email`).

- GET `/auth/callback`:
  - Validates `state` and PKCE.
  - Exchanges the `code` at `https://github.com/login/oauth/access_token`.
  - Optionally fetches GitHub user info (e.g., `GET https://api.github.com/user` and `GET https://api.github.com/user/emails`) to build your domain `Account`.
  - Issues a first‑party JWT via `JsonWebToken` and sets it in a secure, HTTP‑only cookie (`AUTH_COOKIE_NAME`).
  - Redirects the user to `POST_LOGIN_REDIRECT` (default “/”).

- Protected routes:
  - Use `CookieGate` as normal (role/group policies, permissions, etc.). The session cookie established by the OAuth2 callback authenticates the user.

## Provider endpoints (GitHub)

- Authorization URL: https://github.com/login/oauth/authorize
- Token URL: https://github.com/login/oauth/access_token
- User API (optional mapper):
  - https://api.github.com/user
  - https://api.github.com/user/emails

Scopes typically used:
- read:user
- user:email

## Mapping GitHub user → Account

For the example, we map a GitHub user to:

- `Account::new(user_login_or_email, &[Role::User], &[])`

You can extend this to look up roles/groups from your database or organization teams.

## Troubleshooting

- “State mismatch” on callback
  - Ensure you’re using the same domain/port as the configured callback URL.
  - Clear cookies and try again.

- “OAuth2 token exchange failed”
  - Double‑check `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, and the callback URL in GitHub app settings.
  - Confirm `GITHUB_REDIRECT_URL` matches exactly.

- Cookie not present on subsequent requests
  - If you’re using a non‑localhost domain over HTTP, `Secure` cookies may not stick. For development, defaults are relaxed (SameSite=Lax, Secure=false) for localhost. In production, you must serve HTTPS and set `Secure=true`.

- 401 on protected routes
  - The protected route likely uses `CookieGate` with a policy that denies all by default. Ensure login completed and the cookie is set, or adjust the policy (e.g., `.require_login()`).

## Security notes

- In production:
  - Always use HTTPS and set `Secure` cookies.
  - Keep JWT signing keys in a secret manager; rotate periodically.
  - Validate scope needs (request the minimum).
  - Avoid logging access tokens or raw PII. The example logs minimally and never prints secrets.

- PKCE/state cookies are short‑lived and HttpOnly with SameSite=Lax, sufficient for standard cross‑site OAuth flows (browser redirect). Avoid using `SameSite=None` unless you understand the CSRF implications and enforce `Secure`.
