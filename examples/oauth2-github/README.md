# OAuth2 with GitHub example

This example shows how to plug GitHub as an OAuth2 provider into `webgates` using the built-in `Gate::oauth2()` flow. After a successful Authorization Code + PKCE round-trip with GitHub, the example mints a first‑party JWT and sets it as a secure HTTP‑only cookie to authenticate against your app (so you can continue to use the familiar `CookieGate` for protected routes).

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
  - `GITHUB_CLIENT_ID=…`          (required)
  - `GITHUB_CLIENT_SECRET=…`      (required)
  - `GITHUB_REDIRECT_URL=http://localhost:3000/auth/callback` (optional; defaults to `http://{APP_ADDR}/auth/callback`)

- First‑party JWT/session settings:
  - `JWT_ES384_PRIVATE_KEY_PATH=...` and `JWT_ES384_PUBLIC_KEY_PATH=...` (optional; set both to load persistent PEM files)
  - `JWT_ES384_PRIVATE_KEY_PEM=...` and `JWT_ES384_PUBLIC_KEY_PEM=...` (optional; set both to load inline PEM values)
  - `JWT_ISSUER=my-app`                        (optional; default example value)
  - `AUTH_COOKIE_NAME=auth-token`              (optional; default example value)
  - `JWT_TTL_SECS=900`                         (optional; token lifetime in seconds; default `900`)
  - `POST_LOGIN_REDIRECT=/`                    (optional; where to send the user after login)
  - `ALLOW_INSECURE_LOCAL_COOKIES=true`        (optional; useful for intentional local HTTP development)

- Server:
  - `APP_ADDR=127.0.0.1:3000`                  (optional; bind address, default `127.0.0.1:3000`)

If you leave all `JWT_ES384_*` variables unset, the example falls back to `JsonWebTokenOptions::generate_for_testing()` and generates a fresh in-memory ES384 key pair on startup. That is convenient for local development, but JWTs issued before a restart will no longer verify after the process restarts.

If you configure JWT keys, provide a complete pair: either both `_PATH` variables or both inline `_PEM` variables. When both forms are present, the `_PATH` variables take precedence because the example reads the files first.

Example `.env`:

```dotenv
GITHUB_CLIENT_ID=iv1.abc123xyz
GITHUB_CLIENT_SECRET=shhh_its_a_secret
GITHUB_REDIRECT_URL=http://localhost:3000/auth/callback
JWT_ISSUER=my-app
AUTH_COOKIE_NAME=auth-token
JWT_TTL_SECS=900
POST_LOGIN_REDIRECT=/
APP_ADDR=127.0.0.1:3000
ALLOW_INSECURE_LOCAL_COOKIES=true

# Optional persistent JWT keys (set both, or leave all JWT_ES384_* vars unset)
# JWT_ES384_PRIVATE_KEY_PATH=examples/oauth2-github/keys/auth-es384-private.pem
# JWT_ES384_PUBLIC_KEY_PATH=examples/oauth2-github/keys/auth-es384-public.pem

# Optional inline PEM values (omit the _PATH vars if you use these)
# JWT_ES384_PRIVATE_KEY_PEM="-----BEGIN PRIVATE KEY-----..."
# JWT_ES384_PUBLIC_KEY_PEM="-----BEGIN PUBLIC KEY-----..."
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

For the fastest local setup, you can omit all JWT key variables and let the example generate ephemeral keys automatically. If you want logins to remain valid across restarts, configure a persistent PEM key pair instead.

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

- “State mismatch” or “Missing state cookie” on callback
  - Ensure you’re using the same domain/port as the configured callback URL, and that `APP_ADDR` matches the host/port in `GITHUB_REDIRECT_URL` (or the default generated redirect). A port mismatch will prevent the browser from sending the state cookie back.
  - Clear cookies and try again.

- “OAuth2 token exchange failed”
  - Double‑check `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, and the callback URL in GitHub app settings.
  - Confirm `GITHUB_REDIRECT_URL` matches exactly.

- Cookie not present on subsequent requests
  - This example keeps secure cookie settings by default. For local HTTP development, set `ALLOW_INSECURE_LOCAL_COOKIES=true`. In production, serve HTTPS and do not enable the insecure override.

- 401 on protected routes
  - The protected route likely uses `CookieGate` with a policy that denies all by default. Ensure login completed and the cookie is set, or adjust the policy (e.g., `.require_login()`).

## Security notes

- In production:
  - Always use HTTPS and set `Secure` cookies.
  - Keep JWT ES384 private keys only on the auth authority and distribute only
    the matching public key to verifier nodes.
  - Keep key material in a secret manager and rotate deliberately.
  - Validate scope needs (request the minimum).
  - Avoid logging access tokens or raw PII. The example logs minimally and never prints secrets.

- PKCE/state cookies are short‑lived and HttpOnly with SameSite=Lax, sufficient for standard cross‑site OAuth flows (browser redirect). Avoid using `SameSite=None` unless you understand the CSRF implications and enforce `Secure`.
