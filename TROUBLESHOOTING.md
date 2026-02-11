# Troubleshooting

This guide consolidates the most common issues seen when integrating axum-gate with:
- CookieGate (JWT via HTTP-only cookies)
- OAuth2 (Authorization Code + PKCE → first‑party JWT cookie)
- Bearer (JWT via Authorization header, plus static token mode)

If you run into issues, skim the quick checklist first, then jump to the relevant section.

---

## Quick diagnostic checklist

- Environment
  - Are your env vars loaded where your binary runs (workspace root vs example dir)?
  - Is `JWT_SECRET` consistent everywhere you encode/decode JWTs?
  - Is the cookie name consistent between issuers/validators (`AUTH_COOKIE_NAME`)?
  - Is the OAuth2 callback URL exactly correct (including scheme, host, port, and path)?

- Cookies (web browser)
  - Can you see the cookie in dev tools after login? Is it HttpOnly? Does its name match your gate’s cookie template?
  - Is the cookie flagged `Secure` while you are on HTTP (localhost)? That won’t stick.
  - Are `SameSite` and `Secure` appropriate for redirect flows?

- JWT
  - Do the `issuer` and keys (enc/dec) match the ones used where tokens are validated?
  - Is token expiration reasonable (not immediately expired)? Check system clocks on all nodes.

- Bearer
  - Is `Authorization: Bearer <token>` present and correct?
  - Is your middleware in “optional” mode? Optional mode never blocks; 401s then come from another layer.

- OAuth2
  - State mismatch or missing cookies? Browser or domain/port mismatch typically causes this.
  - Token exchange failure? Check client id/secret, callback URL, request timeouts, and firewall/proxy.

- Logs
  - Run with `RUST_LOG=info,axum=info,hyper=info` for basic insight; `debug` can help with exchange flow.

---

## CookieGate (Cookie-based JWT) issues

### 401 on protected routes
Symptoms:
- Every call to a protected route returns 401 despite successful login.

Likely causes:
- Cookie not present (was not set or was set with wrong attributes).
- Cookie name mismatch between issuer and gate configuration.
- JWT codec uses a different key/issuer than the gate.

Resolution:
- Ensure your gate and login/logout handlers use the same cookie name:
  - If you changed the name (e.g., `auth-token`), configure it in both places.
- Ensure you use the same JWT codec and issuer string for issuing and validating:
  - The issuer used to mint `RegisteredClaims` must match `Gate::cookie("issuer", ...)`.
- Inspect cookies in your browser:
  - If cookie shows `Secure=true` on `http://localhost`, the cookie won’t be sent. Use dev defaults or explicitly disable `Secure` for local dev only.

### Cookie isn’t set after login
Symptoms:
- Login endpoint returns 200/redirect, but no cookie appears in dev tools.

Likely causes:
- `Secure=true` cookie on HTTP in development (cookie ignored).
- Domain/path mismatch (cookie scoped away).
- Cookie name mismatch; code sets cookie with one name, gate looks for another.

Resolution:
- For local development:
  - Use `CookieTemplate::recommended()` (in debug builds it defaults to `Secure=false` and `SameSite=Lax`).
  - If you explicitly set `SameSite=None`, you must also set `Secure=true` (browser requirement).
- In production:
  - Always serve HTTPS and set `Secure=true`.
  - Set appropriate `SameSite` (often `Lax` for redirect flows; `Strict` for sensitive operations).
- Verify the cookie `path` and `domain` attributes cover your routes.

### “SameSite=None requires Secure=true” error
Symptoms:
- Builder returns an error or gate route building fails with a message like:
  - SameSite=None requires Secure=true.

Cause:
- You set `SameSite=None` without `Secure=true`.

Resolution:
- In dev: avoid `SameSite=None`; prefer `Lax`.
- In prod: if you must use `SameSite=None`, also set `Secure=true`.

### Issuer or key mismatch
Symptoms:
- Cookie is present, but 401 persists; logs indicate JWT validation issues.

Causes:
- `RegisteredClaims::new(issuer, ...)` used one issuer, while `Gate::cookie("issuer", ...)` used a different one.
- Encoding and decoding keys differ.

Resolution:
- Use a single issuer string consistently.
- Ensure both encoder and decoder use the same symmetric key or coordinated asymmetric keys.

### Clock skew and expiry
Symptoms:
- Intermittent 401 near token issuance/expiry time.

Causes:
- System clock skew or too-short TTL.

Resolution:
- Synchronize clocks (NTP).
- Set a reasonable `JWT_TTL_SECS` in dev and prod.

---

## OAuth2 (Authorization Code + PKCE) issues

### “State mismatch” or “Missing state/PKCE”
Symptoms:
- Callback returns 400 with “OAuth2 authorization failed” or similar.

Causes:
- State/PKCE cookies not present (domain/port change between login and callback).
- You opened login on one host/port but configured callback for another.
- Browser blocked cookies (Secure flag or different site settings).

Resolution:
- Ensure the callback URL exactly matches what you configured in both your OAuth2 provider and your app.
- Keep scheme, host, and port consistent during the login round-trip.
- In dev, use `CookieTemplate::recommended()` defaults for state/PKCE cookies (short-lived, HttpOnly, SameSite=Lax).

### “OAuth2 token exchange failed”
Symptoms:
- 502/400 at callback; log shows token exchange failure.

Causes:
- Wrong client id/secret; callback URL mismatch in provider settings.
- Provider request blocked (firewall/proxy), or request timed out.
- Using wrong OAuth endpoints.

Resolution:
- Double-check provider configuration:
  - GitHub:
    - Authorization URL: https://github.com/login/oauth/authorize
    - Token URL: https://github.com/login/oauth/access_token
  - Ensure `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_REDIRECT_URL` match exactly.
- Verify network egress and DNS.
- Increase timeout (if necessary) in the exchange request.

### Auth cookie not present after successful OAuth2 callback
Symptoms:
- OAuth2 round-trip succeeds, but you don’t receive the first‑party auth cookie.

Causes:
- JWT codec not configured (no `with_jwt_codec`), or account mapper/inserter failed.
- Cookie template name mismatch with your protected routes.
- Post-login redirect occurs before cookie is visible due to domain/path mismatch.

Resolution:
- Ensure your `OAuth2Gate` is configured with:
  - `with_jwt_codec(issuer, codec, ttl_secs)`
  - `with_account_mapper(...)` (and optionally `with_account_repository(...)` for persistence)
  - `configure_cookie_template(|tpl| tpl.name("auth-token"))` matching your `Gate::cookie` usage.
- Check logs for “OAuth2 account mapping failed” or “OAuth2 session issuance failed”.

### Post-login redirect loop
Symptoms:
- After successful login, redirect returns you to login again.

Causes:
- Protected route uses a different cookie name or issuer than the OAuth2Gate used to mint the cookie.
- Cookie not applied to the route path/domain.

Resolution:
- Use a single cookie name across your app.
- Configure `Gate::cookie(...).configure_cookie_template(|tpl| tpl.name("same-name"))`.
- Ensure the cookie path/domain includes the protected routes.

---

## Bearer (Authorization header) issues

### 401 Unauthorized
Symptoms:
- API returns 401 for calls with a token.

Causes:
- Missing or malformed `Authorization` header (`Bearer` scheme required).
- JWT signed with a different key or issuer mismatch.
- Token is expired.

Resolution:
- Use `Authorization: Bearer <token>`.
- Ensure encoding/decoding keys and issuer match.
- Check expiration; increase TTL if appropriate.

### Optional mode confusion
Symptoms:
- You expect 401 on missing token but requests are passing through.

Cause:
- `allow_anonymous_with_optional_user()` was enabled, which never blocks.

Resolution:
- Remove optional mode if you want strict enforcement.
- Optional mode is intended for routes that can use user context when present without denying requests.

### Static token mode mistakes
Symptoms:
- 401 despite sending a shared secret token.

Causes:
- Wrong scheme (`Basic` or a custom header instead of `Bearer`).
- Provided token differs (whitespace, copy/paste, environment mismatch).

Resolution:
- Ensure `Authorization: Bearer <static_token>`.
- Confirm the token exactly matches `with_static_token("...")`.

---

## Observability and diagnostics

- Enable logs:
  - `RUST_LOG=info,axum=info,hyper=info` for typical operation
  - `RUST_LOG=debug,axum=info,hyper=info` to troubleshoot OAuth2 token exchange or cookie handling
- Add structured logs around login/callback:
  - Log endpoints hit, redirect URLs, and completion events (never log secrets or tokens).
- Check cookies with your browser dev tools:
  - Name, Secure, SameSite, Path, Domain, Max-Age/Expires.

---

## Environment variable quick reference (GitHub example)

- GitHub OAuth settings:
  - `GITHUB_CLIENT_ID` (required)
  - `GITHUB_CLIENT_SECRET` (required)
  - `GITHUB_REDIRECT_URL` (default: `http://localhost:3000/auth/callback`)

- First‑party JWT/session:
  - `JWT_SECRET` (required; strong secret in prod)
  - `JWT_ISSUER` (default: `my-app`)
  - `AUTH_COOKIE_NAME` (default: `auth-token`)
  - `JWT_TTL_SECS` (default: `86400`)
  - `POST_LOGIN_REDIRECT` (default: `/`)

- Server:
  - `APP_ADDR` (default: `127.0.0.1:3000`)

Placement:
- If you run with `cargo run -p oauth2-github`, place `.env` at the workspace root.
- If you run from `examples/oauth2-github`, place `.env` in that directory.

---

## When opening an issue

Please include:
- A short description (what you expected vs what happened).
- Which gate type (Cookie/OAuth2/Bearer) and relevant configuration (issuer, cookie name, SameSite/Secure).
- Relevant environment (dev/prod, scheme/host/port, reverse proxy).
- Minimal, redacted logs (no secrets, tokens, or full headers).
- The exact HTTP status and any error message surfaced by the example or crate.

This helps narrow down configuration vs logic errors quickly.

---