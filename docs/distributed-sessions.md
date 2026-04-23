# Distributed session operations handbook

This guide defines the canonical `webgates` session model for distributed
systems.

Use this guide for:

- architecture decisions,
- key-management rollout,
- auth and resource service configuration,
- incident response for compromised sessions or keys,
- and deployment sequencing.

Single-node applications should use the same model. A single-node deployment is
the collocated form of the distributed architecture in this document.

## Canonical architecture

### Roles

- **Auth authority service**
  - verifies login credentials,
  - creates and persists session state,
  - rotates refresh tokens,
  - revokes sessions and session families,
  - mints access JWTs with an ES384 private key.
- **Resource service**
  - validates access JWTs locally,
  - enforces authorization policy,
  - never mints tokens,
  - never performs refresh rotation,
  - never owns session persistence.

### Why this split

- Keeps refresh/session complexity in one place.
- Keeps resource-service request paths local and fast.
- Avoids per-request introspection network calls.
- Preserves the same auth semantics across single-node and distributed
  deployments.

## Trust boundaries

- Private key material is authority-only.
- Resource services receive public key material only.
- Refresh tokens are handled only by authority-owned handlers.
- Access tokens are validated on every resource request.

## Token and claim model

Canonical access-token claims in `webgates` helper-minted flows:

- `iss`: issuer configured by the auth authority.
- `exp`: short-lived expiration.
- `iat`: issued-at timestamp.
- `jti`: always set for helper-minted JWTs.
- `sid`: set when token is session-backed.

Claim semantics:

- `jti` supports replay investigations and token lineage.
- `sid` binds session-backed access tokens to one server-side session identifier.
- Non-session helper-minted JWTs keep `sid` absent.

## TTL and revocation model

The canonical default access-token lifetime is short (15 minutes).

Operational trade-off:

- Revocation consistency across resource nodes is bounded by access-token TTL.
- This is intentional and replaces per-request introspection.

Guidance:

- Keep access-token TTL short unless a specific workload requires a justified
  exception.
- Prefer tighter TTL over added request-path coupling.

## Key management

## Algorithm and formats

- Signing algorithm: **ES384**.
- Public-key discovery format: JWKS (`GET /.well-known/jwks.json`).
- Resource-node baseline configuration: `JWKS_URL`.
- PEM is still used at the authority boundary to load signer keys.

## Key generation

Generate an ES384 keypair:

```bash
mkdir -p keys
openssl ecparam -name secp384r1 -genkey -noout -out keys/auth-es384-private.pem
openssl ec -in keys/auth-es384-private.pem -pubout -out keys/auth-es384-public.pem
```

## Distribution rules

- Auth authority receives both private and public PEM.
- Resource services fetch only public verification keys from JWKS.
- Never copy private keys to resource services.
- Keep key material outside source control.
- Publish JWKS at `/.well-known/jwks.json` from the authority.

## `webgates` codec configuration patterns

Authority signer configuration:

```rust
use webgates::codecs::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims};

let options = JsonWebTokenOptions::from_es384_pem(
    private_pem.as_bytes(),
    public_pem.as_bytes(),
)?;

let codec = JsonWebToken::<JwtClaims<Account<Role, Group>>>::new_with_options(options);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Resource verifier-only configuration through JWKS:

```rust
use distributed::jwks::{JwksConsumerConfig, JwksVerifier};

let verifier = JwksVerifier::bootstrap(
    JwksConsumerConfig::from_jwks_url("http://127.0.0.1:3000/.well-known/jwks.json"),
)
.await?;

let _claims = verifier.verify_token("<jwt>").await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

### JWKS startup and fail-closed behavior

Consumer startup is deterministic:

1. Load optional last-known-good JWKS cache (`JWKS_CACHE_PATH`) when configured.
2. Attempt live JWKS fetch from `JWKS_URL`.
3. If live fetch succeeds, replace in-memory keys and cache.
4. If live fetch fails but cache exists, start in degraded mode with cached keys.
5. If both live fetch and cache are unavailable, startup fails closed.

This keeps request-path verification local and avoids per-request network fetches.

### Refresh and unknown-`kid` recovery

- Background refresh runs periodically (`JWKS_REFRESH_SECS`, default 60s).
- On unknown `kid`, consumers trigger one immediate bounded refresh and retry once.
- If key is still unknown, token is rejected as unauthenticated.

Rotation guidance:

- Publish new key in JWKS before switching signer.
- Keep retired verification key published for at least access-token TTL plus skew.
- Remove retired key only after overlap window closes.

## Authority and resource setup checklist

## Auth authority setup

1. Configure ES384 private and public key material.
2. Configure issuer string, cookie names, and access-token TTL.
3. Wire login endpoints through `login_with_sessions` when using session-backed
   flows.
4. Wire logout endpoint through `logout_with_sessions`.
5. Keep refresh-token renewal in authority-owned session services.

## Resource service setup

1. Configure JWKS consumer with `JWKS_URL`.
2. Configure `Gate::cookie(...)` or `Gate::bearer(...)` with matching issuer.
3. Apply authorization policy per route.
4. Do not expose refresh or session-mutation endpoints.

## Deployment topologies

## Collocated topology (single node)

- Auth authority and resource routes in one process.
- Same responsibilities, same claim semantics, same TTL behavior.

## Split topology (distributed)

- Auth authority as dedicated service.
- One or more resource services with public-key-only validation.
- Shared behavior remains identical from the client perspective.

## Rollout sequence

Recommended rollout for new or migrated environments:

1. Generate ES384 keypair.
2. Deploy authority with signer config.
3. Deploy resources with public key and verifier-only config.
4. Validate login path through authority.
5. Validate resource authorization with authority-issued tokens.
6. Validate logout and renewal through authority endpoints.

## Rollback sequence

If rollout fails:

1. Stop issuing new tokens from the failing authority version.
2. Roll back authority and resource configuration as a pair.
3. Keep issuer and key expectations aligned between rolled-back services.
4. Re-run end-to-end login, authorize, renew, and logout checks.

## Key rotation

Current recommended operational pattern:

- Plan a coordinated rotation window.
- Distribute next public key to resource services.
- Switch authority signer to next private key.
- Ensure all nodes converge on expected public key set.
- Revoke high-risk sessions when compromise is suspected.

If your environment requires uninterrupted overlap windows, document your
multi-key validation approach explicitly in service configuration and release
playbooks.

## Replay and incident response

### Refresh token replay

- Treat refresh-token reuse after rotation as compromise signal.
- Revoke the affected session family.
- Force re-authentication.

### Suspected private key compromise

1. Stop token issuance on compromised authority instance.
2. Rotate ES384 keypair.
3. Deploy new public key to all resource services.
4. Revoke active high-risk sessions.
5. Audit issuance and access logs using `jti` and `sid` correlation.

### Suspected token theft

- Revoke targeted session or family.
- Reduce TTL temporarily if needed during containment.
- Require user re-login for impacted identities.

## Observability and audit guidance

- Log request and correlation identifiers.
- Log auth outcomes and high-level reason categories.
- Avoid logging raw tokens, cookies, or secrets.
- Include `jti` and `sid` in safe internal audit correlation fields when needed.

## Validation commands

From repository root:

```bash
nix develop -c cargo check -p distributed
nix develop -c cargo test -p distributed
nix develop -c cargo test -p webgates --all-features authn
nix develop -c cargo test -p webgates-axum --all-features session
```

## Related references

- `examples/distributed/README.md`
- `webgates-sessions/README.md`
- `webgates-axum/README.md`
- `webgates-codecs/README.md`
