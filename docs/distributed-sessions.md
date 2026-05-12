# Distributed session operations guide

This guide is the operational companion to the rustdoc for `webgates`,
`webgates-sessions`, and `webgates-axum`.

Use rustdoc for:

- API structure and type-level behavior
- session lifecycle and repository contracts
- Axum login, logout, JWKS, and renewal integration
- high-level authority/resource deployment semantics

Use this guide for:

- key-management rollout
- JWKS bootstrap and rotation operations
- deployment sequencing
- rollback planning
- replay and compromise response

The conceptual distributed-session model now lives primarily in rustdoc. This
file intentionally focuses on the remaining operational guidance.

## Key management

### Algorithm and formats

- Signing algorithm: **ES384**.
- Public-key discovery format: JWKS (`GET /.well-known/jwks.json`).
- Resource-node baseline configuration: `JWKS_URL`.
- PEM is still used at the authority boundary to load signer keys.

### Key generation

Generate an ES384 keypair:

```bash
mkdir -p keys
openssl ecparam -name secp384r1 -genkey -noout -out keys/auth-es384-private.pem
openssl ec -in keys/auth-es384-private.pem -pubout -out keys/auth-es384-public.pem
```

### Distribution rules

- Auth authorities receive both private and public PEM.
- Resource services fetch only public verification keys from JWKS.
- Never copy private keys to resource services.
- Keep key material outside source control.
- Publish JWKS at `/.well-known/jwks.json` from the authority.

## JWKS consumer operations

### Startup and fail-closed behavior

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
- If the key is still unknown, the token is rejected as unauthenticated.

### Rotation overlap guidance

- Publish the new key in JWKS before switching the signer.
- Keep the retired verification key published for at least access-token TTL plus skew.
- Remove the retired key only after the overlap window closes.

## Deployment topologies

### Collocated topology (single node)

- Auth authority and resource routes live in one process.
- Responsibilities stay the same as in the distributed model.
- Claim semantics and TTL behavior stay the same.

### Split topology (distributed)

- Auth authority runs as a dedicated service.
- One or more resource services validate with public keys only.
- Client-visible auth behavior remains the same across nodes.

## Rollout sequence

Recommended rollout for new or migrated environments:

1. Generate the ES384 keypair.
2. Deploy the authority with signer configuration.
3. Deploy resources with JWKS-based verifier configuration.
4. Validate login through the authority.
5. Validate resource authorization with authority-issued tokens.
6. Validate logout and renewal through authority-owned endpoints.

## Rollback sequence

If rollout fails:

1. Stop issuing new tokens from the failing authority version.
2. Roll back authority and resource configuration as a pair.
3. Keep issuer and key expectations aligned between rolled-back services.
4. Re-run end-to-end login, authorize, renew, and logout checks.

## Key rotation

Recommended operating pattern:

1. Plan a coordinated rotation window.
2. Publish the next public key in JWKS.
3. Switch the authority signer to the next private key.
4. Wait for all consumer nodes to converge on the expected key set.
5. Remove the retired public key after the overlap window closes.
6. Revoke high-risk sessions when compromise is suspected.

If your environment requires uninterrupted multi-key overlap beyond this basic
flow, document that service-specific policy in your deployment playbooks.

## Replay and incident response

### Refresh-token replay

- Treat refresh-token reuse after rotation as a compromise signal.
- Revoke the affected session family.
- Force re-authentication.

### Suspected private key compromise

1. Stop token issuance on the compromised authority instance.
2. Rotate the ES384 keypair.
3. Publish and deploy the replacement public key to all resource services.
4. Revoke active high-risk sessions.
5. Audit issuance and access logs using `jti` and `sid` correlation.

### Suspected token theft

- Revoke the targeted session or family.
- Reduce access-token TTL temporarily if needed during containment.
- Require user re-login for impacted identities.

## Observability and audit guidance

- Log request and correlation identifiers.
- Log auth outcomes and high-level reason categories.
- Avoid logging raw tokens, cookies, or secrets.
- Include `jti` and `sid` in safe internal audit correlation fields when needed.

## Validation commands

From the repository root:

```bash
nix develop -c cargo check -p distributed
nix develop -c cargo test -p distributed
nix develop -c cargo test -p webgates --all-features
nix develop -c cargo test -p webgates-axum --all-features
```

## Related references

- `examples/distributed/README.md`
- `webgates-sessions/README.md`
- `webgates-axum/README.md`
- `webgates-codecs/README.md`
