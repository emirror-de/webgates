# Release notes

## v1.2.0

`webgates` v1.2.0 improves how authentication cookies are written across `webgates`, `webgates-axum`, and `webgates-sessions`.

The main goal of this release is simple: keep cookie lifetime handling aligned with issued tokens while making the implementation cleaner and more robust.

## Highlights

### More reliable auth cookie expiration

Authentication cookies are now written from typed server-side issuance metadata instead of re-reading expiration information from encoded JWT strings.

This keeps token issuance as the source of truth and improves the overall reliability of cookie expiration handling.

### Better browser compatibility

Persistent cookies now set both:

- `Max-Age`
- `Expires`

This improves compatibility across browsers and clients while preserving the intended lifetime behavior.

### Cleaner internals

`webgates-axum` no longer needs local JWT payload parsing for login and renewal cookie handling.

That makes the adapter layer simpler and removes unnecessary coupling to JWT internals.

## What stays the same

Session renewal still uses verified JWT claims to decide whether a token is valid, near expiry, or expired.

That behavior is intentional and remains the correct security model.

## Compatibility

This release is intended to be a non-breaking minor update, which is why `v1.2.0` is the right version.

Most users should not need to change anything.

If you depend directly on internal authentication result enums such as `LoginResult`, you may want to review those call sites before upgrading.
