# Security Policy

This document outlines the security practices, built-in protections, and deployment guidance for `webgates` v2.0.0-dev.

---

## 1. Supported Versions

| Version | Supported |
| ------- | --------- |
| 2.0.0-dev | ✅ |
| < 2.0.0-dev | ❌ |

Only the latest stable release and the most recent release candidate receive security updates.

---

## 2. Password & Secret Security

### Argon2id Implementation
- **Algorithm**: Uses Argon2id (latest variant) with cryptographically secure parameters
- **Salting**: Each password gets a unique, randomly generated salt using `OsRng`
- PHC string format: Stores Argon2id hashes in the standard PHC string format
- **No Plaintext Storage**: Only Argon2id hashes are persisted; plaintext secrets never touch disk

### Configurable Security Levels
The crate provides three security presets:

| Preset | Memory (MiB) | Time Cost | Parallelism | Use Case |
|--------|--------------|-----------|-------------|----------|
| `HighSecurity` | 64 | 3 | 1 | Production (default in release) |
| `Interactive` | 32 | 2 | 1 | User-facing applications |
| `DevFast` | 4 | 1 | 1 | Development only (debug builds) |

**Default Behavior**:
- Release builds: `HighSecurity` preset automatically
- Debug builds: `DevFast` preset (4 MiB memory, 1 iteration, 1 thread) for faster iteration
### Timing Attack Protection
- **Constant-Time Verification**: Always performs Argon2 computation, even for non-existent accounts
- **Dummy Hash Verification**: Uses a pre-computed dummy hash for non-existent users
- **Unified Error Response**: Returns generic `InvalidCredentials` for both "user not found" and "wrong password"
- **No Early Returns**: Authentication logic defers all branching until after hash computation

---

## 3. JWT Token Security

### Core Security Features
- **HMAC Signature Validation**: All tokens verified with configured signing key
- **Expiration Enforcement**: Standard `exp` claim validation with configurable lifetime
- **Issuer Validation**: Required `iss` claim must match expected issuer
- **Tamper Detection**: Any modification to payload or header invalidates signature
- **Algorithm Consistency**: Enforces that token algorithm matches expected algorithm

### Cryptographic Backend

By default, this crate uses the `rust_crypto` backend for JWT cryptographic operations.
This is a pure Rust implementation that doesn't require external dependencies.

The crate uses the `rust_crypto` backend by default, which is a pure-Rust implementation and does not require external system dependencies.

Note that the `rust_crypto` backend depends on the `rsa` crate which was affected by vulnerability
[RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) (Marvin Attack). This is a timing attack that could
potentially allow key recovery.

### Key Management
- **Development Default**: Uses embedded ES384 development keys (testing only)
- **Production Requirements**:
  - Use a stable ES384 keypair
  - Keep private keys only on auth-authority nodes
  - Distribute only the public key to verifier-only resource nodes
  - Load key material from environment variables, mounted files, or secret management systems
  - Store key material outside source control
  - Rotate keys deliberately with a rollout plan

**Example Production Setup**:
```rust
// Load PEM key material from files or env-backed secrets (recommended)
let private_pem = std::fs::read("/run/secrets/jwt-es384-private.pem")?;
let public_pem = std::fs::read("/run/secrets/jwt-es384-public.pem")?;

// Build options with persistent ES384 keys (avoid JsonWebToken::default in production)
use webgates::codecs::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims};
let options = JsonWebTokenOptions::from_es384_pem(&private_pem, &public_pem)?;

// Create a codec that survives restarts as long as key material remains stable
use std::sync::Arc;
use webgates::prelude::*;
let jwt_codec = Arc::new(
    JsonWebToken::<JwtClaims<Account<Role, Group>>>::new_with_options(options)
);
# Ok::<(), Box<dyn std::error::Error>>(())
```

For verifier-only resource nodes, use `JsonWebTokenOptions::for_es384_verification_only(&public_pem)?` so the node can validate but cannot mint JWTs.

---

## 4. Cookie Security

### Secure Cookie Configuration
When using cookie-based authentication, apply these security settings:

```rust
use webgates::prelude::*;
use cookie::SameSite;
use cookie::time::Duration;

// Recommended production cookie settings
let template = CookieTemplate::recommended()
    .name("auth-token")
    .persistent(Duration::hours(24)) // Explicit expiration
    .same_site(SameSite::Strict);    // Strong CSRF protection
let secure_cookie = template.build_with_value(&token_value);
```

### Security Recommendations
- **Always use `secure(true)` in production** (HTTPS required)
- **Set `http_only(true)`** to prevent JavaScript access (XSS mitigation)
- **Use `SameSite::Strict` or `Lax`** for CSRF protection
- **Avoid `SameSite::None`** unless cross-site requests are required
- **Consider `__Host-` prefix** for additional security (requires Secure + no Domain + Path="/")
- **Optional user context (cookies)**: When you need anonymous routes that can still personalize content, configure CookieGate with `allow_anonymous_with_optional_user()`. This never blocks requests and inserts `Option<Account<..>>` and `Option<RegisteredClaims>`; enforce access in handlers if required.

---

## 5. Authorization Security

### Access Control Model
- **Default Deny**: `Gate` with no policy denies all requests
- **Least Privilege**: Combine roles and permissions narrowly
- **Hierarchical Roles**: Parent-child relationships with explicit traversal
- **Fine-Grained Permissions**: 64-bit deterministic IDs from permission names
- **CookieGate optional mode**: For routes that should never be blocked but may use authenticated context when present, configure CookieGate with `allow_anonymous_with_optional_user()`. This installs `Option<Account<..>>` and `Option<RegisteredClaims>` without enforcing authentication or authorization in the middleware. Handlers must perform any necessary checks.
- **BearerGate modes**: Bearer gate supports (1) strict JWT mode (enforces policy), (2) optional mode via `allow_anonymous_with_optional_user()` (never blocks; inserts optional context), and (3) static token mode via `with_static_token("...")` for internal services.

### Permission System Safety
- **Deterministic Hashing**: Uses SHA-256 prefix for 64-bit permission IDs
- **Collision Validation**: Built-in `validate_permissions![]` macro for compile-time checks
- **Runtime Validation**: `PermissionCollisionChecker` for dynamic permission sets
- **Cross-Node Consistency**: Deterministic hashing ensures identical permission evaluation across distributed deployments

**Example Permission Validation**:
```rust
use webgates::prelude::*;

// Compile-time validation ensures no collisions
validate_permissions![
    "create:user",
    "update:user",
    "delete:user",
    "view:dashboard",
];
```

---

## 6. Rate Limiting Integration

While `webgates` doesn't provide rate limiting directly, it integrates seamlessly with `tower` middleware:

```rust
use tower::{ServiceBuilder, limit::RateLimitLayer, buffer::BufferLayer};

let protected_routes = Router::new()
    .route("/login", post(login_handler))
    .layer(
        ServiceBuilder::new()
            .layer(BufferLayer::new(1024))
            .layer(RateLimitLayer::new(5, Duration::from_secs(60))) // 5/minute
    );
```

**Recommended Rate Limits**:
- Login endpoints: 5-10 requests per minute per IP
- Password reset: 3 requests per hour per email
- Protected APIs: 100-1000 requests per minute per user
- Admin endpoints: 10-50 requests per minute

---

## 7. Storage Backend Security

### Repository Security
- **Interface Separation**: Account and secret repositories can use different backends
- **Least Privilege**: Database users should have minimal required permissions
- **Connection Security**: Use TLS/SSL for database connections in production
- **Backup Encryption**: Ensure backups of authentication data are encrypted

### Supported Backends
| Backend | Feature Flag | Production Ready | Notes |
|---------|--------------|------------------|-------|
| In-Memory | (default) | ❌ Development only | Lost on restart |
| SurrealDB | `surrealdb` | ✅ | Embedded or remote |
| SeaORM | `sea-orm` | ✅ | Multi-database support |

---

## 8. CSRF Protection Considerations

### Cookie-Based Authentication Risks
- **SameSite=None**: Vulnerable to CSRF attacks
- **SameSite=Lax**: Reduced CSRF risk, allows some cross-site navigation
- **SameSite=Strict**: Maximum CSRF protection, may break cross-site workflows

### Mitigation Strategies
1. **Primary**: Use `SameSite=Strict` for sensitive applications
2. **Alternative**: Implement double-submit cookie pattern
3. **API Clients**: Use header-based authentication with the Bearer gate (implemented), or static token mode for internal services

---

## 9. Session Management & Logout

### Stateless JWT Limitations
- **Client-Side Logout**: JWT tokens remain valid until expiration
- **No Server-Side Revocation**: Cannot immediately invalidate specific tokens
- **Global Invalidation**: Requires signing key rotation (invalidates all sessions)

### Logout Security
```rust
// Secure logout using webgates's built-in handler
use webgates::route_handlers::logout;
use axum_extra::extract::CookieJar;
use webgates::prelude::*;

async fn logout_handler(cookie_jar: CookieJar) -> CookieJar {
    let cookie_template = CookieTemplate::recommended().name("auth-token");
    logout(cookie_jar, cookie_template).await
}
```

---

## 10. Observability & Monitoring

### Current State (v2.0.0-dev)
- **Structured Logging**: Comprehensive tracing integration with contextual metadata for all authentication operations
- **Prometheus Metrics**: Built-in counters and histograms (authorization decisions, JWT validation latency, account operations)
- **Audit Logging**: Emits structured tracing events when `audit-logging` is enabled; integrate with your tracing subscriber/sink
- **Security Metrics**: Authorization success/denial tracking, JWT validation monitoring, account lifecycle events

### Prometheus Integration
Enable with the `prometheus` feature flag:

```rust
// Metrics are automatically collected and can be exposed
use webgates::prelude::*;
use webgates::audit::prometheus_metrics;

let registry = prometheus::Registry::new();
prometheus_metrics::install_prometheus_metrics_with_registry(&registry).expect("install metrics");

let app = Router::new()
    .route("/", get(handler).layer(
        Gate::cookie("app", jwt_codec)
            .with_policy(policy)
            .with_prometheus_registry(&registry) // Enable metrics collection
    ))
    .route("/metrics", get(metrics_handler));
```

**Available Metrics**:
- `webgates_authz_authorized_total` - Successful authorization decisions
- `webgates_authz_denied_total` - Denied authorization attempts (by reason)
- `webgates_jwt_invalid_total` - Invalid JWT tokens (by failure type)
- `webgates_account_delete_outcome_total` - Account deletion operations
- `webgates_account_insert_outcome_total` - Account creation operations
- `webgates_authz_decision_seconds` - Authorization decision latency (histogram; by outcome)
- `webgates_jwt_validation_seconds` - JWT validation latency (histogram; by outcome)

**Current Monitoring Setup**:
```rust
use tracing::{info, warn, error};

// Add to your application
tracing_subscriber::fmt()
    .with_max_level(tracing::Level::INFO)
    .init();

// Monitor authentication events
info!("User {} logged in successfully", user_id);
warn!("Failed login attempt for {}", user_id);
error!("Suspicious activity: {} failed attempts from {}", count, ip);
```

---

## 11. Production Hardening Checklist

| Category | Requirement | Status |
|----------|-------------|--------|
| **Transport Security** | ✅ HTTPS with HSTS | Required |
| **JWT Secrets** | ✅ High-entropy (≥32 bytes) | Required |
| **JWT Secrets** | ✅ External secret management | Recommended |
| **Argon2 Config** | ✅ HighSecurity preset in production | Default |
| **Cookie Security** | ✅ Secure, HttpOnly, SameSite | Required |
| **Rate Limiting** | ✅ Login endpoint protection | Recommended |
| **Database Security** | ✅ TLS connections | Required |
| **Backup Encryption** | ✅ Encrypted backups | Required |
| **Monitoring** | ✅ Prometheus metrics (feature flag) | Available |
| **Audit Logging** | ✅ Basic audit logging (feature flag) | Available |

✅ = Built-in or available
⚠️ = Requires external implementation

---

## 12. Security Audit Status

**Current Status**: The project uses automated security scanning with the following configuration:

**Temporarily Disabled Advisories**:
- `RUSTSEC-2024-0436`: Transitive dependency via surrealdb; upstream is tracking a fix/replacement for the `paste` crate

This advisory is actively monitored and will be addressed when the upstream dependency (surrealdb) provides a solution. The decision to temporarily disable allows continued development while proper mitigations are implemented.

**Audit Recommendations**:
- Run `cargo audit` regularly in your projects
- Monitor [RustSec Advisory Database](https://rustsec.org/advisories/)
- Subscribe to security mailing lists for dependencies
- Use `cargo deny` for comprehensive dependency policy enforcement

---

## 13. Input Validation & DoS Prevention

### Built-in Protections
- **Unicode Handling**: Full UTF-8 support for international passwords
- **Memory Safety**: Rust's ownership system prevents buffer overflows
- **Type Safety**: Strong typing prevents injection attacks

### Application-Level Recommendations
```rust
// Implement request size limits
use tower_http::limit::RequestBodyLimitLayer;

let app = Router::new()
    .layer(RequestBodyLimitLayer::new(1024 * 1024)) // 1MB limit
    .route("/login", post(login_handler));

// Validate input lengths
fn validate_password(password: &str) -> Result<(), ValidationError> {
    if password.len() > 128 {
        return Err(ValidationError::TooLong);
    }
    if password.len() < 8 {
        return Err(ValidationError::TooShort);
    }
    Ok(())
}
```

---

## 14. Error Handling Security

### Information Disclosure Prevention
- **Generic Error Messages**: Public APIs return user-friendly, non-revealing errors
- **Detailed Logging**: Full error context logged server-side only
- **Consistent Responses**: Same error format regardless of failure type

### Error Categories
```rust
// User-safe error responses
match auth_result {
    Err(Error::InvalidCredentials) => "Invalid username or password",
    Err(Error::AccountLocked) => "Account temporarily locked",
    Err(_) => "Authentication temporarily unavailable",
}
```

---

## 15. Feature Flags and Security

### Available Feature Flags (v2.0.0-dev)
| Feature | Security Impact | Recommendation |
|---------|-----------------|----------------|
| `full` | ✅ Enables the standard composed authentication stack | Recommended for most applications |
| `surrealdb` | ✅ Production-ready storage | Safe for production |
| `sea-orm` | ✅ Production-ready storage | Safe for production |
| `audit-logging` | ✅ Enhances security monitoring | Recommended for production |
| `prometheus` | ✅ Enables metrics collection | Recommended for production monitoring |

### Security Configuration
```rust
// Production-safe feature configuration
[dependencies]
webgates = {
    version = "2.0.0-dev",
    features = ["audit-logging", "prometheus"]
}
webgates-repositories = { version = "2.0.0-dev", features = ["surrealdb"] }

// Development configuration (faster hashing automatically enabled in debug builds)
[dev-dependencies]
webgates = { version = "2.0.0-dev" }
webgates-repositories = { version = "2.0.0-dev", features = ["surrealdb"] }
```

---

## 16. Reporting Security Vulnerabilities

### Coordinated Disclosure Process

1. **Do NOT** create public GitHub issues for security vulnerabilities
2. **Email**: Send reports to the maintainer (info@emirror.de)
3. **Include**:
   - Detailed vulnerability description
   - Steps to reproduce
   - Potential impact assessment
   - Suggested mitigation (if available)

### Response Timeline
- **Acknowledgment**: Within 48 hours
- **Assessment**: Within 1 week
- **Fix Development**: Within 2-4 weeks (depending on severity)
- **Public Disclosure**: After fix is released and users have time to update

### Security Advisory Publication
- Published on [GitHub Security Advisories](https://github.com/emirror-de/webgates/security/advisories)
- Cross-posted to [RustSec Advisory Database](https://rustsec.org/)
- Included in release changelog with CVE reference if applicable

---

## 17. Compliance Considerations

### Standards Alignment
- **OWASP**: Follows OWASP Authentication Guidelines
- **NIST**: Aligns with NIST Cybersecurity Framework
- **GDPR**: Supports data minimization and secure processing

### Industry-Specific Notes
- **HIPAA**: Additional encryption and audit logging may be required
- **PCI DSS**: Consider additional tokenization for payment applications
- **SOX**: Ensure audit trails are implemented for financial applications
- **SOC 2**: Built-in audit logging and monitoring features support compliance efforts

---

## 18. Development Security Practices

### Secure Development Lifecycle
- **Security-First Design**: Architecture reviews prioritize security
- **Automated Testing**: Security-focused unit and integration tests
- **Dependency Management**: Regular updates and vulnerability scanning with `cargo deny`
- **Code Review**: Security-focused review process

### Testing Security Features
```bash
# Run security-focused tests
cargo test security
cargo test timing_attack
cargo test permission_collision

# Audit dependencies
cargo audit

# Check dependency policies
cargo deny check

# Check for common security issues
cargo clippy -- -D warnings
```

---

## 19. Performance vs Security Trade-offs

### Argon2 Configuration
- **High Security**: Slower but cryptographically stronger (production default)
- **Interactive**: Balanced security and performance for user-facing apps
- **DevFast**: Fast but weaker security (development only)

### JWT vs Session Considerations
- **JWT Pros**: Stateless, scalable, no server-side session storage
- **JWT Cons**: Cannot revoke tokens before expiration, larger cookie size
- **Mitigation**: Short token lifetimes, refresh token rotation (planned v1.1.0)

---

**Stay Secure**: `webgates` v2.0.0-dev provides a robust security foundation with production-ready features. Defense-in-depth requires combining it with proper infrastructure hardening, monitoring, and operational security practices.

For the latest security updates and best practices, monitor the [GitHub repository](https://github.com/emirror-de/webgates) and [security advisories](https://github.com/emirror-de/webgates/security/advisories).
