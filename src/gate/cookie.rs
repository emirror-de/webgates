//! Cookie-based JWT authentication gate for browser apps (HTTP-only cookies).
//!
//! This module implements the cookie-backed gate returned by `Gate::cookie(...)`.
//! It validates a JWT carried in a secure, HTTP-only cookie and enforces an
//! [`AccessPolicy`] in strict mode, or it can operate in an optional, non-blocking
//! mode that merely injects user context if present.
//!
//! Modes and installed request extensions:
//! - Strict (default): validates the cookie JWT and enforces policy; on success
//!   inserts `Account<R, G>` and `RegisteredClaims`; on failure returns 401.
//! - Optional (`allow_anonymous_with_optional_user()`): never blocks; inserts
//!   `Option<Account<R, G>>` and `Option<RegisteredClaims>` where `Some(..)` is
//!   provided only when a valid JWT cookie is present; policy is not evaluated.
//!
//! # Typical usage (strict):
//! ```rust
//! # use axum::{routing::get, Router};
//! # use std::sync::Arc;
//! # use axum_gate::prelude::*;
//! # async fn admin() {}
//! let jwt = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! let policy = AccessPolicy::<Role, Group>::require_role(Role::Admin);
//!
//! let app = Router::<()>::new()
//!     .route("/admin", get(admin))
//!     .layer(
//!         Gate::cookie("my-app", Arc::clone(&jwt))
//!             .with_policy(policy)
//!     );
//! ```
//!
//! # Optional user context (never blocks):
//! ```rust
//! # use std::sync::Arc;
//! # use axum_gate::prelude::*;
//! let jwt = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! let gate = Gate::cookie::<_, Role, Group>("my-app", jwt)
//!     .allow_anonymous_with_optional_user(); // inserts Option<Account>, Option<RegisteredClaims>
//! ```
//!
//! # Convenience for “any authenticated user”:
//! ```rust
//! # use std::sync::Arc;
//! # use axum_gate::prelude::*;
//! let jwt = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! let gate = Gate::cookie::<_, Role, Group>("my-app", jwt)
//!     .require_login(); // baseline role + all supervisors
//! ```
//!
//! # Cookie template configuration
//! ```rust
//! # use std::sync::Arc;
//! # use axum_gate::prelude::*;
//! let jwt = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! let gate = Gate::cookie::<_, Role, Group>("my-app", jwt)
//!     .configure_cookie_template(|tpl| {
//!         tpl.name("auth-token")
//!            .persistent(cookie::time::Duration::hours(24))
//!     })?;
//! # Ok::<_, axum_gate::cookie_template::CookieTemplateBuilderError>(())
//! ```
//!
//! # Security notes
//! - Cookies are built via `CookieTemplate::recommended()` which provides sensible,
//!   environment-aware defaults: `HttpOnly=true`, `Secure` on release builds, strict SameSite
//!   policies by default, and session cookies unless overridden.
//! - If you set `SameSite=None`, `Secure=true` is required by browsers; the template validator
//!   enforces safe combinations.
//! - Always run production behind HTTPS and prefer short-lived JWTs.
//!
//! # Prometheus metrics (feature-gated)
//! - When the `prometheus` feature is enabled you can enable lightweight metrics collection:
//!   - `with_prometheus_metrics()` installs metrics into the default registry
//!   - `with_prometheus_registry(&registry)` installs into a specific registry
//!
//! # Handler extraction examples
//! - Strict mode inserts concrete `Account<R, G>` and `RegisteredClaims` on success
//! - Optional mode inserts `Option<Account<R, G>>` and `Option<RegisteredClaims>`
pub(crate) mod cookie_service;

use self::cookie_service::CookieGateService;
use crate::authz::{AccessHierarchy, AccessPolicy};
use crate::codecs::Codec;
use crate::cookie_template::{CookieTemplate, CookieTemplateBuilderError};

use std::sync::Arc;

use tower::Layer;

/// A configured gate ready to be used as an axum layer.
///
/// This struct is created by `Gate::cookie()` and can be customized
/// with `with_policy()` and `with_cookie_template()` before being applied
/// as a layer to your routes.
///
/// # Troubleshooting
///
/// These issues commonly cause 401 Unauthorized responses and are easy to miss. Check them first:
///
/// 1) Cookie name mismatch
/// - Symptom: Login appears to succeed and a cookie is set, but protected routes still return 401.
/// - Cause: The login flow issued the cookie under one name, while the `CookieGate` middleware is
///   looking for a different cookie name.
/// - Fix: Ensure the same cookie template (or at least the same name) is used for both login and gate.
///   Use `CookieTemplate::recommended().name("your-auth-cookie")` and pass that template to:
///   - the login handler (when setting the cookie), and
///   - `Gate::cookie(...).with_cookie_template(template)`
///
/// 2) Issuer mismatch
/// - Symptom: 401 on protected routes with logs indicating an invalid issuer (if logging enabled).
/// - Cause: The expected issuer configured in `Gate::cookie("issuer", ..)` does not exactly match
///   the `RegisteredClaims::new("issuer", ..)` used when minting the JWT during login. The comparison
///   is exact and case‑sensitive.
/// - Fix: Use the same issuer string in both places (no extra whitespace, same case, consistent per‑environment).
///   Example: `Gate::cookie("my-app", codec)` and `RegisteredClaims::new("my-app", exp)`
///
/// Quick checklist:
/// - Verify cookie name is identical between the login cookie writer and `CookieGate`’s cookie template.
/// - Verify issuer string is identical between `Gate::cookie("<issuer>", ..)` and `RegisteredClaims::new("<issuer>", ..)`.
/// - If you changed cookie attributes (domain/path), ensure they still allow the browser to send the cookie
///   to your protected routes (same host/path scope).
#[derive(Clone)]
pub struct CookieGate<C, R, G>
where
    C: Codec,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq,
{
    issuer: String,
    policy: AccessPolicy<R, G>,
    codec: Arc<C>,
    cookie_template: CookieTemplate,
    // Internal flag set by `allow_anonymous_with_optional_user()`.
    // When true, the layer installs `Option<Account<R,G>>` and `Option<RegisteredClaims>`
    // for every request WITHOUT performing any authentication *or* authorization checks.
    // All requests pass through; handlers are responsible for enforcing policies.
    install_optional_extensions: bool,
}

impl<C, R, G> CookieGate<C, R, G>
where
    C: Codec,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq,
{
    /// Creates a new instance with default values and the given parameter.
    pub(super) fn new_with_codec(issuer: &str, codec: Arc<C>) -> Self {
        Self {
            issuer: issuer.to_string(),
            policy: AccessPolicy::deny_all(),
            codec,
            cookie_template: CookieTemplate::recommended(),
            install_optional_extensions: false,
        }
    }

    /// Sets the access policy for this gate.
    ///
    /// The access policy defines who has access to the protected routes. Access is granted
    /// if the authenticated user meets ANY of the policy requirements (OR logic).
    ///
    /// # Example
    /// ```rust
    /// # use axum_gate::authz::AccessPolicy;
    /// # use axum_gate::accounts::Account;
    /// # use axum_gate::codecs::jwt::{JsonWebToken, JwtClaims};
    /// # use axum_gate::prelude::{Role, Group, Gate};
    /// # use std::sync::Arc;
    /// # let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
    /// let gate = Gate::cookie("my-app", jwt_codec)
    ///     .with_policy(
    ///         AccessPolicy::require_role(Role::Admin)
    ///             .or_require_role(Role::Moderator)
    ///             .or_require_group(Group::new("emergency-access"))
    ///     );
    /// ```
    pub fn with_policy(mut self, policy: AccessPolicy<R, G>) -> Self {
        self.policy = policy;
        self
    }

    /// Configures the cookie template used for authentication.
    ///
    /// The cookie template defines how authentication cookies are created, including
    /// their name, security settings, and expiration. For production use, ensure
    /// cookies are configured securely.
    ///
    /// # Example
    /// ```rust
    /// # use axum_gate::authz::AccessPolicy;
    /// # use axum_gate::accounts::Account;
    /// # use axum_gate::codecs::jwt::{JsonWebToken, JwtClaims};
    /// # use axum_gate::prelude::{Role, Group, Gate, CookieTemplate};
    /// # use std::sync::Arc;
    /// # let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
    /// let cookie_template = CookieTemplate::recommended();
    /// let gate = Gate::cookie("my-app", jwt_codec)
    ///     .with_policy(AccessPolicy::<Role, Group>::deny_all())
    ///     .with_cookie_template(cookie_template);
    /// ```
    pub fn with_cookie_template(mut self, template: CookieTemplate) -> Self {
        self.cookie_template = template;
        self
    }

    /// Allow anonymous access and install optional user context.
    ///
    /// This configures the gate to **SKIP ALL authentication and authorization checks**.
    /// Every request is forwarded. The middleware will insert two extensions:
    /// - `Option<Account<R, G>>`
    /// - `Option<crate::codecs::jwt::RegisteredClaims>`
    ///
    /// They are `Some(..)` only if a valid authentication cookie with a decodable JWT
    /// is present; otherwise they are `None`.
    ///
    /// SECURITY: Because no access policy is enforced in this mode, you MUST
    /// perform any required role / group / permission checks inside your handlers.
    ///
    /// Typical use cases:
    /// - Public or marketing pages that can optionally personalize output
    /// - Gradual migration where routes become protected later
    /// - Soft-auth endpoints (show extra info when a user is logged in)
    pub fn allow_anonymous_with_optional_user(mut self) -> Self {
        self.install_optional_extensions = true;
        self
    }

    /// Convenience: configure the secure cookie template via a closure using the high-level `CookieTemplate`.
    /// Starts from [`CookieTemplate::recommended()`] each time.
    /// Invalid configurations (e.g. SameSite=None without Secure) will panic to surface misconfiguration early.
    ///
    /// # Example
    /// ```rust
    /// # use axum_gate::authz::AccessPolicy;
    /// # use axum_gate::accounts::Account;
    /// # use axum_gate::codecs::jwt::{JsonWebToken, JwtClaims};
    /// # use axum_gate::prelude::{Role, Group, Gate, CookieTemplate};
    /// # use std::sync::Arc;
    /// # let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
    /// let gate = Gate::cookie("my-app", jwt_codec)
    ///     .with_policy(AccessPolicy::<Role, Group>::deny_all())
    ///     .configure_cookie_template(|tpl| {
    ///         tpl.name("auth-token")
    ///            .persistent(cookie::time::Duration::hours(12))
    ///     });
    /// ```
    pub fn configure_cookie_template<F>(mut self, f: F) -> Result<Self, CookieTemplateBuilderError>
    where
        F: FnOnce(CookieTemplate) -> CookieTemplate,
    {
        let template = f(CookieTemplate::recommended());
        template.validate()?;
        self.cookie_template = template;
        Ok(self)
    }

    /// Enables Prometheus metrics for audit logging.
    ///
    /// This is a no-op unless the `prometheus` feature is enabled. It is safe to call
    /// multiple times; metrics will only be registered once.
    #[cfg(feature = "prometheus")]
    pub fn with_prometheus_metrics(self) -> Self {
        // Attempt to install metrics into the default registry; ignore errors to keep builder infallible.
        let _ = crate::audit::prometheus_metrics::install_prometheus_metrics();
        self
    }

    /// Installs Prometheus metrics for audit logging into the provided registry.
    ///
    /// Safe to call multiple times; metrics are only registered once.
    #[cfg(feature = "prometheus")]
    pub fn with_prometheus_registry(self, registry: &prometheus::Registry) -> Self {
        let _ =
            crate::audit::prometheus_metrics::install_prometheus_metrics_with_registry(registry);
        self
    }
}

impl<S, C, R, G> Layer<S> for CookieGate<C, R, G>
where
    C: Codec,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq + Clone,
{
    type Service = CookieGateService<C, R, G, S>;

    fn layer(&self, inner: S) -> Self::Service {
        if self.install_optional_extensions {
            CookieGateService::new_with_optional_extensions(
                inner,
                &self.issuer,
                Arc::clone(&self.codec),
                self.cookie_template.clone(),
            )
        } else {
            CookieGateService::new(
                inner,
                &self.issuer,
                self.policy.clone(),
                Arc::clone(&self.codec),
                self.cookie_template.clone(),
            )
        }
    }
}

impl<C, R, G> CookieGate<C, R, G>
where
    C: Codec,
    R: AccessHierarchy + std::fmt::Display,
    G: Eq,
{
    /// Configures the gate to allow any authenticated user (baseline role + all supervisors).
    ///
    /// This sets the access policy to allow the baseline role (least privileged) and
    /// all roles with higher privilege (according to the derived ordering where higher privilege < lower privilege).
    ///
    /// # Example
    /// ```rust
    /// # use axum_gate::authz::AccessPolicy;
    /// # use axum_gate::accounts::Account;
    /// # use axum_gate::codecs::jwt::{JsonWebToken, JwtClaims};
    /// # use axum_gate::prelude::{Role, Group, Gate};
    /// # use std::sync::Arc;
    /// let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
    /// let gate = Gate::cookie::<_, Role, Group>("my-app", jwt_codec).require_login();
    /// ```
    pub fn require_login(mut self) -> Self {
        let baseline = R::default();
        self.policy = AccessPolicy::require_role_or_supervisor(baseline);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{super::*, *};
    use crate::accounts::Account;
    use crate::groups::Group;
    use crate::roles::Role;

    use crate::codecs::jwt::{JsonWebToken, JwtClaims};
    use std::sync::Arc;

    #[test]
    fn cookie_creates_gate_with_deny_all_policy() {
        let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let gate: CookieGate<_, Role, Group> = Gate::cookie("test-app", jwt_codec);

        assert_eq!(gate.issuer, "test-app");
        assert!(gate.policy.denies_all());
    }

    #[test]
    fn require_login_creates_gate_with_user_or_supervisor_policy() {
        let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let gate: CookieGate<_, Role, Group> = Gate::cookie("test-app", jwt_codec).require_login();

        assert_eq!(gate.issuer, "test-app");
        assert!(!gate.policy.denies_all());
        assert!(gate.policy.has_requirements());

        // Should have one role requirement for User with supervisor access
        let role_requirements = gate.policy.role_requirements();
        assert_eq!(role_requirements.len(), 1);
        assert_eq!(role_requirements[0].role, Role::User);
        assert!(role_requirements[0].allow_supervisor_access);

        // Should not have any group or permission requirements
        assert!(gate.policy.group_requirements().is_empty());
        assert!(gate.policy.permission_requirements().is_empty());
    }

    #[test]
    fn with_policy_updates_access_policy() {
        let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let custom_policy: AccessPolicy<Role, Group> = AccessPolicy::require_role(Role::Admin);

        let gate: CookieGate<_, Role, Group> =
            Gate::cookie("test-app", jwt_codec).with_policy(custom_policy);

        assert!(!gate.policy.denies_all());
        let role_requirements = gate.policy.role_requirements();
        assert_eq!(role_requirements.len(), 1);
        assert_eq!(role_requirements[0].role, Role::Admin);
        assert!(!role_requirements[0].allow_supervisor_access);
    }

    #[test]
    fn with_cookie_template_updates_cookie_configuration() {
        let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let custom_template = CookieTemplate::recommended().name("custom-cookie");

        let _gate: CookieGate<_, Role, Group> =
            Gate::cookie("test-app", jwt_codec).with_cookie_template(custom_template);

        // Note: Cookie type doesn't expose a convenient public getter for name(), so we can't directly test this
        // The test verifies the method compiles and runs without error
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn configure_cookie_template_uses_closure() {
        let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());

        let _gate: CookieGate<_, Role, Group> = Gate::cookie("test-app", jwt_codec)
            .configure_cookie_template(|tpl| {
                tpl.name("configured-cookie")
                    .persistent(::cookie::time::Duration::hours(2))
            })
            .unwrap();

        // Note: Cookie type doesn't expose a convenient public getter for name(), so we can't directly test this
        // The test verifies the method compiles and runs without error
    }

    #[test]
    fn require_login_allows_all_role_hierarchy() {
        let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let gate: CookieGate<_, Role, Group> = Gate::cookie("test-app", jwt_codec).require_login();

        // The policy should allow User role with supervisor access, which means
        // it should allow User, Reporter, Moderator, and Admin roles
        let (role_requirements, _, _) = gate.policy.into_components();
        assert_eq!(role_requirements.len(), 1);

        let requirement = &role_requirements[0];
        assert_eq!(requirement.role, Role::User);
        assert!(requirement.allow_supervisor_access);

        // This effectively allows all roles in the hierarchy since User is the lowest
        // and allow_supervisor_access is true
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn require_login_can_be_chained_with_other_methods() {
        let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let gate: CookieGate<_, Role, Group> = Gate::cookie("test-app", jwt_codec)
            .require_login()
            .configure_cookie_template(|tpl| tpl.name("custom-auth"))
            .unwrap();

        // Note: CookieBuilder doesn't have a public name() method, so we can't directly test this
        // The test verifies the method compiles and runs without error
        assert!(!gate.policy.denies_all());
        assert!(gate.policy.has_requirements());
    }
}
