//! Framework-agnostic cookie gate configuration.
//!
//! This module defines the cookie-backed gate builder without any dependency on
//! web frameworks or middleware stacks. Integration crates (e.g., `webgates-axum`)
//! adapt this configuration into concrete middleware/layers for their transport.
//!
//! - Strict mode (default): enforces the access policy; adapters should reject
//!   unauthorized requests.
//! - Optional mode (`allow_anonymous_with_optional_user`): adapters should skip
//!   authZ/authN enforcement and merely inject optional context if present.
//!
//! The cookie template is validated eagerly by `configure_cookie_template` and
//! lazily by adapters when applying `with_cookie_template`.

use std::fmt::Display;
use std::sync::Arc;

use crate::authz::{AccessHierarchy, AccessPolicy};
use crate::codecs::Codec;
use crate::cookie_template::{CookieTemplate, CookieTemplateBuilderError};

/// Builder/configuration for cookie-backed JWT gates (framework-agnostic).
#[derive(Clone, Debug)]
pub struct CookieGate<C, R, G>
where
    C: Codec,
    R: AccessHierarchy + Eq + Display,
    G: Eq,
{
    issuer: String,
    policy: AccessPolicy<R, G>,
    codec: Arc<C>,
    cookie_template: CookieTemplate,
    install_optional_extensions: bool,
}

impl<C, R, G> CookieGate<C, R, G>
where
    C: Codec,
    R: AccessHierarchy + Eq + Display,
    G: Eq,
{
    /// Internal constructor used by `Gate::cookie`.
    pub fn new_with_codec(issuer: &str, codec: Arc<C>) -> Self
    where
        R: Default,
    {
        Self {
            issuer: issuer.to_string(),
            policy: AccessPolicy::deny_all(),
            codec,
            cookie_template: CookieTemplate::recommended(),
            install_optional_extensions: false,
        }
    }

    /// Set an access policy (OR semantics between requirements).
    pub fn with_policy(mut self, policy: AccessPolicy<R, G>) -> Self {
        self.policy = policy;
        self
    }

    /// Replace the cookie template (adapters may re‑validate on application).
    pub fn with_cookie_template(mut self, template: CookieTemplate) -> Self {
        self.cookie_template = template;
        self
    }

    /// Configure the cookie template via a closure, validating immediately.
    pub fn configure_cookie_template<F>(mut self, f: F) -> Result<Self, CookieTemplateBuilderError>
    where
        F: FnOnce(CookieTemplate) -> CookieTemplate,
    {
        let template = f(CookieTemplate::recommended());
        template.validate()?;
        self.cookie_template = template;
        Ok(self)
    }

    /// Allow anonymous requests and only inject optional user context in adapters.
    ///
    /// In this mode, adapters should never block/deny requests; they may insert
    /// `Option<Account<R, G>>` / `Option<RegisteredClaims>` if a valid JWT cookie
    /// is present, otherwise `None`.
    pub fn allow_anonymous_with_optional_user(mut self) -> Self {
        self.install_optional_extensions = true;
        self
    }

    /// Convenience: allow any authenticated user (baseline role + supervisors).
    pub fn require_login(mut self) -> Self
    where
        R: Default,
    {
        let baseline = R::default();
        self.policy = AccessPolicy::require_role_or_supervisor(baseline);
        self
    }

    /// Issuer configured for this gate.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Access policy (deny-all by default).
    pub fn policy(&self) -> &AccessPolicy<R, G> {
        &self.policy
    }

    /// JWT codec.
    pub fn codec(&self) -> &Arc<C> {
        &self.codec
    }

    /// Cookie template used to read/write the auth cookie.
    pub fn cookie_template(&self) -> &CookieTemplate {
        &self.cookie_template
    }

    /// Whether optional mode is enabled (no blocking; adapters insert Option context).
    pub fn installs_optional_extensions(&self) -> bool {
        self.install_optional_extensions
    }

    /// Adapt this gate into a framework-specific layer using the provided adapter.
    pub fn adapt_with<A>(self, adapter: A) -> A::Output
    where
        A: CookieGateAdapter<C, R, G>,
    {
        adapter.adapt(self)
    }
}

/// Adapter trait to convert a framework-agnostic `CookieGate` into a concrete
/// middleware/layer for a specific web framework or transport.
pub trait CookieGateAdapter<C, R, G>
where
    C: Codec,
    R: AccessHierarchy + Eq + Display,
    G: Eq,
{
    /// Framework-specific output type produced by the adapter (e.g., middleware layer).
    type Output;

    /// Convert a framework-agnostic `CookieGate` into the framework-specific middleware/layer.
    fn adapt(&self, gate: CookieGate<C, R, G>) -> Self::Output;
}
