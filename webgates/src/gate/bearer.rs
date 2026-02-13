//! Framework-agnostic bearer gate configuration.
//!
//! This module holds the shared builder/configuration for bearer authentication
//! (JWT or static token) without pulling any web-framework or middleware
//! dependencies. Integration crates (e.g., `webgates-axum`) consume these types
//! and adapt them into concrete middleware/layers.
//!
//! The design mirrors the previous Axum-specific gate but keeps the core free of
//! `tower`/`http` dependencies. Adapters can map the configuration into their own
//! middleware types via the `BearerGateAdapter` trait.

use std::fmt::Display;
use std::sync::Arc;

use crate::authz::{AccessHierarchy, AccessPolicy};
use crate::codecs::Codec;

/// JWT mode configuration (compile-time).
#[derive(Clone)]
pub struct JwtConfig<R, G>
where
    R: AccessHierarchy + Eq + Display,
    G: Eq,
{
    policy: AccessPolicy<R, G>,
    optional: bool,
}

impl<R, G> std::fmt::Debug for JwtConfig<R, G>
where
    R: AccessHierarchy + Eq + Display,
    G: Eq,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtConfig")
            .field("optional", &self.optional)
            .finish_non_exhaustive()
    }
}

/// Static token mode configuration (compile-time).
#[derive(Clone, Debug)]
pub struct StaticTokenConfig {
    token: String,
    optional: bool,
}

/// Generic bearer gate with compile-time mode parameter.
#[derive(Clone, Debug)]
pub struct BearerGate<C, R, G, M>
where
    C: Codec,
    R: AccessHierarchy + Eq + Display,
    G: Eq,
{
    issuer: String,
    codec: Arc<C>,
    mode: M,
    _phantom: std::marker::PhantomData<(R, G)>,
}

impl<C, R, G> BearerGate<C, R, G, JwtConfig<R, G>>
where
    C: Codec,
    R: AccessHierarchy + Eq + Display,
    G: Eq + Clone,
{
    /// Create a JWT-mode bearer gate configuration with a deny-all policy by default.
    pub fn new_with_codec(issuer: &str, codec: Arc<C>) -> Self
    where
        R: Default,
    {
        Self {
            issuer: issuer.to_string(),
            codec,
            mode: JwtConfig {
                policy: AccessPolicy::deny_all(),
                optional: false,
            },
            _phantom: std::marker::PhantomData,
        }
    }

    /// Set access policy (OR semantics between requirements).
    /// Set the access policy (OR semantics between requirements).
    pub fn with_policy(mut self, policy: AccessPolicy<R, G>) -> Self {
        self.mode.policy = policy;
        self
    }

    /// Turn on optional mode (install `Option<Account>` / `Option<RegisteredClaims>` in adapters).
    /// Enable optional mode; adapters should forward requests and inject optional context.
    pub fn allow_anonymous_with_optional_user(mut self) -> Self {
        self.mode.optional = true;
        self
    }

    /// Convenience: allow any authenticated user (baseline role + supervisors).
    /// Convenience: allow the baseline role and all supervisors according to the hierarchy.
    pub fn require_login(mut self) -> Self
    where
        R: Default,
    {
        let baseline = R::default();
        self.mode.policy = AccessPolicy::require_role_or_supervisor(baseline);
        self
    }

    /// Transition to static token mode (drops policies).
    /// Switch to static token mode; policies are dropped in favor of exact token matching.
    pub fn with_static_token(
        self,
        token: impl Into<String>,
    ) -> BearerGate<C, R, G, StaticTokenConfig> {
        BearerGate {
            issuer: self.issuer,
            codec: self.codec,
            mode: StaticTokenConfig {
                token: token.into(),
                optional: false,
            },
            _phantom: std::marker::PhantomData,
        }
    }

    /// Return the configured issuer string.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Return the configured codec.
    pub fn codec(&self) -> &Arc<C> {
        &self.codec
    }

    /// Return the configured access policy.
    pub fn policy(&self) -> &AccessPolicy<R, G> {
        &self.mode.policy
    }

    /// Whether optional mode is enabled for this gate.
    pub fn is_optional(&self) -> bool {
        self.mode.optional
    }
}

impl<C, R, G> BearerGate<C, R, G, StaticTokenConfig>
where
    C: Codec,
    R: AccessHierarchy + Eq + Display,
    G: Eq + Clone,
{
    /// Enable optional mode (install StaticTokenAuthorized(bool) in adapters).
    /// Enable optional mode for static token gates; adapters should forward all requests.
    pub fn allow_anonymous_with_optional_user(mut self) -> Self {
        self.mode.optional = true;
        self
    }

    /// Return the configured issuer string.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Return the configured codec.
    pub fn codec(&self) -> &Arc<C> {
        &self.codec
    }

    /// Return the configured static bearer token.
    pub fn token(&self) -> &str {
        &self.mode.token
    }

    /// Whether optional mode is enabled for this static token gate.
    pub fn is_optional(&self) -> bool {
        self.mode.optional
    }
}

/// Adapter trait to convert a framework-agnostic `BearerGate` into a concrete
/// middleware/layer for a specific web framework or transport.
///
/// Framework crates implement this trait for their own adapter types to avoid
/// coupling the core crate to tower/http/axum. Example (in an integration
/// crate):
///
/// ```ignore
/// impl<C, R, G, M> BearerGateAdapter<C, R, G, M> for AxumBearerAdapter { .. }
/// ```
pub trait BearerGateAdapter<C, R, G, M>
where
    C: Codec,
    R: AccessHierarchy + Eq + Display,
    G: Eq,
{
    /// Framework-specific output type produced by the adapter (e.g., a middleware layer).
    type Output;

    /// Convert a framework-agnostic `BearerGate` into the framework-specific middleware/layer type.
    fn adapt(&self, gate: BearerGate<C, R, G, M>) -> Self::Output;
}

impl<C, R, G, M> BearerGate<C, R, G, M>
where
    C: Codec,
    R: AccessHierarchy + Eq + Display,
    G: Eq,
{
    /// Convert this gate into a framework-specific layer using the provided adapter.
    pub fn adapt_with<A>(self, adapter: A) -> A::Output
    where
        A: BearerGateAdapter<C, R, G, M>,
    {
        adapter.adapt(self)
    }
}
