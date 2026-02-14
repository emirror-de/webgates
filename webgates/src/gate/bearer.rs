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
//!
//! # Example — Implementing simple in-crate `BearerGateAdapter`s
//!
//! The core crate exposes `BearerGate`, runtime evaluators (`JwtBearerRuntime` and
//! `StaticTokenRuntime`), and the `BearerGateAdapter` trait. Integration code can
//! implement `BearerGateAdapter` to convert a configured `BearerGate` into a
//! framework- or application-specific artifact.
//!
//! The examples below demonstrate minimal, in-crate adapters that return the
//! appropriate runtime evaluators. This keeps the example focused on types within
//! the current crate and shows how adapters can reuse the runtime evaluation
//! without reimplementing validation logic.
//!
//! ```rust
//! use std::sync::Arc;
//! use webgates::prelude::{Account, Group, Role, JsonWebToken, JwtClaims};
//! use webgates::gate::bearer::{BearerGate, BearerGateAdapter, JwtBearerRuntime, StaticTokenRuntime};
//!
//! /// Adapter producing a JWT bearer runtime evaluator.
//! struct JwtRuntimeAdapter;
//!
//! impl<C, R, G> BearerGateAdapter<C, R, G, webgates::gate::bearer::JwtConfig<R, G>> for JwtRuntimeAdapter
//! where
//!     C: webgates::codecs::Codec<Payload = JwtClaims<Account<R, G>>>,
//!     R: webgates::authz::AccessHierarchy + Eq + std::fmt::Display + Clone,
//!     G: Eq + Clone,
//! {
//!     type Output = JwtBearerRuntime<C, R, G>;
//!
//!     fn adapt(&self, gate: BearerGate<C, R, G, webgates::gate::bearer::JwtConfig<R, G>>) -> Self::Output {
//!         // Build and return the runtime evaluator derived from the gate.
//!         gate.runtime()
//!     }
//! }
//!
//! /// Adapter producing a static-token runtime evaluator.
//! struct StaticRuntimeAdapter;
//!
//! impl<C, R, G> BearerGateAdapter<C, R, G, webgates::gate::bearer::StaticTokenConfig> for StaticRuntimeAdapter
//! where
//!     C: webgates::codecs::Codec,
//!     R: webgates::authz::AccessHierarchy + Eq + std::fmt::Display + Clone,
//!     G: Eq + Clone,
//! {
//!     type Output = StaticTokenRuntime<R, G>;
//!
//!     fn adapt(&self, gate: BearerGate<C, R, G, webgates::gate::bearer::StaticTokenConfig>) -> Self::Output {
//!         gate.runtime()
//!     }
//! }
//!
//! // Usage sketch:
//! let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! let jwt_gate = BearerGate::new_with_codec("issuer", Arc::clone(&codec)).require_login();
//! let jwt_runtime = jwt_gate.adapt_with(JwtRuntimeAdapter);
//! let eval = jwt_runtime.evaluate(Some("eyJ..."));
//! match eval {
//!     webgates::gate::bearer::BearerEvaluation::JwtAuthorized { account, .. } => {
//!         // authorized — use `account`
//!     }
//!     webgates::gate::bearer::BearerEvaluation::JwtMissingToken => {
//!         // treat as unauthorized (e.g., return 401)
//!     }
//!     _ => { /* handle other outcomes */ }
//! }
//! ```
//!
//! ## JWT validation
//!
//! The codec used by JWT mode (for example, `JsonWebToken`) performs
//! cryptographic validation (signature, expiry, issuer) via the underlying
//! `jsonwebtoken`-based implementation. Adapters and middleware SHOULD NOT
//! re-validate signatures themselves but rely on the runtime's evaluation and
//! map `BearerEvaluation` variants to framework-specific responses (e.g.,
//! 401/403) or request extensions.

use std::fmt::Display;
use std::sync::Arc;

use crate::accounts::Account;
use crate::authz::{AccessHierarchy, AccessPolicy, AuthorizationService};
use crate::codecs::Codec;
use crate::codecs::jwt::{JwtClaims, JwtValidationResult, JwtValidationService, RegisteredClaims};
use uuid::Uuid;

/// JWT mode configuration (compile-time).
#[derive(Clone)]
pub struct JwtConfig<R, G>
where
    R: AccessHierarchy + Eq + Display,
    G: Eq,
{
    /// Access policy applied in JWT mode.
    policy: AccessPolicy<R, G>,
    /// Whether optional (non-blocking) mode is enabled for JWTs.
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
    /// Exact static bearer token to match.
    token: String,
    /// Whether optional (non-blocking) mode is enabled.
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
    /// Issuer value expected when validating bearer JWTs (unused for static token mode).
    issuer: String,
    /// Shared codec used to decode/encode bearer JWTs.
    codec: Arc<C>,
    /// Mode configuration (JWT or static token).
    mode: M,
    /// Marker to retain generic types without storing them at runtime.
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

/// Outcome of evaluating bearer authentication/authorization independent of any HTTP framework.
#[derive(Debug, Clone)]
pub enum BearerEvaluation<R, G>
where
    R: AccessHierarchy + Eq + Display + Clone,
    G: Eq + Clone,
{
    /// Optional JWT mode: no bearer token present.
    JwtOptionalAnonymous,
    /// Optional JWT mode: token validated; policy not enforced.
    JwtOptionalAuthorized {
        /// Decoded account claims.
        account: Account<R, G>,
        /// Registered JWT claims.
        registered_claims: RegisteredClaims,
    },
    /// Strict JWT mode: required token missing.
    JwtMissingToken,
    /// Strict JWT mode: token failed validation.
    JwtInvalidToken,
    /// Strict JWT mode: issuer mismatch.
    JwtInvalidIssuer {
        /// Expected issuer configured on the gate.
        expected: String,
        /// Actual issuer embedded in the token.
        actual: String,
    },
    /// Strict JWT mode: policy denies all access.
    JwtDenyAllPolicy,
    /// Strict JWT mode: decoded token but policy check failed.
    JwtPolicyDenied {
        /// Identifier of the decoded account.
        account_id: Uuid,
    },
    /// Strict JWT mode: token validated and policy passed.
    JwtAuthorized {
        /// Decoded account claims.
        account: Account<R, G>,
        /// Registered JWT claims.
        registered_claims: RegisteredClaims,
    },
    /// Static token mode: authorized.
    StaticAuthorized,
    /// Static token mode: denied.
    StaticDenied,
    /// Static token optional mode: forwarded with match indicator.
    StaticOptionalAuthorized {
        /// Whether the provided token matched the configured static token.
        matched: bool,
    },
}

/// Runtime evaluator for JWT bearer gates.
#[derive(Clone, Debug)]
pub struct JwtBearerRuntime<C, R, G>
where
    C: Codec,
    R: AccessHierarchy + Eq + Display + Clone,
    G: Eq + Clone,
{
    /// Authorization evaluator built from the configured access policy.
    authorization_service: AuthorizationService<R, G>,
    /// Validates and decodes bearer JWTs for this gate.
    jwt_validation_service: JwtValidationService<C>,
    /// Whether the gate runs in optional (non-blocking) mode.
    optional: bool,
}

impl<C, R, G> JwtBearerRuntime<C, R, G>
where
    C: Codec<Payload = JwtClaims<Account<R, G>>>,
    R: AccessHierarchy + Eq + Display + Clone,
    G: Eq + Clone,
{
    /// Build a runtime evaluator from a configured gate.
    pub fn new(issuer: &str, policy: AccessPolicy<R, G>, codec: Arc<C>, optional: bool) -> Self {
        Self {
            authorization_service: AuthorizationService::new(policy),
            jwt_validation_service: JwtValidationService::new(codec, issuer),
            optional,
        }
    }

    /// Evaluate an optional bearer token.
    pub fn evaluate(&self, token: Option<&str>) -> BearerEvaluation<R, G> {
        if self.optional {
            if let Some(token) = token
                && let JwtValidationResult::Valid(jwt) =
                    self.jwt_validation_service.validate_token(token)
            {
                return BearerEvaluation::JwtOptionalAuthorized {
                    account: jwt.custom_claims,
                    registered_claims: jwt.registered_claims,
                };
            }
            return BearerEvaluation::JwtOptionalAnonymous;
        }

        if self.authorization_service.policy_denies_all_access() {
            return BearerEvaluation::JwtDenyAllPolicy;
        }

        let Some(token) = token else {
            return BearerEvaluation::JwtMissingToken;
        };

        match self.jwt_validation_service.validate_token(token) {
            JwtValidationResult::Valid(jwt) => {
                let account = jwt.custom_claims;
                let registered_claims = jwt.registered_claims;
                let account_id = account.account_id;
                if self.authorization_service.is_authorized(&account) {
                    BearerEvaluation::JwtAuthorized {
                        account,
                        registered_claims,
                    }
                } else {
                    BearerEvaluation::JwtPolicyDenied { account_id }
                }
            }
            JwtValidationResult::InvalidToken => BearerEvaluation::JwtInvalidToken,
            JwtValidationResult::InvalidIssuer { expected, actual } => {
                BearerEvaluation::JwtInvalidIssuer { expected, actual }
            }
        }
    }
}

/// Runtime evaluator for static bearer token gates.
#[derive(Clone, Debug)]
pub struct StaticTokenRuntime<R, G>
where
    R: AccessHierarchy + Eq + Display + Clone,
    G: Eq + Clone,
{
    /// Exact static bearer token to match.
    token: String,
    /// Whether optional (non-blocking) mode is enabled.
    optional: bool,
    /// Marker to retain generic types without runtime storage.
    _phantom: std::marker::PhantomData<(R, G)>,
}

impl<R, G> StaticTokenRuntime<R, G>
where
    R: AccessHierarchy + Eq + Display + Clone,
    G: Eq + Clone,
{
    /// Build a runtime evaluator for static token gates.
    pub fn new(token: impl Into<String>, optional: bool) -> Self {
        Self {
            token: token.into(),
            optional,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Evaluate an optional bearer token string.
    pub fn evaluate(&self, token: Option<&str>) -> BearerEvaluation<R, G> {
        if self.optional {
            return BearerEvaluation::StaticOptionalAuthorized {
                matched: token.is_some() && token == Some(self.token.as_str()),
            };
        }

        if let Some(token) = token
            && token == self.token
        {
            return BearerEvaluation::StaticAuthorized;
        }
        BearerEvaluation::StaticDenied
    }
}

impl<C, R, G> BearerGate<C, R, G, JwtConfig<R, G>>
where
    C: Codec<Payload = JwtClaims<Account<R, G>>>,
    R: AccessHierarchy + Eq + Display + Clone,
    G: Eq + Clone,
{
    /// Create a runtime evaluator that performs JWT validation and policy checks.
    pub fn runtime(&self) -> JwtBearerRuntime<C, R, G>
    where
        R: Default,
    {
        JwtBearerRuntime::new(
            &self.issuer,
            self.mode.policy.clone(),
            Arc::clone(&self.codec),
            self.mode.optional,
        )
    }
}

impl<C, R, G> BearerGate<C, R, G, StaticTokenConfig>
where
    C: Codec,
    R: AccessHierarchy + Eq + Display,
    G: Eq + Clone,
{
    /// Create a runtime evaluator for static token gates.
    pub fn runtime(&self) -> StaticTokenRuntime<R, G> {
        StaticTokenRuntime::new(self.mode.token.clone(), self.mode.optional)
    }
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
