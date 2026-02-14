/*! Framework-agnostic cookie gate configuration.

This module defines the cookie-backed gate builder without any dependency on
web frameworks or middleware stacks. Integration crates adapt this configuration
into concrete middleware/layers for their transport.

- Strict mode (default): enforces the access policy; adapters should reject
  unauthorized requests.
- Optional mode (`allow_anonymous_with_optional_user`): adapters should skip
  authZ/authN enforcement and merely inject optional context if present.

The cookie template is validated eagerly by `configure_cookie_template` and
lazily by adapters when applying `with_cookie_template`.

# Example — Implementing a simple in-crate `CookieGateAdapter`

The core crate exposes `CookieGate`, its `CookieGateRuntime` evaluator and the
`CookieGateAdapter` trait. Integration code can implement `CookieGateAdapter`
to convert a configured `CookieGate` into a framework- or application-specific
artifact.

The example below demonstrates a minimal, framework-agnostic adapter that
adapts a `CookieGate` into its `CookieGateRuntime`. This is useful for systems
that want to perform cookie/JWT evaluation in a custom place (for example, in
a bespoke middleware pipeline) while keeping the gate configuration in the
core crate.

```rust
use std::sync::Arc;

// Local crate types used by the gate
use crate::accounts::Account;
use crate::codecs::jwt::{JsonWebToken, JwtClaims};
use crate::gate::cookie::{CookieGate, CookieGateAdapter, CookieGateRuntime, CookieEvaluation};
use crate::groups::Group;
use crate::roles::Role;

/// A trivial adapter that turns a configured `CookieGate` into the corresponding
/// `CookieGateRuntime`. In a real integration this adapter could instead produce
/// a middleware layer, a closure-based handler, or any framework-specific type.
struct RuntimeAdapter;

impl<C, R, G> CookieGateAdapter<C, R, G> for RuntimeAdapter
where
    // The runtime requires a codec that decodes JwtClaims<Account<R, G>>
    C: crate::codecs::Codec<Payload = JwtClaims<Account<R, G>>>,
    R: crate::authz::AccessHierarchy + Eq + std::fmt::Display + Clone,
    G: Eq + Clone,
{
    // We choose the runtime evaluator as the adapter output
    type Output = CookieGateRuntime<C, R, G>;

    fn adapt(&self, gate: CookieGate<C, R, G>) -> Self::Output {
        // Build the runtime from the configured gate and return it.
        // Adapters that create framework middleware would construct and return
        // the middleware layer here instead.
        gate.runtime()
    }
}

fn example_usage() {
    // Create a codec (placeholder default implementation provided in this crate)
    let jwt_codec: Arc<JsonWebToken<JwtClaims<Account<Role, Group>>>> =
        Arc::new(JsonWebToken::default());

    // Configure a gate (deny-all by default)
    let gate = CookieGate::new_with_codec("my-issuer", Arc::clone(&jwt_codec))
        .require_login();

    // Adapt the gate into a runtime evaluator using our adapter
    let runtime: CookieGateRuntime<_, Role, Group> = gate.adapt_with(RuntimeAdapter);

    // Evaluate an incoming (optional) token string
    // In a real middleware you'd extract the cookie value from the HTTP request.
    let token: Option<&str> = Some("eyJ..."); // example token string

    let result = runtime.evaluate(token);

    // Map the evaluation to application behaviour
    match result {
        CookieEvaluation::Authorized { account, registered_claims } => {
            // AuthN + AuthZ succeeded — proceed with `account` context
            tracing::info!("authorized account {}", account.account_id);
            let _exp = registered_claims.exp; // example usage
        }
        CookieEvaluation::OptionalAuthorized { account, registered_claims } => {
            // Optional mode: we have a valid token but the gate is non-blocking
            let _ = (account, registered_claims);
        }
        CookieEvaluation::OptionalAnonymous => {
            // Optional mode: no token present
        }
        CookieEvaluation::MissingToken => {
            // Strict mode: absent token -> treat as unauthorized (e.g., return 401)
        }
        CookieEvaluation::InvalidToken | CookieEvaluation::InvalidIssuer { .. } => {
            // Token problems -> return 401
        }
        CookieEvaluation::PolicyDenied { account_id } => {
            // AuthN succeeded but AuthZ failed -> return 403
            tracing::warn!("authorization denied for account {}", account_id);
        }
        CookieEvaluation::DenyAllPolicy => {
            // Gate configured to deny all access
        }
    }
}
```

This example is intentionally small and focused on the core crate. Real adapters
typically:

- convert the `CookieEvaluation` into framework responses (401/403),
- inject decoded account/claims into request extensions, or
- wire metrics and logging for auth events.

For more complex wiring you can construct a middleware type here and return it
from `adapt`, keeping all gate configuration and runtime semantics inside the
core crate.

Note: JWT validation (signature verification and standard claim checks) is
already performed by the configured codec (which itself uses the `jsonwebtoken`
crate under the hood). Adapters and middleware SHOULD NOT re-validate tokens —
they should rely on the runtime's outcome (`CookieEvaluation`) and map it to
framework-specific behaviour (e.g., 401/403 or request extensions).
*/

use std::fmt::Display;
use std::sync::Arc;

use crate::accounts::Account;
use crate::authz::{AccessHierarchy, AccessPolicy, AuthorizationService};
use crate::codecs::Codec;
use crate::codecs::jwt::{JwtClaims, JwtValidationResult, JwtValidationService, RegisteredClaims};
use crate::cookie_template::{CookieTemplate, CookieTemplateBuilderError};
use uuid::Uuid;

/// Builder/configuration for cookie-backed JWT gates (framework-agnostic).
#[derive(Clone, Debug)]
pub struct CookieGate<C, R, G>
where
    C: Codec,
    R: AccessHierarchy + Eq + Display,
    G: Eq,
{
    /// Expected issuer for JWT validation.
    issuer: String,
    /// Access policy configured for this gate.
    policy: AccessPolicy<R, G>,
    /// Shared JWT codec used to decode/encode tokens.
    codec: Arc<C>,
    /// Template describing how to read/write the authentication cookie.
    cookie_template: CookieTemplate,
    /// When true, the gate runs in optional mode and never blocks requests.
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

/// Outcome of evaluating a cookie gate token independent of any HTTP framework.
///
/// This enables adapters (e.g., Axum, Warp) to perform authentication and
/// authorization in the core crate and then map the outcome to their transport.
#[derive(Debug, Clone)]
pub enum CookieEvaluation<R, G>
where
    R: AccessHierarchy + Eq + Display + Clone,
    G: Eq + Clone,
{
    /// Optional mode: no valid token present.
    OptionalAnonymous,
    /// Optional mode: valid token decoded; policy not enforced.
    OptionalAuthorized {
        /// Decoded account claims from the JWT.
        account: Account<R, G>,
        /// Registered (standard) JWT claims.
        registered_claims: RegisteredClaims,
    },
    /// Strict mode: required token is missing.
    MissingToken,
    /// Strict mode: token failed validation.
    InvalidToken,
    /// Strict mode: token issuer mismatch.
    InvalidIssuer {
        /// Expected issuer configured on the gate.
        expected: String,
        /// Actual issuer value found in the token.
        actual: String,
    },
    /// Strict mode: policy denies all (empty requirements).
    DenyAllPolicy,
    /// Strict mode: decoded token but policy check failed.
    PolicyDenied {
        /// Account identifier from the decoded token when authorization failed.
        account_id: Uuid,
    },
    /// Strict mode: token validated and policy passed.
    Authorized {
        /// Decoded account claims from the JWT.
        account: Account<R, G>,
        /// Registered (standard) JWT claims.
        registered_claims: RegisteredClaims,
    },
}

/// Runtime evaluator built from a `CookieGate` that executes validation and
/// authorization independent of any HTTP framework.
#[derive(Clone, Debug)]
pub struct CookieGateRuntime<C, R, G>
where
    C: Codec,
    R: AccessHierarchy + Eq + Display + Clone,
    G: Eq + Clone,
{
    /// Authorization evaluator built from the configured access policy.
    authorization_service: AuthorizationService<R, G>,
    /// Validates and decodes JWTs for this gate.
    jwt_validation_service: JwtValidationService<C>,
    /// Indicates whether the gate runs in optional (non-blocking) mode.
    install_optional_extensions: bool,
}

impl<C, R, G> CookieGateRuntime<C, R, G>
where
    C: Codec<Payload = JwtClaims<Account<R, G>>>,
    R: AccessHierarchy + Eq + Display + Clone,
    G: Eq + Clone,
{
    /// Build a runtime evaluator from a configured gate.
    pub fn new(gate: &CookieGate<C, R, G>) -> Self {
        Self {
            authorization_service: AuthorizationService::new(gate.policy().clone()),
            jwt_validation_service: JwtValidationService::new(
                Arc::clone(gate.codec()),
                gate.issuer(),
            ),
            install_optional_extensions: gate.installs_optional_extensions(),
        }
    }

    /// Whether the gate is in optional mode (never blocks requests).
    pub fn is_optional(&self) -> bool {
        self.install_optional_extensions
    }

    /// Evaluate an optional token string and return the authorization outcome.
    pub fn evaluate(&self, token: Option<&str>) -> CookieEvaluation<R, G> {
        if self.install_optional_extensions {
            if let Some(token) = token
                && let JwtValidationResult::Valid(jwt) =
                    self.jwt_validation_service.validate_token(token)
            {
                return CookieEvaluation::OptionalAuthorized {
                    account: jwt.custom_claims,
                    registered_claims: jwt.registered_claims,
                };
            }
            return CookieEvaluation::OptionalAnonymous;
        }

        if self.authorization_service.policy_denies_all_access() {
            return CookieEvaluation::DenyAllPolicy;
        }

        let Some(token) = token else {
            return CookieEvaluation::MissingToken;
        };

        match self.jwt_validation_service.validate_token(token) {
            JwtValidationResult::Valid(jwt) => {
                let account = jwt.custom_claims;
                let registered_claims = jwt.registered_claims;
                let account_id = account.account_id;
                if self.authorization_service.is_authorized(&account) {
                    CookieEvaluation::Authorized {
                        account,
                        registered_claims,
                    }
                } else {
                    CookieEvaluation::PolicyDenied { account_id }
                }
            }
            JwtValidationResult::InvalidToken => CookieEvaluation::InvalidToken,
            JwtValidationResult::InvalidIssuer { expected, actual } => {
                CookieEvaluation::InvalidIssuer { expected, actual }
            }
        }
    }
}

impl<C, R, G> CookieGate<C, R, G>
where
    C: Codec,
    R: AccessHierarchy + Eq + Display + Clone,
    G: Eq + Clone,
{
    /// Create a runtime evaluator that performs JWT validation and policy checks.
    pub fn runtime(&self) -> CookieGateRuntime<C, R, G>
    where
        C: Codec<Payload = JwtClaims<Account<R, G>>>,
    {
        CookieGateRuntime::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codecs::jwt::{JsonWebToken, JwtClaims};
    use crate::groups::Group;
    use crate::roles::Role;
    use std::sync::Arc;

    #[test]
    fn optional_mode_missing_token_is_anonymous() {
        let gate = CookieGate::<_, Role, Group>::new_with_codec(
            "issuer",
            Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default()),
        )
        .allow_anonymous_with_optional_user();

        let runtime = gate.runtime();
        let result = runtime.evaluate(None);

        assert!(matches!(result, CookieEvaluation::OptionalAnonymous));
    }

    #[test]
    fn strict_mode_with_deny_all_policy_short_circuits() {
        let gate = CookieGate::<_, Role, Group>::new_with_codec(
            "issuer",
            Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default()),
        );

        let runtime = gate.runtime();
        let result = runtime.evaluate(None);

        assert!(matches!(result, CookieEvaluation::DenyAllPolicy));
    }
}
