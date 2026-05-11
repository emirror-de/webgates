//! Gate entry point for tonic server-side authentication and authorization.
//!
//! Use [`crate::gate::Gate`] as the canonical entry point for bearer-token gates
//! on tonic services.

use std::sync::Arc;

use webgates::accounts::Account;
use webgates::authz::access_hierarchy::AccessHierarchy;
use webgates::codecs::Codec;
use webgates::codecs::jwt::JwtClaims;

pub mod bearer;
pub mod remote_jwks_bearer;

/// Tonic-facing gate entry point.
///
/// Use [`Gate::bearer`] to create bearer-token middleware for tonic services.
///
/// # Example
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use webgates::accounts::Account;
/// use webgates::authz::access_policy::AccessPolicy;
/// use webgates::roles::Role;
/// use webgates::groups::Group;
/// use webgates_codecs::jwt::{JsonWebToken, JwtClaims};
/// use webgates_tonic::gate::Gate;
///
/// let codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
/// let layer = Gate::bearer("my-svc", codec)
///     .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin));
/// ```
#[derive(Clone, Debug)]
pub struct Gate;

impl Gate {
    /// Returns a bearer-token gate for tonic services.
    ///
    /// The returned [`bearer::BearerGate`] starts in JWT mode with a deny-all
    /// policy by default. Use builder methods to configure policy or transition
    /// into static-token mode.
    pub fn bearer<C, R, G>(
        issuer: &str,
        codec: Arc<C>,
    ) -> bearer::BearerGate<C, R, G, bearer::JwtConfig<R, G>>
    where
        C: Codec<Payload = JwtClaims<Account<R, G>>>,
        R: AccessHierarchy + Eq + std::fmt::Display + Default + Clone + Send + Sync + 'static,
        G: Eq + Clone + Send + Sync + 'static,
    {
        bearer::BearerGate::new_with_codec(issuer, codec)
    }
}
