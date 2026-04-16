//! Gate entry point for tonic server-side authentication and authorization.
//!
//! Use [`Gate`] as the canonical entry point to construct bearer token gates
//! for tonic services. The module also exposes the [`bearer`] submodule for
//! handler-visible types.

use std::sync::Arc;

use webgates::accounts::Account;
use webgates::authz::access_hierarchy::AccessHierarchy;
use webgates::codecs::Codec;
use webgates::codecs::jwt::JwtClaims;

pub mod bearer;

/// Tonic-facing gate entry point.
///
/// Use [`Gate::bearer`] to create bearer token middleware for tonic services.
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
    /// Create a bearer-based gate for tonic services (JWT mode, deny-all policy by default).
    ///
    /// Returns a [`bearer::BearerGate`] in JWT mode. Use the builder methods to configure
    /// the policy before applying the gate as a tower [`Layer`](tower::Layer).
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
