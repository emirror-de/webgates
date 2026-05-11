//! Framework-agnostic gate entry points.
//!
//! This module is where most application code starts once you move beyond the
//! raw domain model. A [`Gate`] describes how requests should be authenticated
//! and authorized, while adapter crates translate that configuration into
//! framework-specific middleware or handlers.
//!
//! Common entry points are:
//!
//! - [`Gate::cookie`] for JWTs stored in cookies
//! - [`Gate::bearer`] for `Authorization: Bearer ...`
//! - [`Gate::oauth2`] for OAuth2-driven gate configuration when enabled

use std::fmt::Display;
use std::sync::Arc;

use self::adapter::GateAdapter;
use crate::authz::access_hierarchy::AccessHierarchy;
use crate::codecs::Codec;

pub mod adapter;
pub mod bearer;
#[cfg(feature = "cookies")]
pub mod cookie;
#[cfg(feature = "oauth2")]
pub mod oauth2;

/// Entry point for constructing framework-agnostic gate configurations.
///
/// `Gate` is a namespace-style builder entry point. The returned gate values
/// hold configuration and policy, while adapters or runtimes perform the
/// actual request evaluation.
#[derive(Clone, Debug, Default)]
pub struct Gate;

impl Gate {
    /// Creates a cookie-based gate configuration.
    ///
    /// The returned gate starts with a deny-all policy until you add a policy
    /// or call a convenience method such as `require_login()`.
    #[cfg(feature = "cookies")]
    pub fn cookie<C, R, G>(issuer: &str, codec: Arc<C>) -> cookie::CookieGate<C, R, G>
    where
        C: Codec,
        R: AccessHierarchy + Eq + Display + Default,
        G: Eq,
    {
        cookie::CookieGate::new_with_codec(issuer, codec)
    }

    /// Creates a bearer-based gate configuration in JWT mode.
    ///
    /// The returned gate starts with a deny-all policy until you add a policy
    /// or call a convenience method such as `require_login()`.
    pub fn bearer<C, R, G>(
        issuer: &str,
        codec: Arc<C>,
    ) -> bearer::BearerGate<C, R, G, bearer::JwtConfig<R, G>>
    where
        C: Codec,
        R: AccessHierarchy + Eq + Display + Default,
        G: Eq + Clone,
    {
        bearer::BearerGate::new_with_codec(issuer, codec)
    }

    /// Creates an OAuth2 gate configuration.
    ///
    /// This builder is available only when the `oauth2` feature is enabled.
    #[cfg(feature = "oauth2")]
    pub fn oauth2<R, G>() -> oauth2::OAuth2Gate<R, G>
    where
        R: AccessHierarchy + Eq + Display + Default + Send + Sync + 'static,
        G: Eq + Clone + Send + Sync + 'static,
    {
        oauth2::OAuth2Gate::new()
    }
}

/// Extension trait that adds `adapt_with(...)` to gate types.
///
/// Concrete gate types implement this trait so application or integration code
/// can hand them to a framework-specific adapter without each gate needing its
/// own duplicated convenience method.
///
/// # Example
///
/// ```ignore
/// let gate = CookieGate::new_with_codec(...);
/// let runtime = gate.adapt_with(MyAdapter);
/// ```
pub trait GateExt: Sized {
    /// Adapts this gate into a framework-specific artifact using `adapter`.
    ///
    /// The adapter type must implement [`GateAdapter<Self>`]. This default
    /// method forwards to `adapter.adapt(self)`.
    fn adapt_with<A>(self, adapter: A) -> A::Output
    where
        A: GateAdapter<Self>,
    {
        adapter.adapt(self)
    }
}
