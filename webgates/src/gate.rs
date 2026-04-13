//! Framework-agnostic gate entry points that delegate to bearer, cookie, and OAuth2 modules.

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

/// Entry point for constructing gate configurations.
#[derive(Clone, Debug, Default)]
pub struct Gate;

impl Gate {
    /// Create a cookie-based gate configuration (deny-all policy by default).
    #[cfg(feature = "cookies")]
    pub fn cookie<C, R, G>(issuer: &str, codec: Arc<C>) -> cookie::CookieGate<C, R, G>
    where
        C: Codec,
        R: AccessHierarchy + Eq + Display + Default,
        G: Eq,
    {
        cookie::CookieGate::new_with_codec(issuer, codec)
    }

    /// Create a bearer-based gate configuration (JWT mode, deny-all policy by default).
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

    /// Create an OAuth2 gate configuration.
    #[cfg(feature = "oauth2")]
    pub fn oauth2<R, G>() -> oauth2::OAuth2Gate<R, G>
    where
        R: AccessHierarchy + Eq + Display + Default + Send + Sync + 'static,
        G: Eq + Clone + Send + Sync + 'static,
    {
        oauth2::OAuth2Gate::new()
    }
}

/// Extension trait for gate types that provides a default `adapt_with`
/// convenience method.
///
/// Implement this trait for concrete gate types (the trait has a default
/// implementation so the impl bodies are intentionally empty). The default
/// forwards to the provided `GateAdapter<G>`.
///
/// Example:
/// ```ignore
/// let gate = CookieGate::new_with_codec(...);
/// let runtime = gate.adapt_with(MyAdapter);
/// ```
pub trait GateExt: Sized {
    /// Adapt this gate into a framework-specific artifact using `adapter`.
    ///
    /// The adapter type must implement `GateAdapter<Self>`. This default method
    /// simply calls `adapter.adapt(self)`.
    fn adapt_with<A>(self, adapter: A) -> A::Output
    where
        A: GateAdapter<Self>,
    {
        adapter.adapt(self)
    }
}
