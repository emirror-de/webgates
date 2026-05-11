//! Shared adapter primitives for framework-specific gate integration.
//!
//! This module defines the small generic traits that let framework adapters turn
//! a framework-agnostic gate into something concrete, such as middleware,
//! layers, handlers, or runtime evaluators.
//!
//! The two exported items are:
//!
//! - `GateAdapter<G>` — a generic adapter trait for any gate type `G`.
//! - `GateExt` — an extension trait that adds a default `adapt_with` method to
//!   gate types.

/// Generic adapter trait for a gate type `G`.
///
/// Implementors convert a framework-agnostic gate value into a framework- or
/// application-specific artifact, such as a middleware layer or runtime object.
///
/// This trait is intentionally minimal: it mirrors the existing per-gate adapter
/// traits (like `CookieGateAdapter`) so we can add a single `adapt_with`
/// convenience method to all gate types without duplicating it in every gate
/// implementation.
pub trait GateAdapter<G> {
    /// Framework-specific output type produced by the adapter.
    type Output;

    /// Converts the provided `gate` into the adapter's output type.
    fn adapt(&self, gate: G) -> Self::Output;
}
