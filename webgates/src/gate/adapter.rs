//! Extension traits and adapter bridge implementations for gate adapters.
//!
//! This module provides two small, generic primitives that centralize the
//! `adapt_with` convenience method and allow existing, concrete adapter traits
//! (e.g. `CookieGateAdapter`, `BearerGateAdapter`) to interoperate without
//! changing their definitions.
//!
//! The two exported items are:
//!
//! - `GateAdapter<G>` — a generic adapter trait for any gate type `G`.
//! - `GateExt` — an extension trait that adds a default `adapt_with` method to
//!   gate types.

/// Generic adapter trait for a gate type `G`.
///
/// Implementors convert a framework-agnostic gate value into a framework- or
/// application-specific artifact (for example, a middleware layer).
///
/// This trait is intentionally minimal: it mirrors the existing per-gate adapter
/// traits (like `CookieGateAdapter`) so we can add a single `adapt_with`
/// convenience method to all gate types without duplicating it in every gate
/// implementation.
pub trait GateAdapter<G> {
    /// Framework-specific output type produced by the adapter (e.g., middleware
    /// layer, runtime evaluator).
    type Output;

    /// Convert the provided `gate` into the adapter's `Output`.
    fn adapt(&self, gate: G) -> Self::Output;
}
