#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
//! Axum gate entry points bridging core gate configuration to axum adapters.
//!
//! The core crate owns framework-agnostic gate configuration. This module
//! adapts those builders into axum-specific middleware by translating the
//! core configuration into the axum gate implementations (`cookie`, `bearer`,
//! `oauth2`).

use std::sync::Arc;

use webgates::accounts::Account;
use webgates::authz::AccessHierarchy;
use webgates::codecs::Codec;
use webgates::codecs::jwt::JwtClaims;
use webgates::gate::{self as core_gate, Gate as CoreGate};

pub mod bearer;
pub mod cookie;
pub mod oauth2;

/// Axum-facing Gate entry point.
#[derive(Clone, Debug, Default)]
pub struct Gate;

impl Gate {
    /// Create a cookie-based gate as an axum layer using the core configuration.
    pub fn cookie<C, R, G>(issuer: &str, codec: Arc<C>) -> cookie::CookieGate<C, R, G>
    where
        C: Codec<Payload = JwtClaims<Account<R, G>>>,
        R: AccessHierarchy + Eq + std::fmt::Display + Default + Clone + Send + Sync + 'static,
        G: Eq + Clone + Send + Sync + 'static,
    {
        let core = CoreGate::cookie::<C, R, G>(issuer, Arc::clone(&codec));
        core.adapt_with(CookieAdapter)
    }

    /// Create a bearer-based gate as an axum layer using the core configuration.
    pub fn bearer<C, R, G>(
        issuer: &str,
        codec: Arc<C>,
    ) -> bearer::BearerGate<C, R, G, bearer::JwtConfig<R, G>>
    where
        C: Codec,
        R: AccessHierarchy + Eq + std::fmt::Display + Default + Clone + Send + Sync + 'static,
        G: Eq + Clone + Send + Sync + 'static,
    {
        let core = CoreGate::bearer::<C, R, G>(issuer, Arc::clone(&codec));
        core.adapt_with(BearerAdapter)
    }

    /// OAuth2 gate builder (axum-specific) remains provided directly.
    pub fn oauth2<R, G>() -> oauth2::OAuth2Gate<R, G>
    where
        R: AccessHierarchy + Eq + std::fmt::Display + Send + Sync + 'static,
        G: Eq + Clone + Send + Sync + 'static,
    {
        oauth2::OAuth2Gate::new()
    }
}

/// Adapter converting core cookie gate configuration into the axum cookie layer.
#[derive(Clone, Debug, Default)]
struct CookieAdapter;

impl<C, R, G> core_gate::cookie::CookieGateAdapter<C, R, G> for CookieAdapter
where
    C: Codec<Payload = JwtClaims<Account<R, G>>>,
    R: AccessHierarchy + Eq + std::fmt::Display + Default + Clone + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    type Output = cookie::CookieGate<C, R, G>;

    fn adapt(&self, gate: core_gate::cookie::CookieGate<C, R, G>) -> Self::Output {
        let mut adapted =
            cookie::CookieGate::new_with_codec(gate.issuer(), Arc::clone(gate.codec()));
        adapted = adapted.with_policy(gate.policy().clone());
        adapted = adapted.with_cookie_template(gate.cookie_template().clone());
        if gate.installs_optional_extensions() {
            adapted = adapted.allow_anonymous_with_optional_user();
        }
        adapted
    }
}

/// Adapter converting core bearer gate configuration into the axum bearer layer.
#[derive(Clone, Debug, Default)]
struct BearerAdapter;

impl<C, R, G> core_gate::bearer::BearerGateAdapter<C, R, G, core_gate::bearer::JwtConfig<R, G>>
    for BearerAdapter
where
    C: Codec,
    R: AccessHierarchy + Eq + std::fmt::Display + Default + Clone + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    type Output = bearer::BearerGate<C, R, G, bearer::JwtConfig<R, G>>;

    fn adapt(
        &self,
        gate: core_gate::bearer::BearerGate<C, R, G, core_gate::bearer::JwtConfig<R, G>>,
    ) -> Self::Output {
        let mut adapted =
            bearer::BearerGate::new_with_codec(gate.issuer(), Arc::clone(gate.codec()));
        adapted = adapted.with_policy(gate.policy().clone());
        if gate.is_optional() {
            adapted = adapted.allow_anonymous_with_optional_user();
        }
        adapted
    }
}

impl<C, R, G> core_gate::bearer::BearerGateAdapter<C, R, G, core_gate::bearer::StaticTokenConfig>
    for BearerAdapter
where
    C: Codec,
    R: AccessHierarchy + Eq + std::fmt::Display + Default + Clone + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    type Output = bearer::BearerGate<C, R, G, bearer::StaticTokenConfig>;

    fn adapt(
        &self,
        gate: core_gate::bearer::BearerGate<C, R, G, core_gate::bearer::StaticTokenConfig>,
    ) -> Self::Output {
        let mut adapted =
            bearer::BearerGate::new_with_codec(gate.issuer(), Arc::clone(gate.codec()))
                .with_static_token(gate.token().to_owned());
        if gate.is_optional() {
            adapted = adapted.allow_anonymous_with_optional_user();
        }
        adapted
    }
}
