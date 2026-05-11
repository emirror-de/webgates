#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
//! Axum gate entry points.
//!
//! This module is the main middleware-facing entry point for `webgates-axum`.
//! It adapts the framework-agnostic gate builders from `webgates` into Axum
//! middleware layers and wrappers.

use std::sync::Arc;

use webgates::accounts::Account;
use webgates::authz::access_hierarchy::AccessHierarchy;
use webgates::codecs::Codec;
use webgates::codecs::jwt::JwtClaims;
use webgates::gate::{self as core_gate, Gate as CoreGate, GateExt};

pub mod bearer;
pub mod cookie;
pub mod oauth2;
pub mod remote_jwks_cookie;

/// Axum-facing gate entry point.
///
/// Use this type when you want to protect Axum routes with cookie, bearer, or
/// OAuth2 gate behavior.
#[derive(Clone, Debug, Default)]
pub struct Gate;

impl Gate {
    /// Creates a cookie-based Axum gate layer using the core configuration model.
    pub fn cookie<C, R, G>(issuer: &str, codec: Arc<C>) -> cookie::CookieGate<C, R, G>
    where
        C: Codec<Payload = JwtClaims<Account<R, G>>>,
        R: AccessHierarchy + Eq + std::fmt::Display + Default + Clone + Send + Sync + 'static,
        G: Eq + Clone + Send + Sync + 'static,
    {
        let core = CoreGate::cookie::<C, R, G>(issuer, Arc::clone(&codec));
        core.adapt_with(CookieAdapter)
    }

    /// Creates a bearer-based Axum gate layer using the core configuration model.
    pub fn bearer<C, R, G>(issuer: &str, codec: Arc<C>) -> bearer::BearerGate<C, R, G, impl Clone>
    where
        C: Codec,
        R: AccessHierarchy + Eq + std::fmt::Display + Default + Clone + Send + Sync + 'static,
        G: Eq + Clone + Send + Sync + 'static,
    {
        let core = CoreGate::bearer::<C, R, G>(issuer, Arc::clone(&codec));
        core.adapt_with(BearerAdapter)
    }

    /// Creates an Axum OAuth2 gate builder adapted from the core OAuth2 configuration.
    pub fn oauth2<R, G>() -> oauth2::OAuth2Gate<R, G>
    where
        R: AccessHierarchy + Eq + std::fmt::Display + Send + Sync + 'static,
        G: Eq + Clone + Send + Sync + 'static,
    {
        let core = CoreGate::oauth2::<R, G>();
        core.adapt_with(OAuth2Adapter)
    }
}

/// Adapter converting core cookie gate configuration into the Axum cookie layer.
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

/// Adapter converting core bearer gate configuration into the Axum bearer layer.
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

/// Adapter converting core OAuth2 gate configuration into the axum OAuth2 wrapper.
///
/// The adapter returns the axum-side `oauth2::OAuth2Gate` wrapper. This is a
/// thin mapping: we construct the wrapper and let integrators further configure
/// it (for example, set a custom token exchanger) before calling `into_router`.
#[derive(Clone, Debug, Default)]
struct OAuth2Adapter;

impl<R, G> core_gate::oauth2::OAuth2GateAdapter<R, G> for OAuth2Adapter
where
    R: AccessHierarchy + Eq + std::fmt::Display + Send + Sync + 'static,
    G: Eq + Clone + Send + Sync + 'static,
{
    type Output = oauth2::OAuth2Gate<R, G>;

    fn adapt(&self, gate: core_gate::oauth2::OAuth2Gate<R, G>) -> Self::Output {
        // Convert the core builder into a validated, cloneable config snapshot
        // and map it into the axum-side wrapper via its builder methods.
        match gate.into_config() {
            Ok(cfg) => {
                let mut wrapper = oauth2::OAuth2Gate::new();

                // Basic endpoints and client info
                wrapper = wrapper
                    .auth_url(cfg.auth_url.clone())
                    .token_url(cfg.token_url.clone())
                    .client_id(cfg.client_id.clone());

                if let Some(secret) = cfg.client_secret.clone() {
                    wrapper = wrapper.client_secret(secret);
                }

                wrapper = wrapper.redirect_url(cfg.redirect_url.clone());

                // Scopes
                for scope in cfg.scopes.into_iter() {
                    wrapper = wrapper.add_scope(scope);
                }

                // Cookie templates
                wrapper = wrapper
                    .with_state_cookie_template(cfg.state_cookie_template.clone())
                    .with_pkce_cookie_template(cfg.pkce_cookie_template.clone())
                    .with_cookie_template(cfg.auth_cookie_template.clone());

                // Optional post-login redirect
                if let Some(redirect) = cfg.post_login_redirect.clone() {
                    wrapper = wrapper.with_post_login_redirect(redirect);
                }

                // Async mapper (if present) — forward the Arc into the wrapper.
                if let Some(mapper) = cfg.mapper.clone() {
                    wrapper = wrapper.with_account_mapper(move |token_resp| (mapper)(token_resp));
                }

                // Account inserter (if present) — forward the Arc into the wrapper.
                if let Some(inserter) = cfg.account_inserter.clone() {
                    wrapper = wrapper.with_account_inserter(move |account| (inserter)(account));
                }

                // Note: we intentionally do not attempt to map `jwt_encoder` here.
                // The axum wrapper exposes `with_jwt_codec(issuer, codec, ttl)`
                // which is a more ergonomic integration point for adapters that
                // have a concrete `Codec` available. Leaving `jwt_encoder` out
                // keeps the adapter mapping generic and lets integrators wire
                // encoding explicitly if required.

                wrapper
            }
            // On validation failure, fall back to an empty wrapper (caller will
            // see errors when attempting to `into_router`). Adapter could also
            // choose to surface the error — keeping the minimal fallback here.
            Err(_) => oauth2::OAuth2Gate::new(),
        }
    }
}
