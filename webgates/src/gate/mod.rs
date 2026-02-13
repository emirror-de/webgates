#![allow(dead_code)]
//! Framework-agnostic gate entry points that delegate to bearer and cookie modules.

use std::fmt::Display;
use std::sync::Arc;

use crate::authz::AccessHierarchy;
use crate::codecs::Codec;

pub mod bearer;
pub mod cookie;

/// Entry point for constructing gate configurations.
#[derive(Clone, Debug, Default)]
pub struct Gate;

impl Gate {
    /// Create a cookie-based gate configuration (deny-all policy by default).
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
}
