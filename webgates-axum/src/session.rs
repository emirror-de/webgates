#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
//! Cookie-backed session middleware for Axum.
//!
//! This module provides [`CookieSessionLayer`], an outer middleware layer that
//! performs transparent session renewal for cookie-based authentication flows.
//!
//! The intended composition is:
//! 1. apply [`CookieSessionLayer`] as the outer layer
//! 2. apply `webgates_axum::gate::Gate::cookie(...)` as the inner layer
//!
//! This keeps responsibilities separated:
//! - [`CookieSessionLayer`] owns refresh-cookie handling, renewal decisions, and
//!   response cookie mutation
//! - the existing cookie gate owns auth-token validation and authorization
//!
//! # Renewal model
//!
//! The layer implements the agreed option B behavior:
//! - valid auth token outside the proactive renewal window: pass through
//! - near-expiry auth token: attempt opportunistic renewal, but continue on
//!   failure
//! - expired auth token: require successful renewal before continuing
//! - invalid auth token: reject immediately without attempting renewal
//!
//! On successful renewal, the layer:
//! - rewrites the incoming auth cookie so inner middleware sees the fresh token
//! - appends `Set-Cookie` headers for the renewed auth and refresh cookies on
//!   the outgoing response
//!
//! The layer is framework-specific, but it delegates all renewal rules and
//! persistence behavior to `webgates-sessions`.

mod cookie_session_layer;
mod cookie_session_service;

pub use cookie_session_layer::CookieSessionLayer;
