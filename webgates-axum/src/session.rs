#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
//! Cookie-backed session middleware for Axum.
//!
//! This module provides the Axum middleware used for transparent session renewal
//! in cookie-backed authentication flows.
//!
//! If you use session-backed auth in Axum, this is the main middleware module to read.
//!
//! The intended composition is:
//! 1. apply `cookie_session_layer::CookieSessionLayer` as the outer layer
//! 2. apply `webgates_axum::gate::Gate::cookie(...)` as the inner layer
//!
//! This keeps responsibilities separated:
//! - `cookie_session_layer::CookieSessionLayer` owns refresh-cookie handling,
//!   renewal decisions, and
//!   response cookie mutation
//! - the existing cookie gate owns auth-token validation and authorization
//!
//! # Renewal model
//!
//! The layer applies the following renewal behavior:
//! - valid auth token outside the proactive renewal window: pass through
//! - near-expiry auth token: attempt opportunistic renewal, but continue on
//!   failure
//! - expired auth token: require successful renewal before continuing
//! - invalid auth token: reject immediately without attempting renewal
//!
//! # Missing, expired, and invalid auth cookies
//!
//! When this layer is composed outside `webgates_axum::gate::Gate::cookie(...)`,
//! the request behavior is:
//!
//! - absent auth cookie: this layer does not attempt renewal and forwards the
//!   request to the inner cookie gate unchanged
//! - expired auth cookie: this layer requires a successful refresh-cookie-based
//!   renewal before the request may continue
//! - invalid auth cookie: this layer rejects the request immediately and does
//!   not attempt renewal
//!
//! The final result for an absent auth cookie still depends on how the inner
//! cookie gate is configured:
//!
//! - strict cookie-gate mode returns `401 Unauthorized`
//! - optional cookie-gate mode forwards the request and installs optional user
//!   context
//!
//! On successful renewal, the layer:
//! - rewrites the incoming auth cookie so inner middleware sees the fresh token
//! - appends `Set-Cookie` headers for the renewed auth and refresh cookies on
//!   the outgoing response
//!
//! The layer is framework-specific, but it delegates all renewal rules and
//! persistence behavior to `webgates-sessions`.

/// Axum layer for transparent cookie-backed session renewal.
pub mod cookie_session_layer;
mod cookie_session_service;
