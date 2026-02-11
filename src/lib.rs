#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

//! # webgates
//!
//! Flexible, type-safe authentication and authorization for axum using JWTs and optional OAuth2.
//! Supports cookie and bearer authentication, plus an OAuth2 Authorization Code + PKCE login flow
//! that mints a first-party JWT cookie for browser sessions. Designed for single nodes and
//! distributed systems with multiple storage backends.
//!
//! ## Key Features
//!
//! - **Cookie and bearer JWT authentication** - Choose HTTP-only cookies or Authorization: Bearer
//! - **OAuth2 login flow builder** - Authorization Code + PKCE; mints first-party JWT cookies
//! - **Role-based access control** - Hierarchical roles with supervisor inheritance
//! - **Group-based access control** - Organize users by teams, departments, or projects
//! - **Permission system** - Fine-grained permissions with deterministic hashing
//! - **Multiple storage backends** - In-memory, SurrealDB, SeaORM support
//! - **Distributed system ready** - Zero-synchronization permission system
//! - **Pre-built handlers** - Login/logout endpoints with timing attack protection
//! - **Optional anonymous context** - Install `Option<Account>` and `Option<RegisteredClaims>`
//! - **Static token mode** - Simple shared-secret bearer auth for internal services
//! - **Audit and metrics (feature-gated)** - Structured audit logs and Prometheus metrics

#[cfg(feature = "server")]
pub mod audit;
#[cfg(all(feature = "server", feature = "storage-seaorm"))]
pub mod comma_separated_value;
#[cfg(feature = "server")]
pub mod cookie_template;
