//! Session logout primitives.
//!
//! This module defines the framework-agnostic types that drive session
//! revocation flows. Transport adapters remain responsible for extracting
//! cookies, headers, and request metadata before calling into these models.

use crate::session::{SessionFamilyId, SessionId};

/// The requested scope of a logout operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogoutScope {
    /// Revoke only the current session.
    CurrentSession,
    /// Revoke every session that belongs to the same session family.
    SessionFamily,
}

/// Input required to revoke an existing session.
///
/// Higher-level adapters and services populate this value from the currently
/// authenticated session context.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LogoutRequest {
    /// The session targeted by the logout operation.
    pub session_id: SessionId,
    /// The family that owns the targeted session.
    pub family_id: SessionFamilyId,
    /// The revocation scope to apply.
    pub scope: LogoutScope,
}

impl LogoutRequest {
    /// Creates a new logout request.
    #[must_use]
    pub fn new(session_id: SessionId, family_id: SessionFamilyId, scope: LogoutScope) -> Self {
        Self {
            session_id,
            family_id,
            scope,
        }
    }
}

/// Outcome produced by a logout operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogoutOutcome {
    /// The current session was revoked.
    CurrentSessionRevoked,
    /// The full session family was revoked.
    SessionFamilyRevoked,
}
