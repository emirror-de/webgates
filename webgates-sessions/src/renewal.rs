//! Renewal orchestration models for session auto-renewal.
//!
//! This module defines framework-agnostic renewal inputs, typed auth-token
//! state, deterministic decision logic, and high-level renewal outcomes.

use std::time::{Duration, SystemTime};

use crate::lease::LeaseAcquisition;
use crate::session::{Session, SessionId};
use crate::tokens::IssuedTokenPair;

/// Indicates whether a caller is attempting renewal proactively or because the
/// current auth token can no longer be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RenewalRequirement {
    /// Attempt renewal opportunistically while the current auth token remains
    /// valid.
    Proactive,
    /// Require a successful renewal before the request can proceed.
    Required,
}

/// Describes the observed state of the current auth token.
///
/// This type is intentionally framework agnostic. HTTP adapters and other
/// delivery layers can translate transport-specific validation results into
/// this domain-level model before invoking session renewal logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthTokenState {
    /// The auth token is currently valid and does not need renewal.
    Valid {
        /// Remaining time until the token expires.
        expires_in: Duration,
    },
    /// The auth token is still valid but has entered the proactive renewal
    /// window.
    NearExpiry {
        /// Remaining time until the token expires.
        expires_in: Duration,
    },
    /// The auth token has expired.
    Expired {
        /// Amount of time elapsed since expiry.
        expired_for: Duration,
    },
    /// The auth token is malformed, revoked, or otherwise invalid.
    Invalid,
}

impl AuthTokenState {
    /// Returns `true` when the current token may still authorize the request.
    #[must_use]
    pub fn is_currently_usable(self) -> bool {
        matches!(self, Self::Valid { .. } | Self::NearExpiry { .. })
    }

    /// Returns `true` when the token has entered the proactive renewal window.
    #[must_use]
    pub fn should_attempt_proactive_renewal(self) -> bool {
        matches!(self, Self::NearExpiry { .. })
    }

    /// Returns `true` when successful renewal is required before a caller may
    /// continue.
    #[must_use]
    pub fn requires_renewal(self) -> bool {
        matches!(self, Self::Expired { .. })
    }

    /// Returns `true` when the token must be rejected without renewal.
    #[must_use]
    pub fn is_invalid(self) -> bool {
        matches!(self, Self::Invalid)
    }
}

/// Input passed into the renewal decision flow.
///
/// This request captures only the deterministic, framework-agnostic inputs
/// needed to decide whether renewal should be attempted.
///
/// # Examples
///
/// ```
/// use std::time::{Duration, SystemTime};
/// use webgates_sessions::renewal::{
///     AuthTokenState, RenewalDecision, RenewalOrchestrator, RenewalRequest,
///     RenewalRequirement,
/// };
/// use webgates_sessions::session::SessionId;
///
/// let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
/// let request = RenewalRequest::new(
///     SessionId::new(),
///     AuthTokenState::NearExpiry { expires_in: Duration::from_secs(60) },
///     RenewalRequirement::Proactive,
///     now,
/// );
///
/// let decision = RenewalOrchestrator::new().decide(&request);
/// assert_eq!(decision, RenewalDecision::AttemptProactiveRenewal);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewalRequest {
    /// Session currently associated with the caller.
    pub session_id: SessionId,
    /// The current auth-token state observed by the caller.
    pub auth_token_state: AuthTokenState,
    /// Whether the renewal is opportunistic or mandatory.
    pub requirement: RenewalRequirement,
    /// Current wall-clock time used for deterministic decision making.
    pub now: SystemTime,
}

impl RenewalRequest {
    /// Creates a new renewal request.
    #[must_use]
    pub fn new(
        session_id: SessionId,
        auth_token_state: AuthTokenState,
        requirement: RenewalRequirement,
        now: SystemTime,
    ) -> Self {
        Self {
            session_id,
            auth_token_state,
            requirement,
            now,
        }
    }
}

/// High-level decision produced before repository-backed renewal work begins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RenewalDecision {
    /// No renewal attempt should be made.
    NoRenewal,
    /// Renewal may be attempted, but failure does not necessarily block the
    /// caller.
    AttemptProactiveRenewal,
    /// Renewal must succeed before the caller can continue.
    RequireRenewal,
    /// The caller must be rejected immediately without attempting renewal.
    Reject,
}

/// Context captured while a renewal attempt is in progress.
///
/// # Examples
///
/// ```
/// use std::time::{Duration, SystemTime};
/// use webgates_sessions::renewal::{
///     AuthTokenState, RenewalAttempt, RenewalRequest, RenewalRequirement,
/// };
/// use webgates_sessions::session::{Session, SessionFamilyId, SessionId};
///
/// let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
/// let session = Session::new(
///     SessionFamilyId::new(),
///     "user-42",
///     now,
///     now + Duration::from_secs(3_600),
/// );
/// let request = RenewalRequest::new(
///     session.session_id,
///     AuthTokenState::Expired { expired_for: Duration::from_secs(5) },
///     RenewalRequirement::Required,
///     now,
/// );
/// let attempt = RenewalAttempt::new(session.clone(), request);
///
/// assert_eq!(attempt.session_id(), session.session_id);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewalAttempt {
    /// Session selected for renewal.
    pub session: Session,
    /// Original request that triggered the attempt.
    pub request: RenewalRequest,
}

impl RenewalAttempt {
    /// Creates a new renewal attempt context.
    #[must_use]
    pub fn new(session: Session, request: RenewalRequest) -> Self {
        Self { session, request }
    }

    /// Returns the identifier of the session being renewed.
    #[must_use]
    pub fn session_id(&self) -> SessionId {
        self.request.session_id
    }
}

/// Outcome returned by the renewal orchestration layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewalOutcome {
    /// No renewal was necessary.
    NotNeeded,
    /// Renewal was attempted but could not proceed because another actor
    /// currently owns the lease or renewal slot.
    LeaseUnavailable {
        /// Observed lease-acquisition result.
        acquisition: LeaseAcquisition,
    },
    /// Renewal completed successfully and produced replacement tokens.
    Renewed {
        /// Session that remains active after renewal.
        session: Session,
        /// Newly issued auth and refresh tokens.
        tokens: IssuedTokenPair,
    },
    /// Renewal detected refresh-token replay and requires broader revocation.
    ReplayDetected {
        /// Session associated with the detected replay.
        session_id: SessionId,
    },
    /// Renewal cannot proceed because the request is not authorized.
    Rejected,
}

impl RenewalOutcome {
    /// Returns the newly issued token pair when renewal succeeded.
    #[must_use]
    pub fn issued_tokens(&self) -> Option<&IssuedTokenPair> {
        match self {
            Self::Renewed { tokens, .. } => Some(tokens),
            Self::NotNeeded
            | Self::LeaseUnavailable { .. }
            | Self::ReplayDetected { .. }
            | Self::Rejected => None,
        }
    }

    /// Returns the renewed session when renewal succeeded.
    #[must_use]
    pub fn session(&self) -> Option<&Session> {
        match self {
            Self::Renewed { session, .. } => Some(session),
            Self::NotNeeded
            | Self::LeaseUnavailable { .. }
            | Self::ReplayDetected { .. }
            | Self::Rejected => None,
        }
    }
}

/// Stateless decision helper for renewal orchestration.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use webgates_sessions::renewal::{
///     AuthTokenState, RenewalDecision, RenewalOrchestrator, RenewalRequirement,
/// };
///
/// let orchestrator = RenewalOrchestrator::new();
///
/// assert_eq!(
///     orchestrator.decide_for_state(
///         AuthTokenState::Valid { expires_in: Duration::from_secs(300) },
///         RenewalRequirement::Proactive,
///     ),
///     RenewalDecision::NoRenewal,
/// );
///
/// assert_eq!(
///     orchestrator.decide_for_state(
///         AuthTokenState::Expired { expired_for: Duration::from_secs(10) },
///         RenewalRequirement::Required,
///     ),
///     RenewalDecision::RequireRenewal,
/// );
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct RenewalOrchestrator;

impl RenewalOrchestrator {
    /// Creates a new renewal orchestrator.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Decides whether a renewal attempt should be made from token state alone.
    #[must_use]
    pub fn decide_for_state(
        &self,
        auth_token_state: AuthTokenState,
        requirement: RenewalRequirement,
    ) -> RenewalDecision {
        match (auth_token_state, requirement) {
            (AuthTokenState::Invalid, _) => RenewalDecision::Reject,
            (AuthTokenState::Expired { .. }, _) => RenewalDecision::RequireRenewal,
            (AuthTokenState::NearExpiry { .. }, RenewalRequirement::Proactive) => {
                RenewalDecision::AttemptProactiveRenewal
            }
            (AuthTokenState::NearExpiry { .. }, RenewalRequirement::Required) => {
                RenewalDecision::RequireRenewal
            }
            (AuthTokenState::Valid { .. }, _) => RenewalDecision::NoRenewal,
        }
    }

    /// Decides whether a renewal attempt should be made for the given request.
    #[must_use]
    pub fn decide(&self, request: &RenewalRequest) -> RenewalDecision {
        self.decide_for_state(request.auth_token_state, request.requirement)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn session_id() -> SessionId {
        SessionId::from_uuid(Uuid::now_v7())
    }

    #[test]
    fn proactive_near_expiry_requests_attempt_renewal() {
        let orchestrator = RenewalOrchestrator::new();
        let request = RenewalRequest::new(
            session_id(),
            AuthTokenState::NearExpiry {
                expires_in: Duration::from_secs(45),
            },
            RenewalRequirement::Proactive,
            SystemTime::UNIX_EPOCH,
        );

        assert_eq!(
            orchestrator.decide(&request),
            RenewalDecision::AttemptProactiveRenewal
        );
    }

    #[test]
    fn required_near_expiry_requests_require_renewal() {
        let orchestrator = RenewalOrchestrator::new();
        let request = RenewalRequest::new(
            session_id(),
            AuthTokenState::NearExpiry {
                expires_in: Duration::from_secs(10),
            },
            RenewalRequirement::Required,
            SystemTime::UNIX_EPOCH,
        );

        assert_eq!(
            orchestrator.decide(&request),
            RenewalDecision::RequireRenewal
        );
    }

    #[test]
    fn expired_requests_require_renewal() {
        let orchestrator = RenewalOrchestrator::new();
        let request = RenewalRequest::new(
            session_id(),
            AuthTokenState::Expired {
                expired_for: Duration::from_secs(30),
            },
            RenewalRequirement::Required,
            SystemTime::UNIX_EPOCH,
        );

        assert_eq!(
            orchestrator.decide(&request),
            RenewalDecision::RequireRenewal
        );
    }

    #[test]
    fn valid_requests_do_not_trigger_renewal() {
        let orchestrator = RenewalOrchestrator::new();
        let request = RenewalRequest::new(
            session_id(),
            AuthTokenState::Valid {
                expires_in: Duration::from_secs(600),
            },
            RenewalRequirement::Proactive,
            SystemTime::UNIX_EPOCH,
        );

        assert_eq!(orchestrator.decide(&request), RenewalDecision::NoRenewal);
    }

    #[test]
    fn invalid_requests_are_rejected() {
        let orchestrator = RenewalOrchestrator::new();
        let request = RenewalRequest::new(
            session_id(),
            AuthTokenState::Invalid,
            RenewalRequirement::Proactive,
            SystemTime::UNIX_EPOCH,
        );

        assert_eq!(orchestrator.decide(&request), RenewalDecision::Reject);
    }

    #[test]
    fn auth_token_state_helpers_match_expected_behavior() {
        let valid = AuthTokenState::Valid {
            expires_in: Duration::from_secs(60),
        };
        let near_expiry = AuthTokenState::NearExpiry {
            expires_in: Duration::from_secs(15),
        };
        let expired = AuthTokenState::Expired {
            expired_for: Duration::from_secs(5),
        };
        let invalid = AuthTokenState::Invalid;

        assert!(valid.is_currently_usable());
        assert!(!valid.should_attempt_proactive_renewal());
        assert!(!valid.requires_renewal());
        assert!(!valid.is_invalid());

        assert!(near_expiry.is_currently_usable());
        assert!(near_expiry.should_attempt_proactive_renewal());
        assert!(!near_expiry.requires_renewal());
        assert!(!near_expiry.is_invalid());

        assert!(!expired.is_currently_usable());
        assert!(!expired.should_attempt_proactive_renewal());
        assert!(expired.requires_renewal());
        assert!(!expired.is_invalid());

        assert!(!invalid.is_currently_usable());
        assert!(!invalid.should_attempt_proactive_renewal());
        assert!(!invalid.requires_renewal());
        assert!(invalid.is_invalid());
    }
}
