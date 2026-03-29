//! Session domain types.
//!
//! This module owns the framework-agnostic session model used by issuance,
//! renewal, revocation, and repository orchestration.

use std::time::SystemTime;

use uuid::Uuid;

/// Unique identifier for a single session record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(Uuid);

impl SessionId {
    /// Creates a new session identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Creates a session identifier from an existing UUID.
    #[must_use]
    pub fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    /// Returns the underlying UUID value.
    #[must_use]
    pub fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for a session family.
///
/// A session family groups related sessions so higher-level logic can revoke
/// them together when replay or broader logout behavior requires it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionFamilyId(Uuid);

impl SessionFamilyId {
    /// Creates a new session-family identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Creates a session-family identifier from an existing UUID.
    #[must_use]
    pub fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    /// Returns the underlying UUID value.
    #[must_use]
    pub fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for SessionFamilyId {
    fn default() -> Self {
        Self::new()
    }
}

/// Persisted session state tracked by the session layer.
///
/// This is the canonical framework-agnostic session record used by repository
/// contracts and higher-level renewal services.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// Stable session identifier.
    pub session_id: SessionId,
    /// Owning session family identifier.
    pub family_id: SessionFamilyId,
    /// Stable subject identifier that owns the session.
    pub subject_id: String,
    /// Creation timestamp for the session.
    pub created_at: SystemTime,
    /// Expiration timestamp for the session.
    pub expires_at: SystemTime,
    /// Last observed activity timestamp for the session.
    pub last_seen_at: Option<SystemTime>,
    /// Whether the session is currently revoked.
    pub revoked: bool,
}

impl Session {
    /// Creates a new active session record.
    #[must_use]
    pub fn new(
        family_id: SessionFamilyId,
        subject_id: impl Into<String>,
        created_at: SystemTime,
        expires_at: SystemTime,
    ) -> Self {
        Self {
            session_id: SessionId::new(),
            family_id,
            subject_id: subject_id.into(),
            created_at,
            expires_at,
            last_seen_at: None,
            revoked: false,
        }
    }

    /// Returns a copy of the session with an updated `last_seen_at` value.
    #[must_use]
    pub fn touched(mut self, last_seen_at: SystemTime) -> Self {
        self.last_seen_at = Some(last_seen_at);
        self
    }

    /// Returns a copy of the session marked as revoked.
    #[must_use]
    pub fn revoked(mut self) -> Self {
        self.revoked = true;
        self
    }

    /// Returns `true` when the session is active at `now`.
    #[must_use]
    pub fn is_active_at(&self, now: SystemTime) -> bool {
        !self.revoked && self.expires_at > now
    }

    /// Returns `true` when the session has expired at `now`.
    #[must_use]
    pub fn is_expired_at(&self, now: SystemTime) -> bool {
        self.expires_at <= now
    }
}

/// Canonical repository-facing session record.
///
/// This alias exists so repository contracts can express intent clearly without
/// introducing a second parallel session model.
pub type SessionRecord = Session;

/// Repository-facing summary of a session family.
///
/// This view captures the minimum metadata needed for family-wide revocation and
/// replay handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionFamilyRecord {
    /// Stable family identifier.
    pub family_id: SessionFamilyId,
    /// Stable subject identifier that owns the family.
    pub subject_id: String,
    /// Creation timestamp for the family.
    pub created_at: SystemTime,
    /// Whether the full family has been revoked.
    pub revoked: bool,
}

impl SessionFamilyRecord {
    /// Creates a new active session-family record.
    #[must_use]
    pub fn new(
        family_id: SessionFamilyId,
        subject_id: impl Into<String>,
        created_at: SystemTime,
    ) -> Self {
        Self {
            family_id,
            subject_id: subject_id.into(),
            created_at,
            revoked: false,
        }
    }

    /// Returns a copy of the family marked as revoked.
    #[must_use]
    pub fn revoked(mut self) -> Self {
        self.revoked = true;
        self
    }

    /// Returns `true` when the family is still active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.revoked
    }
}

/// Repository-facing record for the currently active refresh token of a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRefreshRecord {
    /// Session that owns the refresh token.
    pub session_id: SessionId,
    /// Session family that owns the refresh token.
    pub family_id: SessionFamilyId,
    /// Timestamp when the current refresh token expires.
    pub expires_at: SystemTime,
    /// Whether the refresh token is currently revoked.
    pub revoked: bool,
}

impl SessionRefreshRecord {
    /// Creates a new active refresh-token record.
    #[must_use]
    pub fn new(session_id: SessionId, family_id: SessionFamilyId, expires_at: SystemTime) -> Self {
        Self {
            session_id,
            family_id,
            expires_at,
            revoked: false,
        }
    }

    /// Returns a copy of the refresh-token record marked as revoked.
    #[must_use]
    pub fn revoked(mut self) -> Self {
        self.revoked = true;
        self
    }

    /// Returns `true` when the refresh token is active at `now`.
    #[must_use]
    pub fn is_active_at(&self, now: SystemTime) -> bool {
        !self.revoked && self.expires_at > now
    }

    /// Returns `true` when the refresh token has expired at `now`.
    #[must_use]
    pub fn is_expired_at(&self, now: SystemTime) -> bool {
        self.expires_at <= now
    }
}

/// Combined repository lookup result used when locating session state by a
/// refresh token hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLookup {
    /// Session matched by the lookup.
    pub session: SessionRecord,
    /// Session family that owns the matched session.
    pub family: SessionFamilyRecord,
    /// Current refresh-token record for the matched session.
    pub refresh: SessionRefreshRecord,
}

impl SessionLookup {
    /// Creates a new combined session lookup result.
    #[must_use]
    pub fn new(
        session: SessionRecord,
        family: SessionFamilyRecord,
        refresh: SessionRefreshRecord,
    ) -> Self {
        Self {
            session,
            family,
            refresh,
        }
    }

    /// Returns `true` when all looked-up state is currently active at `now`.
    #[must_use]
    pub fn is_active_at(&self, now: SystemTime) -> bool {
        self.session.is_active_at(now) && self.family.is_active() && self.refresh.is_active_at(now)
    }
}

/// Input used to record session activity updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionTouch {
    /// Session to update.
    pub session_id: SessionId,
    /// New activity timestamp to persist.
    pub last_seen_at: SystemTime,
}

impl SessionTouch {
    /// Creates a new session-touch input.
    #[must_use]
    pub fn new(session_id: SessionId, last_seen_at: SystemTime) -> Self {
        Self {
            session_id,
            last_seen_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Session, SessionFamilyId, SessionFamilyRecord, SessionLookup, SessionRefreshRecord,
        SessionTouch,
    };
    use std::time::{Duration, SystemTime};

    #[test]
    fn new_session_is_active_and_not_revoked() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let session = Session::new(
            SessionFamilyId::new(),
            "user-123",
            now,
            now + Duration::from_secs(60),
        );

        assert!(!session.revoked);
        assert!(session.last_seen_at.is_none());
        assert!(session.is_active_at(now));
        assert!(!session.is_expired_at(now));
    }

    #[test]
    fn touched_session_updates_last_seen() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let touched_at = now + Duration::from_secs(10);
        let session = Session::new(
            SessionFamilyId::new(),
            "user-123",
            now,
            now + Duration::from_secs(60),
        )
        .touched(touched_at);

        assert_eq!(session.last_seen_at, Some(touched_at));
    }

    #[test]
    fn revoked_session_is_not_active() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let session = Session::new(
            SessionFamilyId::new(),
            "user-123",
            now,
            now + Duration::from_secs(60),
        )
        .revoked();

        assert!(session.revoked);
        assert!(!session.is_active_at(now));
    }

    #[test]
    fn expired_session_reports_expired() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let session = Session::new(
            SessionFamilyId::new(),
            "user-123",
            now,
            now + Duration::from_secs(1),
        );

        assert!(session.is_expired_at(now + Duration::from_secs(1)));
        assert!(!session.is_active_at(now + Duration::from_secs(1)));
    }

    #[test]
    fn family_record_reports_activity_state() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let active_family = SessionFamilyRecord::new(SessionFamilyId::new(), "user-123", now);
        let revoked_family = active_family.clone().revoked();

        assert!(active_family.is_active());
        assert!(!revoked_family.is_active());
    }

    #[test]
    fn refresh_record_reports_activity_state() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let refresh = SessionRefreshRecord::new(
            super::SessionId::new(),
            SessionFamilyId::new(),
            now + Duration::from_secs(60),
        );
        let revoked = refresh.clone().revoked();

        assert!(refresh.is_active_at(now));
        assert!(!refresh.is_expired_at(now));
        assert!(!revoked.is_active_at(now));
    }

    #[test]
    fn lookup_is_active_only_when_all_components_are_active() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let family = SessionFamilyRecord::new(SessionFamilyId::new(), "user-123", now);
        let session = Session::new(
            family.family_id,
            "user-123",
            now,
            now + Duration::from_secs(60),
        );
        let refresh = SessionRefreshRecord::new(
            session.session_id,
            family.family_id,
            now + Duration::from_secs(60),
        );

        let lookup = SessionLookup::new(session.clone(), family.clone(), refresh.clone());
        let revoked_lookup = SessionLookup::new(session.revoked(), family, refresh);

        assert!(lookup.is_active_at(now));
        assert!(!revoked_lookup.is_active_at(now));
    }

    #[test]
    fn session_touch_captures_target_and_timestamp() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let touch = SessionTouch::new(super::SessionId::new(), now);

        assert_eq!(touch.last_seen_at, now);
    }
}
