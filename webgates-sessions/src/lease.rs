//! Renewal lease types used to coordinate session refresh attempts.

use std::time::{Duration, SystemTime};

use uuid::Uuid;

use crate::session::SessionId;

/// Uniquely identifies a single lease acquisition attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LeaseId(Uuid);

impl LeaseId {
    /// Creates a new random lease identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Returns the underlying UUID value.
    #[must_use]
    pub fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for LeaseId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for LeaseId {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

/// Configuration for how long a renewal lease remains valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseTtl(Duration);

impl LeaseTtl {
    /// Creates a new lease TTL.
    #[must_use]
    pub const fn new(duration: Duration) -> Self {
        Self(duration)
    }

    /// Returns the configured duration.
    #[must_use]
    pub const fn duration(self) -> Duration {
        self.0
    }

    /// Returns `true` when the TTL is zero.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0.is_zero()
    }
}

impl Default for LeaseTtl {
    fn default() -> Self {
        Self(Duration::from_secs(30))
    }
}

/// Timestamp until which a lease remains valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LeaseUntil(SystemTime);

impl LeaseUntil {
    /// Creates a new expiry timestamp.
    #[must_use]
    pub fn new(value: SystemTime) -> Self {
        Self(value)
    }

    /// Computes an expiry timestamp from `acquired_at` plus `ttl`.
    #[must_use]
    pub fn from_acquired_at(acquired_at: SystemTime, ttl: LeaseTtl) -> Self {
        Self(acquired_at + ttl.duration())
    }

    /// Returns the underlying timestamp.
    #[must_use]
    pub fn into_inner(self) -> SystemTime {
        self.0
    }

    /// Returns `true` when the lease is still valid at `now`.
    #[must_use]
    pub fn is_active_at(self, now: SystemTime) -> bool {
        now < self.0
    }

    /// Returns `true` when the lease has expired at `now`.
    #[must_use]
    pub fn is_expired_at(self, now: SystemTime) -> bool {
        !self.is_active_at(now)
    }
}

/// Represents an active renewal lease stored for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenewalLease {
    /// Session currently guarded by this lease.
    pub session_id: SessionId,
    /// Identifier of the active lease holder.
    pub lease_id: LeaseId,
    /// Time when the lease was acquired.
    pub acquired_at: SystemTime,
    /// Timestamp until which the lease remains valid.
    pub lease_until: LeaseUntil,
}

impl RenewalLease {
    /// Creates a new renewal lease with an explicit expiry timestamp.
    #[must_use]
    pub fn new(
        session_id: SessionId,
        lease_id: LeaseId,
        acquired_at: SystemTime,
        lease_until: LeaseUntil,
    ) -> Self {
        Self {
            session_id,
            lease_id,
            acquired_at,
            lease_until,
        }
    }

    /// Creates a new renewal lease from `acquired_at` and a TTL.
    #[must_use]
    pub fn from_ttl(
        session_id: SessionId,
        lease_id: LeaseId,
        acquired_at: SystemTime,
        ttl: LeaseTtl,
    ) -> Self {
        Self {
            session_id,
            lease_id,
            acquired_at,
            lease_until: LeaseUntil::from_acquired_at(acquired_at, ttl),
        }
    }

    /// Returns `true` when the lease is still active at `now`.
    #[must_use]
    pub fn is_active_at(self, now: SystemTime) -> bool {
        self.lease_until.is_active_at(now)
    }

    /// Returns `true` when the lease has expired at `now`.
    #[must_use]
    pub fn is_expired_at(self, now: SystemTime) -> bool {
        self.lease_until.is_expired_at(now)
    }
}

/// Outcome of attempting to acquire a renewal lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseAcquisition {
    /// The caller acquired the lease and may proceed with renewal.
    Acquired(RenewalLease),
    /// Another caller already holds a valid lease.
    HeldByOther {
        /// The currently active lease that prevented acquisition.
        active_lease: RenewalLease,
    },
    /// The session is no longer eligible for renewal.
    Unavailable,
}
