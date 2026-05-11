//! Session repository contracts.
//!
//! This module defines the framework-agnostic persistence boundary used by
//! `webgates-sessions` services.
//!
//! If you implement session storage for a new backend, this is the main module
//! you will work with.

use crate::lease::LeaseAcquisition;
use crate::lease::RenewalLease;
use crate::session::SessionFamilyId;
use crate::session::SessionFamilyRecord;
use crate::session::SessionId;
use crate::session::SessionLookup;
use crate::session::SessionRecord;
use crate::session::SessionRefreshRecord;
use crate::session::SessionTouch;
use crate::tokens::RefreshTokenHash;
use crate::tokens::RefreshTokenHashRef;

/// Result alias used by session persistence contracts.
pub type RepositoryResult<T> = std::result::Result<T, RepositoryError>;

/// Repository error used by the session contract surface.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RepositoryError {
    /// The requested session record could not be found.
    #[error("session not found")]
    SessionNotFound,

    /// The requested session family record could not be found.
    #[error("session family not found")]
    SessionFamilyNotFound,

    /// The repository rejected a concurrent update.
    #[error("concurrent session update detected")]
    Conflict,

    /// Stored session state was invalid or internally inconsistent.
    #[error("invalid persisted session state")]
    InvalidState,

    /// The backend returned a safe, caller-facing error summary.
    #[error("{message}")]
    Backend {
        /// Safe backend failure summary.
        message: String,
    },
}

impl RepositoryError {
    /// Creates a backend error with a safe, caller-facing message.
    #[must_use]
    pub fn backend(message: impl Into<String>) -> Self {
        Self::Backend {
            message: message.into(),
        }
    }
}

/// Input required to persist a newly issued session.
///
/// # Examples
///
/// ```
/// use std::time::{Duration, SystemTime};
/// use webgates_sessions::repository::CreateSession;
/// use webgates_sessions::session::{Session, SessionFamilyId};
/// use webgates_sessions::tokens::RefreshTokenHash;
///
/// let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
/// let session = Session::new(
///     SessionFamilyId::new(),
///     "user-42",
///     now,
///     now + Duration::from_secs(3_600),
/// );
/// let hash = RefreshTokenHash::new("abc123def456").unwrap();
///
/// let input = CreateSession {
///     session: session.clone(),
///     refresh_token_hash: hash.clone(),
/// };
///
/// assert_eq!(input.session, session);
/// assert_eq!(input.refresh_token_hash, hash);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSession {
    /// Full session record to persist.
    pub session: SessionRecord,
    /// Active refresh-token hash associated with the session.
    pub refresh_token_hash: RefreshTokenHash,
}

/// Input required to atomically rotate a refresh token.
///
/// # Examples
///
/// ```
/// use std::time::{Duration, SystemTime};
/// use webgates_sessions::lease::{LeaseId, LeaseTtl, RenewalLease};
/// use webgates_sessions::repository::RotateRefreshToken;
/// use webgates_sessions::session::{Session, SessionFamilyId, SessionFamilyRecord};
/// use webgates_sessions::tokens::RefreshTokenHash;
///
/// let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
/// let family_id = SessionFamilyId::new();
/// let session = Session::new(
///     family_id,
///     "user-42",
///     now,
///     now + Duration::from_secs(3_600),
/// );
/// let family = SessionFamilyRecord::new(family_id, "user-42", now);
/// let lease = RenewalLease::from_ttl(
///     session.session_id,
///     LeaseId::new(),
///     now,
///     LeaseTtl::new(Duration::from_secs(30)),
/// );
///
/// let input = RotateRefreshToken {
///     session_id: session.session_id,
///     family,
///     lease,
///     previous_refresh_token_hash: RefreshTokenHash::new("prev-hash-abc").unwrap(),
///     next_refresh_token_hash: RefreshTokenHash::new("next-hash-xyz").unwrap(),
///     next_session: session.clone().touched(now),
/// };
///
/// assert_eq!(input.session_id, session.session_id);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateRefreshToken {
    /// Session that is being renewed.
    pub session_id: SessionId,
    /// Session family that owns the session.
    pub family: SessionFamilyRecord,
    /// Lease expected to authorize this rotation.
    pub lease: RenewalLease,
    /// Previously active refresh-token hash.
    pub previous_refresh_token_hash: RefreshTokenHash,
    /// Newly issued refresh-token hash to persist.
    pub next_refresh_token_hash: RefreshTokenHash,
    /// Updated session record that should become current after rotation.
    pub next_session: SessionRecord,
}

/// Result of attempting an atomic refresh-token rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotateRefreshTokenOutcome {
    /// Rotation succeeded and the new refresh token is now active.
    Rotated,
    /// The session no longer exists or is no longer active.
    SessionMissing,
    /// The lease was missing, expired, or owned by another renewal attempt.
    LeaseUnavailable,
    /// The previous refresh token no longer matched the persisted active token.
    ///
    /// Callers should treat this as potential replay and apply family
    /// revocation rules as appropriate.
    RefreshTokenMismatch,
}

/// Scope used when revoking session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeSessionScope {
    /// Revoke only the current session.
    CurrentSession,
    /// Revoke every session in the same family.
    SessionFamily,
}

/// Repository boundary for session persistence and lease coordination.
///
/// Implementations are expected to keep lease acquisition, token rotation, and
/// revocation semantics correct under concurrent access.
pub trait SessionRepository: Send + Sync {
    /// Creates a new persisted session and stores its active refresh-token hash.
    fn create_session(
        &self,
        input: CreateSession,
    ) -> impl std::future::Future<Output = RepositoryResult<()>> + Send;

    /// Looks up session state by the presented refresh-token hash.
    fn find_session_by_refresh_token_hash<'a>(
        &'a self,
        refresh_token_hash: RefreshTokenHashRef<'a>,
    ) -> impl std::future::Future<Output = RepositoryResult<Option<SessionLookup>>> + Send + 'a;

    /// Loads the current session record by identifier.
    fn find_session(
        &self,
        session_id: SessionId,
    ) -> impl std::future::Future<Output = RepositoryResult<Option<SessionRecord>>> + Send;

    /// Loads summary information for a session family.
    fn find_family(
        &self,
        family_id: SessionFamilyId,
    ) -> impl std::future::Future<Output = RepositoryResult<Option<SessionFamilyRecord>>> + Send;

    /// Loads the current refresh-token record for a session.
    fn find_refresh_record(
        &self,
        session_id: SessionId,
    ) -> impl std::future::Future<Output = RepositoryResult<Option<SessionRefreshRecord>>> + Send;

    /// Attempts to acquire or observe the renewal lease for a session.
    fn try_acquire_renewal_lease(
        &self,
        session_id: SessionId,
        lease: RenewalLease,
    ) -> impl std::future::Future<Output = RepositoryResult<LeaseAcquisition>> + Send;

    /// Atomically rotates the active refresh token for an existing session.
    fn rotate_refresh_token(
        &self,
        input: RotateRefreshToken,
    ) -> impl std::future::Future<Output = RepositoryResult<RotateRefreshTokenOutcome>> + Send;

    /// Revokes the specified session or its full family.
    fn revoke_session(
        &self,
        session_id: SessionId,
        scope: RevokeSessionScope,
    ) -> impl std::future::Future<Output = RepositoryResult<()>> + Send;

    /// Revokes every session that belongs to the provided family.
    fn revoke_family(
        &self,
        family_id: SessionFamilyId,
    ) -> impl std::future::Future<Output = RepositoryResult<()>> + Send;

    /// Records session activity such as a later `last_seen_at` update.
    fn touch_session(
        &self,
        touch: SessionTouch,
    ) -> impl std::future::Future<Output = RepositoryResult<()>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::{LeaseAcquisition, LeaseId, LeaseTtl, RenewalLease};
    use crate::session::{Session, SessionFamilyRecord};
    use std::time::{Duration, SystemTime};

    #[derive(Debug, Clone, Copy, Default)]
    struct ContractRepository;

    impl SessionRepository for ContractRepository {
        async fn create_session(&self, _input: CreateSession) -> RepositoryResult<()> {
            Ok(())
        }

        async fn find_session_by_refresh_token_hash<'a>(
            &'a self,
            _refresh_token_hash: RefreshTokenHashRef<'a>,
        ) -> RepositoryResult<Option<SessionLookup>> {
            Ok(None)
        }

        async fn find_session(
            &self,
            _session_id: SessionId,
        ) -> RepositoryResult<Option<SessionRecord>> {
            Ok(None)
        }

        async fn find_family(
            &self,
            _family_id: SessionFamilyId,
        ) -> RepositoryResult<Option<SessionFamilyRecord>> {
            Ok(None)
        }

        async fn find_refresh_record(
            &self,
            _session_id: SessionId,
        ) -> RepositoryResult<Option<SessionRefreshRecord>> {
            Ok(None)
        }

        async fn try_acquire_renewal_lease(
            &self,
            _session_id: SessionId,
            lease: RenewalLease,
        ) -> RepositoryResult<LeaseAcquisition> {
            Ok(LeaseAcquisition::Acquired(lease))
        }

        async fn rotate_refresh_token(
            &self,
            _input: RotateRefreshToken,
        ) -> RepositoryResult<RotateRefreshTokenOutcome> {
            Ok(RotateRefreshTokenOutcome::Rotated)
        }

        async fn revoke_session(
            &self,
            _session_id: SessionId,
            _scope: RevokeSessionScope,
        ) -> RepositoryResult<()> {
            Ok(())
        }

        async fn revoke_family(&self, _family_id: SessionFamilyId) -> RepositoryResult<()> {
            Ok(())
        }

        async fn touch_session(&self, _touch: SessionTouch) -> RepositoryResult<()> {
            Ok(())
        }
    }

    fn assert_session_repository<T: SessionRepository>(_repository: &T) {}

    fn sample_time() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000)
    }

    fn sample_hash(value: &str) -> RefreshTokenHash {
        match RefreshTokenHash::new(value) {
            Ok(hash) => hash,
            Err(error) => panic!("expected valid refresh-token hash: {error}"),
        }
    }

    fn sample_session() -> SessionRecord {
        let now = sample_time();

        Session::new(
            SessionFamilyId::new(),
            "subject-123",
            now,
            now + Duration::from_secs(3_600),
        )
    }

    fn sample_lease(session_id: SessionId) -> RenewalLease {
        RenewalLease::from_ttl(
            session_id,
            LeaseId::new(),
            sample_time(),
            LeaseTtl::new(Duration::from_secs(30)),
        )
    }

    #[test]
    fn backend_error_constructor_keeps_message() {
        let error = RepositoryError::backend("safe backend summary");

        assert_eq!(
            error,
            RepositoryError::Backend {
                message: String::from("safe backend summary"),
            }
        );
    }

    #[tokio::test]
    async fn repository_trait_contracts_are_callable() {
        let repository = ContractRepository;
        assert_session_repository(&repository);

        let session = sample_session();
        let family =
            SessionFamilyRecord::new(session.family_id, session.subject_id.clone(), sample_time());
        let lease = sample_lease(session.session_id);
        let create_input = CreateSession {
            session: session.clone(),
            refresh_token_hash: sample_hash("active-refresh-hash"),
        };
        let rotate_input = RotateRefreshToken {
            session_id: session.session_id,
            family,
            lease,
            previous_refresh_token_hash: sample_hash("previous-refresh-hash"),
            next_refresh_token_hash: sample_hash("next-refresh-hash"),
            next_session: session
                .clone()
                .touched(sample_time() + Duration::from_secs(10)),
        };
        let touch = SessionTouch::new(session.session_id, sample_time() + Duration::from_secs(20));

        assert_eq!(repository.create_session(create_input).await, Ok(()));
        assert!(matches!(
            repository
                .find_session_by_refresh_token_hash("lookup-refresh-hash")
                .await,
            Ok(None)
        ));
        assert!(matches!(
            repository.find_session(session.session_id).await,
            Ok(None)
        ));
        assert!(matches!(
            repository.find_family(session.family_id).await,
            Ok(None)
        ));
        assert!(matches!(
            repository.find_refresh_record(session.session_id).await,
            Ok(None)
        ));
        assert_eq!(
            repository
                .try_acquire_renewal_lease(session.session_id, lease)
                .await,
            Ok(LeaseAcquisition::Acquired(lease))
        );
        assert_eq!(
            repository.rotate_refresh_token(rotate_input).await,
            Ok(RotateRefreshTokenOutcome::Rotated)
        );
        assert_eq!(
            repository
                .revoke_session(session.session_id, RevokeSessionScope::CurrentSession)
                .await,
            Ok(())
        );
        assert_eq!(repository.revoke_family(session.family_id).await, Ok(()));
        assert_eq!(repository.touch_session(touch).await, Ok(()));
    }
}
