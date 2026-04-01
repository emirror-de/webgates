//! In-memory session repository for deterministic tests and local composition.
//!
//! This module provides a framework-agnostic [`webgates_sessions::repository::SessionRepository`]
//! implementation backed by in-process state. It is intended for unit and
//! integration testing of session issuance, renewal, lease coordination, and
//! revocation semantics without requiring an external persistence backend.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

use webgates_sessions::lease::{LeaseAcquisition, RenewalLease};
use webgates_sessions::repository::{
    CreateSession, RepositoryError, RepositoryResult, RevokeSessionScope, RotateRefreshToken,
    RotateRefreshTokenOutcome, SessionRepository,
};
use webgates_sessions::session::{
    SessionFamilyId, SessionFamilyRecord, SessionId, SessionLookup, SessionRecord,
    SessionRefreshRecord, SessionTouch,
};
use webgates_sessions::tokens::{RefreshTokenHash, RefreshTokenHashRef};

/// In-memory session repository implementation.
///
/// This repository is intended for deterministic tests and local composition
/// where process-local state is sufficient.
#[derive(Debug, Clone, Default)]
pub struct MemorySessionRepository {
    state: Arc<Mutex<RepositoryState>>,
}

#[derive(Debug, Default)]
struct RepositoryState {
    sessions: HashMap<SessionId, StoredSession>,
    refresh_index: HashMap<String, SessionId>,
    families: HashMap<SessionFamilyId, SessionFamilyRecord>,
    leases: HashMap<SessionId, RenewalLease>,
}

#[derive(Debug, Clone)]
struct StoredSession {
    session: SessionRecord,
    refresh: StoredRefresh,
}

#[derive(Debug, Clone)]
struct StoredRefresh {
    hash: RefreshTokenHash,
    record: SessionRefreshRecord,
}

impl MemorySessionRepository {
    /// Creates an empty in-memory repository.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionRepository for MemorySessionRepository {
    async fn create_session(&self, input: CreateSession) -> RepositoryResult<()> {
        let mut guard = self.state.lock().await;

        if guard.sessions.contains_key(&input.session.session_id) {
            return Err(RepositoryError::Conflict);
        }

        let family = guard
            .families
            .entry(input.session.family_id)
            .or_insert_with(|| {
                SessionFamilyRecord::new(
                    input.session.family_id,
                    input.session.subject_id.clone(),
                    input.session.created_at,
                )
            })
            .clone();

        if family.subject_id != input.session.subject_id {
            return Err(RepositoryError::InvalidState);
        }

        let refresh_record = SessionRefreshRecord::new(
            input.session.session_id,
            input.session.family_id,
            input.session.expires_at,
        );

        guard.refresh_index.insert(
            input.refresh_token_hash.as_str().to_owned(),
            input.session.session_id,
        );
        guard.sessions.insert(
            input.session.session_id,
            StoredSession {
                session: input.session,
                refresh: StoredRefresh {
                    hash: input.refresh_token_hash,
                    record: refresh_record,
                },
            },
        );

        Ok(())
    }

    async fn find_session_by_refresh_token_hash<'a>(
        &'a self,
        refresh_token_hash: RefreshTokenHashRef<'a>,
    ) -> RepositoryResult<Option<SessionLookup>> {
        let guard = self.state.lock().await;

        let Some(session_id) = guard.refresh_index.get(refresh_token_hash).copied() else {
            return Ok(None);
        };

        Ok(guard.lookup_by_session_id(session_id))
    }

    async fn find_session(&self, session_id: SessionId) -> RepositoryResult<Option<SessionRecord>> {
        let guard = self.state.lock().await;
        Ok(guard
            .sessions
            .get(&session_id)
            .map(|stored| stored.session.clone()))
    }

    async fn find_family(
        &self,
        family_id: SessionFamilyId,
    ) -> RepositoryResult<Option<SessionFamilyRecord>> {
        let guard = self.state.lock().await;
        Ok(guard.families.get(&family_id).cloned())
    }

    async fn find_refresh_record(
        &self,
        session_id: SessionId,
    ) -> RepositoryResult<Option<SessionRefreshRecord>> {
        let guard = self.state.lock().await;
        Ok(guard
            .sessions
            .get(&session_id)
            .map(|stored| stored.refresh.record.clone()))
    }

    async fn try_acquire_renewal_lease(
        &self,
        session_id: SessionId,
        lease: RenewalLease,
    ) -> RepositoryResult<LeaseAcquisition> {
        let mut guard = self.state.lock().await;

        let Some(stored) = guard.sessions.get(&session_id) else {
            return Ok(LeaseAcquisition::Unavailable);
        };

        let Some(family) = guard.families.get(&stored.session.family_id) else {
            return Err(RepositoryError::InvalidState);
        };

        if stored.session.revoked || stored.refresh.record.revoked || family.revoked {
            return Ok(LeaseAcquisition::Unavailable);
        }

        match guard.leases.get(&session_id).copied() {
            Some(active_lease) if active_lease.is_active_at(lease.acquired_at) => {
                Ok(LeaseAcquisition::HeldByOther { active_lease })
            }
            Some(_) => {
                guard.leases.insert(session_id, lease);
                Ok(LeaseAcquisition::Acquired(lease))
            }
            None => {
                guard.leases.insert(session_id, lease);
                Ok(LeaseAcquisition::Acquired(lease))
            }
        }
    }

    async fn rotate_refresh_token(
        &self,
        input: RotateRefreshToken,
    ) -> RepositoryResult<RotateRefreshTokenOutcome> {
        let mut guard = self.state.lock().await;

        let Some(stored) = guard.sessions.get(&input.session_id) else {
            return Ok(RotateRefreshTokenOutcome::SessionMissing);
        };

        let Some(family) = guard.families.get(&stored.session.family_id) else {
            return Err(RepositoryError::InvalidState);
        };

        if family.family_id != input.family.family_id
            || family.subject_id != input.family.subject_id
            || family.revoked != input.family.revoked
        {
            return Err(RepositoryError::Conflict);
        }

        if stored.session.family_id != input.family.family_id {
            return Err(RepositoryError::InvalidState);
        }

        if stored.session.revoked || stored.refresh.record.revoked || family.revoked {
            return Ok(RotateRefreshTokenOutcome::SessionMissing);
        }

        match guard.leases.get(&input.session_id).copied() {
            Some(active_lease)
                if active_lease.lease_id == input.lease.lease_id
                    && active_lease.is_active_at(input.lease.acquired_at) => {}
            Some(_) | None => return Ok(RotateRefreshTokenOutcome::LeaseUnavailable),
        }

        if stored.refresh.hash != input.previous_refresh_token_hash {
            guard.leases.remove(&input.session_id);
            return Ok(RotateRefreshTokenOutcome::RefreshTokenMismatch);
        }

        if input.next_session.session_id != input.session_id
            || input.next_session.family_id != input.family.family_id
        {
            return Err(RepositoryError::InvalidState);
        }

        let previous_hash_key = stored.refresh.hash.as_str().to_owned();
        let next_refresh_record = SessionRefreshRecord::new(
            input.next_session.session_id,
            input.next_session.family_id,
            input.next_session.expires_at,
        );

        guard.refresh_index.remove(&previous_hash_key);
        guard.refresh_index.insert(
            input.next_refresh_token_hash.as_str().to_owned(),
            input.next_session.session_id,
        );
        guard.leases.remove(&input.session_id);
        guard.sessions.insert(
            input.session_id,
            StoredSession {
                session: input.next_session,
                refresh: StoredRefresh {
                    hash: input.next_refresh_token_hash,
                    record: next_refresh_record,
                },
            },
        );

        Ok(RotateRefreshTokenOutcome::Rotated)
    }

    async fn revoke_session(
        &self,
        session_id: SessionId,
        scope: RevokeSessionScope,
    ) -> RepositoryResult<()> {
        match scope {
            RevokeSessionScope::CurrentSession => {
                let mut guard = self.state.lock().await;
                guard.revoke_single_session(session_id)
            }
            RevokeSessionScope::SessionFamily => {
                let family_id = {
                    let guard = self.state.lock().await;
                    let Some(stored) = guard.sessions.get(&session_id) else {
                        return Err(RepositoryError::SessionNotFound);
                    };
                    stored.session.family_id
                };

                self.revoke_family(family_id).await
            }
        }
    }

    async fn revoke_family(&self, family_id: SessionFamilyId) -> RepositoryResult<()> {
        let mut guard = self.state.lock().await;

        let Some(family) = guard.families.get_mut(&family_id) else {
            return Err(RepositoryError::SessionFamilyNotFound);
        };
        family.revoked = true;

        let session_ids: Vec<SessionId> = guard
            .sessions
            .iter()
            .filter_map(|(session_id, stored)| {
                (stored.session.family_id == family_id).then_some(*session_id)
            })
            .collect();

        for session_id in session_ids {
            guard.revoke_single_session_state(session_id)?;
        }

        Ok(())
    }

    async fn touch_session(&self, touch: SessionTouch) -> RepositoryResult<()> {
        let mut guard = self.state.lock().await;

        let Some(stored) = guard.sessions.get_mut(&touch.session_id) else {
            return Err(RepositoryError::SessionNotFound);
        };

        stored.session.last_seen_at = Some(touch.last_seen_at);
        Ok(())
    }
}

impl RepositoryState {
    fn lookup_by_session_id(&self, session_id: SessionId) -> Option<SessionLookup> {
        let stored = self.sessions.get(&session_id)?;
        let family = self.families.get(&stored.session.family_id)?.clone();

        Some(SessionLookup::new(
            stored.session.clone(),
            family,
            stored.refresh.record.clone(),
        ))
    }

    fn revoke_single_session(&mut self, session_id: SessionId) -> RepositoryResult<()> {
        self.revoke_single_session_state(session_id)
            .map_err(|error| match error {
                RepositoryError::SessionNotFound => RepositoryError::SessionNotFound,
                other => other,
            })
    }

    fn revoke_single_session_state(&mut self, session_id: SessionId) -> RepositoryResult<()> {
        let Some(stored) = self.sessions.get_mut(&session_id) else {
            return Err(RepositoryError::SessionNotFound);
        };

        stored.session.revoked = true;
        stored.refresh.record.revoked = true;
        self.refresh_index.remove(stored.refresh.hash.as_str());
        self.leases.remove(&session_id);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MemorySessionRepository;
    use std::time::{Duration, SystemTime};
    use webgates_sessions::lease::{LeaseAcquisition, LeaseId, LeaseTtl, RenewalLease};
    use webgates_sessions::repository::{
        CreateSession, RevokeSessionScope, RotateRefreshToken, RotateRefreshTokenOutcome,
        SessionRepository,
    };
    use webgates_sessions::session::{
        Session, SessionFamilyId, SessionFamilyRecord, SessionId, SessionRefreshRecord,
        SessionTouch,
    };
    use webgates_sessions::tokens::RefreshTokenHash;

    fn sample_time() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(10_000)
    }

    fn sample_hash(value: &str) -> RefreshTokenHash {
        match RefreshTokenHash::new(value) {
            Ok(hash) => hash,
            Err(error) => panic!("expected valid refresh-token hash: {error}"),
        }
    }

    fn sample_session() -> Session {
        let now = sample_time();

        Session::new(
            SessionFamilyId::new(),
            "subject-123",
            now,
            now + Duration::from_secs(3_600),
        )
    }

    fn sample_family(session: &Session) -> SessionFamilyRecord {
        SessionFamilyRecord::new(
            session.family_id,
            session.subject_id.clone(),
            session.created_at,
        )
    }

    fn sample_refresh(session: &Session) -> SessionRefreshRecord {
        SessionRefreshRecord::new(session.session_id, session.family_id, session.expires_at)
    }

    fn sample_lease(session_id: SessionId, acquired_at: SystemTime) -> RenewalLease {
        RenewalLease::from_ttl(
            session_id,
            LeaseId::new(),
            acquired_at,
            LeaseTtl::new(Duration::from_secs(30)),
        )
    }

    async fn store_session(
        repository: &MemorySessionRepository,
        session: Session,
        refresh_hash: &str,
    ) {
        let result = repository
            .create_session(CreateSession {
                session,
                refresh_token_hash: sample_hash(refresh_hash),
            })
            .await;

        assert_eq!(result, Ok(()));
    }

    #[tokio::test]
    async fn create_and_lookup_session_by_refresh_hash() {
        let repository = MemorySessionRepository::new();
        let session = sample_session();

        store_session(&repository, session.clone(), "refresh-hash-1").await;

        let lookup = match repository
            .find_session_by_refresh_token_hash("refresh-hash-1")
            .await
        {
            Ok(Some(lookup)) => lookup,
            Ok(None) => panic!("expected session lookup to exist"),
            Err(error) => panic!("expected successful lookup: {error}"),
        };

        assert_eq!(lookup.session, session);
        assert_eq!(lookup.family, sample_family(&session));
        assert_eq!(lookup.refresh, sample_refresh(&session));
    }

    #[tokio::test]
    async fn acquire_lease_returns_held_by_other_while_active_lease_exists() {
        let repository = MemorySessionRepository::new();
        let session = sample_session();
        let now = sample_time();

        store_session(&repository, session.clone(), "refresh-hash-2").await;

        let first_lease = sample_lease(session.session_id, now);
        let first = repository
            .try_acquire_renewal_lease(session.session_id, first_lease)
            .await;
        assert_eq!(first, Ok(LeaseAcquisition::Acquired(first_lease)));

        let second_lease = sample_lease(session.session_id, now + Duration::from_secs(5));
        let second = repository
            .try_acquire_renewal_lease(session.session_id, second_lease)
            .await;

        assert_eq!(
            second,
            Ok(LeaseAcquisition::HeldByOther {
                active_lease: first_lease,
            })
        );
    }

    #[tokio::test]
    async fn acquire_lease_replaces_expired_lease() {
        let repository = MemorySessionRepository::new();
        let session = sample_session();
        let now = sample_time();

        store_session(&repository, session.clone(), "refresh-hash-3").await;

        let expired_lease = sample_lease(session.session_id, now);
        let acquired = repository
            .try_acquire_renewal_lease(session.session_id, expired_lease)
            .await;
        assert_eq!(acquired, Ok(LeaseAcquisition::Acquired(expired_lease)));

        let next_lease = sample_lease(session.session_id, now + Duration::from_secs(31));
        let reacquired = repository
            .try_acquire_renewal_lease(session.session_id, next_lease)
            .await;
        assert_eq!(reacquired, Ok(LeaseAcquisition::Acquired(next_lease)));
    }

    #[tokio::test]
    async fn rotate_refresh_token_updates_lookup_and_clears_lease() {
        let repository = MemorySessionRepository::new();
        let now = sample_time();
        let session = sample_session();

        store_session(&repository, session.clone(), "refresh-hash-4").await;

        let lease = sample_lease(session.session_id, now);
        let lease_result = repository
            .try_acquire_renewal_lease(session.session_id, lease)
            .await;
        assert_eq!(lease_result, Ok(LeaseAcquisition::Acquired(lease)));

        let family = match repository.find_family(session.family_id).await {
            Ok(Some(family)) => family,
            Ok(None) => panic!("expected family to exist"),
            Err(error) => panic!("expected successful family lookup: {error}"),
        };

        let next_session = session
            .clone()
            .touched(now + Duration::from_secs(10))
            .touched(now + Duration::from_secs(20));

        let outcome = repository
            .rotate_refresh_token(RotateRefreshToken {
                session_id: session.session_id,
                family,
                lease,
                previous_refresh_token_hash: sample_hash("refresh-hash-4"),
                next_refresh_token_hash: sample_hash("refresh-hash-4-next"),
                next_session: next_session.clone(),
            })
            .await;

        assert_eq!(outcome, Ok(RotateRefreshTokenOutcome::Rotated));

        let old_lookup = repository
            .find_session_by_refresh_token_hash("refresh-hash-4")
            .await;
        assert_eq!(old_lookup, Ok(None));

        let new_lookup = match repository
            .find_session_by_refresh_token_hash("refresh-hash-4-next")
            .await
        {
            Ok(Some(lookup)) => lookup,
            Ok(None) => panic!("expected rotated session lookup to exist"),
            Err(error) => panic!("expected successful rotated lookup: {error}"),
        };

        assert_eq!(new_lookup.session, next_session);

        let reacquire = repository
            .try_acquire_renewal_lease(
                session.session_id,
                sample_lease(session.session_id, now + Duration::from_secs(1)),
            )
            .await;

        assert!(matches!(reacquire, Ok(LeaseAcquisition::Acquired(_))));
    }

    #[tokio::test]
    async fn rotate_refresh_token_detects_hash_mismatch() {
        let repository = MemorySessionRepository::new();
        let now = sample_time();
        let session = sample_session();

        store_session(&repository, session.clone(), "refresh-hash-5").await;

        let lease = sample_lease(session.session_id, now);
        let lease_result = repository
            .try_acquire_renewal_lease(session.session_id, lease)
            .await;
        assert_eq!(lease_result, Ok(LeaseAcquisition::Acquired(lease)));

        let family = match repository.find_family(session.family_id).await {
            Ok(Some(family)) => family,
            Ok(None) => panic!("expected family to exist"),
            Err(error) => panic!("expected family lookup to succeed: {error}"),
        };

        let outcome = repository
            .rotate_refresh_token(RotateRefreshToken {
                session_id: session.session_id,
                family,
                lease,
                previous_refresh_token_hash: sample_hash("wrong-refresh-hash"),
                next_refresh_token_hash: sample_hash("refresh-hash-5-next"),
                next_session: session.clone().touched(now + Duration::from_secs(5)),
            })
            .await;

        assert_eq!(outcome, Ok(RotateRefreshTokenOutcome::RefreshTokenMismatch));
    }

    #[tokio::test]
    async fn revoke_current_session_marks_session_and_refresh_as_revoked() {
        let repository = MemorySessionRepository::new();
        let session = sample_session();

        store_session(&repository, session.clone(), "refresh-hash-6").await;

        let revoke = repository
            .revoke_session(session.session_id, RevokeSessionScope::CurrentSession)
            .await;
        assert_eq!(revoke, Ok(()));

        let stored_session = match repository.find_session(session.session_id).await {
            Ok(Some(stored)) => stored,
            Ok(None) => panic!("expected stored session to exist"),
            Err(error) => panic!("expected session lookup to succeed: {error}"),
        };
        let refresh_record = match repository.find_refresh_record(session.session_id).await {
            Ok(Some(record)) => record,
            Ok(None) => panic!("expected refresh record to exist"),
            Err(error) => panic!("expected refresh record lookup to succeed: {error}"),
        };

        assert!(stored_session.revoked);
        assert!(refresh_record.revoked);
        assert_eq!(
            repository
                .find_session_by_refresh_token_hash("refresh-hash-6")
                .await,
            Ok(None)
        );
    }

    #[tokio::test]
    async fn revoke_family_marks_all_sessions_in_family_as_revoked() {
        let repository = MemorySessionRepository::new();
        let first = sample_session();
        let second = Session {
            session_id: SessionId::new(),
            family_id: first.family_id,
            subject_id: first.subject_id.clone(),
            created_at: first.created_at + Duration::from_secs(1),
            expires_at: first.expires_at + Duration::from_secs(1),
            last_seen_at: None,
            revoked: false,
        };

        store_session(&repository, first.clone(), "refresh-hash-7a").await;
        store_session(&repository, second.clone(), "refresh-hash-7b").await;

        let revoke = repository.revoke_family(first.family_id).await;
        assert_eq!(revoke, Ok(()));

        let first_session = match repository.find_session(first.session_id).await {
            Ok(Some(session)) => session,
            Ok(None) => panic!("expected first session to exist"),
            Err(error) => panic!("expected first session lookup to succeed: {error}"),
        };
        let second_session = match repository.find_session(second.session_id).await {
            Ok(Some(session)) => session,
            Ok(None) => panic!("expected second session to exist"),
            Err(error) => panic!("expected second session lookup to succeed: {error}"),
        };
        let family = match repository.find_family(first.family_id).await {
            Ok(Some(family)) => family,
            Ok(None) => panic!("expected family to exist"),
            Err(error) => panic!("expected family lookup to succeed: {error}"),
        };

        assert!(first_session.revoked);
        assert!(second_session.revoked);
        assert!(family.revoked);
        assert_eq!(
            repository
                .find_session_by_refresh_token_hash("refresh-hash-7a")
                .await,
            Ok(None)
        );
        assert_eq!(
            repository
                .find_session_by_refresh_token_hash("refresh-hash-7b")
                .await,
            Ok(None)
        );
    }

    #[tokio::test]
    async fn touch_session_updates_last_seen_timestamp() {
        let repository = MemorySessionRepository::new();
        let session = sample_session();
        let touched_at = sample_time() + Duration::from_secs(42);

        store_session(&repository, session.clone(), "refresh-hash-8").await;

        let result = repository
            .touch_session(SessionTouch::new(session.session_id, touched_at))
            .await;
        assert_eq!(result, Ok(()));

        let stored_session = match repository.find_session(session.session_id).await {
            Ok(Some(session)) => session,
            Ok(None) => panic!("expected stored session to exist"),
            Err(error) => panic!("expected session lookup to succeed: {error}"),
        };

        assert_eq!(stored_session.last_seen_at, Some(touched_at));
    }

    #[tokio::test]
    async fn second_concurrent_lease_acquisition_is_blocked_until_first_expires() {
        let repository = MemorySessionRepository::new();
        let session = sample_session();
        let now = sample_time();

        store_session(&repository, session.clone(), "refresh-hash-9").await;

        let first_lease = sample_lease(session.session_id, now);
        let second_lease = sample_lease(session.session_id, now + Duration::from_secs(1));

        let first = repository
            .try_acquire_renewal_lease(session.session_id, first_lease)
            .await;
        let second = repository
            .try_acquire_renewal_lease(session.session_id, second_lease)
            .await;

        assert_eq!(first, Ok(LeaseAcquisition::Acquired(first_lease)));
        assert_eq!(
            second,
            Ok(LeaseAcquisition::HeldByOther {
                active_lease: first_lease,
            })
        );
    }

    #[tokio::test]
    async fn expired_lease_allows_follow_up_rotation_to_succeed() {
        let repository = MemorySessionRepository::new();
        let now = sample_time();
        let session = sample_session();

        store_session(&repository, session.clone(), "refresh-hash-10").await;

        let expired_lease = sample_lease(session.session_id, now);
        let lease_result = repository
            .try_acquire_renewal_lease(session.session_id, expired_lease)
            .await;
        assert_eq!(lease_result, Ok(LeaseAcquisition::Acquired(expired_lease)));

        let replacement_lease = sample_lease(session.session_id, now + Duration::from_secs(31));
        let reacquired = repository
            .try_acquire_renewal_lease(session.session_id, replacement_lease)
            .await;
        assert_eq!(
            reacquired,
            Ok(LeaseAcquisition::Acquired(replacement_lease))
        );

        let family = match repository.find_family(session.family_id).await {
            Ok(Some(family)) => family,
            Ok(None) => panic!("expected family to exist"),
            Err(error) => panic!("expected successful family lookup: {error}"),
        };

        let next_session = session.clone().touched(now + Duration::from_secs(32));

        let outcome = repository
            .rotate_refresh_token(RotateRefreshToken {
                session_id: session.session_id,
                family,
                lease: replacement_lease,
                previous_refresh_token_hash: sample_hash("refresh-hash-10"),
                next_refresh_token_hash: sample_hash("refresh-hash-10-next"),
                next_session: next_session.clone(),
            })
            .await;

        assert_eq!(outcome, Ok(RotateRefreshTokenOutcome::Rotated));

        let lookup = match repository
            .find_session_by_refresh_token_hash("refresh-hash-10-next")
            .await
        {
            Ok(Some(lookup)) => lookup,
            Ok(None) => panic!("expected rotated lookup to exist"),
            Err(error) => panic!("expected rotated lookup to succeed: {error}"),
        };

        assert_eq!(lookup.session, next_session);
    }

    #[tokio::test]
    async fn replay_detection_outcome_preserves_current_active_refresh_token() {
        let repository = MemorySessionRepository::new();
        let now = sample_time();
        let session = sample_session();

        store_session(&repository, session.clone(), "refresh-hash-11").await;

        let lease = sample_lease(session.session_id, now);
        let lease_result = repository
            .try_acquire_renewal_lease(session.session_id, lease)
            .await;
        assert_eq!(lease_result, Ok(LeaseAcquisition::Acquired(lease)));

        let family = match repository.find_family(session.family_id).await {
            Ok(Some(family)) => family,
            Ok(None) => panic!("expected family to exist"),
            Err(error) => panic!("expected family lookup to succeed: {error}"),
        };

        let outcome = repository
            .rotate_refresh_token(RotateRefreshToken {
                session_id: session.session_id,
                family,
                lease,
                previous_refresh_token_hash: sample_hash("stale-refresh-hash"),
                next_refresh_token_hash: sample_hash("refresh-hash-11-next"),
                next_session: session.clone().touched(now + Duration::from_secs(5)),
            })
            .await;

        assert_eq!(outcome, Ok(RotateRefreshTokenOutcome::RefreshTokenMismatch));

        let original_lookup = match repository
            .find_session_by_refresh_token_hash("refresh-hash-11")
            .await
        {
            Ok(Some(lookup)) => lookup,
            Ok(None) => panic!("expected original lookup to remain active"),
            Err(error) => panic!("expected original lookup to succeed: {error}"),
        };

        assert_eq!(original_lookup.session.session_id, session.session_id);
        assert_eq!(
            repository
                .find_session_by_refresh_token_hash("refresh-hash-11-next")
                .await,
            Ok(None)
        );
    }

    #[tokio::test]
    async fn family_revocation_blocks_subsequent_renewal_lease_acquisition() {
        let repository = MemorySessionRepository::new();
        let session = sample_session();
        let now = sample_time();

        store_session(&repository, session.clone(), "refresh-hash-12").await;

        let revoke = repository.revoke_family(session.family_id).await;
        assert_eq!(revoke, Ok(()));

        let lease = sample_lease(session.session_id, now + Duration::from_secs(1));
        let acquisition = repository
            .try_acquire_renewal_lease(session.session_id, lease)
            .await;

        assert_eq!(acquisition, Ok(LeaseAcquisition::Unavailable));
    }
}
