//! SurrealDB-backed session repository adapter.
//!
//! This module keeps SurrealDB-specific persistence concerns at the adapter
//! boundary while implementing the framework-agnostic
//! `webgates_sessions::repository::SessionRepository` contract.
//!
//! The adapter stores two record families:
//! - session families
//! - individual sessions with embedded refresh-token and lease state
//!
//! Renewal leases are modeled as part of the stored session record so lease
//! acquisition and refresh-token rotation can be coordinated through
//! compare-and-swap style checks.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use surrealdb_types::{RecordId, RecordIdKey, SurrealValue, Uuid as SurrealUuid};
use uuid::Uuid;
use webgates_sessions::lease::{LeaseAcquisition, LeaseId, LeaseUntil, RenewalLease};
use webgates_sessions::repository::{
    CreateSession, RepositoryError, RepositoryResult, RevokeSessionScope, RotateRefreshToken,
    RotateRefreshTokenOutcome, SessionRepository,
};
use webgates_sessions::session::{
    SessionFamilyId, SessionFamilyRecord, SessionId, SessionLookup, SessionRecord,
    SessionRefreshRecord, SessionTouch,
};
use webgates_sessions::tokens::{RefreshTokenHash, RefreshTokenHashRef};

use super::SurrealDbRepository;

/// SurrealDB persistence record for a session family.
#[derive(Clone, Debug, Serialize, Deserialize, SurrealValue)]
struct SurrealSessionFamilyRecord {
    family_id: Uuid,
    subject_id: String,
    created_at_unix_seconds: u64,
    revoked: bool,
}

impl SurrealSessionFamilyRecord {
    fn from_domain(record: SessionFamilyRecord) -> RepositoryResult<Self> {
        Ok(Self {
            family_id: record.family_id.into_uuid(),
            subject_id: record.subject_id,
            created_at_unix_seconds: system_time_to_unix_seconds(record.created_at)?,
            revoked: record.revoked,
        })
    }

    fn into_domain(self) -> RepositoryResult<SessionFamilyRecord> {
        Ok(SessionFamilyRecord {
            family_id: SessionFamilyId::from_uuid(self.family_id),
            subject_id: self.subject_id,
            created_at: unix_seconds_to_system_time(self.created_at_unix_seconds),
            revoked: self.revoked,
        })
    }
}

/// SurrealDB persistence record for a session.
#[derive(Clone, Debug, Serialize, Deserialize, SurrealValue)]
struct SurrealSessionRecord {
    session_id: Uuid,
    family_id: Uuid,
    subject_id: String,
    created_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    last_seen_at_unix_seconds: Option<u64>,
    revoked: bool,
    active_refresh_token_hash: String,
    active_refresh_expires_at_unix_seconds: u64,
    active_refresh_revoked: bool,
    lease: Option<SurrealLeaseRecord>,
}

impl SurrealSessionRecord {
    fn from_parts(
        session: SessionRecord,
        refresh_token_hash: RefreshTokenHash,
        refresh_record: SessionRefreshRecord,
        lease: Option<RenewalLease>,
    ) -> RepositoryResult<Self> {
        Ok(Self {
            session_id: session.session_id.into_uuid(),
            family_id: session.family_id.into_uuid(),
            subject_id: session.subject_id,
            created_at_unix_seconds: system_time_to_unix_seconds(session.created_at)?,
            expires_at_unix_seconds: system_time_to_unix_seconds(session.expires_at)?,
            last_seen_at_unix_seconds: session
                .last_seen_at
                .map(system_time_to_unix_seconds)
                .transpose()?,
            revoked: session.revoked,
            active_refresh_token_hash: refresh_token_hash.into_inner(),
            active_refresh_expires_at_unix_seconds: system_time_to_unix_seconds(
                refresh_record.expires_at,
            )?,
            active_refresh_revoked: refresh_record.revoked,
            lease: lease.map(SurrealLeaseRecord::from_domain),
        })
    }

    fn to_session_record(&self) -> SessionRecord {
        SessionRecord {
            session_id: SessionId::from_uuid(self.session_id),
            family_id: SessionFamilyId::from_uuid(self.family_id),
            subject_id: self.subject_id.clone(),
            created_at: unix_seconds_to_system_time(self.created_at_unix_seconds),
            expires_at: unix_seconds_to_system_time(self.expires_at_unix_seconds),
            last_seen_at: self
                .last_seen_at_unix_seconds
                .map(unix_seconds_to_system_time),
            revoked: self.revoked,
        }
    }

    fn to_refresh_record(&self) -> SessionRefreshRecord {
        SessionRefreshRecord {
            session_id: SessionId::from_uuid(self.session_id),
            family_id: SessionFamilyId::from_uuid(self.family_id),
            expires_at: unix_seconds_to_system_time(self.active_refresh_expires_at_unix_seconds),
            revoked: self.active_refresh_revoked,
        }
    }
}

/// SurrealDB persistence record for an active renewal lease.
#[derive(Clone, Debug, Serialize, Deserialize, SurrealValue)]
struct SurrealLeaseRecord {
    lease_id: Uuid,
    acquired_at_unix_seconds: u64,
    lease_until_unix_seconds: u64,
}

impl SurrealLeaseRecord {
    fn from_domain(lease: RenewalLease) -> Self {
        Self {
            lease_id: lease.lease_id.into_uuid(),
            acquired_at_unix_seconds: system_time_to_unix_seconds_lossy(lease.acquired_at),
            lease_until_unix_seconds: system_time_to_unix_seconds_lossy(
                lease.lease_until.into_inner(),
            ),
        }
    }

    fn to_domain_for_session(&self, session_id: SessionId) -> RenewalLease {
        RenewalLease::new(
            session_id,
            LeaseId::from(self.lease_id),
            unix_seconds_to_system_time(self.acquired_at_unix_seconds),
            LeaseUntil::new(unix_seconds_to_system_time(self.lease_until_unix_seconds)),
        )
    }
}

impl<S> SessionRepository for SurrealDbRepository<S>
where
    S: Connection,
{
    async fn bootstrap(&self) -> RepositoryResult<()> {
        self.bootstrap_session_tables().await.map(|_| ())
    }

    async fn create_session(&self, input: CreateSession) -> RepositoryResult<()> {
        let repo = self.bootstrap_session_tables().await?;

        let family_table = sessions_family_table_name();
        let session_table = sessions_table_name();

        let family_record = SurrealSessionFamilyRecord::from_domain(SessionFamilyRecord::new(
            input.session.family_id,
            input.session.subject_id.clone(),
            input.session.created_at,
        ))?;

        let refresh_record = SessionRefreshRecord::new(
            input.session.session_id,
            input.session.family_id,
            input.session.expires_at,
        );

        let session_record = SurrealSessionRecord::from_parts(
            input.session.clone(),
            input.refresh_token_hash,
            refresh_record,
            None,
        )?;

        let family_record_id = family_record_id(input.session.family_id, &family_table);
        let existing_family: Option<SurrealSessionFamilyRecord> = repo
            .db
            .select(family_record_id.clone())
            .await
            .map_err(map_backend_error)?;

        if existing_family.is_none() {
            let _: Option<SurrealSessionFamilyRecord> = repo
                .db
                .insert(family_record_id)
                .content(family_record)
                .await
                .map_err(map_backend_error)?;
        }

        let session_record_id = session_record_id(input.session.session_id, &session_table);
        let existing_session: Option<SurrealSessionRecord> = repo
            .db
            .select(session_record_id.clone())
            .await
            .map_err(map_backend_error)?;

        if existing_session.is_some() {
            return Err(RepositoryError::Conflict);
        }

        let _: Option<SurrealSessionRecord> = repo
            .db
            .insert(session_record_id)
            .content(session_record)
            .await
            .map_err(map_backend_error)?;

        Ok(())
    }

    async fn find_session_by_refresh_token_hash<'a>(
        &'a self,
        refresh_token_hash: RefreshTokenHashRef<'a>,
    ) -> RepositoryResult<Option<SessionLookup>> {
        let repo = self.bootstrap_session_tables().await?;

        let session_table = sessions_table_name();
        let family_table = sessions_family_table_name();

        let query = "SELECT * FROM type::table($session_table) WHERE active_refresh_token_hash = $refresh_hash LIMIT 1";

        let mut response = repo
            .db
            .query(query)
            .bind(("session_table", session_table.clone()))
            .bind(("refresh_hash", refresh_token_hash.to_string()))
            .await
            .map_err(map_backend_error)?;

        let stored_session: Option<SurrealSessionRecord> =
            response.take(0).map_err(map_backend_error)?;

        let Some(stored_session) = stored_session else {
            return Ok(None);
        };

        if stored_session.revoked || stored_session.active_refresh_revoked {
            return Ok(None);
        }

        let family_id = SessionFamilyId::from_uuid(stored_session.family_id);
        let family_record_id = family_record_id(family_id, &family_table);
        let stored_family: Option<SurrealSessionFamilyRecord> = repo
            .db
            .select(family_record_id)
            .await
            .map_err(map_backend_error)?;

        let Some(stored_family) = stored_family else {
            return Err(RepositoryError::InvalidState);
        };

        Ok(Some(SessionLookup::new(
            stored_session.to_session_record(),
            stored_family.into_domain()?,
            stored_session.to_refresh_record(),
        )))
    }

    async fn find_session(&self, session_id: SessionId) -> RepositoryResult<Option<SessionRecord>> {
        let repo = self.bootstrap_session_tables().await?;

        let session_table = sessions_table_name();
        let record_id = session_record_id(session_id, &session_table);
        let stored: Option<SurrealSessionRecord> =
            repo.db.select(record_id).await.map_err(map_backend_error)?;

        Ok(stored.map(|record| record.to_session_record()))
    }

    async fn find_family(
        &self,
        family_id: SessionFamilyId,
    ) -> RepositoryResult<Option<SessionFamilyRecord>> {
        let repo = self.bootstrap_session_tables().await?;

        let family_table = sessions_family_table_name();
        let record_id = family_record_id(family_id, &family_table);
        let stored: Option<SurrealSessionFamilyRecord> =
            repo.db.select(record_id).await.map_err(map_backend_error)?;

        stored
            .map(SurrealSessionFamilyRecord::into_domain)
            .transpose()
    }

    async fn find_refresh_record(
        &self,
        session_id: SessionId,
    ) -> RepositoryResult<Option<SessionRefreshRecord>> {
        let repo = self.bootstrap_session_tables().await?;

        let session_table = sessions_table_name();
        let record_id = session_record_id(session_id, &session_table);
        let stored: Option<SurrealSessionRecord> =
            repo.db.select(record_id).await.map_err(map_backend_error)?;

        Ok(stored.map(|record| record.to_refresh_record()))
    }

    async fn try_acquire_renewal_lease(
        &self,
        session_id: SessionId,
        lease: RenewalLease,
    ) -> RepositoryResult<LeaseAcquisition> {
        let repo = self.bootstrap_session_tables().await?;

        let session_table = sessions_table_name();
        let record_id = session_record_id(session_id, &session_table);
        let stored: Option<SurrealSessionRecord> = repo
            .db
            .select(record_id.clone())
            .await
            .map_err(map_backend_error)?;

        let Some(mut stored) = stored else {
            return Ok(LeaseAcquisition::Unavailable);
        };

        if stored.revoked || stored.active_refresh_revoked {
            return Ok(LeaseAcquisition::Unavailable);
        }

        if let Some(active_lease) = stored
            .lease
            .as_ref()
            .map(|record| record.to_domain_for_session(session_id))
            && active_lease.is_active_at(lease.acquired_at)
        {
            return Ok(LeaseAcquisition::HeldByOther { active_lease });
        }

        stored.lease = Some(SurrealLeaseRecord::from_domain(lease));

        let _: Option<SurrealSessionRecord> = repo
            .db
            .update(record_id)
            .content(stored)
            .await
            .map_err(map_backend_error)?;

        Ok(LeaseAcquisition::Acquired(lease))
    }

    async fn rotate_refresh_token(
        &self,
        input: RotateRefreshToken,
    ) -> RepositoryResult<RotateRefreshTokenOutcome> {
        let repo = self.bootstrap_session_tables().await?;

        let session_table = sessions_table_name();
        let family_table = sessions_family_table_name();

        let session_record_id = session_record_id(input.session_id, &session_table);
        let stored_session: Option<SurrealSessionRecord> = repo
            .db
            .select(session_record_id.clone())
            .await
            .map_err(map_backend_error)?;

        let Some(stored_session) = stored_session else {
            return Ok(RotateRefreshTokenOutcome::SessionMissing);
        };

        let family_record_id = family_record_id(input.family.family_id, &family_table);
        let stored_family: Option<SurrealSessionFamilyRecord> = repo
            .db
            .select(family_record_id)
            .await
            .map_err(map_backend_error)?;

        let Some(stored_family) = stored_family else {
            return Err(RepositoryError::InvalidState);
        };

        let stored_family = stored_family.into_domain()?;
        if stored_family != input.family {
            return Err(RepositoryError::Conflict);
        }

        if stored_session.revoked || stored_session.active_refresh_revoked || stored_family.revoked
        {
            return Ok(RotateRefreshTokenOutcome::SessionMissing);
        }

        let Some(active_lease) = stored_session
            .lease
            .as_ref()
            .map(|record| record.to_domain_for_session(input.session_id))
        else {
            return Ok(RotateRefreshTokenOutcome::LeaseUnavailable);
        };

        if active_lease.lease_id != input.lease.lease_id
            || active_lease.is_expired_at(input.lease.acquired_at)
        {
            return Ok(RotateRefreshTokenOutcome::LeaseUnavailable);
        }

        if stored_session.active_refresh_token_hash != input.previous_refresh_token_hash.as_str() {
            return Ok(RotateRefreshTokenOutcome::RefreshTokenMismatch);
        }

        if input.next_session.session_id != input.session_id
            || input.next_session.family_id != input.family.family_id
        {
            return Err(RepositoryError::InvalidState);
        }

        let refresh_record = SessionRefreshRecord::new(
            input.next_session.session_id,
            input.next_session.family_id,
            input.next_session.expires_at,
        );

        let updated = SurrealSessionRecord::from_parts(
            input.next_session,
            input.next_refresh_token_hash,
            refresh_record,
            None,
        )?;

        let _: Option<SurrealSessionRecord> = repo
            .db
            .update(session_record_id)
            .content(updated)
            .await
            .map_err(map_backend_error)?;

        Ok(RotateRefreshTokenOutcome::Rotated)
    }

    async fn revoke_session(
        &self,
        session_id: SessionId,
        scope: RevokeSessionScope,
    ) -> RepositoryResult<()> {
        match scope {
            RevokeSessionScope::CurrentSession => {
                let repo = self.bootstrap_session_tables().await?;

                let session_table = sessions_table_name();
                let record_id = session_record_id(session_id, &session_table);
                let stored: Option<SurrealSessionRecord> = repo
                    .db
                    .select(record_id.clone())
                    .await
                    .map_err(map_backend_error)?;

                let Some(mut stored) = stored else {
                    return Err(RepositoryError::SessionNotFound);
                };

                stored.revoked = true;
                stored.active_refresh_revoked = true;
                stored.lease = None;

                let _: Option<SurrealSessionRecord> = repo
                    .db
                    .update(record_id)
                    .content(stored)
                    .await
                    .map_err(map_backend_error)?;

                Ok(())
            }
            RevokeSessionScope::SessionFamily => {
                let family = self.find_session(session_id).await?;
                let Some(session) = family else {
                    return Err(RepositoryError::SessionNotFound);
                };
                self.revoke_family(session.family_id).await
            }
        }
    }

    async fn revoke_family(&self, family_id: SessionFamilyId) -> RepositoryResult<()> {
        let repo = self.bootstrap_session_tables().await?;

        let family_table = sessions_family_table_name();
        let session_table = sessions_table_name();

        let family_record_id = family_record_id(family_id, &family_table);
        let stored_family: Option<SurrealSessionFamilyRecord> = repo
            .db
            .select(family_record_id.clone())
            .await
            .map_err(map_backend_error)?;

        let Some(mut stored_family) = stored_family else {
            return Err(RepositoryError::SessionFamilyNotFound);
        };

        stored_family.revoked = true;

        let _: Option<SurrealSessionFamilyRecord> = repo
            .db
            .update(family_record_id)
            .content(stored_family)
            .await
            .map_err(map_backend_error)?;

        let query = "SELECT * FROM type::table($session_table) WHERE family_id = $family_id ORDER BY created_at_unix_seconds ASC";
        let mut response = repo
            .db
            .query(query)
            .bind(("session_table", session_table.clone()))
            .bind(("family_id", family_id.into_uuid()))
            .await
            .map_err(map_backend_error)?;

        let stored_sessions: Vec<SurrealSessionRecord> =
            response.take(0).map_err(map_backend_error)?;

        for mut stored_session in stored_sessions {
            stored_session.revoked = true;
            stored_session.active_refresh_revoked = true;
            stored_session.lease = None;

            let record_id = session_record_id(
                SessionId::from_uuid(stored_session.session_id),
                &session_table,
            );

            let _: Option<SurrealSessionRecord> = repo
                .db
                .update(record_id)
                .content(stored_session)
                .await
                .map_err(map_backend_error)?;
        }

        Ok(())
    }

    async fn touch_session(&self, touch: SessionTouch) -> RepositoryResult<()> {
        let repo = self.bootstrap_session_tables().await?;

        let session_table = sessions_table_name();
        let record_id = session_record_id(touch.session_id, &session_table);
        let stored: Option<SurrealSessionRecord> = repo
            .db
            .select(record_id.clone())
            .await
            .map_err(map_backend_error)?;

        let Some(mut stored) = stored else {
            return Err(RepositoryError::SessionNotFound);
        };

        stored.last_seen_at_unix_seconds = Some(system_time_to_unix_seconds(touch.last_seen_at)?);

        let _: Option<SurrealSessionRecord> = repo
            .db
            .update(record_id)
            .content(stored)
            .await
            .map_err(map_backend_error)?;

        Ok(())
    }
}

fn sessions_table_name() -> String {
    "webgates_sessions".to_string()
}

impl<S> SurrealDbRepository<S>
where
    S: Connection,
{
    async fn bootstrap_session_tables(&self) -> RepositoryResult<SurrealDbRepository<S>> {
        let repo = self.use_ns_db().await.map_err(map_bootstrap_error)?;

        repo.session_schema_initialized
            .get_or_try_init(|| async {
                let family_table = sessions_family_table_name();
                let session_table = sessions_table_name();

                repo.define_schemaless_table(&family_table).await?;
                repo.define_schemaless_table(&session_table).await?;

                let define_refresh_hash_index = format!(
                    "DEFINE INDEX IF NOT EXISTS webgates_sessions_refresh_token_hash_idx ON {} FIELDS active_refresh_token_hash UNIQUE",
                    session_table
                );
                repo.db
                    .query(define_refresh_hash_index)
                    .await
                    .map_err(map_bootstrap_error)?;

                let define_family_id_index = format!(
                    "DEFINE INDEX IF NOT EXISTS webgates_sessions_family_id_idx ON {} FIELDS family_id",
                    session_table
                );
                repo.db
                    .query(define_family_id_index)
                    .await
                    .map_err(map_bootstrap_error)?;

                Ok(())
            })
            .await?;

        Ok(repo)
    }

    async fn define_schemaless_table(&self, table_name: &str) -> RepositoryResult<()> {
        let query = "DEFINE TABLE IF NOT EXISTS $table SCHEMALESS;";

        self.db
            .query(query)
            .bind(("table", table_name.to_string()))
            .await
            .map(|_| ())
            .map_err(map_bootstrap_error)
    }
}

fn sessions_family_table_name() -> String {
    "webgates_session_families".to_string()
}

fn session_record_id(session_id: SessionId, table_name: &str) -> RecordId {
    RecordId::new(
        table_name.to_string(),
        RecordIdKey::from(SurrealUuid::from(session_id.into_uuid())),
    )
}

fn family_record_id(family_id: SessionFamilyId, table_name: &str) -> RecordId {
    RecordId::new(
        table_name.to_string(),
        RecordIdKey::from(SurrealUuid::from(family_id.into_uuid())),
    )
}

fn system_time_to_unix_seconds(value: SystemTime) -> RepositoryResult<u64> {
    value
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| RepositoryError::InvalidState)
}

fn system_time_to_unix_seconds_lossy(value: SystemTime) -> u64 {
    value
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn unix_seconds_to_system_time(value: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(value)
}

fn map_bootstrap_error(error: impl std::fmt::Display) -> RepositoryError {
    RepositoryError::bootstrap(format!(
        "surrealdb session repository bootstrap failed: {error}"
    ))
}

fn map_backend_error(error: impl std::fmt::Display) -> RepositoryError {
    RepositoryError::backend(format!(
        "surrealdb session repository operation failed: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::surrealdb::DatabaseScope;
    use std::time::Duration;
    use surrealdb::Surreal;
    use surrealdb::engine::local::{Db, Mem};
    use webgates_sessions::lease::{LeaseAcquisition, LeaseId, LeaseTtl, RenewalLease};
    use webgates_sessions::repository::{
        CreateSession, RevokeSessionScope, RotateRefreshToken, RotateRefreshTokenOutcome,
        SessionRepository,
    };
    use webgates_sessions::session::{
        Session, SessionFamilyId, SessionFamilyRecord, SessionId, SessionTouch,
    };
    use webgates_sessions::tokens::RefreshTokenHash;

    fn sample_time() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(10_000)
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

    fn sample_lease(session_id: SessionId, acquired_at: SystemTime) -> RenewalLease {
        RenewalLease::from_ttl(
            session_id,
            LeaseId::new(),
            acquired_at,
            LeaseTtl::new(Duration::from_secs(30)),
        )
    }

    async fn repository() -> SurrealDbRepository<Db> {
        let db = match Surreal::new::<Mem>(()).await {
            Ok(db) => db,
            Err(error) => panic!("expected in-memory surrealdb instance: {error}"),
        };

        match SurrealDbRepository::new(db, DatabaseScope::default()) {
            Ok(repository) => repository,
            Err(error) => panic!("expected surrealdb repository construction to succeed: {error}"),
        }
    }

    async fn store_session(
        repository: &SurrealDbRepository<Db>,
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

    #[test]
    fn bootstrap_error_mapper_uses_bootstrap_variant() {
        let mapped = map_bootstrap_error("boom");

        assert_eq!(
            mapped,
            RepositoryError::Bootstrap {
                message: String::from("surrealdb session repository bootstrap failed: boom"),
            }
        );
    }

    #[tokio::test]
    async fn bootstrap_initializes_session_storage() {
        let repository = repository().await;

        assert_eq!(repository.bootstrap().await, Ok(()));
    }

    #[tokio::test]
    async fn create_and_lookup_session_by_refresh_hash() {
        let repository = repository().await;
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
        assert_eq!(
            lookup.refresh,
            SessionRefreshRecord::new(session.session_id, session.family_id, session.expires_at)
        );
    }

    #[tokio::test]
    async fn acquire_lease_returns_held_by_other_while_active_lease_exists() {
        let repository = repository().await;
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
        let repository = repository().await;
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
        let repository = repository().await;
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

        let next_session = session.clone().touched(now + Duration::from_secs(20));

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
        let repository = repository().await;
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
            Err(error) => panic!("expected successful family lookup: {error}"),
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
        let repository = repository().await;
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
        let repository = repository().await;
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
        let repository = repository().await;
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
}
