/// Stateless service for transport-level logout.
pub struct LogoutService {}

/// Stateless service for session-backed logout.
///
/// This service keeps session revocation in the framework-agnostic core while
/// transport adapters remain responsible for cookie removal and request-bound
/// session extraction.
#[cfg(feature = "sessions")]
pub struct SessionLogoutService<R> {
    revoker: crate::sessions::services::SessionRevoker<R>,
}

impl LogoutService {
    /// Creates a new logout service.
    pub fn new() -> Self {
        Self {}
    }

    /// Performs transport-level logout.
    ///
    /// In cookie-based authentication systems, logout is usually implemented by
    /// removing the authentication cookie. This method currently has no extra
    /// business logic, but gives callers a stable service entry point that can
    /// evolve without changing adapter code.
    pub fn logout(&self) {}
}

#[cfg(feature = "sessions")]
impl<R> SessionLogoutService<R>
where
    R: crate::sessions::repository::SessionRepository,
{
    /// Creates a new session-backed logout service.
    pub fn new(repository: R) -> Self {
        Self {
            revoker: crate::sessions::services::SessionRevoker::new(repository),
        }
    }

    /// Revokes the session state targeted by `request`.
    ///
    /// Use this service when logout should invalidate persisted session state,
    /// not just clear transport-level cookies.
    pub async fn logout(
        &self,
        request: crate::sessions::logout::LogoutRequest,
    ) -> crate::sessions::errors::Result<crate::sessions::logout::LogoutOutcome> {
        self.revoker.revoke_session(request).await
    }
}

impl Default for LogoutService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[cfg(feature = "sessions")]
mod tests {
    use super::{LogoutService, SessionLogoutService};
    use crate::sessions::logout::{LogoutOutcome, LogoutRequest, LogoutScope};
    use crate::sessions::repository::{
        CreateSession, RepositoryResult, RevokeSessionScope, RotateRefreshToken,
        RotateRefreshTokenOutcome, SessionRepository,
    };
    use crate::sessions::session::{
        SessionFamilyId, SessionFamilyRecord, SessionId, SessionLookup, SessionRecord,
        SessionRefreshRecord, SessionTouch,
    };
    use crate::sessions::tokens::RefreshTokenHashRef;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct DummySessionRepository {
        revoked_sessions: Arc<Mutex<Vec<(SessionId, RevokeSessionScope)>>>,
        revoked_families: Arc<Mutex<Vec<SessionFamilyId>>>,
    }

    impl SessionRepository for DummySessionRepository {
        async fn bootstrap(&self) -> RepositoryResult<()> {
            Ok(())
        }

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
            _lease: crate::sessions::lease::RenewalLease,
        ) -> RepositoryResult<crate::sessions::lease::LeaseAcquisition> {
            Ok(crate::sessions::lease::LeaseAcquisition::Unavailable)
        }

        async fn rotate_refresh_token(
            &self,
            _input: RotateRefreshToken,
        ) -> RepositoryResult<RotateRefreshTokenOutcome> {
            Ok(RotateRefreshTokenOutcome::LeaseUnavailable)
        }

        async fn revoke_session(
            &self,
            session_id: SessionId,
            scope: RevokeSessionScope,
        ) -> RepositoryResult<()> {
            match self.revoked_sessions.lock() {
                Ok(mut revoked_sessions) => {
                    revoked_sessions.push((session_id, scope));
                }
                Err(error) => {
                    panic!("session revocation lock should not be poisoned: {}", error);
                }
            }
            Ok(())
        }

        async fn revoke_family(&self, family_id: SessionFamilyId) -> RepositoryResult<()> {
            match self.revoked_families.lock() {
                Ok(mut revoked_families) => {
                    revoked_families.push(family_id);
                }
                Err(error) => {
                    panic!("family revocation lock should not be poisoned: {}", error);
                }
            }
            Ok(())
        }

        async fn touch_session(&self, _touch: SessionTouch) -> RepositoryResult<()> {
            Ok(())
        }
    }

    #[test]
    fn classic_logout_service_is_constructible() {
        let service = LogoutService::new();
        service.logout();
    }

    #[tokio::test]
    async fn session_logout_service_revokes_current_session() {
        let repository = DummySessionRepository::default();
        let service = SessionLogoutService::new(repository.clone());
        let session_id = SessionId::new();
        let family_id = SessionFamilyId::new();

        let outcome = match service
            .logout(LogoutRequest::new(
                session_id,
                family_id,
                LogoutScope::CurrentSession,
            ))
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => panic!("session logout should succeed: {}", error),
        };

        assert_eq!(outcome, LogoutOutcome::CurrentSessionRevoked);
        let revoked_sessions = match repository.revoked_sessions.lock() {
            Ok(revoked_sessions) => revoked_sessions,
            Err(error) => panic!("session revocation lock should not be poisoned: {}", error),
        };
        assert_eq!(
            revoked_sessions.as_slice(),
            &[(session_id, RevokeSessionScope::CurrentSession)]
        );
    }

    #[tokio::test]
    async fn session_logout_service_revokes_session_family() {
        let repository = DummySessionRepository::default();
        let service = SessionLogoutService::new(repository.clone());
        let session_id = SessionId::new();
        let family_id = SessionFamilyId::new();

        let outcome = match service
            .logout(LogoutRequest::new(
                session_id,
                family_id,
                LogoutScope::SessionFamily,
            ))
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => panic!("session family logout should succeed: {}", error),
        };

        assert_eq!(outcome, LogoutOutcome::SessionFamilyRevoked);
        let revoked_families = match repository.revoked_families.lock() {
            Ok(revoked_families) => revoked_families,
            Err(error) => panic!("family revocation lock should not be poisoned: {}", error),
        };
        assert_eq!(revoked_families.as_slice(), &[family_id]);
    }
}
