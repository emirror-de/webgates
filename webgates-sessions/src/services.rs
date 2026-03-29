//! Session service layer.
//!
//! This module composes the framework-agnostic session domain, repository
//! contracts, and token issuance primitives into cohesive workflows for:
//!
//! - issuing new sessions
//! - renewing existing sessions
//! - revoking sessions during logout
//!
//! The services in this module stay transport agnostic. HTTP adapters and other
//! delivery layers remain responsible for cookie handling, header parsing, and
//! response mutation.

use std::time::SystemTime;

use crate::config::{ConfigResult, SessionConfig};
use crate::errors::Result;
use crate::lease::{LeaseAcquisition, LeaseId, RenewalLease};
use crate::logout::{LogoutOutcome, LogoutRequest, LogoutScope};
use crate::renewal::{
    AuthTokenState, RenewalDecision, RenewalOrchestrator, RenewalOutcome, RenewalRequest,
    RenewalRequirement,
};
use crate::repository::{
    CreateSession, RevokeSessionScope, RotateRefreshToken, RotateRefreshTokenOutcome,
    SessionRepository,
};
use crate::session::{Session, SessionFamilyId};
use crate::tokens::{
    AuthTokenIssuer, IssuedSessionTokens, RefreshTokenGenerator, RefreshTokenHasher,
    RefreshTokenPlaintext, TokenPairIssuer,
};

/// Result of issuing a brand-new session.
///
/// This value keeps the persisted session record together with the client-facing
/// token material that was produced for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedSession {
    /// Newly created session state.
    pub session: Session,
    /// Issued auth and refresh tokens plus the persisted refresh-token hash.
    pub tokens: IssuedSessionTokens,
}

impl IssuedSession {
    /// Creates a new issued-session result.
    #[must_use]
    pub fn new(session: Session, tokens: IssuedSessionTokens) -> Self {
        Self { session, tokens }
    }
}

/// Service that issues new session state and token pairs.
#[derive(Debug, Clone)]
pub struct SessionIssuer<R, A, G, H> {
    config: SessionConfig,
    repository: R,
    token_pair_issuer: TokenPairIssuer<A, G, H>,
}

impl<R, A, G, H> SessionIssuer<R, A, G, H> {
    /// Creates a new session issuer from validated configuration, a repository,
    /// and a token-pair issuer.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when `config` is internally inconsistent.
    pub fn new(
        config: SessionConfig,
        repository: R,
        token_pair_issuer: TokenPairIssuer<A, G, H>,
    ) -> ConfigResult<Self> {
        Ok(Self {
            config: config.validate()?,
            repository,
            token_pair_issuer,
        })
    }
}

impl<R, A, G, H> SessionIssuer<R, A, G, H>
where
    R: SessionRepository,
    A: AuthTokenIssuer<Session>,
    G: RefreshTokenGenerator,
    H: RefreshTokenHasher,
{
    /// Issues a new session for `subject_id`, persists it, and returns the
    /// issued tokens.
    ///
    /// # Errors
    ///
    /// Returns a session error when token issuance or persistence fails.
    pub async fn issue_session(
        &self,
        subject_id: impl Into<String>,
        now: SystemTime,
    ) -> Result<IssuedSession> {
        let session = Session::new(
            SessionFamilyId::new(),
            subject_id,
            now,
            now + self.config.refresh_token_ttl,
        );
        let tokens = self.token_pair_issuer.issue_for_subject(&session)?;

        self.repository
            .create_session(CreateSession {
                session: session.clone(),
                refresh_token_hash: tokens.refresh_token_hash.clone(),
            })
            .await?;

        Ok(IssuedSession::new(session, tokens))
    }
}

/// Service that renews existing sessions using refresh-token rotation.
#[derive(Debug, Clone)]
pub struct SessionRenewer<R, A, G, H> {
    config: SessionConfig,
    repository: R,
    token_pair_issuer: TokenPairIssuer<A, G, H>,
    orchestrator: RenewalOrchestrator,
}

impl<R, A, G, H> SessionRenewer<R, A, G, H> {
    /// Creates a new session renewer.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when `config` is internally inconsistent.
    pub fn new(
        config: SessionConfig,
        repository: R,
        token_pair_issuer: TokenPairIssuer<A, G, H>,
    ) -> ConfigResult<Self> {
        Ok(Self {
            config: config.validate()?,
            repository,
            token_pair_issuer,
            orchestrator: RenewalOrchestrator::new(),
        })
    }
}

impl<R, A, G, H> SessionRenewer<R, A, G, H>
where
    R: SessionRepository,
    A: AuthTokenIssuer<Session>,
    G: RefreshTokenGenerator,
    H: RefreshTokenHasher,
{
    /// Attempts to renew a session using the presented refresh token.
    ///
    /// Valid auth tokens that are not yet near expiry short-circuit to
    /// [`RenewalOutcome::NotNeeded`] without touching persistence.
    ///
    /// # Errors
    ///
    /// Returns a session error when hashing, repository access, token issuance,
    /// or family revocation fails.
    pub async fn renew_session(
        &self,
        auth_token_state: AuthTokenState,
        requirement: RenewalRequirement,
        refresh_token: &RefreshTokenPlaintext,
        now: SystemTime,
    ) -> Result<RenewalOutcome> {
        let preliminary_decision = self
            .orchestrator
            .decide_for_state(auth_token_state, requirement);

        match preliminary_decision {
            RenewalDecision::NoRenewal => return Ok(RenewalOutcome::NotNeeded),
            RenewalDecision::Reject => return Ok(RenewalOutcome::Rejected),
            RenewalDecision::AttemptProactiveRenewal | RenewalDecision::RequireRenewal => {}
        }

        let presented_refresh_token_hash =
            self.token_pair_issuer.hash_refresh_token(refresh_token)?;
        let lookup = self
            .repository
            .find_session_by_refresh_token_hash(presented_refresh_token_hash.as_str())
            .await?;

        let Some(lookup) = lookup else {
            return Ok(RenewalOutcome::Rejected);
        };

        if !lookup.is_active_at(now) {
            return Ok(RenewalOutcome::Rejected);
        }

        let request = RenewalRequest::new(
            lookup.session.session_id,
            auth_token_state,
            requirement,
            now,
        );

        match self.orchestrator.decide(&request) {
            RenewalDecision::NoRenewal => return Ok(RenewalOutcome::NotNeeded),
            RenewalDecision::Reject => return Ok(RenewalOutcome::Rejected),
            RenewalDecision::AttemptProactiveRenewal | RenewalDecision::RequireRenewal => {}
        }

        let proposed_lease = RenewalLease::from_ttl(
            lookup.session.session_id,
            LeaseId::new(),
            now,
            self.config.renewal_lease_ttl,
        );

        let acquisition = self
            .repository
            .try_acquire_renewal_lease(lookup.session.session_id, proposed_lease)
            .await?;

        let acquired_lease = match acquisition {
            LeaseAcquisition::Acquired(lease) => lease,
            LeaseAcquisition::HeldByOther { .. } | LeaseAcquisition::Unavailable => {
                return Ok(RenewalOutcome::LeaseUnavailable { acquisition });
            }
        };

        let mut next_session = lookup.session.clone().touched(now);
        next_session.expires_at = now + self.config.refresh_token_ttl;

        let issued = self.token_pair_issuer.issue_for_subject(&next_session)?;
        let rotate_outcome = self
            .repository
            .rotate_refresh_token(RotateRefreshToken {
                session_id: next_session.session_id,
                family: lookup.family.clone(),
                lease: acquired_lease,
                previous_refresh_token_hash: presented_refresh_token_hash,
                next_refresh_token_hash: issued.refresh_token_hash.clone(),
                next_session: next_session.clone(),
            })
            .await?;

        match rotate_outcome {
            RotateRefreshTokenOutcome::Rotated => Ok(RenewalOutcome::Renewed {
                session: next_session,
                tokens: issued.token_pair,
            }),
            RotateRefreshTokenOutcome::SessionMissing => Ok(RenewalOutcome::Rejected),
            RotateRefreshTokenOutcome::LeaseUnavailable => Ok(RenewalOutcome::LeaseUnavailable {
                acquisition: LeaseAcquisition::Unavailable,
            }),
            RotateRefreshTokenOutcome::RefreshTokenMismatch => {
                self.repository
                    .revoke_family(lookup.family.family_id)
                    .await?;
                Ok(RenewalOutcome::ReplayDetected {
                    session_id: lookup.session.session_id,
                })
            }
        }
    }
}

/// Service that revokes session state during logout flows.
#[derive(Debug, Clone)]
pub struct SessionRevoker<R> {
    repository: R,
}

impl<R> SessionRevoker<R> {
    /// Creates a new session revoker.
    #[must_use]
    pub fn new(repository: R) -> Self {
        Self { repository }
    }
}

impl<R> SessionRevoker<R>
where
    R: SessionRepository,
{
    /// Revokes the session state targeted by `request`.
    ///
    /// # Errors
    ///
    /// Returns a session error when the repository revocation operation fails.
    pub async fn revoke_session(&self, request: LogoutRequest) -> Result<LogoutOutcome> {
        match request.scope {
            LogoutScope::CurrentSession => {
                self.repository
                    .revoke_session(request.session_id, RevokeSessionScope::CurrentSession)
                    .await?;
                Ok(LogoutOutcome::CurrentSessionRevoked)
            }
            LogoutScope::SessionFamily => {
                self.repository.revoke_family(request.family_id).await?;
                Ok(LogoutOutcome::SessionFamilyRevoked)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::{LeaseAcquisition, LeaseId, LeaseTtl, RenewalLease};
    use crate::repository::{CreateSession, RotateRefreshToken};
    use crate::session::{
        SessionFamilyRecord, SessionId, SessionLookup, SessionRefreshRecord, SessionTouch,
    };
    use crate::tokens::{
        AuthToken, OpaqueRefreshTokenGenerator, RefreshTokenLength, Sha256RefreshTokenHasher,
    };
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex;

    #[derive(Debug, Clone, Copy)]
    struct StaticSessionAuthTokenIssuer;

    impl AuthTokenIssuer<Session> for StaticSessionAuthTokenIssuer {
        type Error = crate::errors::TokenError;

        fn issue_auth_token(
            &self,
            session: &Session,
        ) -> std::result::Result<AuthToken, Self::Error> {
            AuthToken::new(format!("auth-{}", session.subject_id))
        }
    }

    #[derive(Debug, Clone)]
    struct MockRepository {
        state: Arc<Mutex<MockRepositoryState>>,
    }

    #[derive(Debug, Clone)]
    struct MockRepositoryState {
        created_sessions: Vec<CreateSession>,
        lookup_result: Option<SessionLookup>,
        lookup_calls: usize,
        lease_acquisition: Option<LeaseAcquisition>,
        rotate_outcome: RotateRefreshTokenOutcome,
        rotate_inputs: Vec<RotateRefreshToken>,
        revoked_sessions: Vec<(SessionId, RevokeSessionScope)>,
        revoked_families: Vec<SessionFamilyId>,
    }

    impl Default for MockRepositoryState {
        fn default() -> Self {
            Self {
                created_sessions: Vec::new(),
                lookup_result: None,
                lookup_calls: 0,
                lease_acquisition: None,
                rotate_outcome: RotateRefreshTokenOutcome::Rotated,
                rotate_inputs: Vec::new(),
                revoked_sessions: Vec::new(),
                revoked_families: Vec::new(),
            }
        }
    }

    impl MockRepository {
        fn new() -> Self {
            Self {
                state: Arc::new(Mutex::new(MockRepositoryState::default())),
            }
        }
    }

    impl SessionRepository for MockRepository {
        fn create_session(
            &self,
            input: CreateSession,
        ) -> impl std::future::Future<Output = crate::repository::RepositoryResult<()>> + Send
        {
            let state = Arc::clone(&self.state);

            async move {
                state.lock().await.created_sessions.push(input);
                Ok(())
            }
        }

        fn find_session_by_refresh_token_hash<'a>(
            &'a self,
            _refresh_token_hash: crate::tokens::RefreshTokenHashRef<'a>,
        ) -> impl std::future::Future<
            Output = crate::repository::RepositoryResult<Option<SessionLookup>>,
        > + Send
        + 'a {
            let state = Arc::clone(&self.state);

            async move {
                let mut guard = state.lock().await;
                guard.lookup_calls += 1;
                Ok(guard.lookup_result.clone())
            }
        }

        async fn find_session(
            &self,
            _session_id: SessionId,
        ) -> crate::repository::RepositoryResult<Option<crate::session::SessionRecord>> {
            Ok(None)
        }

        async fn find_family(
            &self,
            _family_id: SessionFamilyId,
        ) -> crate::repository::RepositoryResult<Option<SessionFamilyRecord>> {
            Ok(None)
        }

        async fn find_refresh_record(
            &self,
            _session_id: SessionId,
        ) -> crate::repository::RepositoryResult<Option<SessionRefreshRecord>> {
            Ok(None)
        }

        async fn try_acquire_renewal_lease(
            &self,
            _session_id: SessionId,
            lease: RenewalLease,
        ) -> crate::repository::RepositoryResult<LeaseAcquisition> {
            let configured = self.state.lock().await.lease_acquisition;
            Ok(configured.unwrap_or(LeaseAcquisition::Acquired(lease)))
        }

        async fn rotate_refresh_token(
            &self,
            input: RotateRefreshToken,
        ) -> crate::repository::RepositoryResult<RotateRefreshTokenOutcome> {
            let mut guard = self.state.lock().await;
            guard.rotate_inputs.push(input);
            Ok(guard.rotate_outcome)
        }

        async fn revoke_session(
            &self,
            session_id: SessionId,
            scope: RevokeSessionScope,
        ) -> crate::repository::RepositoryResult<()> {
            self.state
                .lock()
                .await
                .revoked_sessions
                .push((session_id, scope));
            Ok(())
        }

        async fn revoke_family(
            &self,
            family_id: SessionFamilyId,
        ) -> crate::repository::RepositoryResult<()> {
            self.state.lock().await.revoked_families.push(family_id);
            Ok(())
        }

        async fn touch_session(
            &self,
            _touch: SessionTouch,
        ) -> crate::repository::RepositoryResult<()> {
            Ok(())
        }
    }

    fn sample_time() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(10_000)
    }

    fn valid_config() -> SessionConfig {
        SessionConfig::default()
    }

    fn valid_refresh_token(value: &str) -> RefreshTokenPlaintext {
        match RefreshTokenPlaintext::new(value) {
            Ok(token) => token,
            Err(error) => panic!("expected valid refresh token: {error}"),
        }
    }

    fn token_pair_issuer() -> TokenPairIssuer<
        StaticSessionAuthTokenIssuer,
        OpaqueRefreshTokenGenerator,
        Sha256RefreshTokenHasher,
    > {
        let generator = match RefreshTokenLength::new(48) {
            Ok(length) => OpaqueRefreshTokenGenerator::new(length),
            Err(error) => panic!("expected valid refresh-token length: {error}"),
        };

        TokenPairIssuer::new(
            StaticSessionAuthTokenIssuer,
            generator,
            Sha256RefreshTokenHasher,
        )
    }

    fn sample_lookup(now: SystemTime) -> SessionLookup {
        let session = Session::new(
            SessionFamilyId::new(),
            "subject-123",
            now - Duration::from_secs(30),
            now + Duration::from_secs(3_600),
        );
        let family = SessionFamilyRecord::new(
            session.family_id,
            session.subject_id.clone(),
            now - Duration::from_secs(30),
        );
        let refresh = SessionRefreshRecord::new(
            session.session_id,
            session.family_id,
            now + Duration::from_secs(3_600),
        );

        SessionLookup::new(session, family, refresh)
    }

    fn sample_lease(session_id: SessionId, now: SystemTime) -> RenewalLease {
        RenewalLease::from_ttl(
            session_id,
            LeaseId::new(),
            now,
            LeaseTtl::new(Duration::from_secs(30)),
        )
    }

    #[tokio::test]
    async fn session_issuer_persists_session_and_returns_tokens() {
        let repository = MockRepository::new();
        let issuer =
            match SessionIssuer::new(valid_config(), repository.clone(), token_pair_issuer()) {
                Ok(issuer) => issuer,
                Err(error) => panic!("expected valid session issuer configuration: {error}"),
            };
        let now = sample_time();

        let issued = match issuer.issue_session("subject-123", now).await {
            Ok(issued) => issued,
            Err(error) => panic!("expected successful session issuance: {error}"),
        };

        let guard = repository.state.lock().await;

        assert_eq!(issued.session.subject_id, "subject-123");
        assert_eq!(guard.created_sessions.len(), 1);
        assert_eq!(guard.created_sessions[0].session, issued.session);
        assert_eq!(
            guard.created_sessions[0].refresh_token_hash,
            issued.tokens.refresh_token_hash
        );
    }

    #[tokio::test]
    async fn renewer_returns_not_needed_without_repository_lookup_for_valid_tokens() {
        let repository = MockRepository::new();
        let renewer =
            match SessionRenewer::new(valid_config(), repository.clone(), token_pair_issuer()) {
                Ok(renewer) => renewer,
                Err(error) => panic!("expected valid renewer configuration: {error}"),
            };
        let now = sample_time();
        let refresh_token = valid_refresh_token("refresh-token-not-used");

        let outcome = match renewer
            .renew_session(
                AuthTokenState::Valid {
                    expires_in: Duration::from_secs(600),
                },
                RenewalRequirement::Proactive,
                &refresh_token,
                now,
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => panic!("expected successful renewal evaluation: {error}"),
        };

        assert_eq!(outcome, RenewalOutcome::NotNeeded);
        assert_eq!(repository.state.lock().await.lookup_calls, 0);
    }

    #[tokio::test]
    async fn renewer_rotates_and_returns_tokens_when_renewal_succeeds() {
        let repository = MockRepository::new();
        let now = sample_time();
        {
            let mut guard = repository.state.lock().await;
            let lookup = sample_lookup(now);
            guard.lookup_result = Some(lookup.clone());
            guard.lease_acquisition = Some(LeaseAcquisition::Acquired(sample_lease(
                lookup.session.session_id,
                now,
            )));
            guard.rotate_outcome = RotateRefreshTokenOutcome::Rotated;
        }

        let renewer =
            match SessionRenewer::new(valid_config(), repository.clone(), token_pair_issuer()) {
                Ok(renewer) => renewer,
                Err(error) => panic!("expected valid renewer configuration: {error}"),
            };
        let refresh_token = valid_refresh_token("lookup-refresh-token");

        let outcome = match renewer
            .renew_session(
                AuthTokenState::NearExpiry {
                    expires_in: Duration::from_secs(30),
                },
                RenewalRequirement::Proactive,
                &refresh_token,
                now,
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => panic!("expected successful renewal: {error}"),
        };

        let guard = repository.state.lock().await;

        match outcome {
            RenewalOutcome::Renewed { session, tokens } => {
                assert_eq!(session.last_seen_at, Some(now));
                assert_eq!(session.expires_at, now + valid_config().refresh_token_ttl);
                assert_eq!(tokens.auth_token.as_str(), "auth-subject-123");
                assert_eq!(guard.rotate_inputs.len(), 1);
                assert_eq!(guard.rotate_inputs[0].next_session, session);
            }
            other => panic!("expected renewed outcome, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn renewer_reports_lease_unavailable_when_another_actor_holds_it() {
        let repository = MockRepository::new();
        let now = sample_time();
        let lookup = sample_lookup(now);
        let active_lease = sample_lease(lookup.session.session_id, now);
        {
            let mut guard = repository.state.lock().await;
            guard.lookup_result = Some(lookup.clone());
            guard.lease_acquisition = Some(LeaseAcquisition::HeldByOther { active_lease });
        }

        let renewer =
            match SessionRenewer::new(valid_config(), repository.clone(), token_pair_issuer()) {
                Ok(renewer) => renewer,
                Err(error) => panic!("expected valid renewer configuration: {error}"),
            };
        let refresh_token = valid_refresh_token("lookup-refresh-token");

        let outcome = match renewer
            .renew_session(
                AuthTokenState::NearExpiry {
                    expires_in: Duration::from_secs(15),
                },
                RenewalRequirement::Proactive,
                &refresh_token,
                now,
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => panic!("expected renewal outcome: {error}"),
        };

        assert_eq!(
            outcome,
            RenewalOutcome::LeaseUnavailable {
                acquisition: LeaseAcquisition::HeldByOther { active_lease },
            }
        );
    }

    #[tokio::test]
    async fn renewer_revokes_family_on_refresh_token_replay() {
        let repository = MockRepository::new();
        let now = sample_time();
        let lookup = sample_lookup(now);
        {
            let mut guard = repository.state.lock().await;
            guard.lookup_result = Some(lookup.clone());
            guard.lease_acquisition = Some(LeaseAcquisition::Acquired(sample_lease(
                lookup.session.session_id,
                now,
            )));
            guard.rotate_outcome = RotateRefreshTokenOutcome::RefreshTokenMismatch;
        }

        let renewer =
            match SessionRenewer::new(valid_config(), repository.clone(), token_pair_issuer()) {
                Ok(renewer) => renewer,
                Err(error) => panic!("expected valid renewer configuration: {error}"),
            };
        let refresh_token = valid_refresh_token("lookup-refresh-token");

        let outcome = match renewer
            .renew_session(
                AuthTokenState::Expired {
                    expired_for: Duration::from_secs(5),
                },
                RenewalRequirement::Required,
                &refresh_token,
                now,
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => panic!("expected replay outcome: {error}"),
        };

        assert_eq!(
            outcome,
            RenewalOutcome::ReplayDetected {
                session_id: lookup.session.session_id,
            }
        );
        assert_eq!(
            repository.state.lock().await.revoked_families,
            vec![lookup.family.family_id]
        );
    }

    #[tokio::test]
    async fn revoker_maps_logout_scopes_to_repository_operations() {
        let repository = MockRepository::new();
        let revoker = SessionRevoker::new(repository.clone());
        let session = sample_lookup(sample_time()).session;

        let current_outcome = match revoker
            .revoke_session(LogoutRequest::new(
                session.session_id,
                session.family_id,
                LogoutScope::CurrentSession,
            ))
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => panic!("expected successful current-session revocation: {error}"),
        };

        let family_outcome = match revoker
            .revoke_session(LogoutRequest::new(
                session.session_id,
                session.family_id,
                LogoutScope::SessionFamily,
            ))
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => panic!("expected successful family revocation: {error}"),
        };

        let guard = repository.state.lock().await;

        assert_eq!(current_outcome, LogoutOutcome::CurrentSessionRevoked);
        assert_eq!(family_outcome, LogoutOutcome::SessionFamilyRevoked);
        assert_eq!(
            guard.revoked_sessions,
            vec![(session.session_id, RevokeSessionScope::CurrentSession)]
        );
        assert_eq!(guard.revoked_families, vec![session.family_id]);
    }
}
