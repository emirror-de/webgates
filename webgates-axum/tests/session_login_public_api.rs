// Regression test: session-login boundary types are publicly reachable and constructible.
//
// This test proves that downstream users can name `login_with_sessions`,
// `SessionLoginRequest`, and `SessionLoginDependencies` from the canonical public
// module path and construct them from other public types without relying on any
// private module path.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum_extra::extract::CookieJar;
use webgates::cookie_template::CookieTemplate;
use webgates::credentials::Credentials;
use webgates::groups::Group;
use webgates::roles::Role;
use webgates::sessions::config::SessionConfig;
use webgates::sessions::lease::{LeaseAcquisition, RenewalLease};
use webgates::sessions::repository::{
    CreateSession, RepositoryResult, RevokeSessionScope, RotateRefreshToken,
    RotateRefreshTokenOutcome,
};
use webgates::sessions::session::{
    SessionFamilyId, SessionFamilyRecord, SessionId, SessionLookup, SessionRecord,
    SessionRefreshRecord, SessionTouch,
};
use webgates::sessions::tokens::{AuthToken, AuthTokenIssuer, RefreshTokenHashRef};
use webgates::sessions::{errors::TokenError, session::Session};
// These are the exact public paths downstream users must be able to use.
use webgates_axum::route_handlers::login::SessionLoginDependencies;
use webgates_axum::route_handlers::login::SessionLoginRequest;
use webgates_axum::route_handlers::login::login_with_sessions;
use webgates_repositories::memory::account::MemoryAccountRepository;
use webgates_repositories::memory::secret::MemorySecretRepository;

/// Minimal in-memory session repository for test isolation.
#[derive(Clone, Default)]
struct StubSessionRepository;

impl webgates::sessions::repository::SessionRepository for StubSessionRepository {
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

/// Minimal static auth-token issuer for test isolation.
#[derive(Clone, Copy)]
struct StubAuthTokenIssuer;

impl AuthTokenIssuer<Session> for StubAuthTokenIssuer {
    type Error = TokenError;

    fn issue_auth_token(
        &self,
        session: &Session,
    ) -> impl std::future::Future<Output = Result<AuthToken, Self::Error>> + Send {
        std::future::ready(AuthToken::new(format!("stub-{}", session.subject_id)))
    }
}

/// Proves that `SessionLoginRequest` can be constructed from public types only.
#[test]
fn public_session_login_inputs_are_constructible() {
    // Construct `SessionLoginRequest` using only the public API surface.
    let request = SessionLoginRequest {
        credentials: Credentials::new(&"user@example.com".to_string(), "password"),
        session_config: SessionConfig::default(),
        auth_cookie_template: CookieTemplate::recommended().name("auth-token"),
        refresh_cookie_template: CookieTemplate::recommended().name("refresh-token"),
        now: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
    };

    // Verify every public field is accessible by name.
    let _ = request.credentials;
    let _ = request.session_config;
    let _ = request.auth_cookie_template;
    let _ = request.refresh_cookie_template;
    let _ = request.now;
}

/// Proves that `SessionLoginDependencies` can be constructed from public types only.
#[test]
fn public_session_login_dependencies_are_constructible() {
    let secret_repo = Arc::new(
        MemorySecretRepository::new_with_argon2_hasher()
            .expect("secret repository construction should succeed"),
    );
    let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());

    // Construct `SessionLoginDependencies` using only the public API surface.
    let deps = SessionLoginDependencies {
        secret_verifier: secret_repo,
        account_repository: account_repo,
        session_repository: StubSessionRepository,
        auth_token_issuer: StubAuthTokenIssuer,
    };

    // Verify every public field is accessible by name.
    let _ = deps.secret_verifier;
    let _ = deps.account_repository;
    let _ = deps.session_repository;
    let _ = deps.auth_token_issuer;
}

/// Proves that `login_with_sessions` can be called using the canonical public
/// import path. This test also exercises the reject-invalid-credentials path to
/// confirm the handler's error branch is reachable.
#[tokio::test]
async fn public_session_login_types_are_importable_and_handler_rejects_unknown_user() {
    let secret_repo = Arc::new(
        MemorySecretRepository::new_with_argon2_hasher()
            .expect("secret repository construction should succeed"),
    );
    let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());

    let result = login_with_sessions::<_, _, _, _, Role, Group>(
        CookieJar::new(),
        SessionLoginRequest {
            credentials: Credentials::new(&"unknown@example.com".to_string(), "password"),
            session_config: SessionConfig::default(),
            auth_cookie_template: CookieTemplate::recommended().name("auth-token"),
            refresh_cookie_template: CookieTemplate::recommended().name("refresh-token"),
            now: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
        },
        SessionLoginDependencies {
            secret_verifier: secret_repo,
            account_repository: account_repo,
            session_repository: StubSessionRepository,
            auth_token_issuer: StubAuthTokenIssuer,
        },
    )
    .await;

    assert!(
        matches!(result, Err(axum::http::StatusCode::UNAUTHORIZED)),
        "expected UNAUTHORIZED for an unknown user, got: {:?}",
        result,
    );
}
