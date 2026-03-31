use webgates::accounts::Account;
use webgates::authn::{LoginResult, LoginService, SessionLoginResult, SessionLoginService};
use webgates::authz::AccessHierarchy;
use webgates::codecs::Codec;
use webgates::codecs::jwt::{JwtClaims, RegisteredClaims};
use webgates::cookie_template::CookieTemplate;
use webgates::credentials::Credentials;
use webgates::credentials::CredentialsVerifier;
use webgates::sessions::config::SessionConfig;
use webgates::sessions::repository::SessionRepository;
use webgates::sessions::session::Session;
use webgates::sessions::tokens::AuthTokenIssuer;
use webgates_repositories::account_repository::AccountRepository;

use std::sync::Arc;
use std::time::SystemTime;

use axum::http::StatusCode;
use axum_extra::extract::CookieJar;
use tracing::error;

/// Authenticates user credentials and creates a JWT authentication cookie.
///
/// This handler validates the provided credentials against the secret repository,
/// retrieves the corresponding account from the account repository, and creates
/// a signed JWT cookie containing the user's authentication information.
///
/// # Arguments
/// * `cookie_jar` - The incoming cookie jar to add the auth cookie to
/// * `credentials` - User credentials for authentication
/// * `registered_claims` - JWT registered claims (issuer, expiration, etc.)
/// * `secret_verifier` - Repository for verifying user passwords
/// * `account_repository` - Repository for loading user account data
/// * `codec` - JWT codec for creating signed tokens
/// * `cookie_template` - Template for creating the authentication cookie
///
/// # Returns
/// * `Ok(CookieJar)` - Updated cookie jar with authentication cookie
/// * `Err(StatusCode)` - HTTP error code indicating failure reason
///   - `UNAUTHORIZED` - Invalid credentials (covers both non-existent users and wrong passwords)
///   - `INTERNAL_SERVER_ERROR` - System error during authentication
///
/// # Example Response Codes
/// - 200: Login successful, cookie set
/// - 401: Invalid username/password or account not found
/// - 500: Internal server error
pub async fn login<CredVeri, AccRepo, C, R, G>(
    cookie_jar: CookieJar,
    credentials: Credentials<String>,
    registered_claims: RegisteredClaims,
    secret_verifier: Arc<CredVeri>,
    account_repository: Arc<AccRepo>,
    codec: Arc<C>,
    cookie_template: CookieTemplate,
) -> Result<CookieJar, StatusCode>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
    CredVeri: CredentialsVerifier,
    AccRepo: AccountRepository<R, G>,
    C: Codec<Payload = JwtClaims<Account<R, G>>>,
{
    #[cfg(feature = "audit-logging")]
    let user_id = credentials.id.clone();
    #[cfg(feature = "audit-logging")]
    let _audit_span = tracing::span!(tracing::Level::INFO, "auth.login", user_id = %user_id);
    #[cfg(feature = "audit-logging")]
    let _audit_enter = _audit_span.enter();
    #[cfg(feature = "audit-logging")]
    tracing::info!(user_id = %user_id, "login_attempt");

    let login_service = LoginService::<R, G>::new();

    let result = login_service
        .authenticate(
            credentials,
            registered_claims,
            secret_verifier,
            account_repository,
            codec,
        )
        .await;

    match result {
        LoginResult::Success(jwt_string) => {
            let cookie = cookie_template.build_with_value(&jwt_string);
            #[cfg(feature = "audit-logging")]
            tracing::info!(user_id = %user_id, "login_success");
            Ok(cookie_jar.add(cookie))
        }
        LoginResult::InvalidCredentials {
            user_message: _,
            support_code,
        } => {
            match support_code.as_deref() {
                Some(code) => {
                    error!(
                        "Login failed - Invalid credentials [Support Code: {}]",
                        code
                    );
                }
                None => {
                    error!("Login failed - Invalid credentials");
                }
            }
            #[cfg(feature = "audit-logging")]
            {
                match support_code.as_deref() {
                    Some(code) => {
                        tracing::warn!(user_id = %user_id, support_code = %code, "login_failed_invalid_credentials")
                    }
                    None => {
                        tracing::warn!(user_id = %user_id, "login_failed_invalid_credentials")
                    }
                }
            }
            Err(StatusCode::UNAUTHORIZED)
        }
        LoginResult::InternalError {
            user_message: _,
            technical_message,
            support_code,
            retryable,
        } => {
            let code_info = support_code
                .as_deref()
                .map(|c| format!(" [Support Code: {}]", c))
                .unwrap_or_default();
            let retry_info = if retryable {
                " [Retryable]"
            } else {
                " [Non-retryable]"
            };
            error!(
                "Login internal error{}{}: {}",
                code_info, retry_info, technical_message
            );
            #[cfg(feature = "audit-logging")]
            {
                match support_code.as_deref() {
                    Some(code) => {
                        tracing::error!(user_id = %user_id, support_code = %code, retryable = retryable, error = %technical_message, "login_internal_error")
                    }
                    None => {
                        tracing::error!(user_id = %user_id, retryable = retryable, error = %technical_message, "login_internal_error")
                    }
                }
            }
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Dependencies required for session-backed login.
///
/// This groups the inner-layer services and repositories so the HTTP adapter
/// can pass one explicit dependency object instead of a long argument list.
pub struct SessionLoginDependencies<CredVeri, AccRepo, SessRepo, A> {
    /// Repository used to verify submitted credentials.
    pub secret_verifier: Arc<CredVeri>,
    /// Repository used to load the authenticated account.
    pub account_repository: Arc<AccRepo>,
    /// Repository used to persist session state.
    pub session_repository: SessRepo,
    /// Issuer used to mint auth tokens bound to session state.
    pub auth_token_issuer: A,
}

/// Session-backed login configuration for cookie issuance.
///
/// This keeps deterministic issuance inputs and cookie templates together at the
/// HTTP boundary.
pub struct SessionLoginRequest {
    /// User credentials submitted for authentication.
    pub credentials: Credentials<String>,
    /// Session issuance configuration.
    pub session_config: SessionConfig,
    /// Template for the auth cookie written after successful login.
    pub auth_cookie_template: CookieTemplate,
    /// Template for the refresh-token cookie written after successful login.
    pub refresh_cookie_template: CookieTemplate,
    /// Current wall-clock time used for deterministic session issuance.
    pub now: SystemTime,
}

/// Authenticates user credentials and creates auth and refresh-token cookies.
///
/// This handler is the session-backed variant of [`login`]. It validates the
/// provided credentials against the secret repository, loads the account from
/// the account repository, issues a session-backed auth and refresh token pair,
/// and writes both cookies in the HTTP adapter layer.
///
/// # Arguments
/// * `cookie_jar` - The incoming cookie jar to add cookies to
/// * `request` - Session-backed login request data and cookie templates
/// * `dependencies` - Session-backed login repositories and token issuer
///
/// # Returns
/// * `Ok(CookieJar)` - Updated cookie jar with auth and refresh cookies
/// * `Err(StatusCode)` - HTTP error code indicating failure reason
pub async fn login_with_sessions<CredVeri, AccRepo, SessRepo, A, R, G>(
    cookie_jar: CookieJar,
    request: SessionLoginRequest,
    dependencies: SessionLoginDependencies<CredVeri, AccRepo, SessRepo, A>,
) -> Result<CookieJar, StatusCode>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
    CredVeri: CredentialsVerifier,
    AccRepo: AccountRepository<R, G>,
    SessRepo: SessionRepository,
    A: AuthTokenIssuer<Session>,
    A::Error: std::fmt::Display,
{
    let SessionLoginRequest {
        credentials,
        session_config,
        auth_cookie_template,
        refresh_cookie_template,
        now,
    } = request;
    let SessionLoginDependencies {
        secret_verifier,
        account_repository,
        session_repository,
        auth_token_issuer,
    } = dependencies;

    #[cfg(feature = "audit-logging")]
    let user_id = credentials.id.clone();
    #[cfg(feature = "audit-logging")]
    let _audit_span =
        tracing::span!(tracing::Level::INFO, "auth.login.session", user_id = %user_id);
    #[cfg(feature = "audit-logging")]
    let _audit_enter = _audit_span.enter();
    #[cfg(feature = "audit-logging")]
    tracing::info!(user_id = %user_id, "session_login_attempt");

    let login_service = SessionLoginService::<R, G>::new();

    let result = login_service
        .authenticate_with_sessions(
            credentials,
            secret_verifier,
            account_repository,
            session_repository,
            auth_token_issuer,
            session_config,
            now,
        )
        .await;

    match result {
        SessionLoginResult::Success(issued_session) => {
            let auth_cookie = auth_cookie_template
                .build_with_value(issued_session.tokens.token_pair.auth_token.as_str());
            let refresh_cookie = refresh_cookie_template
                .build_with_value(issued_session.tokens.token_pair.refresh_token.as_str());
            #[cfg(feature = "audit-logging")]
            tracing::info!(user_id = %user_id, "session_login_success");
            Ok(cookie_jar.add(auth_cookie).add(refresh_cookie))
        }
        SessionLoginResult::InvalidCredentials {
            user_message: _,
            support_code,
        } => {
            match support_code.as_deref() {
                Some(code) => {
                    error!(
                        "Session login failed - Invalid credentials [Support Code: {}]",
                        code
                    );
                }
                None => {
                    error!("Session login failed - Invalid credentials");
                }
            }
            #[cfg(feature = "audit-logging")]
            {
                match support_code.as_deref() {
                    Some(code) => {
                        tracing::warn!(user_id = %user_id, support_code = %code, "session_login_failed_invalid_credentials")
                    }
                    None => {
                        tracing::warn!(user_id = %user_id, "session_login_failed_invalid_credentials")
                    }
                }
            }
            Err(StatusCode::UNAUTHORIZED)
        }
        SessionLoginResult::InternalError {
            user_message: _,
            technical_message,
            support_code,
            retryable,
        } => {
            let code_info = support_code
                .as_deref()
                .map(|c| format!(" [Support Code: {}]", c))
                .unwrap_or_default();
            let retry_info = if retryable {
                " [Retryable]"
            } else {
                " [Non-retryable]"
            };
            error!(
                "Session login internal error{}{}: {}",
                code_info, retry_info, technical_message
            );
            #[cfg(feature = "audit-logging")]
            {
                match support_code.as_deref() {
                    Some(code) => {
                        tracing::error!(user_id = %user_id, support_code = %code, retryable = retryable, error = %technical_message, "session_login_internal_error")
                    }
                    None => {
                        tracing::error!(user_id = %user_id, retryable = retryable, error = %technical_message, "session_login_internal_error")
                    }
                }
            }
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    use axum_extra::extract::cookie::Cookie;
    use tokio::sync::RwLock;
    use webgates::groups::Group;
    use webgates::roles::Role;
    use webgates::secrets::Secret;
    use webgates::secrets::hashing::argon2::Argon2Hasher;
    use webgates::sessions::lease::{LeaseAcquisition, RenewalLease};
    use webgates::sessions::repository::{
        CreateSession, RepositoryResult, RevokeSessionScope, RotateRefreshToken,
        RotateRefreshTokenOutcome,
    };
    use webgates::sessions::session::{
        SessionFamilyId, SessionFamilyRecord, SessionId, SessionLookup, SessionRecord,
        SessionRefreshRecord, SessionTouch,
    };
    use webgates::sessions::tokens::{AuthToken, RefreshTokenHashRef};
    use webgates_repositories::memory::account::MemoryAccountRepository;
    use webgates_repositories::memory::secret::MemorySecretRepository;
    use webgates_repositories::secret_repository::SecretRepository;

    #[derive(Clone, Default)]
    struct DummySessionRepository {
        created_sessions: Arc<RwLock<Vec<CreateSession>>>,
    }

    #[derive(Clone, Copy, Default)]
    struct StaticSessionAuthTokenIssuer;

    impl AuthTokenIssuer<Session> for StaticSessionAuthTokenIssuer {
        type Error = webgates::sessions::errors::TokenError;

        fn issue_auth_token(
            &self,
            session: &Session,
        ) -> std::result::Result<AuthToken, Self::Error> {
            AuthToken::new(format!("auth-{}", session.subject_id))
        }
    }

    impl SessionRepository for DummySessionRepository {
        async fn create_session(&self, input: CreateSession) -> RepositoryResult<()> {
            self.created_sessions.write().await.push(input);
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

    async fn build_login_dependencies() -> (
        Arc<MemorySecretRepository>,
        Arc<MemoryAccountRepository<Role, Group>>,
        DummySessionRepository,
    ) {
        let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
        let secret_repo = Arc::new(match MemorySecretRepository::new_with_argon2_hasher() {
            Ok(repo) => repo,
            Err(error) => panic!("secret repository construction should succeed: {}", error),
        });
        let session_repo = DummySessionRepository::default();

        let mut account = Account::new("user@example.com");
        account.groups = vec![Group::new("staff")];
        let stored_account = match account_repo.store_account(account).await {
            Ok(Some(account)) => account,
            Ok(None) => panic!("stored account should be returned"),
            Err(error) => panic!("account storage should succeed: {}", error),
        };

        let secret = match Secret::new(
            &stored_account.account_id,
            "correct-password",
            match Argon2Hasher::new_recommended() {
                Ok(hasher) => hasher,
                Err(error) => panic!("hasher construction should succeed: {}", error),
            },
        ) {
            Ok(secret) => secret,
            Err(error) => panic!("secret construction should succeed: {}", error),
        };
        if let Err(error) = secret_repo.store_secret(secret).await {
            panic!("secret storage should succeed: {}", error);
        }

        (secret_repo, account_repo, session_repo)
    }

    fn cookie_value<'a>(jar: &'a CookieJar, name: &str) -> Option<&'a str> {
        jar.get(name).map(Cookie::value)
    }

    #[tokio::test]
    async fn login_with_sessions_sets_auth_and_refresh_cookies() {
        let (secret_repo, account_repo, session_repo) = build_login_dependencies().await;
        let cookie_jar = CookieJar::new();
        let auth_cookie_template = CookieTemplate::recommended().name("auth-token");
        let refresh_cookie_template = CookieTemplate::recommended().name("refresh-token");
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);

        let result = login_with_sessions::<_, _, _, _, Role, Group>(
            cookie_jar,
            SessionLoginRequest {
                credentials: Credentials::new(&"user@example.com".to_string(), "correct-password"),
                session_config: SessionConfig::default(),
                auth_cookie_template,
                refresh_cookie_template,
                now,
            },
            SessionLoginDependencies {
                secret_verifier: secret_repo,
                account_repository: account_repo,
                session_repository: session_repo.clone(),
                auth_token_issuer: StaticSessionAuthTokenIssuer,
            },
        )
        .await;

        let updated_jar = match result {
            Ok(cookie_jar) => cookie_jar,
            Err(status) => panic!("session-backed login should succeed: {}", status),
        };
        let auth_cookie = match cookie_value(&updated_jar, "auth-token") {
            Some(cookie) => cookie,
            None => panic!("auth cookie should be present after login"),
        };
        let refresh_cookie = match cookie_value(&updated_jar, "refresh-token") {
            Some(cookie) => cookie,
            None => panic!("refresh cookie should be present after login"),
        };

        assert_eq!(auth_cookie, "auth-user@example.com");
        assert!(!refresh_cookie.is_empty());
        assert_eq!(session_repo.created_sessions.read().await.len(), 1);
    }

    #[tokio::test]
    async fn login_with_sessions_rejects_invalid_credentials() {
        let (secret_repo, account_repo, session_repo) = build_login_dependencies().await;
        let cookie_jar = CookieJar::new();

        let result = login_with_sessions::<_, _, _, _, Role, Group>(
            cookie_jar,
            SessionLoginRequest {
                credentials: Credentials::new(&"user@example.com".to_string(), "wrong-password"),
                session_config: SessionConfig::default(),
                auth_cookie_template: CookieTemplate::recommended().name("auth-token"),
                refresh_cookie_template: CookieTemplate::recommended().name("refresh-token"),
                now: SystemTime::UNIX_EPOCH + Duration::from_secs(10_000),
            },
            SessionLoginDependencies {
                secret_verifier: secret_repo,
                account_repository: account_repo,
                session_repository: session_repo,
                auth_token_issuer: StaticSessionAuthTokenIssuer,
            },
        )
        .await;

        assert!(matches!(result, Err(StatusCode::UNAUTHORIZED)));
    }

    #[tokio::test]
    async fn login_with_sessions_issues_persisted_session_for_authenticated_user() {
        let (secret_repo, account_repo, session_repo) = build_login_dependencies().await;

        let result = login_with_sessions::<_, _, _, _, Role, Group>(
            CookieJar::new(),
            SessionLoginRequest {
                credentials: Credentials::new(&"user@example.com".to_string(), "correct-password"),
                session_config: SessionConfig::default(),
                auth_cookie_template: CookieTemplate::recommended().name("auth-token"),
                refresh_cookie_template: CookieTemplate::recommended().name("refresh-token"),
                now: SystemTime::UNIX_EPOCH + Duration::from_secs(20_000),
            },
            SessionLoginDependencies {
                secret_verifier: secret_repo,
                account_repository: account_repo,
                session_repository: session_repo.clone(),
                auth_token_issuer: StaticSessionAuthTokenIssuer,
            },
        )
        .await;

        if let Err(status) = result {
            panic!("session-backed login should succeed: {}", status);
        }

        let created_sessions = session_repo.created_sessions.read().await;
        assert_eq!(created_sessions.len(), 1);
        assert_eq!(created_sessions[0].session.subject_id, "user@example.com");
        assert!(!created_sessions[0].refresh_token_hash.as_str().is_empty());
    }
}
