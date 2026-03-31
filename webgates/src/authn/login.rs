//! Login service providing constant-time, enumeration-resistant authentication.
//!
//! This module validates credentials, issues JWTs via a provided codec, and
//! deliberately obscures whether an account exists to reduce username
//! enumeration risk.
//!
//! # Security Features
//!
//! - Constant-time credential verification using `subtle::Choice` to combine user-exists and hash-match decisions
//! - Dummy UUID hashing for missing accounts to equalize timing between "user not found" and "wrong password"
//! - Unified invalid-credentials responses to mitigate user enumeration
//! - Stateless service; cryptographic operations live in credential verifiers and repositories
use crate::accounts::Account;
use crate::authz::AccessHierarchy;
use crate::codecs::Codec;
use crate::codecs::jwt::{JwtClaims, RegisteredClaims};
use crate::credentials::Credentials;
use crate::credentials::CredentialsVerifier;
use crate::verification_result::VerificationResult;
use webgates_repositories::account_repository::AccountRepository;

use std::sync::Arc;
use std::time::SystemTime;

use subtle::Choice;
use tracing::{debug, error};
use uuid::Uuid;
use webgates_sessions::config::SessionConfig;
use webgates_sessions::services::{IssuedSession, SessionIssuer};
use webgates_sessions::tokens::{
    AuthTokenIssuer, OpaqueRefreshTokenGenerator, Sha256RefreshTokenHasher, TokenPairIssuer,
};

/// Result of a login attempt produced by [`LoginService::authenticate`].
///
/// The variants deliberately avoid revealing whether an account exists to
/// mitigate username enumeration attacks. Both an unknown user and an
/// incorrect password are collapsed into [`LoginResult::InvalidCredentials`].
#[derive(Debug)]
pub enum LoginResult {
    /// Authentication succeeded and contains the issued JWT (already UTF‑8).
    Success(String),
    /// Credentials were invalid (unknown user OR wrong password).
    InvalidCredentials {
        /// User-friendly message
        user_message: String,
        /// Support reference code
        support_code: Option<String>,
    },
    /// An internal / infrastructural error (repository failure, hashing, JWT, etc.).
    InternalError {
        /// User-friendly message
        user_message: String,
        /// Technical message for developers
        technical_message: String,
        /// Support reference code
        support_code: Option<String>,
        /// Whether this error is retryable
        retryable: bool,
    },
}

impl LoginResult {
    /// Create an invalid credentials result with user-friendly messaging
    pub fn invalid_credentials(user_message: Option<String>, support_code: Option<String>) -> Self {
        LoginResult::InvalidCredentials {
            user_message: user_message.unwrap_or_else(|| {
                "The username or password you entered is incorrect. Please check your credentials and try again.".to_string()
            }),
            support_code,
        }
    }

    /// Create an internal error result with comprehensive messaging
    pub fn internal_error(
        user_message: impl Into<String>,
        technical_message: impl Into<String>,
        support_code: Option<&str>,
        retryable: bool,
    ) -> Self {
        LoginResult::InternalError {
            user_message: user_message.into(),
            technical_message: technical_message.into(),
            support_code: support_code.map(|s| s.to_string()),
            retryable,
        }
    }

    /// Get user-friendly message for any result type
    pub fn user_message(&self) -> String {
        match self {
            LoginResult::Success(_) => "Sign-in successful! Welcome back.".to_string(),
            LoginResult::InvalidCredentials { user_message, .. } => user_message.clone(),
            LoginResult::InternalError { user_message, .. } => user_message.clone(),
        }
    }

    /// Get support code if available
    pub fn support_code(&self) -> Option<String> {
        match self {
            LoginResult::Success(_) => None,
            LoginResult::InvalidCredentials { support_code, .. } => support_code.clone(),
            LoginResult::InternalError { support_code, .. } => support_code.clone(),
        }
    }

    /// Get technical details for developers/logs
    pub fn technical_message(&self) -> Option<String> {
        match self {
            LoginResult::Success(_) => None,
            LoginResult::InvalidCredentials { .. } => {
                Some("Invalid credentials provided".to_string())
            }
            LoginResult::InternalError {
                technical_message, ..
            } => Some(technical_message.clone()),
        }
    }

    /// Whether this result indicates a retryable error
    pub fn is_retryable(&self) -> bool {
        match self {
            LoginResult::Success(_) => false,
            LoginResult::InvalidCredentials { .. } => true,
            LoginResult::InternalError { retryable, .. } => *retryable,
        }
    }
}

/// Result of a session-backed login attempt produced by
/// [`SessionLoginService::authenticate`].
#[derive(Debug)]
pub enum SessionLoginResult {
    /// Authentication succeeded and returned an issued session plus client-facing
    /// auth and refresh tokens.
    Success(IssuedSession),
    /// Credentials were invalid (unknown user OR wrong password).
    InvalidCredentials {
        /// User-friendly message.
        user_message: String,
        /// Support reference code.
        support_code: Option<String>,
    },
    /// An internal / infrastructural error (repository failure, hashing, token
    /// issuance, persistence, etc.).
    InternalError {
        /// User-friendly message.
        user_message: String,
        /// Technical message for developers.
        technical_message: String,
        /// Support reference code.
        support_code: Option<String>,
        /// Whether this error is retryable.
        retryable: bool,
    },
}

impl SessionLoginResult {
    /// Create an invalid credentials result with user-friendly messaging.
    pub fn invalid_credentials(user_message: Option<String>, support_code: Option<String>) -> Self {
        Self::InvalidCredentials {
            user_message: user_message.unwrap_or_else(|| {
                "The username or password you entered is incorrect. Please check your credentials and try again.".to_string()
            }),
            support_code,
        }
    }

    /// Create an internal error result with comprehensive messaging.
    pub fn internal_error(
        user_message: impl Into<String>,
        technical_message: impl Into<String>,
        support_code: Option<&str>,
        retryable: bool,
    ) -> Self {
        Self::InternalError {
            user_message: user_message.into(),
            technical_message: technical_message.into(),
            support_code: support_code.map(|s| s.to_string()),
            retryable,
        }
    }

    /// Get user-friendly message for any result type.
    pub fn user_message(&self) -> String {
        match self {
            Self::Success(_) => "Sign-in successful! Welcome back.".to_string(),
            Self::InvalidCredentials { user_message, .. } => user_message.clone(),
            Self::InternalError { user_message, .. } => user_message.clone(),
        }
    }

    /// Get support code if available.
    pub fn support_code(&self) -> Option<String> {
        match self {
            Self::Success(_) => None,
            Self::InvalidCredentials { support_code, .. } => support_code.clone(),
            Self::InternalError { support_code, .. } => support_code.clone(),
        }
    }

    /// Get technical details for developers/logs.
    pub fn technical_message(&self) -> Option<String> {
        match self {
            Self::Success(_) => None,
            Self::InvalidCredentials { .. } => Some("Invalid credentials provided".to_string()),
            Self::InternalError {
                technical_message, ..
            } => Some(technical_message.clone()),
        }
    }

    /// Whether this result indicates a retryable error.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Success(_) => false,
            Self::InvalidCredentials { .. } => true,
            Self::InternalError { retryable, .. } => *retryable,
        }
    }
}

/// Stateless service implementing constant‑time, enumeration‑resistant
/// authentication logic.
///
/// It always performs:
/// 1. Account lookup by user identifier.
/// 2. Credential verification against either the real account UUID or a
///    fixed dummy UUID when the account is absent.
///
/// This equalises timing characteristics between "user not found" and
/// "wrong password" cases.
///
/// Type Params:
/// * `R` - Role type implementing [`AccessHierarchy`]
/// * `G` - Group type
pub struct LoginService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    _phantom: std::marker::PhantomData<(R, G)>,
}

/// Stateless service implementing constant-time, enumeration-resistant
/// authentication plus session-backed token-pair issuance.
///
/// This service preserves the same credential-verification behavior as
/// [`LoginService`] but issues auth and refresh token pairs through
/// `webgates-sessions` after successful authentication.
pub struct SessionLoginService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    _phantom: std::marker::PhantomData<(R, G)>,
}

impl<R, G> LoginService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    /// Creates a new stateless `LoginService`.
    ///
    /// The instance holds no mutable state; it is cheap to clone or recreate.
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<R, G> SessionLoginService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    /// Creates a new stateless `SessionLoginService`.
    ///
    /// The instance holds no mutable state; it is cheap to clone or recreate.
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<R, G> LoginService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    /// Authenticates a user in a timing‑safe, enumeration‑resistant fashion.
    ///
    /// Steps:
    /// 1. Query account repository by user identifier.
    /// 2. Always invoke credential verification using either the real account
    ///    UUID or a fixed dummy UUID when the user is absent / lookup failed.
    /// 3. Combine (user_exists AND password_matches) with constant‑time bit logic.
    /// 4. On success, encode a JWT with the supplied registered claims.
    ///
    /// Returns:
    /// * [`LoginResult::Success`] with a JWT string on success.
    /// * [`LoginResult::InvalidCredentials`] for any auth failure that should not leak detail.
    /// * [`LoginResult::InternalError`] for infrastructural issues (these should be logged).
    ///
    /// Security: Avoids early returns that would create observable timing
    /// differences between "user not found" and "wrong password".
    pub async fn authenticate<CredVeri, AccRepo, C>(
        &self,
        credentials: Credentials<String>,
        registered_claims: RegisteredClaims,
        credentials_verifier: Arc<CredVeri>,
        account_repository: Arc<AccRepo>,
        codec: Arc<C>,
    ) -> LoginResult
    where
        CredVeri: CredentialsVerifier,
        AccRepo: AccountRepository<R, G>,
        AccRepo::Error: std::fmt::Display + Send + Sync + 'static,
        C: Codec<Payload = JwtClaims<Account<R, G>>>,
    {
        #[cfg(feature = "audit-logging")]
        let _audit_span =
            tracing::span!(tracing::Level::INFO, "auth.login", user_id = %credentials.id);
        #[cfg(feature = "audit-logging")]
        let _audit_enter = _audit_span.enter();
        #[cfg(feature = "audit-logging")]
        tracing::info!(user_id = %credentials.id, "login_attempt");
        let account_query_result = account_repository
            .query_account_by_user_id(&credentials.id)
            .await;

        let (account_opt, verification_uuid, user_exists_choice, query_error_opt) =
            match account_query_result {
                Ok(Some(acc)) => {
                    debug!("Account found for user_id: {}", credentials.id);
                    (Some(acc.clone()), acc.account_id, Choice::from(1u8), None)
                }
                Ok(None) => {
                    debug!("Account not found for user_id: {}", credentials.id);
                    let dummy_uuid = Uuid::from_bytes([
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x01,
                    ]);
                    (None, dummy_uuid, Choice::from(0u8), None)
                }
                Err(e) => {
                    error!("Error querying account: {}", e);
                    let dummy_uuid = Uuid::from_bytes([
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x01,
                    ]);
                    (None, dummy_uuid, Choice::from(0u8), Some(e))
                }
            };

        if let Some(error) = query_error_opt {
            return LoginResult::internal_error(
                "We're experiencing technical difficulties. Please try signing in again.",
                format!("Account repository query failed: {}", error),
                Some("repository_query"),
                true,
            );
        }

        let creds_to_verify = Credentials::new(&verification_uuid, &credentials.secret);
        let verification_result = credentials_verifier
            .verify_credentials(creds_to_verify)
            .await;

        let auth_success_choice = match verification_result {
            Ok(VerificationResult::Ok) => {
                debug!(
                    "Credentials verified successfully for UUID: {}",
                    verification_uuid
                );
                Choice::from(1u8)
            }
            Ok(VerificationResult::Unauthorized) => {
                debug!(
                    "Credentials verification failed for UUID: {}",
                    verification_uuid
                );
                Choice::from(0u8)
            }
            Err(e) => {
                error!("Error verifying credentials: {}", e);
                return LoginResult::internal_error(
                    "We're having trouble with the authentication system. Please try again.",
                    format!("Credential verification failed: {}", e),
                    Some("credential_verification"),
                    true,
                );
            }
        };

        let final_success_choice = user_exists_choice & auth_success_choice;
        let login_successful: bool = final_success_choice.into();

        if login_successful {
            if let Some(account) = account_opt {
                let claims = JwtClaims::new(account, registered_claims);
                let jwt = match codec.encode(&claims) {
                    Ok(token) => token,
                    Err(e) => {
                        error!("Error encoding JWT: {}", e);
                        return LoginResult::internal_error(
                            "We're having trouble completing your sign-in. Please try again.",
                            format!("JWT encoding failed: {}", e),
                            Some("jwt_encoding"),
                            true,
                        );
                    }
                };
                let jwt_string = match String::from_utf8(jwt) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Error converting JWT to string: {}", e);
                        return LoginResult::internal_error(
                            "We're having trouble completing your sign-in. Please try again.",
                            format!("JWT string conversion failed: {}", e),
                            Some("jwt_conversion"),
                            true,
                        );
                    }
                };
                debug!("Login successful, JWT generated");
                LoginResult::Success(jwt_string)
            } else {
                error!("Internal error: login marked successful but no account available");
                LoginResult::internal_error(
                    "There was an unexpected issue with your authentication. Please try signing in again.",
                    "Authentication state inconsistency: successful verification but no account data",
                    Some("auth_state_inconsistency"),
                    false,
                )
            }
        } else {
            debug!("Login failed - invalid credentials");
            LoginResult::invalid_credentials(None, None)
        }
    }
}

impl<R, G> SessionLoginService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    /// Authenticates a user and issues a session-backed auth/refresh token pair.
    #[allow(clippy::too_many_arguments)]
    pub async fn authenticate_with_sessions<CredVeri, AccRepo, SessRepo, A>(
        &self,
        credentials: Credentials<String>,
        credentials_verifier: Arc<CredVeri>,
        account_repository: Arc<AccRepo>,
        session_repository: SessRepo,
        auth_token_issuer: A,
        session_config: SessionConfig,
        now: SystemTime,
    ) -> SessionLoginResult
    where
        CredVeri: CredentialsVerifier,
        AccRepo: AccountRepository<R, G>,
        AccRepo::Error: std::fmt::Display + Send + Sync + 'static,
        SessRepo: webgates_sessions::repository::SessionRepository,
        A: AuthTokenIssuer<webgates_sessions::session::Session>,
        A::Error: std::fmt::Display,
    {
        #[cfg(feature = "audit-logging")]
        let _audit_span =
            tracing::span!(tracing::Level::INFO, "auth.login.session", user_id = %credentials.id);
        #[cfg(feature = "audit-logging")]
        let _audit_enter = _audit_span.enter();
        #[cfg(feature = "audit-logging")]
        tracing::info!(user_id = %credentials.id, "session_login_attempt");

        let account_query_result = account_repository
            .query_account_by_user_id(&credentials.id)
            .await;

        let (account_opt, verification_uuid, user_exists_choice, query_error_opt) =
            match account_query_result {
                Ok(Some(acc)) => {
                    debug!("Account found for user_id: {}", credentials.id);
                    (Some(acc.clone()), acc.account_id, Choice::from(1u8), None)
                }
                Ok(None) => {
                    debug!("Account not found for user_id: {}", credentials.id);
                    let dummy_uuid = Uuid::from_bytes([
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x01,
                    ]);
                    (None, dummy_uuid, Choice::from(0u8), None)
                }
                Err(e) => {
                    error!("Error querying account: {}", e);
                    let dummy_uuid = Uuid::from_bytes([
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x01,
                    ]);
                    (None, dummy_uuid, Choice::from(0u8), Some(e))
                }
            };

        if let Some(error) = query_error_opt {
            return SessionLoginResult::internal_error(
                "We're experiencing technical difficulties. Please try signing in again.",
                format!("Account repository query failed: {}", error),
                Some("repository_query"),
                true,
            );
        }

        let creds_to_verify = Credentials::new(&verification_uuid, &credentials.secret);
        let verification_result = credentials_verifier
            .verify_credentials(creds_to_verify)
            .await;

        let auth_success_choice = match verification_result {
            Ok(VerificationResult::Ok) => {
                debug!(
                    "Credentials verified successfully for UUID: {}",
                    verification_uuid
                );
                Choice::from(1u8)
            }
            Ok(VerificationResult::Unauthorized) => {
                debug!(
                    "Credentials verification failed for UUID: {}",
                    verification_uuid
                );
                Choice::from(0u8)
            }
            Err(e) => {
                error!("Error verifying credentials: {}", e);
                return SessionLoginResult::internal_error(
                    "We're having trouble with the authentication system. Please try again.",
                    format!("Credential verification failed: {}", e),
                    Some("credential_verification"),
                    true,
                );
            }
        };

        let final_success_choice = user_exists_choice & auth_success_choice;
        let login_successful: bool = final_success_choice.into();

        if !login_successful {
            debug!("Session login failed - invalid credentials");
            return SessionLoginResult::invalid_credentials(None, None);
        }

        let Some(account) = account_opt else {
            error!("Internal error: session login marked successful but no account available");
            return SessionLoginResult::internal_error(
                "There was an unexpected issue with your authentication. Please try signing in again.",
                "Authentication state inconsistency: successful verification but no account data",
                Some("auth_state_inconsistency"),
                false,
            );
        };

        let refresh_token_generator = OpaqueRefreshTokenGenerator::default();
        let refresh_token_hasher = Sha256RefreshTokenHasher;
        let token_pair_issuer = TokenPairIssuer::new(
            auth_token_issuer,
            refresh_token_generator,
            refresh_token_hasher,
        );

        let session_issuer =
            match SessionIssuer::new(session_config, session_repository, token_pair_issuer) {
                Ok(issuer) => issuer,
                Err(error) => {
                    error!("Error constructing session issuer: {}", error);
                    return SessionLoginResult::internal_error(
                        "We're having trouble completing your sign-in. Please try again.",
                        format!("Session issuer construction failed: {}", error),
                        Some("session_issuer_construction"),
                        true,
                    );
                }
            };

        match session_issuer
            .issue_session(account.user_id.clone(), now)
            .await
        {
            Ok(issued_session) => {
                debug!("Session login successful, auth and refresh tokens generated");
                SessionLoginResult::Success(issued_session)
            }
            Err(error) => {
                error!("Error issuing session-backed tokens: {}", error);
                SessionLoginResult::internal_error(
                    "We're having trouble completing your sign-in. Please try again.",
                    format!("Session issuance failed: {}", error),
                    Some("session_issuance"),
                    true,
                )
            }
        }
    }
}

impl<R, G> Default for LoginService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<R, G> Default for SessionLoginService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::codecs::jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER as JWT_CRYPTO_PROVIDER;
    use crate::codecs::jwt::{JsonWebToken, JwtClaims};
    use crate::groups::Group;
    use crate::roles::Role;
    use crate::secrets::Secret;
    use crate::secrets::hashing::argon2::Argon2Hasher;
    use std::time::{Duration, Instant};
    use webgates_repositories::memory::account::MemoryAccountRepository;
    use webgates_repositories::memory::secret::MemorySecretRepository;
    use webgates_repositories::secret_repository::SecretRepository;

    fn median(durs: &[Duration]) -> Duration {
        let mut v = durs.to_vec();
        v.sort();
        v[v.len() / 2]
    }

    fn install_jwt_crypto_provider() {
        let _ = JWT_CRYPTO_PROVIDER.install_default();
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    #[allow(clippy::expect_used)]
    async fn test_timing_attack_protection() {
        install_jwt_crypto_provider();
        let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
        let secret_repo = Arc::new(MemorySecretRepository::new_with_argon2_hasher().unwrap());
        let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let login_service = LoginService::new();

        let existing_user = "existing@example.com";
        let password = "test_password";
        let mut account = Account::new(existing_user);
        account.groups = vec![Group::new("test-group")];
        let stored_account = account_repo.store_account(account).await.unwrap().unwrap();

        let secret = Secret::new(
            &stored_account.account_id,
            password,
            Argon2Hasher::new_recommended().unwrap(),
        )
        .expect("secret");
        secret_repo.store_secret(secret).await.unwrap();

        let registered_claims = crate::codecs::jwt::RegisteredClaims::new(
            "test-issuer",
            chrono::Utc::now().timestamp() as u64 + 3600,
        );

        {
            let creds = Credentials::new(&"nonexistent@example.com".to_string(), "pw");
            let _ = login_service
                .authenticate(
                    creds,
                    registered_claims.clone(),
                    secret_repo.clone(),
                    account_repo.clone(),
                    jwt_codec.clone(),
                )
                .await;
            let creds = Credentials::new(&existing_user.to_string(), "wrong_pw");
            let _ = login_service
                .authenticate(
                    creds,
                    registered_claims.clone(),
                    secret_repo.clone(),
                    account_repo.clone(),
                    jwt_codec.clone(),
                )
                .await;
        }

        let iterations = 4;
        let mut nonexistent_times = Vec::with_capacity(iterations);
        let mut wrong_times = Vec::with_capacity(iterations);

        for i in 0..iterations {
            if i % 2 == 0 {
                let creds = Credentials::new(&"nonexistent@example.com".to_string(), "any_pw");
                let start = Instant::now();
                let r = login_service
                    .authenticate(
                        creds,
                        registered_claims.clone(),
                        secret_repo.clone(),
                        account_repo.clone(),
                        jwt_codec.clone(),
                    )
                    .await;
                assert!(matches!(r, LoginResult::InvalidCredentials { .. }));
                nonexistent_times.push(start.elapsed());

                let creds = Credentials::new(&existing_user.to_string(), "wrong_pw");
                let start = Instant::now();
                let r = login_service
                    .authenticate(
                        creds,
                        registered_claims.clone(),
                        secret_repo.clone(),
                        account_repo.clone(),
                        jwt_codec.clone(),
                    )
                    .await;
                assert!(matches!(r, LoginResult::InvalidCredentials { .. }));
                wrong_times.push(start.elapsed());
            } else {
                let creds = Credentials::new(&existing_user.to_string(), "wrong_pw");
                let start = Instant::now();
                let r = login_service
                    .authenticate(
                        creds,
                        registered_claims.clone(),
                        secret_repo.clone(),
                        account_repo.clone(),
                        jwt_codec.clone(),
                    )
                    .await;
                assert!(matches!(r, LoginResult::InvalidCredentials { .. }));
                wrong_times.push(start.elapsed());

                let creds = Credentials::new(&"nonexistent@example.com".to_string(), "any_pw");
                let start = Instant::now();
                let r = login_service
                    .authenticate(
                        creds,
                        registered_claims.clone(),
                        secret_repo.clone(),
                        account_repo.clone(),
                        jwt_codec.clone(),
                    )
                    .await;
                assert!(matches!(r, LoginResult::InvalidCredentials { .. }));
                nonexistent_times.push(start.elapsed());
            }
        }

        let med_nonexistent = median(&nonexistent_times);
        let med_wrong = median(&wrong_times);
        let med_success = {
            let creds = Credentials::new(&existing_user.to_string(), password);
            let start = Instant::now();
            let r = login_service
                .authenticate(
                    creds,
                    registered_claims.clone(),
                    secret_repo.clone(),
                    account_repo.clone(),
                    jwt_codec.clone(),
                )
                .await;
            assert!(matches!(r, LoginResult::Success(_)));
            vec![start.elapsed()]
        }[0];

        let (fast, slow) = if med_nonexistent < med_wrong {
            (med_nonexistent, med_wrong)
        } else {
            (med_wrong, med_nonexistent)
        };
        let diff = slow - fast;
        let relative = diff.as_secs_f64() / fast.as_secs_f64().max(1e-9);

        let relative_threshold = 0.75;
        let absolute_threshold_ms: u128 = 150;

        assert!(
            diff.as_millis() < absolute_threshold_ms || relative < relative_threshold,
            "Timing difference suspicious: diff={}ms, rel={:.2}",
            diff.as_millis(),
            relative
        );

        assert!(med_success.as_millis() >= 1, "success path too fast");
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn test_login_result_no_user_enumeration() {
        install_jwt_crypto_provider();
        let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
        let secret_repo = Arc::new(MemorySecretRepository::new_with_argon2_hasher().unwrap());
        let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let login_service = LoginService::new();

        let registered_claims = crate::codecs::jwt::RegisteredClaims::new(
            "test-issuer",
            chrono::Utc::now().timestamp() as u64 + 3600,
        );

        let nonexistent_credentials =
            Credentials::new(&"nonexistent@example.com".to_string(), "password");
        let result = login_service
            .authenticate(
                nonexistent_credentials,
                registered_claims,
                secret_repo,
                account_repo,
                jwt_codec,
            )
            .await;

        assert!(matches!(result, LoginResult::InvalidCredentials { .. }));
    }
}
