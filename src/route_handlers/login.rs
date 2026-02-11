use crate::accounts::{Account, AccountRepository};
use crate::authn::{LoginResult, LoginService};
use crate::authz::AccessHierarchy;
use crate::codecs::Codec;
use crate::codecs::jwt::{JwtClaims, RegisteredClaims};
use crate::cookie_template::CookieTemplate;
use crate::credentials::Credentials;
use crate::credentials::CredentialsVerifier;

use std::sync::Arc;

use axum::http::StatusCode;
use axum_extra::extract::CookieJar;
use tracing::error;
use uuid::Uuid;

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
    CredVeri: CredentialsVerifier<Uuid>,
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
