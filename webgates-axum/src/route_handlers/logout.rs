use webgates::authn::{LogoutService, SessionLogoutService};
use webgates::sessions::logout::{LogoutRequest, LogoutScope};
use webgates::sessions::repository::SessionRepository;
use webgates::sessions::session::{SessionFamilyId, SessionId};

use axum_extra::extract::CookieJar;

/// Logs out a user by removing their authentication cookie.
///
/// This handler creates a cookie with the same name as the authentication cookie
/// but removes its value, effectively logging out the user. The browser will
/// delete the cookie when it receives this response.
///
/// # Arguments
/// * `cookie_jar` - The incoming cookie jar
/// * `cookie_template` - CookieTemplate matching the authentication cookie to remove
///
/// # Returns
/// The updated cookie jar with the authentication cookie removed.
///
/// # Example
/// ```rust
/// use webgates_axum::route_handlers::logout;
/// use axum_extra::extract::CookieJar;
/// use webgates::cookie_template::CookieTemplate;
///
/// async fn logout_handler(cookie_jar: CookieJar) -> CookieJar {
///     let cookie_template = CookieTemplate::recommended().name("auth-token");
///     logout(cookie_jar, cookie_template).await
/// }
/// ```
pub async fn logout(
    cookie_jar: CookieJar,
    cookie_template: webgates::cookie_template::CookieTemplate,
) -> CookieJar {
    #[cfg(feature = "audit-logging")]
    let _audit_span = tracing::span!(tracing::Level::INFO, "auth.logout");
    #[cfg(feature = "audit-logging")]
    let _audit_enter = _audit_span.enter();
    #[cfg(feature = "audit-logging")]
    tracing::info!("logout");

    let logout_service = LogoutService::new();
    logout_service.logout();

    let cookie = cookie_template.build_removal();
    cookie_jar.remove(cookie)
}

/// Logs out a user by revoking session state and removing both auth and refresh cookies.
///
/// This handler keeps session revocation in the framework-agnostic core while the
/// HTTP adapter remains responsible for clearing transport-specific cookies.
///
/// # Arguments
/// * `cookie_jar` - The incoming cookie jar
/// * `session_repository` - Repository used to revoke the targeted session state
/// * `session_id` - Session to revoke
/// * `family_id` - Session family owning the targeted session
/// * `scope` - Whether to revoke only the current session or the full family
/// * `auth_cookie_template` - CookieTemplate matching the auth cookie to remove
/// * `refresh_cookie_template` - CookieTemplate matching the refresh cookie to remove
///
/// # Returns
/// * `Ok(CookieJar)` - Updated cookie jar with both cookies removed
/// * `Err(webgates::sessions::errors::SessionError)` - Session revocation failure
pub async fn logout_with_sessions<R>(
    cookie_jar: CookieJar,
    session_repository: R,
    session_id: SessionId,
    family_id: SessionFamilyId,
    scope: LogoutScope,
    auth_cookie_template: webgates::cookie_template::CookieTemplate,
    refresh_cookie_template: webgates::cookie_template::CookieTemplate,
) -> webgates::sessions::errors::Result<CookieJar>
where
    R: SessionRepository,
{
    #[cfg(feature = "audit-logging")]
    let _audit_span = tracing::span!(tracing::Level::INFO, "auth.logout.session");
    #[cfg(feature = "audit-logging")]
    let _audit_enter = _audit_span.enter();
    #[cfg(feature = "audit-logging")]
    tracing::info!("session_logout");

    let logout_service = SessionLogoutService::new(session_repository);
    logout_service
        .logout(LogoutRequest::new(session_id, family_id, scope))
        .await?;

    let auth_cookie = auth_cookie_template.build_removal();
    let refresh_cookie = refresh_cookie_template.build_removal();

    Ok(cookie_jar.remove(auth_cookie).remove(refresh_cookie))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use axum_extra::extract::cookie::Cookie;
    use webgates::sessions::lease::{LeaseAcquisition, RenewalLease};
    use webgates::sessions::repository::{
        CreateSession, RepositoryResult, RevokeSessionScope, RotateRefreshToken,
        RotateRefreshTokenOutcome,
    };
    use webgates::sessions::session::{
        SessionFamilyRecord, SessionLookup, SessionRecord, SessionRefreshRecord, SessionTouch,
    };
    use webgates::sessions::tokens::RefreshTokenHashRef;

    #[derive(Clone, Default)]
    struct DummySessionRepository {
        revoked_sessions: Arc<Mutex<Vec<(SessionId, RevokeSessionScope)>>>,
        revoked_families: Arc<Mutex<Vec<SessionFamilyId>>>,
    }

    impl SessionRepository for DummySessionRepository {
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
            _lease: RenewalLease,
        ) -> RepositoryResult<LeaseAcquisition> {
            Ok(LeaseAcquisition::Unavailable)
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

    fn cookie_value<'a>(jar: &'a CookieJar, name: &str) -> Option<&'a str> {
        jar.get(name).map(Cookie::value)
    }

    #[tokio::test]
    async fn logout_with_sessions_revokes_current_session_and_clears_both_cookies() {
        let repository = DummySessionRepository::default();
        let session_id = SessionId::new();
        let family_id = SessionFamilyId::new();
        let auth_cookie_template =
            webgates::cookie_template::CookieTemplate::recommended().name("auth-token");
        let refresh_cookie_template =
            webgates::cookie_template::CookieTemplate::recommended().name("refresh-token");

        let cookie_jar = CookieJar::new()
            .add(auth_cookie_template.build_with_value("auth-value"))
            .add(refresh_cookie_template.build_with_value("refresh-value"));

        let updated_jar = match logout_with_sessions(
            cookie_jar,
            repository.clone(),
            session_id,
            family_id,
            LogoutScope::CurrentSession,
            auth_cookie_template.clone(),
            refresh_cookie_template.clone(),
        )
        .await
        {
            Ok(cookie_jar) => cookie_jar,
            Err(error) => panic!("session logout should succeed: {}", error),
        };

        let revoked_sessions = match repository.revoked_sessions.lock() {
            Ok(revoked_sessions) => revoked_sessions,
            Err(error) => panic!("session revocation lock should not be poisoned: {}", error),
        };
        assert_eq!(
            revoked_sessions.as_slice(),
            &[(session_id, RevokeSessionScope::CurrentSession)]
        );
        assert!(cookie_value(&updated_jar, "auth-token").is_none());
        assert!(cookie_value(&updated_jar, "refresh-token").is_none());
    }

    #[tokio::test]
    async fn logout_with_sessions_revokes_session_family_and_clears_both_cookies() {
        let repository = DummySessionRepository::default();
        let session_id = SessionId::new();
        let family_id = SessionFamilyId::new();
        let auth_cookie_template =
            webgates::cookie_template::CookieTemplate::recommended().name("auth-token");
        let refresh_cookie_template =
            webgates::cookie_template::CookieTemplate::recommended().name("refresh-token");

        let cookie_jar = CookieJar::new()
            .add(auth_cookie_template.build_with_value("auth-value"))
            .add(refresh_cookie_template.build_with_value("refresh-value"));

        let updated_jar = match logout_with_sessions(
            cookie_jar,
            repository.clone(),
            session_id,
            family_id,
            LogoutScope::SessionFamily,
            auth_cookie_template.clone(),
            refresh_cookie_template.clone(),
        )
        .await
        {
            Ok(cookie_jar) => cookie_jar,
            Err(error) => panic!("session family logout should succeed: {}", error),
        };

        let revoked_families = match repository.revoked_families.lock() {
            Ok(revoked_families) => revoked_families,
            Err(error) => panic!("family revocation lock should not be poisoned: {}", error),
        };
        assert_eq!(revoked_families.as_slice(), &[family_id]);
        assert!(cookie_value(&updated_jar, "auth-token").is_none());
        assert!(cookie_value(&updated_jar, "refresh-token").is_none());
    }
}
