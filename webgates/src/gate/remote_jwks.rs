use std::fmt::Display;
use std::sync::Arc;

use crate::accounts::Account;
use crate::authz::access_hierarchy::AccessHierarchy;
use crate::authz::access_policy::AccessPolicy;
use crate::authz::authorization_service::AuthorizationService;
use crate::codecs::jwt::RegisteredClaims;
use crate::codecs::jwt::validation_service::JwtClaimsVerifier;
use crate::codecs::jwt::{JwtClaims, validation_result::JwtValidationResult};
use uuid::Uuid;

/// Outcome of evaluating a cookie token against a remote-JWKS verifier.
#[derive(Debug, Clone)]
pub enum RemoteCookieEvaluation<R, G>
where
    R: AccessHierarchy + Eq + Display + Clone,
    G: Eq + Clone,
{
    OptionalAnonymous,
    OptionalAuthorized {
        account: Account<R, G>,
        registered_claims: RegisteredClaims,
    },
    MissingToken,
    InvalidToken,
    InvalidIssuer {
        expected: String,
        actual: String,
    },
    DenyAllPolicy,
    PolicyDenied {
        account_id: Uuid,
    },
    Authorized {
        account: Account<R, G>,
        registered_claims: RegisteredClaims,
    },
}

/// Framework-agnostic runtime for cookie verification via a remote-JWKS verifier.
#[derive(Clone)]
pub struct RemoteJwksCookieGateRuntime<V, R, G>
where
    V: JwtClaimsVerifier<JwtClaims<Account<R, G>>>,
    R: AccessHierarchy + Eq + Display + Clone,
    G: Eq + Clone,
{
    authorization_service: AuthorizationService<R, G>,
    verifier: Arc<V>,
    expected_issuer: String,
    install_optional_extensions: bool,
}

impl<V, R, G> RemoteJwksCookieGateRuntime<V, R, G>
where
    V: JwtClaimsVerifier<JwtClaims<Account<R, G>>>,
    R: AccessHierarchy + Eq + Display + Clone,
    G: Eq + Clone,
{
    pub fn new(
        verifier: Arc<V>,
        expected_issuer: impl Into<String>,
        policy: AccessPolicy<R, G>,
        install_optional_extensions: bool,
    ) -> Self {
        Self {
            authorization_service: AuthorizationService::new(policy),
            verifier,
            expected_issuer: expected_issuer.into(),
            install_optional_extensions,
        }
    }

    pub fn evaluate(&self, token: Option<&str>) -> RemoteCookieEvaluation<R, G> {
        if self.install_optional_extensions {
            if let Some(token) = token {
                match self.verifier.verify_token(token) {
                    Ok(jwt) if jwt.registered_claims.issuer == self.expected_issuer => {
                        return RemoteCookieEvaluation::OptionalAuthorized {
                            account: jwt.custom_claims,
                            registered_claims: jwt.registered_claims,
                        };
                    }
                    _ => {}
                }
            }
            return RemoteCookieEvaluation::OptionalAnonymous;
        }

        if self.authorization_service.policy_denies_all_access() {
            return RemoteCookieEvaluation::DenyAllPolicy;
        }

        let Some(token) = token else {
            return RemoteCookieEvaluation::MissingToken;
        };

        match self.verifier.verify_token(token) {
            Ok(jwt) => {
                let account = jwt.custom_claims;
                let registered_claims = jwt.registered_claims;

                if registered_claims.issuer != self.expected_issuer {
                    return RemoteCookieEvaluation::InvalidIssuer {
                        expected: self.expected_issuer.clone(),
                        actual: registered_claims.issuer,
                    };
                }

                let account_id = account.account_id;
                if self.authorization_service.is_authorized(&account) {
                    RemoteCookieEvaluation::Authorized {
                        account,
                        registered_claims,
                    }
                } else {
                    RemoteCookieEvaluation::PolicyDenied { account_id }
                }
            }
            Err(_) => RemoteCookieEvaluation::InvalidToken,
        }
    }

    pub fn verifier(&self) -> Arc<V> {
        Arc::clone(&self.verifier)
    }

    pub fn expected_issuer(&self) -> &str {
        &self.expected_issuer
    }

    pub fn policy(&self) -> AccessPolicy<R, G> {
        self.authorization_service.clone_policy()
    }

    pub fn with_optional_extensions(mut self, optional: bool) -> Self {
        self.install_optional_extensions = optional;
        self
    }
}

/// Map existing local validation results into remote-cookie evaluations.
pub fn map_validation_result_to_remote_evaluation<R, G>(
    result: JwtValidationResult<Account<R, G>>,
) -> RemoteCookieEvaluation<R, G>
where
    R: AccessHierarchy + Eq + Display + Clone,
    G: Eq + Clone,
{
    match result {
        JwtValidationResult::Valid(jwt) => RemoteCookieEvaluation::Authorized {
            account: jwt.custom_claims,
            registered_claims: jwt.registered_claims,
        },
        JwtValidationResult::InvalidToken => RemoteCookieEvaluation::InvalidToken,
        JwtValidationResult::InvalidIssuer { expected, actual } => {
            RemoteCookieEvaluation::InvalidIssuer { expected, actual }
        }
    }
}
