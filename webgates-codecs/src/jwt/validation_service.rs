//! Services for validating decoded JWTs against application expectations.
//!
//! This submodule contains [`JwtValidationService`], which validates raw token
//! strings using a configured codec and checks issuer expectations.
//!
//! The service keeps validation behavior narrow and explicit:
//! - decode the token with the configured codec
//! - reject tokens that fail codec-level validation
//! - reject tokens whose issuer does not match the configured issuer
//!
//! Expiration, signature, and other JWT-level checks remain owned by the
//! configured codec and its underlying JWT validation settings.
use crate::Codec;
use crate::jwt::JwtClaims;
use crate::jwt::validation_result::JwtValidationResult;

use std::sync::Arc;

use tracing::{debug, warn};
use webgates_core::accounts::Account;
use webgates_core::authz::AccessHierarchy;

/// Service responsible for validating raw JWT token strings.
///
/// This service applies application-level validation on top of the configured
/// codec:
/// - decode the token into typed claims
/// - verify the expected issuer
///
/// Expiration, signature, algorithm, and claim-shape validation are delegated
/// to the codec.
#[derive(Debug, Clone)]
pub struct JwtValidationService<C> {
    codec: Arc<C>,
    expected_issuer: String,
}

impl<C> JwtValidationService<C> {
    /// Creates a new JWT validation service.
    ///
    /// # Parameters
    /// - `codec`: codec used to decode and validate raw JWT tokens
    /// - `expected_issuer`: issuer that decoded tokens must contain
    pub fn new(codec: Arc<C>, expected_issuer: &str) -> Self {
        Self {
            codec,
            expected_issuer: expected_issuer.to_owned(),
        }
    }
}

impl<C, R, G> JwtValidationService<C>
where
    C: Codec<Payload = JwtClaims<Account<R, G>>>,
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    /// Validates a JWT token from its raw string representation.
    ///
    /// Validation happens in two steps:
    /// 1. decode the token with the configured codec
    /// 2. verify the configured issuer against the decoded claims
    ///
    /// # Parameters
    /// - `token_value`: raw JWT token string
    ///
    /// # Returns
    /// - [`JwtValidationResult::Valid`] when decoding succeeds and the issuer matches
    /// - [`JwtValidationResult::InvalidToken`] when decoding fails
    /// - [`JwtValidationResult::InvalidIssuer`] when decoding succeeds but the issuer differs
    pub fn validate_token(&self, token_value: &str) -> JwtValidationResult<Account<R, G>> {
        let jwt = match self.codec.decode(token_value.as_bytes()) {
            Ok(jwt) => jwt,
            Err(error) => {
                debug!(error = %error, "JWT token decoding failed");
                return JwtValidationResult::InvalidToken;
            }
        };

        debug!(
            account_id = %jwt.custom_claims.account_id,
            issuer = %jwt.registered_claims.issuer,
            "JWT token decoded successfully"
        );

        if !jwt.has_issuer(&self.expected_issuer) {
            warn!(
                expected_issuer = %self.expected_issuer,
                actual_issuer = %jwt.registered_claims.issuer,
                account_id = %jwt.custom_claims.account_id,
                "JWT issuer validation failed"
            );
            return JwtValidationResult::InvalidIssuer {
                expected: self.expected_issuer.clone(),
                actual: jwt.registered_claims.issuer,
            };
        }

        JwtValidationResult::Valid(jwt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::{JwtError, JwtOperation};
    use crate::jwt::RegisteredClaims;

    use std::sync::Arc;

    use uuid::Uuid;
    use webgates_core::groups::Group;
    use webgates_core::permissions::Permissions;
    use webgates_core::roles::Role;

    #[derive(Clone)]
    struct MockCodec {
        should_fail_decode: bool,
        mock_issuer: String,
    }

    impl MockCodec {
        fn new() -> Self {
            Self {
                should_fail_decode: false,
                mock_issuer: "test-issuer".to_string(),
            }
        }

        fn with_decode_failure() -> Self {
            Self {
                should_fail_decode: true,
                mock_issuer: String::new(),
            }
        }

        fn with_different_issuer() -> Self {
            Self {
                should_fail_decode: false,
                mock_issuer: "different-issuer".to_string(),
            }
        }
    }

    impl Codec for MockCodec {
        type Payload = JwtClaims<Account<Role, Group>>;

        fn decode(&self, _encoded_value: &[u8]) -> crate::Result<Self::Payload> {
            if self.should_fail_decode {
                return Err(crate::Error::Jwt(JwtError::processing(
                    JwtOperation::Decode,
                    "Mock decode failure",
                )));
            }

            let account = Account {
                account_id: Uuid::now_v7(),
                user_id: "test_user".to_string(),
                roles: vec![Role::User],
                groups: vec![Group::new("engineering")],
                permissions: Permissions::new(),
            };

            let registered_claims = RegisteredClaims {
                issuer: self.mock_issuer.clone(),
                subject: Some("test".to_string()),
                audience: None,
                expiration_time: 9_999_999_999,
                not_before_time: None,
                issued_at_time: 1_000_000_000,
                jwt_id: None,
            };

            Ok(JwtClaims {
                custom_claims: account,
                registered_claims,
            })
        }

        fn encode(&self, _payload: &Self::Payload) -> crate::Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn validation_service_returns_valid_result_for_matching_issuer() {
        let codec = Arc::new(MockCodec::new());
        let service = JwtValidationService::new(codec, "test-issuer");

        let result = service.validate_token("valid-token");

        match result {
            JwtValidationResult::Valid(jwt) => {
                assert_eq!(jwt.custom_claims.user_id, "test_user");
                assert_eq!(jwt.registered_claims.issuer, "test-issuer");
            }
            other => panic!("Expected valid token result, got {other:?}"),
        }
    }

    #[test]
    fn validation_service_returns_invalid_token_when_decoding_fails() {
        let codec = Arc::new(MockCodec::with_decode_failure());
        let service = JwtValidationService::new(codec, "test-issuer");

        let result = service.validate_token("invalid-token");

        assert!(matches!(result, JwtValidationResult::InvalidToken));
    }

    #[test]
    fn validation_service_returns_invalid_issuer_when_issuer_differs() {
        let codec = Arc::new(MockCodec::with_different_issuer());
        let service = JwtValidationService::new(codec, "expected-issuer");

        let result = service.validate_token("valid-token");

        match result {
            JwtValidationResult::InvalidIssuer { expected, actual } => {
                assert_eq!(expected, "expected-issuer");
                assert_eq!(actual, "different-issuer");
            }
            other => panic!("Expected invalid issuer result, got {other:?}"),
        }
    }
}
