use super::JwtValidationResult;
use super::{Codec, JwtClaims};
use crate::accounts::Account;
use crate::authz::AccessHierarchy;

use std::sync::Arc;
use tracing::{debug, warn};

/// Service responsible for JWT token validation.
///
/// This service handles all aspects of JWT token validation including:
/// - Token decoding using the provided codec
/// - Issuer validation
/// - Token expiration (handled by the underlying jsonwebtoken library)
#[derive(Debug, Clone)]
pub struct JwtValidationService<C> {
    codec: Arc<C>,
    expected_issuer: String,
}

impl<C> JwtValidationService<C> {
    /// Creates a new JWT validation service.
    ///
    /// # Parameters
    /// - `codec`: The codec used for decoding JWT tokens
    /// - `expected_issuer`: The issuer that tokens must have to be considered valid
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
    /// This method performs the following validations:
    /// 1. Attempts to decode the token using the configured codec
    /// 2. Validates the issuer matches the expected issuer
    /// 3. Token expiration is automatically handled by the jsonwebtoken library
    ///
    /// # Parameters
    /// - `token_value`: The raw JWT token string
    ///
    /// # Returns
    /// - `JwtValidationResult::Valid` if the token is valid and authorized
    /// - `JwtValidationResult::InvalidToken` if the token cannot be decoded
    /// - `JwtValidationResult::InvalidIssuer` if the issuer doesn't match
    pub fn validate_token(&self, token_value: &str) -> JwtValidationResult<Account<R, G>> {
        // Attempt to decode the JWT token
        let jwt = match self.codec.decode(token_value.as_bytes()) {
            Ok(jwt) => jwt,
            Err(e) => {
                debug!("Could not decode JWT token: {e}");
                return JwtValidationResult::InvalidToken;
            }
        };

        debug!(
            "JWT token decoded successfully for account: {}",
            jwt.custom_claims.account_id
        );

        // Validate the issuer
        if !jwt.has_issuer(&self.expected_issuer) {
            warn!(
                "JWT issuer validation failed. Expected: '{}', Actual: {:?}, Account: {}",
                self.expected_issuer, jwt.registered_claims.issuer, jwt.custom_claims.account_id
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
    use crate::groups::Group;
    use crate::permissions::Permissions;
    use crate::roles::Role;
    use std::sync::Arc;

    // Mock codec for testing
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
                mock_issuer: "".to_string(),
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

        fn decode(&self, _data: &[u8]) -> crate::errors::Result<Self::Payload> {
            if self.should_fail_decode {
                return Err(crate::errors::Error::Jwt(
                    crate::codecs::JwtError::processing(
                        crate::codecs::JwtOperation::Decode,
                        "Mock decode failure",
                    ),
                ));
            }

            use crate::codecs::jwt::RegisteredClaims;

            use uuid::Uuid;

            let account = Account {
                account_id: Uuid::new_v4(),
                user_id: "test_user".to_string(),
                roles: vec![Role::User],
                groups: vec![Group::new("engineering")],
                permissions: Permissions::new(),
            };

            let registered_claims = RegisteredClaims {
                issuer: self.mock_issuer.clone(),
                subject: Some("test".to_string()),
                audience: None,
                expiration_time: 9999999999, // Far future
                not_before_time: None,
                issued_at_time: 1000000000, // Past time
                jwt_id: None,
            };

            Ok(JwtClaims {
                custom_claims: account,
                registered_claims,
            })
        }

        fn encode(&self, _payload: &Self::Payload) -> crate::errors::Result<Vec<u8>> {
            unimplemented!()
        }
    }

    #[test]
    fn validation_service_valid_token() {
        let codec = Arc::new(MockCodec::new());
        let service = JwtValidationService::new(codec, "test-issuer");

        let result = service.validate_token("valid-token");

        match result {
            JwtValidationResult::Valid(jwt) => {
                assert_eq!(jwt.custom_claims.user_id, "test_user");
                assert_eq!(jwt.registered_claims.issuer, "test-issuer".to_string());
            }
            _ => panic!("Expected valid token result"),
        }
    }

    #[test]
    fn validation_service_invalid_token() {
        let codec = Arc::new(MockCodec::with_decode_failure());
        let service = JwtValidationService::new(codec, "test-issuer");

        let result = service.validate_token("invalid-token");

        assert!(matches!(result, JwtValidationResult::InvalidToken));
    }

    #[test]
    fn validation_service_invalid_issuer() {
        let codec = Arc::new(MockCodec::with_different_issuer());
        let service = JwtValidationService::new(codec, "expected-issuer");

        let result = service.validate_token("valid-token");

        match result {
            JwtValidationResult::InvalidIssuer { expected, actual } => {
                assert_eq!(expected, "expected-issuer");
                assert_eq!(actual, "different-issuer".to_string());
            }
            _ => panic!("Expected invalid issuer result"),
        }
    }
}
