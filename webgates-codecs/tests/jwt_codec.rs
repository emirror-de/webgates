use std::sync::Arc;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use uuid::Uuid;
use webgates_codecs::Codec;
use webgates_codecs::jwt::validation_result::JwtValidationResult;
use webgates_codecs::jwt::validation_service::JwtValidationService;
use webgates_codecs::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims, RegisteredClaims};
use webgates_core::accounts::Account;
use webgates_core::groups::Group;
use webgates_core::permissions::Permissions;
use webgates_core::roles::Role;

type TestAccount = Account<Role, Group>;
type TestClaims = JwtClaims<TestAccount>;

fn sample_account() -> TestAccount {
    TestAccount {
        account_id: Uuid::now_v7(),
        user_id: "user@example.com".to_string(),
        roles: vec![Role::User],
        groups: vec![Group::new("engineering")],
        permissions: Permissions::new(),
    }
}

fn sample_registered_claims(issuer: &str) -> RegisteredClaims {
    RegisteredClaims {
        issuer: issuer.to_string(),
        subject: Some("user@example.com".to_string()),
        audience: None,
        expiration_time: 4_102_444_800,
        not_before_time: None,
        issued_at_time: 1_700_000_000,
        jwt_id: Some("jwt-test-id".to_string()),
    }
}

fn sample_claims(issuer: &str) -> TestClaims {
    JwtClaims::new(sample_account(), sample_registered_claims(issuer))
}

fn codec_with_shared_secret(secret: &[u8]) -> JsonWebToken<TestClaims> {
    JsonWebToken::new_with_options(
        JsonWebTokenOptions::default()
            .with_encoding_key(EncodingKey::from_secret(secret))
            .with_decoding_key(DecodingKey::from_secret(secret)),
    )
}

#[test]
fn jwt_codec_round_trip_preserves_claims() {
    let codec = codec_with_shared_secret(b"integration-test-secret");
    let claims = sample_claims("issuer-a");

    let encoded = match codec.encode(&claims) {
        Ok(value) => value,
        Err(error) => panic!("encoding should succeed: {error}"),
    };
    let decoded = match codec.decode(&encoded) {
        Ok(value) => value,
        Err(error) => panic!("decoding should succeed: {error}"),
    };

    assert_eq!(decoded.custom_claims, claims.custom_claims);
    assert_eq!(
        decoded.registered_claims.issuer,
        claims.registered_claims.issuer
    );
    assert_eq!(
        decoded.registered_claims.subject,
        claims.registered_claims.subject
    );
    assert_eq!(
        decoded.registered_claims.expiration_time,
        claims.registered_claims.expiration_time
    );
    assert_eq!(
        decoded.registered_claims.jwt_id,
        claims.registered_claims.jwt_id
    );
}

#[test]
fn jwt_codec_rejects_token_signed_with_different_secret() {
    let encoder = codec_with_shared_secret(b"encoder-secret");
    let decoder = codec_with_shared_secret(b"decoder-secret");
    let claims = sample_claims("issuer-a");

    let encoded = match encoder.encode(&claims) {
        Ok(value) => value,
        Err(error) => panic!("encoding should succeed: {error}"),
    };
    let result = decoder.decode(&encoded);

    assert!(result.is_err());
}

#[test]
fn jwt_validation_service_accepts_valid_token_with_expected_issuer() {
    let codec = Arc::new(codec_with_shared_secret(b"validation-secret"));
    let service = JwtValidationService::new(Arc::clone(&codec), "issuer-a");
    let claims = sample_claims("issuer-a");

    let token = match codec.encode(&claims) {
        Ok(value) => value,
        Err(error) => panic!("encoding should succeed: {error}"),
    };
    let token = match String::from_utf8(token) {
        Ok(value) => value,
        Err(error) => panic!("JWT output must be valid UTF-8: {error}"),
    };

    let result = service.validate_token(&token);

    match result {
        JwtValidationResult::Valid(jwt) => {
            assert_eq!(jwt.custom_claims, claims.custom_claims);
            assert_eq!(jwt.registered_claims.issuer, "issuer-a");
        }
        other => panic!("expected valid token result, got {other:?}"),
    }
}

#[test]
fn jwt_validation_service_rejects_token_with_unexpected_issuer() {
    let codec = Arc::new(codec_with_shared_secret(b"validation-secret"));
    let service = JwtValidationService::new(Arc::clone(&codec), "issuer-b");
    let claims = sample_claims("issuer-a");

    let token = match codec.encode(&claims) {
        Ok(value) => value,
        Err(error) => panic!("encoding should succeed: {error}"),
    };
    let token = match String::from_utf8(token) {
        Ok(value) => value,
        Err(error) => panic!("JWT output must be valid UTF-8: {error}"),
    };

    let result = service.validate_token(&token);

    match result {
        JwtValidationResult::InvalidIssuer { expected, actual } => {
            assert_eq!(expected, "issuer-b");
            assert_eq!(actual, "issuer-a");
        }
        other => panic!("expected invalid issuer result, got {other:?}"),
    }
}

#[test]
fn jwt_validation_service_rejects_malformed_token() {
    let codec = Arc::new(codec_with_shared_secret(b"validation-secret"));
    let service = JwtValidationService::new(codec, "issuer-a");

    let result = service.validate_token("not-a-jwt");

    assert!(matches!(result, JwtValidationResult::InvalidToken));
}

#[test]
fn jwt_codec_rejects_token_when_header_validation_configuration_differs() {
    let issuer = "issuer-a";
    let secret = b"header-secret";
    let claims = sample_claims(issuer);

    let mut encoding_header = Header::new(Algorithm::HS512);
    encoding_header.typ = Some("JWT".to_string());

    let mut validation = Validation::new(Algorithm::HS512);
    validation.validate_exp = false;

    let encoder = JsonWebToken::new_with_options(
        JsonWebTokenOptions::default()
            .with_encoding_key(EncodingKey::from_secret(secret))
            .with_decoding_key(DecodingKey::from_secret(secret))
            .with_header(encoding_header)
            .with_validation(validation.clone()),
    );

    let decoder: JsonWebToken<TestClaims> = JsonWebToken::new_with_options(
        JsonWebTokenOptions::default()
            .with_encoding_key(EncodingKey::from_secret(secret))
            .with_decoding_key(DecodingKey::from_secret(secret))
            .with_validation(validation),
    );

    let encoded = match encoder.encode(&claims) {
        Ok(value) => value,
        Err(error) => panic!("encoding should succeed: {error}"),
    };
    let result = decoder.decode(&encoded);

    assert!(result.is_err());
}
