use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::runtime::Builder;

use jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER as JWT_CRYPTO_PROVIDER;
use jsonwebtoken::{Algorithm, Validation};
use uuid::Uuid;
use webgates_codecs::Codec;
use webgates_codecs::jwt::authority::JwtAuthority;
use webgates_codecs::jwt::jwks::EcP384Jwk;
use webgates_codecs::jwt::validation_result::JwtValidationResult;
use webgates_codecs::jwt::validation_service::JwtValidationService;
use webgates_codecs::jwt::{
    Es384KeyPairLoader, Es384KeyPairPaths, JsonWebToken, JsonWebTokenOptions, JwtClaims,
    RegisteredClaims,
};
use webgates_core::accounts::Account;
use webgates_core::groups::Group;
use webgates_core::permissions::Permissions;
use webgates_core::roles::Role;

type TestAccount = Account<Role, Group>;
type TestClaims = JwtClaims<TestAccount>;

fn install_jwt_crypto_provider() {
    let _ = JWT_CRYPTO_PROVIDER.install_default();
}

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
        session_id: Some("session-test-id".to_string()),
    }
}

fn sample_claims(issuer: &str) -> TestClaims {
    JwtClaims::new(sample_account(), sample_registered_claims(issuer))
}

const TEST_ES384_PRIVATE_KEY_PEM: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCFT7MfRqWZfNgVX/cH
bxFTlPkBeCKqjsLkZXD/J3ZYHV1EtQksdrKtOzTr2hMs6pmhZANiAASyND9eQ5Qk
7ZteSEPMpExbVJenRWwyobExJMb62mmp3eA7Fszy8uBbLj8HRB16y3QbLcTxCBoo
ldBXfNFzM133OuTV2bBWXq5h34l+A0h4gU/odZ678LfAgnrRYMG4ZjU=
-----END PRIVATE KEY-----
"#;

const TEST_ES384_PUBLIC_KEY_PEM: &[u8] = br#"-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEsjQ/XkOUJO2bXkhDzKRMW1SXp0VsMqGx
MSTG+tppqd3gOxbM8vLgWy4/B0Qdest0Gy3E8QgaKJXQV3zRczNd9zrk1dmwVl6u
Yd+JfgNIeIFP6HWeu/C3wIJ60WDBuGY1
-----END PUBLIC KEY-----
"#;

const TEST_ES384_OTHER_PRIVATE_KEY_PEM: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDB+1q4EZvYXQ3jWm7pD
6DJfNwhAq8iLFT6J0k+ja+YV5sURv+fD4Sm8Am95H5NGN72hZANiAASgM9NZeKU6
1B2Bx8XnGhV6r+4PknGX3xR4tS2/Rbft9jIf5d2zyQzQJpvAr9Y7V2Q99vSE+N6k
9lknw5rmiLzso+e3+WIBVjPKkT4MSZ9lNIV5hQ9lBAW0Kn6D16Yrb+Y=
-----END PRIVATE KEY-----
"#;

const TEST_ES384_OTHER_PUBLIC_KEY_PEM: &[u8] = br#"-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEoDPTWXilOtQdgcfF5xoVeq/uD5Jxl98U
eLUtv0W37fYyH+Xds8kM0CabwK/WO1dkPfb0hPjepPZZJ8Oa5oi87KPnt/liAVYz
ypE+DEmfZTSFeYUPZQQFtCp+g9emK2/m
-----END PUBLIC KEY-----
"#;

fn codec_with_es384_keys(private_key: &[u8], public_key: &[u8]) -> JsonWebToken<TestClaims> {
    let options = match JsonWebTokenOptions::from_es384_pem(private_key, public_key) {
        Ok(options) => options,
        Err(error) => panic!("expected valid ES384 key options: {error}"),
    };

    JsonWebToken::new_with_options(options)
}

fn unique_temp_dir(label: &str) -> std::path::PathBuf {
    let unique = format!(
        "webgates-codecs-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    std::env::temp_dir().join(unique)
}

fn block_on_test_future<F, T>(future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|error| panic!("failed to build test tokio runtime: {error}"))
        .block_on(future)
}

#[test]
fn jwt_codec_round_trip_preserves_claims() {
    install_jwt_crypto_provider();
    let codec = codec_with_es384_keys(TEST_ES384_PRIVATE_KEY_PEM, TEST_ES384_PUBLIC_KEY_PEM);
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
    install_jwt_crypto_provider();
    let encoder = codec_with_es384_keys(TEST_ES384_PRIVATE_KEY_PEM, TEST_ES384_PUBLIC_KEY_PEM);
    let decoder = codec_with_es384_keys(
        TEST_ES384_OTHER_PRIVATE_KEY_PEM,
        TEST_ES384_OTHER_PUBLIC_KEY_PEM,
    );
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
    install_jwt_crypto_provider();
    let codec = Arc::new(codec_with_es384_keys(
        TEST_ES384_PRIVATE_KEY_PEM,
        TEST_ES384_PUBLIC_KEY_PEM,
    ));
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
    install_jwt_crypto_provider();
    let codec = Arc::new(codec_with_es384_keys(
        TEST_ES384_PRIVATE_KEY_PEM,
        TEST_ES384_PUBLIC_KEY_PEM,
    ));
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
    install_jwt_crypto_provider();
    let codec = Arc::new(codec_with_es384_keys(
        TEST_ES384_PRIVATE_KEY_PEM,
        TEST_ES384_PUBLIC_KEY_PEM,
    ));
    let service = JwtValidationService::new(codec, "issuer-a");

    let result = service.validate_token("not-a-jwt");

    assert!(matches!(result, JwtValidationResult::InvalidToken));
}

#[test]
fn jwt_codec_rejects_token_when_header_validation_configuration_differs() {
    install_jwt_crypto_provider();
    let issuer = "issuer-a";
    let claims = sample_claims(issuer);

    let mut validation = Validation::new(Algorithm::ES384);
    validation.validate_exp = false;

    let base_options = match JsonWebTokenOptions::from_es384_pem(
        TEST_ES384_PRIVATE_KEY_PEM,
        TEST_ES384_PUBLIC_KEY_PEM,
    ) {
        Ok(options) => options,
        Err(error) => panic!("expected valid ES384 key options: {error}"),
    };
    let encoder = JsonWebToken::new_with_options(
        base_options
            .with_key_id("encoder-kid")
            .with_validation(validation.clone()),
    );

    let decoder_options = match JsonWebTokenOptions::from_es384_pem(
        TEST_ES384_PRIVATE_KEY_PEM,
        TEST_ES384_PUBLIC_KEY_PEM,
    ) {
        Ok(options) => options,
        Err(error) => panic!("expected valid ES384 key options: {error}"),
    };
    let decoder: JsonWebToken<TestClaims> =
        JsonWebToken::new_with_options(decoder_options.with_validation(validation));

    let encoded = match encoder.encode(&claims) {
        Ok(value) => value,
        Err(error) => panic!("encoding should succeed: {error}"),
    };
    let result = decoder.decode(&encoded);

    assert!(result.is_err());
}

#[test]
fn es384_key_pair_loader_initializes_and_loads_missing_key_files() {
    let dir = unique_temp_dir("init-create");
    let paths = Es384KeyPairPaths::new(dir.join("jwt/private.pem"), dir.join("jwt/public.pem"));
    let loader = Es384KeyPairLoader::new(
        paths.private_key_path().to_path_buf(),
        paths.public_key_path().to_path_buf(),
    );

    let key_pair = block_on_test_future(loader.initialize_if_required())
        .unwrap_or_else(|error| panic!("key initialization should succeed: {error}"));

    assert_eq!(key_pair.paths(), &paths);
    assert!(key_pair.private_key_path().is_file());
    assert!(key_pair.public_key_path().is_file());
    JsonWebTokenOptions::from_es384_pem(key_pair.private_key_pem(), key_pair.public_key_pem())
        .unwrap_or_else(|error| panic!("generated key pair should be valid: {error}"));
    let _: JsonWebToken<TestClaims> = key_pair
        .to_codec()
        .unwrap_or_else(|error| panic!("generated key pair should build a codec: {error}"));
    let authority: JwtAuthority<TestClaims> = key_pair
        .to_authority()
        .unwrap_or_else(|error| panic!("generated key pair should build an authority: {error}"));
    assert_eq!(
        authority.key_id(),
        authority.jwks_provider().key_id().expect("kid must be set")
    );

    std::fs::remove_dir_all(&dir)
        .unwrap_or_else(|error| panic!("temporary directory should be removable: {error}"));
}

#[test]
fn es384_key_pair_loader_reuses_existing_key_files() {
    let dir = unique_temp_dir("init-reuse");
    let paths = Es384KeyPairPaths::new(dir.join("jwt/private.pem"), dir.join("jwt/public.pem"));
    let loader = Es384KeyPairLoader::new(
        paths.private_key_path().to_path_buf(),
        paths.public_key_path().to_path_buf(),
    );
    std::fs::create_dir_all(dir.join("jwt"))
        .unwrap_or_else(|error| panic!("temporary directory should be creatable: {error}"));
    std::fs::write(paths.private_key_path(), TEST_ES384_PRIVATE_KEY_PEM)
        .unwrap_or_else(|error| panic!("private key fixture should be writable: {error}"));
    std::fs::write(paths.public_key_path(), TEST_ES384_PUBLIC_KEY_PEM)
        .unwrap_or_else(|error| panic!("public key fixture should be writable: {error}"));

    let key_pair = block_on_test_future(loader.initialize_if_required())
        .unwrap_or_else(|error| panic!("existing keys should be reused: {error}"));

    assert_eq!(key_pair.paths(), &paths);
    assert_eq!(key_pair.private_key_pem(), TEST_ES384_PRIVATE_KEY_PEM);
    assert_eq!(key_pair.public_key_pem(), TEST_ES384_PUBLIC_KEY_PEM);

    std::fs::remove_dir_all(&dir)
        .unwrap_or_else(|error| panic!("temporary directory should be removable: {error}"));
}

#[test]
fn es384_key_pair_loader_rejects_partial_key_state() {
    let dir = unique_temp_dir("init-partial");
    let paths = Es384KeyPairPaths::new(dir.join("jwt/private.pem"), dir.join("jwt/public.pem"));
    let loader = Es384KeyPairLoader::new(
        paths.private_key_path().to_path_buf(),
        paths.public_key_path().to_path_buf(),
    );
    std::fs::create_dir_all(dir.join("jwt"))
        .unwrap_or_else(|error| panic!("temporary directory should be creatable: {error}"));
    std::fs::write(paths.private_key_path(), TEST_ES384_PRIVATE_KEY_PEM)
        .unwrap_or_else(|error| panic!("private key fixture should be writable: {error}"));

    let result = block_on_test_future(loader.initialize_if_required());

    assert!(result.is_err());

    std::fs::remove_dir_all(&dir)
        .unwrap_or_else(|error| panic!("temporary directory should be removable: {error}"));
}

#[test]
fn jwt_codec_adds_kid_header_when_encoding() {
    install_jwt_crypto_provider();

    let claims = sample_claims("issuer-a");
    let codec = codec_with_es384_keys(TEST_ES384_PRIVATE_KEY_PEM, TEST_ES384_PUBLIC_KEY_PEM);

    let encoded = codec.encode(&claims).expect("encoding should succeed");
    let encoded = String::from_utf8(encoded).expect("token should be utf8");
    let header = jsonwebtoken::decode_header(&encoded).expect("header should decode");

    assert_eq!(header.alg, Algorithm::ES384);
    assert_eq!(header.typ.as_deref(), Some("JWT"));
    assert!(header.kid.is_some());
}

#[test]
fn jwks_verification_rejects_missing_kid() {
    install_jwt_crypto_provider();

    let claims = sample_claims("issuer-a");

    let mut validation = Validation::new(Algorithm::ES384);
    validation.validate_exp = false;

    let legacy_encoder = JsonWebToken::new_with_options(
        JsonWebTokenOptions::from_es384_pem(TEST_ES384_PRIVATE_KEY_PEM, TEST_ES384_PUBLIC_KEY_PEM)
            .expect("options")
            .with_validation(validation.clone())
            .with_verification_keys(std::collections::HashMap::new(), true),
    );

    let encoded = legacy_encoder
        .encode(&claims)
        .expect("encoding should succeed");
    let encoded = String::from_utf8(encoded).expect("token should be utf8");
    let mut header = jsonwebtoken::decode_header(&encoded).expect("header should decode");
    header.kid = None;
    let token_without_kid = jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_ec_pem(TEST_ES384_PRIVATE_KEY_PEM).expect("enc key"),
    )
    .expect("re-encode token");

    let jwk = EcP384Jwk::from_public_key_pem("kid-a", TEST_ES384_PUBLIC_KEY_PEM)
        .expect("jwk conversion should succeed");
    let decoder: JsonWebToken<TestClaims> = JsonWebToken::new_with_options(
        JsonWebTokenOptions::for_es384_jwks_keys(&[jwk])
            .expect("jwks options")
            .with_validation(validation),
    );

    let result = decoder.decode(token_without_kid.as_bytes());
    assert!(result.is_err());
}

#[test]
fn jwt_options_rejects_invalid_es384_key_material() {
    install_jwt_crypto_provider();

    let result = JsonWebTokenOptions::from_es384_pem(b"invalid", b"invalid");

    assert!(result.is_err());
}

#[test]
fn registered_claims_new_sets_jti_and_supports_sid() {
    let claims = RegisteredClaims::new("issuer-a", 4_102_444_800).with_session_id("session-42");

    assert!(claims.jwt_id.is_some());
    assert_eq!(claims.session_id.as_deref(), Some("session-42"));
}
