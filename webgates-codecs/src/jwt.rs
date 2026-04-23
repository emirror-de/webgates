//! JWT infrastructure components.
//!
//! This module provides:
//! - registered JWT claims via [`RegisteredClaims`]
//! - combined application and registered claims via [`JwtClaims`]
//! - a configurable JWT codec via [`JsonWebToken`] and [`JsonWebTokenOptions`]
//! - validation helpers in [`validation_service`] and [`validation_result`]
//!
//! The implementation is framework-agnostic and depends only on shared types
//! from `webgates-core` plus the codec abstractions from this crate.
//!
//! Prefer the canonical module-owned public paths for validation helpers:
//! - [`validation_service::JwtValidationService`]
//! - [`validation_result::JwtValidationResult`]

use crate::errors::{JwtError, JwtOperation};
use crate::{Codec, Error, Result};

use std::collections::HashMap;
use std::collections::HashSet;
use std::marker::PhantomData;
use std::sync::RwLock;

use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode_header};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_with::skip_serializing_none;
use uuid::Uuid;

pub mod authority;
pub mod jwks;
pub mod remote_verifier;
pub mod validation_result;
pub mod validation_service;

fn validation_with_es384_only() -> Validation {
    let mut validation = Validation::new(Algorithm::ES384);
    validation.algorithms = vec![Algorithm::ES384];
    validation
}

fn canonical_es384_header_with_kid(kid: &str) -> Header {
    let mut header = Header::new(Algorithm::ES384);
    header.typ = Some("JWT".to_string());
    header.kid = Some(kid.to_string());
    header
}

/// Registered/reserved claims defined by the JWT specification.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[skip_serializing_none]
pub struct RegisteredClaims {
    /// Issuer of the JWT.
    #[serde(rename = "iss")]
    pub issuer: String,
    /// Subject of the JWT.
    #[serde(rename = "sub")]
    pub subject: Option<String>,
    /// Recipient for which the JWT is intended.
    #[serde(rename = "aud")]
    pub audience: Option<HashSet<String>>,
    /// Time after which the JWT expires.
    #[serde(rename = "exp")]
    pub expiration_time: u64,
    /// Time before which the JWT must not be accepted for processing.
    #[serde(rename = "nbf")]
    pub not_before_time: Option<u64>,
    /// Time at which the JWT was issued.
    #[serde(rename = "iat")]
    pub issued_at_time: u64,
    /// Unique token identifier.
    #[serde(rename = "jti")]
    pub jwt_id: Option<String>,
    /// Session identifier for session-backed tokens.
    #[serde(rename = "sid")]
    pub session_id: Option<String>,
}

impl RegisteredClaims {
    /// Creates new registered claims and sets `issued_at_time` to `Utc::now()`.
    pub fn new(issuer: &str, expiration_time: u64) -> Self {
        // chrono::DateTime::timestamp() returns i64; use a checked conversion so a
        // negative timestamp (clock correction, pre-epoch test date) does not wrap
        // silently to a very large u64 and produce a malformed `iat` claim.
        let issued_at_time = u64::try_from(Utc::now().timestamp()).unwrap_or(0);
        Self {
            issuer: issuer.to_string(),
            subject: None,
            audience: None,
            expiration_time,
            not_before_time: None,
            issued_at_time,
            jwt_id: Some(Uuid::now_v7().to_string()),
            session_id: None,
        }
    }

    /// Returns updated claims with an explicit session identifier.
    #[must_use]
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }
}

/// Combined registered and application-specific JWT claims.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct JwtClaims<CustomClaims> {
    /// Standard JWT registered claims.
    #[serde(flatten)]
    pub registered_claims: RegisteredClaims,
    /// Application-specific claims.
    #[serde(flatten)]
    pub custom_claims: CustomClaims,
}

impl<CustomClaims> JwtClaims<CustomClaims> {
    /// Creates a new combined claims value.
    pub fn new(custom_claims: CustomClaims, registered_claims: RegisteredClaims) -> Self {
        Self {
            custom_claims,
            registered_claims,
        }
    }

    /// Returns `true` when the issuer matches `issuer`.
    pub fn has_issuer(&self, issuer: &str) -> bool {
        self.registered_claims.issuer == issuer
    }
}

/// Options used to configure a [`JsonWebToken`] codec.
#[derive(Debug, Clone)]
pub struct JsonWebTokenOptions {
    /// Key for ES384 encoding.
    encoding_key: Option<EncodingKey>,
    /// Canonical key id used when minting JWTs.
    key_id: String,
    /// Public verification keys indexed by `kid`.
    decoding_keys_by_kid: HashMap<String, DecodingKey>,
    /// Legacy fallback verification key when no `kid` was provided in the token.
    fallback_decoding_key: Option<DecodingKey>,
    /// Header used for encoding.
    header: Header,
    /// Validation options used during decoding.
    validation: Validation,
}

const DEV_ES384_PRIVATE_KEY_PEM: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCFT7MfRqWZfNgVX/cH
bxFTlPkBeCKqjsLkZXD/J3ZYHV1EtQksdrKtOzTr2hMs6pmhZANiAASyND9eQ5Qk
7ZteSEPMpExbVJenRWwyobExJMb62mmp3eA7Fszy8uBbLj8HRB16y3QbLcTxCBoo
ldBXfNFzM133OuTV2bBWXq5h34l+A0h4gU/odZ678LfAgnrRYMG4ZjU=
-----END PRIVATE KEY-----
"#;

const DEV_ES384_PUBLIC_KEY_PEM: &[u8] = br#"-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEsjQ/XkOUJO2bXkhDzKRMW1SXp0VsMqGx
MSTG+tppqd3gOxbM8vLgWy4/B0Qdest0Gy3E8QgaKJXQV3zRczNd9zrk1dmwVl6u
Yd+JfgNIeIFP6HWeu/C3wIJ60WDBuGY1
-----END PUBLIC KEY-----
"#;

impl Default for JsonWebTokenOptions {
    /// Creates ES384 encoding and decoding keys from built-in development keys.
    ///
    /// This default is intended for tests and local development only. Production
    /// deployments should provide explicit key material with
    /// [`JsonWebTokenOptions::from_es384_pem`].
    fn default() -> Self {
        match Self::from_es384_pem(DEV_ES384_PRIVATE_KEY_PEM, DEV_ES384_PUBLIC_KEY_PEM) {
            Ok(options) => options,
            Err(error) => panic!("failed to initialize default ES384 JWT options: {error}"),
        }
    }
}

impl JsonWebTokenOptions {
    /// Creates ES384 JWT options from PEM-encoded private and public keys.
    ///
    /// # Errors
    ///
    /// Returns a JWT processing error when either key cannot be parsed.
    pub fn from_es384_pem(private_key_pem: &[u8], public_key_pem: &[u8]) -> Result<Self> {
        let encoding_key = EncodingKey::from_ec_pem(private_key_pem).map_err(|error| {
            Error::Jwt(JwtError::processing(
                JwtOperation::Encode,
                format!("failed to parse ES384 private key: {error}"),
            ))
        })?;
        let decoding_key = DecodingKey::from_ec_pem(public_key_pem).map_err(|error| {
            Error::Jwt(JwtError::processing(
                JwtOperation::Decode,
                format!("failed to parse ES384 public key: {error}"),
            ))
        })?;
        let key_id = jwks::es384_kid_from_public_key_pem(public_key_pem)?;
        let header = canonical_es384_header_with_kid(&key_id);
        let validation = validation_with_es384_only();
        let mut decoding_keys_by_kid = HashMap::new();
        decoding_keys_by_kid.insert(key_id.clone(), decoding_key.clone());

        Ok(Self {
            encoding_key: Some(encoding_key),
            key_id,
            decoding_keys_by_kid,
            fallback_decoding_key: Some(decoding_key),
            header,
            validation,
        })
    }

    /// Creates verification-only ES384 JWT options from a PEM public key.
    ///
    /// Codecs built from these options can decode and validate tokens but will
    /// reject encoding attempts.
    ///
    /// # Errors
    ///
    /// Returns a JWT processing error when the public key cannot be parsed.
    pub fn for_es384_verification_only(public_key_pem: &[u8]) -> Result<Self> {
        let decoding_key = DecodingKey::from_ec_pem(public_key_pem).map_err(|error| {
            Error::Jwt(JwtError::processing(
                JwtOperation::Decode,
                format!("failed to parse ES384 public key: {error}"),
            ))
        })?;
        let key_id = jwks::es384_kid_from_public_key_pem(public_key_pem)?;
        let header = canonical_es384_header_with_kid(&key_id);
        let validation = validation_with_es384_only();
        let mut decoding_keys_by_kid = HashMap::new();
        decoding_keys_by_kid.insert(key_id.clone(), decoding_key.clone());

        Ok(Self {
            encoding_key: None,
            key_id,
            decoding_keys_by_kid,
            fallback_decoding_key: Some(decoding_key),
            header,
            validation,
        })
    }

    /// Creates verification-only ES384 options from JWKS keys.
    ///
    /// This enables key selection by `kid` and rejects JWTs that do not include
    /// a matching `kid`.
    ///
    /// # Errors
    ///
    /// Returns a JWT processing error if no valid ES384 verification key can be
    /// constructed from the provided JWKS entries.
    pub fn for_es384_jwks_keys(keys: &[jwks::EcP384Jwk]) -> Result<Self> {
        if keys.is_empty() {
            return Err(Error::Jwt(JwtError::processing(
                JwtOperation::Validate,
                "JWKS key set is empty",
            )));
        }

        let mut decoding_keys_by_kid = HashMap::new();
        for key in keys {
            let decoding_key = key.to_decoding_key()?;
            decoding_keys_by_kid.insert(key.kid.clone(), decoding_key);
        }

        let key_id = keys[0].kid.clone();
        let header = canonical_es384_header_with_kid(&key_id);
        let validation = validation_with_es384_only();

        Ok(Self {
            encoding_key: None,
            key_id,
            decoding_keys_by_kid,
            fallback_decoding_key: None,
            header,
            validation,
        })
    }

    /// Returns the active signing key id (`kid`).
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the number of configured verification keys.
    pub fn verification_key_count(&self) -> usize {
        self.decoding_keys_by_kid.len()
    }

    /// Returns whether verification accepts missing `kid` by using a fallback
    /// decoding key.
    pub fn allows_missing_kid_fallback(&self) -> bool {
        self.fallback_decoding_key.is_some()
    }

    /// Returns updated options with an explicit `kid` for signing.
    ///
    /// This always keeps a canonical ES384 JWT header (`alg = ES384`,
    /// `typ = JWT`, `kid = ...`).
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        let key_id = key_id.into();
        self.key_id = key_id.clone();
        self.header = canonical_es384_header_with_kid(&key_id);
        self
    }

    /// Returns updated options with a replaced verification-key map.
    ///
    /// The first key is used as fallback only when
    /// `allow_missing_kid_fallback` is `true`.
    pub fn with_verification_keys(
        mut self,
        keys: HashMap<String, DecodingKey>,
        allow_missing_kid_fallback: bool,
    ) -> Self {
        let fallback = if allow_missing_kid_fallback {
            keys.values().next().cloned()
        } else {
            None
        };
        self.decoding_keys_by_kid = keys;
        self.fallback_decoding_key = fallback;
        self
    }

    /// Returns updated options with an added verification key.
    pub fn with_added_verification_key(mut self, kid: impl Into<String>, key: DecodingKey) -> Self {
        self.decoding_keys_by_kid.insert(kid.into(), key);
        self
    }

    /// Returns updated options with custom validation settings.
    pub fn with_validation(self, validation: Validation) -> Self {
        let mut validation = validation;
        validation.algorithms = vec![Algorithm::ES384];

        Self { validation, ..self }
    }
}

/// JWT codec backed by the `jsonwebtoken` crate.
///
/// # Key management
///
/// The default constructor uses built-in ES384 development keys.
/// This is convenient for tests or local development.
///
/// For persistent sessions across restarts or multiple instances, construct the
/// codec with explicit keys via [`JsonWebToken::new_with_options`].
#[derive(Clone)]
pub struct JsonWebToken<P> {
    enc_key: Option<EncodingKey>,
    key_id: String,
    verification_state: std::sync::Arc<RwLock<VerificationState>>,
    header: Header,
    validation: Validation,
    phantom_payload: PhantomData<P>,
}

#[derive(Clone)]
struct VerificationState {
    dec_keys_by_kid: HashMap<String, DecodingKey>,
    fallback_dec_key: Option<DecodingKey>,
}

impl<P> JsonWebToken<P> {
    /// Creates a codec from explicit options.
    pub fn new_with_options(options: JsonWebTokenOptions) -> Self {
        let JsonWebTokenOptions {
            encoding_key,
            key_id,
            decoding_keys_by_kid,
            fallback_decoding_key,
            header,
            validation,
        } = options;

        Self {
            enc_key: encoding_key,
            key_id,
            verification_state: std::sync::Arc::new(RwLock::new(VerificationState {
                dec_keys_by_kid: decoding_keys_by_kid,
                fallback_dec_key: fallback_decoding_key,
            })),
            header,
            validation,
            phantom_payload: PhantomData,
        }
    }

    /// Returns the signing `kid` used by this codec.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the number of currently configured verification keys.
    pub fn verification_key_count(&self) -> usize {
        self.verification_state
            .read()
            .map(|state| state.dec_keys_by_kid.len())
            .unwrap_or(0)
    }

    /// Returns whether a verification key for the given `kid` exists.
    pub fn has_verification_key(&self, kid: &str) -> bool {
        self.verification_state
            .read()
            .map(|state| state.dec_keys_by_kid.contains_key(kid))
            .unwrap_or(false)
    }

    /// Returns whether this codec allows verification without `kid`.
    pub fn allows_missing_kid_fallback(&self) -> bool {
        self.verification_state
            .read()
            .map(|state| state.fallback_dec_key.is_some())
            .unwrap_or(false)
    }

    /// Atomically replaces all verification keys.
    pub fn replace_verification_keys(
        &self,
        keys: HashMap<String, DecodingKey>,
        allow_missing_kid_fallback: bool,
    ) {
        if let Ok(mut state) = self.verification_state.write() {
            let fallback = if allow_missing_kid_fallback {
                keys.values().next().cloned()
            } else {
                None
            };
            state.dec_keys_by_kid = keys;
            state.fallback_dec_key = fallback;
        }
    }

    /// Atomically replaces all verification keys from canonical ES384 JWK entries.
    ///
    /// # Errors
    ///
    /// Returns an error when any provided key cannot be converted.
    pub fn replace_verification_keys_from_jwks(
        &self,
        keys: &[jwks::EcP384Jwk],
        allow_missing_kid_fallback: bool,
    ) -> Result<()> {
        let mut decoding_keys = HashMap::new();
        for key in keys {
            let decoding_key = key.to_decoding_key()?;
            decoding_keys.insert(key.kid.clone(), decoding_key);
        }
        self.replace_verification_keys(decoding_keys, allow_missing_kid_fallback);
        Ok(())
    }

    fn decoding_key_for_header(&self, header: &Header) -> Result<DecodingKey> {
        if header.alg != Algorithm::ES384 {
            return Err(Error::Jwt(JwtError::processing(
                JwtOperation::Validate,
                format!(
                    "JWT header algorithm mismatch: expected ES384 but got {:?}",
                    header.alg
                ),
            )));
        }

        if header.typ.as_deref() != Some("JWT") {
            return Err(Error::Jwt(JwtError::processing(
                JwtOperation::Validate,
                "JWT header `typ` must be `JWT`",
            )));
        }

        let state = self.verification_state.read().map_err(|_| {
            Error::Jwt(JwtError::processing(
                JwtOperation::Validate,
                "verification key state lock is poisoned",
            ))
        })?;

        if let Some(kid) = header.kid.as_deref() {
            return state.dec_keys_by_kid.get(kid).cloned().ok_or_else(|| {
                Error::Jwt(JwtError::processing(
                    JwtOperation::Validate,
                    format!("JWT `kid` `{kid}` is not configured for verification"),
                ))
            });
        }

        state.fallback_dec_key.clone().ok_or_else(|| {
            Error::Jwt(JwtError::processing(
                JwtOperation::Validate,
                "JWT header is missing `kid` and no fallback verification key is configured",
            ))
        })
    }
}

impl<P> Default for JsonWebToken<P> {
    fn default() -> Self {
        Self::new_with_options(JsonWebTokenOptions::default())
    }
}

impl<P> Codec for JsonWebToken<P>
where
    P: Serialize + DeserializeOwned + Clone,
{
    type Payload = P;

    fn encode(&self, payload: &Self::Payload) -> Result<Vec<u8>> {
        let Some(enc_key) = &self.enc_key else {
            return Err(Error::Jwt(JwtError::processing(
                JwtOperation::Encode,
                "JWT encoding key is not configured for this codec",
            )));
        };
        let token = jsonwebtoken::encode(&self.header, payload, enc_key).map_err(|error| {
            Error::Jwt(JwtError::processing(
                JwtOperation::Encode,
                format!("JWT encoding failed: {error}"),
            ))
        })?;

        Ok(token.into_bytes())
    }

    fn decode(&self, encoded_value: &[u8]) -> Result<Self::Payload> {
        let header = decode_header(std::str::from_utf8(encoded_value).map_err(|error| {
            Error::Jwt(JwtError::processing(
                JwtOperation::Decode,
                format!("JWT bytes are not valid UTF-8: {error}"),
            ))
        })?)
        .map_err(|error| {
            Error::Jwt(JwtError::processing_with_preview(
                JwtOperation::Decode,
                format!("JWT header decoding failed: {error}"),
                Some(format!("token_len={}", encoded_value.len())),
            ))
        })?;

        let decoding_key = self.decoding_key_for_header(&header)?;

        let claims =
            jsonwebtoken::decode::<Self::Payload>(encoded_value, &decoding_key, &self.validation)
                .map_err(|error| {
                // Do not include token bytes in the error to avoid leaking token
                // material into logs or error messages if log levels are
                // misconfigured.  Report only the byte length for diagnostics.
                Error::Jwt(JwtError::processing_with_preview(
                    JwtOperation::Decode,
                    format!("JWT decoding failed: {error}"),
                    Some(format!("token_len={}", encoded_value.len())),
                ))
            })?;

        Ok(claims.claims)
    }
}
