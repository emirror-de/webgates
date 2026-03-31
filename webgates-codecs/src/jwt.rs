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

use std::collections::HashSet;
use std::marker::PhantomData;

use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_with::skip_serializing_none;

pub mod validation_result;
pub mod validation_service;

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
            jwt_id: None,
        }
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
    /// Key for encoding.
    pub enc_key: EncodingKey,
    /// Key for decoding.
    pub dec_key: DecodingKey,
    /// Header used for encoding.
    pub header: Option<Header>,
    /// Validation options used during decoding.
    pub validation: Option<Validation>,
}

impl Default for JsonWebTokenOptions {
    /// Creates symmetric encoding/decoding keys from a random secret using **HMAC-SHA256 (HS256)**.
    ///
    /// This is suitable for tests and ephemeral development only.
    ///
    /// # Algorithm guidance
    ///
    /// The default algorithm is HS256 (symmetric HMAC). For production use, prefer HS256,
    /// ES256, or ES384 (ECDSA). **Do not use RSA-based algorithms** (RS256, RS384, RS512,
    /// PS256, PS384, PS512) until [RUSTSEC-2023-0071] (Marvin Attack timing side-channel
    /// in the `rsa` crate) is patched upstream — currently no fix is available.
    ///
    /// [RUSTSEC-2023-0071]: https://rustsec.org/advisories/RUSTSEC-2023-0071
    fn default() -> Self {
        use rand::{Rng, distr::Alphanumeric, rng};

        let authentication_secret: String = rng()
            .sample_iter(&Alphanumeric)
            .take(60)
            .map(char::from)
            .collect();

        Self {
            enc_key: EncodingKey::from_secret(authentication_secret.as_bytes()),
            dec_key: DecodingKey::from_secret(authentication_secret.as_bytes()),
            header: Some(Header::default()),
            validation: Some(Validation::default()),
        }
    }
}

impl JsonWebTokenOptions {
    /// Returns updated options with a custom encoding key.
    pub fn with_encoding_key(self, enc_key: EncodingKey) -> Self {
        Self { enc_key, ..self }
    }

    /// Returns updated options with a custom decoding key.
    pub fn with_decoding_key(self, dec_key: DecodingKey) -> Self {
        Self { dec_key, ..self }
    }

    /// Returns updated options with a custom header.
    pub fn with_header(self, header: Header) -> Self {
        Self {
            header: Some(header),
            ..self
        }
    }

    /// Returns updated options with custom validation settings.
    pub fn with_validation(self, validation: Validation) -> Self {
        Self {
            validation: Some(validation),
            ..self
        }
    }
}

/// JWT codec backed by the `jsonwebtoken` crate.
///
/// # Key management
///
/// The default constructor generates a fresh random symmetric signing key.
/// This is convenient for tests or short-lived local development, but it also
/// means tokens issued by one instance become invalid when a new instance with
/// a different random key is created.
///
/// For persistent sessions across restarts or multiple instances, construct the
/// codec with explicit keys via [`JsonWebToken::new_with_options`].
#[derive(Clone)]
pub struct JsonWebToken<P> {
    enc_key: EncodingKey,
    dec_key: DecodingKey,
    header: Header,
    validation: Validation,
    phantom_payload: PhantomData<P>,
}

impl<P> JsonWebToken<P> {
    /// Creates a codec from explicit options.
    pub fn new_with_options(options: JsonWebTokenOptions) -> Self {
        let JsonWebTokenOptions {
            enc_key,
            dec_key,
            header,
            validation,
        } = options;

        Self {
            enc_key,
            dec_key,
            header: header.unwrap_or_default(),
            validation: validation.unwrap_or_default(),
            phantom_payload: PhantomData,
        }
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
        let token =
            jsonwebtoken::encode(&self.header, payload, &self.enc_key).map_err(|error| {
                Error::Jwt(JwtError::processing(
                    JwtOperation::Encode,
                    format!("JWT encoding failed: {error}"),
                ))
            })?;

        Ok(token.into_bytes())
    }

    fn decode(&self, encoded_value: &[u8]) -> Result<Self::Payload> {
        let claims =
            jsonwebtoken::decode::<Self::Payload>(encoded_value, &self.dec_key, &self.validation)
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

        if self.header != claims.header {
            return Err(Error::Jwt(JwtError::processing(
                JwtOperation::Validate,
                "Header of the decoded value does not match the one used for encoding",
            )));
        }

        Ok(claims.claims)
    }
}
