//! JWT infrastructure components.
//!
use super::Codec;
use crate::errors::JwtError;
use crate::errors::JwtOperation;
use crate::errors::{Error, Result};
use crate::jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
pub use validation_result::JwtValidationResult;
pub use validation_service::JwtValidationService;

use std::collections::HashSet;
use std::marker::PhantomData;

use chrono::Utc;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_with::skip_serializing_none;

mod validation_result;
mod validation_service;

/// Registered/reserved claims by IANA/JWT spec, see
/// [auth0](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-token-claims) for more
/// information.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[skip_serializing_none]
pub struct RegisteredClaims {
    /// Issuer of the JWT
    #[serde(rename = "iss")]
    pub issuer: String,
    /// Subject of the JWT (the user)
    #[serde(rename = "sub")]
    pub subject: Option<String>,
    /// Recipient for which the JWT is intended
    #[serde(rename = "aud")]
    pub audience: Option<HashSet<String>>,
    /// Time after which the JWT expires
    #[serde(rename = "exp")]
    pub expiration_time: u64,
    /// Time before which the JWT must not be accepted for processing
    #[serde(rename = "nbf")]
    pub not_before_time: Option<u64>,
    /// Time at which the JWT was issued; can be used to determine age of the JWT
    #[serde(rename = "iat")]
    pub issued_at_time: u64,
    /// Unique identifier; can be used to prevent the JWT from being replayed (allows a token to be used only once)
    #[serde(rename = "jti")]
    pub jwt_id: Option<String>,
}

impl RegisteredClaims {
    /// Initializes the claims. Automatically sets the `issued_at_time` to `Utc::now`.
    pub fn new(issuer: &str, expiration_time: u64) -> Self {
        Self {
            issuer: issuer.to_string(),
            subject: None,
            audience: None,
            expiration_time,
            not_before_time: None,
            issued_at_time: Utc::now().timestamp() as u64,
            jwt_id: None,
        }
    }
}

/// Combination of claims used within `axum-gate` and encoded with [JsonWebToken] codec.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JwtClaims<CustomClaims> {
    /// The registered claims of a JWT.
    #[serde(flatten)]
    pub registered_claims: RegisteredClaims,
    /// Your custom claims that are added to the JWT.
    #[serde(flatten)]
    pub custom_claims: CustomClaims,
}

impl<CustomClaims> JwtClaims<CustomClaims> {
    /// Creates new claims with the given registered claims.
    pub fn new(custom_claims: CustomClaims, registered_claims: RegisteredClaims) -> Self {
        Self {
            custom_claims,
            registered_claims,
        }
    }

    /// Checks whether the issuer equals to the given value.
    pub fn has_issuer(&self, issuer: &str) -> bool {
        self.registered_claims.issuer == issuer
    }
}

/// Options to configure the [JsonWebToken] codec.
pub struct JsonWebTokenOptions {
    /// Key for encoding.
    pub enc_key: EncodingKey,
    /// Key for decoding.
    pub dec_key: DecodingKey,
    /// The header used for encoding.
    pub header: Option<Header>,
    /// Validation options.
    pub validation: Option<Validation>,
}

impl Default for JsonWebTokenOptions {
    /// Creates a random, alphanumeric 60 char key and uses it for en- and decoding (symmetric).
    /// [Header] and [Validation] are set with its default values.
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
    /// Adds the given encoding key.
    pub fn with_encoding_key(self, enc_key: EncodingKey) -> Self {
        Self { enc_key, ..self }
    }

    /// Adds the given decoding key.
    pub fn with_decoding_key(self, dec_key: DecodingKey) -> Self {
        Self { dec_key, ..self }
    }

    /// Adds the given header.
    pub fn with_header(self, header: Header) -> Self {
        Self {
            header: Some(header),
            ..self
        }
    }

    /// Adds the given validation.
    pub fn with_validation(self, validation: Validation) -> Self {
        Self {
            validation: Some(validation),
            ..self
        }
    }
}

/// Encrypts and validates JWTs using the configured keys and the `jsonwebtoken` crate.
///
/// # Key Management (IMPORTANT)
///
/// The default `JsonWebToken` (and its underlying `JsonWebTokenOptions::default()`) generates
/// a fresh, random 60-character symmetric signing key every time a new instance is created.
/// This is convenient for tests or ephemeral development sessions, but it also means that
/// previously issued tokens become invalid whenever you create a NEW `JsonWebToken` via
/// `JsonWebToken::default()` (or `JsonWebTokenOptions::default()`), because each call
/// generates a fresh random key. If you construct exactly one instance at startup and
/// reuse it for the whole process lifetime, tokens remain valid for that lifetime;
/// but creating additional instances later (including, but not limited to, during a
/// process restart or horizontal scaling) invalidates tokens produced by earlier instances.
///
/// If you need session continuity beyond a single in-memory instance (e.g. across process
/// restarts, deployments, horizontal scaling, or any re-instantiation), you MUST provide
/// a stable (persistent) key. Do this by constructing a `JsonWebToken` with explicit
/// `JsonWebTokenOptions` using a key loaded from an environment variable, file, KMS,
/// or another secret management system.
///
/// ## Providing a Persistent Symmetric Key
/// ```rust
/// use std::sync::Arc;
/// use axum_gate::codecs::jwt::{JsonWebToken, JwtClaims, RegisteredClaims, JsonWebTokenOptions};
/// use axum_gate::accounts::Account;
/// use axum_gate::prelude::{Role, Group};
/// use jsonwebtoken::{EncodingKey, DecodingKey};
///
/// // For the example we define a stable secret. In real code, load from env or secret manager.
/// let secret = "test-secret".to_string();
///
/// // Construct symmetric encoding/decoding keys
/// let enc_key = EncodingKey::from_secret(secret.as_bytes());
/// let dec_key = DecodingKey::from_secret(secret.as_bytes());
///
/// // Build options manually (do NOT call `JsonWebTokenOptions::default()` here)
/// let options = JsonWebTokenOptions {
///     enc_key,
///     dec_key,
///     header: None,       // Use default header
///     validation: None,   // Use default validation
/// };
///
/// // Create a codec that will survive restarts as long as JWT_SECRET stays the same
/// let jwt_codec = Arc::new(
///     JsonWebToken::<JwtClaims<Account<Role, Group>>>::new_with_options(options)
/// );
/// ```
///
/// ## When It Is Safe to Use the Default
/// - Unit / integration tests
/// - Short-lived local development where logout on restart is acceptable
/// - Disposable preview environments
///
/// ## When You Should NOT Use the Default
/// - Production services
/// - Any environment where user sessions must persist across restarts
/// - Multi-instance / horizontally scaled deployments
///
/// In those cases always supply a deterministic key source.
#[derive(Clone)]
pub struct JsonWebToken<P> {
    /// Key for encoding.
    enc_key: EncodingKey,
    /// Key for decoding.
    dec_key: DecodingKey,
    /// The header used for encoding.
    pub header: Header,
    /// Validation options for the JWT.
    pub validation: Validation,
    phantom_payload: PhantomData<P>,
}

impl<P> JsonWebToken<P> {
    /// Creates a new instance with the given options.
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
            header: header.unwrap_or(Header::default()),
            validation: validation.unwrap_or(Validation::default()),
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
        let web_token =
            jsonwebtoken::encode(&self.header, payload, &self.enc_key).map_err(|e| {
                Error::Jwt(JwtError::processing(
                    JwtOperation::Encode,
                    format!("JWT encoding failed: {e}"),
                ))
            })?;
        Ok(web_token.as_bytes().to_vec())
    }
    /// Decodes the given value.
    ///
    /// # Errors
    /// Returns an error if the header stored in [JsonWebToken] does not match the decoded value.
    /// The header can be retrieved from [JsonWebToken::header].
    fn decode(&self, encoded_value: &[u8]) -> Result<Self::Payload> {
        let claims =
            jsonwebtoken::decode::<Self::Payload>(&encoded_value, &self.dec_key, &self.validation)
                .map_err(|e| {
                    Error::Jwt(JwtError::processing_with_preview(
                        JwtOperation::Decode,
                        format!("JWT decoding failed: {e}"),
                        Some(
                            String::from_utf8_lossy(encoded_value)
                                .chars()
                                .take(20)
                                .collect::<String>()
                                + "...",
                        ),
                    ))
                })?;

        if self.header != claims.header {
            return Err(Error::Jwt(JwtError::processing(
                JwtOperation::Validate,
                "Header of the decoded value does not match the one used for encoding".to_string(),
            )));
        }

        Ok(claims.claims)
    }
}
