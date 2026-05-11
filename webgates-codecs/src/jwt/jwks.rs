//! JWKS document and ES384 key conversion support.
//!
//! This module contains the JWKS-facing types used when you want to expose or
//! consume public verification keys in a standard JSON Web Key Set format.

use crate::errors::{JwtError, JwtOperation};
use crate::{Error, Result};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, EllipticCurveKeyParameters,
    EllipticCurveKeyType, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse,
};
use p384::EncodedPoint;
use p384::elliptic_curve::sec1::ToEncodedPoint;
use p384::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};

/// Canonical JWKS document shape for ES384 public verification keys.
///
/// Use this when you want to publish or transport a set of verification keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwksDocument {
    /// Public key list.
    pub keys: Vec<EcP384Jwk>,
}

impl JwksDocument {
    /// Convert this JWKS document into a `jsonwebtoken` JWK set.
    pub fn to_jsonwebtoken_jwk_set(&self) -> JwkSet {
        JwkSet {
            keys: self
                .keys
                .iter()
                .map(EcP384Jwk::to_jsonwebtoken_jwk)
                .collect(),
        }
    }
}

/// Framework-agnostic provider for publishing JWKS documents.
///
/// This is a small helper for auth authorities that need to expose a stable
/// public JWKS document.
#[derive(Clone, Debug)]
pub struct JwksProvider {
    document: JwksDocument,
}

impl JwksProvider {
    /// Build a JWKS provider from authority public key PEM and explicit `kid`.
    ///
    /// # Errors
    ///
    /// Returns an error if the public key cannot be converted into a canonical
    /// ES384 JWK.
    pub fn from_es384_public_pem_with_kid(
        public_key_pem: &[u8],
        kid: impl Into<String>,
    ) -> Result<Self> {
        let key = EcP384Jwk::from_public_key_pem(kid, public_key_pem)?;
        Ok(Self {
            document: JwksDocument { keys: vec![key] },
        })
    }

    /// Build a JWKS provider from authority public key PEM with derived `kid`.
    ///
    /// # Errors
    ///
    /// Returns an error if key parsing or key-id derivation fails.
    pub fn from_es384_public_pem(public_key_pem: &[u8]) -> Result<Self> {
        let kid = es384_kid_from_public_key_pem(public_key_pem)?;
        Self::from_es384_public_pem_with_kid(public_key_pem, kid)
    }

    /// Returns the published JWKS document.
    pub fn document(&self) -> &JwksDocument {
        &self.document
    }

    /// Returns the first configured key id.
    pub fn key_id(&self) -> Option<&str> {
        self.document.keys.first().map(|key| key.kid.as_str())
    }
}

/// Canonical ES384 public JWK entry.
///
/// This type models one ES384 verification key in JWKS-compatible form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcP384Jwk {
    /// Stable key identifier used in JWT `kid` headers.
    pub kid: String,
    /// Key type. Must be `EC`.
    pub kty: String,
    /// Curve. Must be `P-384`.
    pub crv: String,
    /// Algorithm. Must be `ES384`.
    pub alg: String,
    /// Intended use. Must be `sig`.
    #[serde(rename = "use")]
    pub use_: String,
    /// Base64url-encoded x coordinate.
    pub x: String,
    /// Base64url-encoded y coordinate.
    pub y: String,
}

impl EcP384Jwk {
    /// Build a canonical ES384 public JWK from PEM-encoded public key material.
    ///
    /// # Errors
    ///
    /// Returns an error when the PEM cannot be parsed as a P-384 public key.
    pub fn from_public_key_pem(kid: impl Into<String>, public_key_pem: &[u8]) -> Result<Self> {
        let public_key = p384::PublicKey::from_public_key_pem(
            std::str::from_utf8(public_key_pem).map_err(|error| {
                Error::Jwt(JwtError::processing(
                    JwtOperation::Validate,
                    format!("invalid UTF-8 in ES384 public PEM: {error}"),
                ))
            })?,
        )
        .map_err(|error| {
            Error::Jwt(JwtError::processing(
                JwtOperation::Validate,
                format!("failed to parse ES384 public PEM: {error}"),
            ))
        })?;
        let encoded = public_key.to_encoded_point(false);
        let x = encoded.x().ok_or_else(|| {
            Error::Jwt(JwtError::processing(
                JwtOperation::Validate,
                "ES384 public key did not contain an x coordinate",
            ))
        })?;
        let y = encoded.y().ok_or_else(|| {
            Error::Jwt(JwtError::processing(
                JwtOperation::Validate,
                "ES384 public key did not contain a y coordinate",
            ))
        })?;

        Ok(Self {
            kid: kid.into(),
            kty: "EC".to_string(),
            crv: "P-384".to_string(),
            alg: "ES384".to_string(),
            use_: "sig".to_string(),
            x: URL_SAFE_NO_PAD.encode(x),
            y: URL_SAFE_NO_PAD.encode(y),
        })
    }

    /// Validate the canonical ES384 JWK shape.
    ///
    /// # Errors
    ///
    /// Returns an error when required fields are missing or not ES384-compatible.
    pub fn validate(&self) -> Result<()> {
        if self.kid.trim().is_empty() {
            return Err(Error::Jwt(JwtError::processing(
                JwtOperation::Validate,
                "JWKS key id (`kid`) must not be empty",
            )));
        }
        if self.kty != "EC" {
            return Err(Error::Jwt(JwtError::processing(
                JwtOperation::Validate,
                format!("unsupported JWKS key type `{}`; expected `EC`", self.kty),
            )));
        }
        if self.crv != "P-384" {
            return Err(Error::Jwt(JwtError::processing(
                JwtOperation::Validate,
                format!("unsupported JWKS curve `{}`; expected `P-384`", self.crv),
            )));
        }
        if self.alg != "ES384" {
            return Err(Error::Jwt(JwtError::processing(
                JwtOperation::Validate,
                format!(
                    "unsupported JWKS algorithm `{}`; expected `ES384`",
                    self.alg
                ),
            )));
        }
        if self.use_ != "sig" {
            return Err(Error::Jwt(JwtError::processing(
                JwtOperation::Validate,
                format!("unsupported JWKS key use `{}`; expected `sig`", self.use_),
            )));
        }

        let x = URL_SAFE_NO_PAD.decode(self.x.as_bytes()).map_err(|error| {
            Error::Jwt(JwtError::processing(
                JwtOperation::Validate,
                format!("invalid base64url `x` coordinate in JWKS key: {error}"),
            ))
        })?;
        let y = URL_SAFE_NO_PAD.decode(self.y.as_bytes()).map_err(|error| {
            Error::Jwt(JwtError::processing(
                JwtOperation::Validate,
                format!("invalid base64url `y` coordinate in JWKS key: {error}"),
            ))
        })?;
        if x.len() != 48 || y.len() != 48 {
            return Err(Error::Jwt(JwtError::processing(
                JwtOperation::Validate,
                "JWKS ES384 coordinates must be 48 bytes each",
            )));
        }

        Ok(())
    }

    /// Convert this JWK into a `jsonwebtoken` decoding key.
    ///
    /// # Errors
    ///
    /// Returns an error when the key is invalid or not ES384-compatible.
    pub fn to_decoding_key(&self) -> Result<DecodingKey> {
        self.validate()?;

        let jwk = self.to_jsonwebtoken_jwk();
        DecodingKey::from_jwk(&jwk).map_err(|error| {
            Error::Jwt(JwtError::processing(
                JwtOperation::Decode,
                format!(
                    "failed to convert JWKS key `{}` into decoding key: {error}",
                    self.kid
                ),
            ))
        })
    }

    fn to_jsonwebtoken_jwk(&self) -> Jwk {
        Jwk {
            common: CommonParameters {
                public_key_use: Some(PublicKeyUse::Signature),
                key_algorithm: Some(KeyAlgorithm::ES384),
                key_id: Some(self.kid.clone()),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve: EllipticCurve::P384,
                x: self.x.clone(),
                y: self.y.clone(),
            }),
        }
    }
}

/// Builds a deterministic key identifier for a PEM-encoded ES384 public key.
///
/// The resulting value is stable for the same public key bytes.
///
/// # Errors
///
/// Returns an error if the key cannot be parsed as a P-384 public key.
pub fn es384_kid_from_public_key_pem(public_key_pem: &[u8]) -> Result<String> {
    let digest_source = match p384::PublicKey::from_public_key_pem(
        std::str::from_utf8(public_key_pem).map_err(|error| {
            Error::Jwt(JwtError::processing(
                JwtOperation::Validate,
                format!("invalid UTF-8 in ES384 public PEM: {error}"),
            ))
        })?,
    ) {
        Ok(public_key) => EncodedPoint::from(public_key).as_bytes().to_vec(),
        Err(_) => DecodingKey::from_ec_pem(public_key_pem)
            .map(|key| key.as_bytes().to_vec())
            .map_err(|error| {
                Error::Jwt(JwtError::processing(
                    JwtOperation::Validate,
                    format!("failed to parse ES384 public PEM for kid derivation: {error}"),
                ))
            })?,
    };

    let digest = sha2::Sha256::digest(digest_source);
    Ok(format!("es384-{}", URL_SAFE_NO_PAD.encode(digest)))
}

use sha2::Digest as _;

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ES384_PUBLIC_KEY_PEM: &[u8] = br#"-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEsjQ/XkOUJO2bXkhDzKRMW1SXp0VsMqGx
MSTG+tppqd3gOxbM8vLgWy4/B0Qdest0Gy3E8QgaKJXQV3zRczNd9zrk1dmwVl6u
Yd+JfgNIeIFP6HWeu/C3wIJ60WDBuGY1
-----END PUBLIC KEY-----
"#;

    #[test]
    fn jwk_from_public_pem_round_trips_with_decoding_key() {
        let jwk = match EcP384Jwk::from_public_key_pem("test-kid", TEST_ES384_PUBLIC_KEY_PEM) {
            Ok(jwk) => jwk,
            Err(error) => panic!("jwk conversion should succeed: {error}"),
        };

        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, "P-384");
        assert_eq!(jwk.alg, "ES384");
        assert_eq!(jwk.use_, "sig");
        assert_eq!(jwk.kid, "test-kid");

        let key = match jwk.to_decoding_key() {
            Ok(key) => key,
            Err(error) => panic!("decoding key conversion should succeed: {error}"),
        };
        assert!(!key.as_bytes().is_empty());

        let serialized = match serde_json::to_string(&JwksDocument {
            keys: vec![jwk.clone()],
        }) {
            Ok(serialized) => serialized,
            Err(error) => panic!("jwks serialization should succeed: {error}"),
        };
        let deserialized: JwksDocument = match serde_json::from_str(&serialized) {
            Ok(deserialized) => deserialized,
            Err(error) => panic!("jwks deserialization should succeed: {error}"),
        };
        assert_eq!(deserialized.keys[0], jwk);
    }

    #[test]
    fn jwk_validation_rejects_non_es384_fields() {
        let mut jwk = match EcP384Jwk::from_public_key_pem("test-kid", TEST_ES384_PUBLIC_KEY_PEM) {
            Ok(jwk) => jwk,
            Err(error) => panic!("jwk conversion should succeed: {error}"),
        };
        jwk.alg = "ES256".to_string();
        assert!(jwk.validate().is_err());

        let mut jwk = match EcP384Jwk::from_public_key_pem("test-kid", TEST_ES384_PUBLIC_KEY_PEM) {
            Ok(jwk) => jwk,
            Err(error) => panic!("jwk conversion should succeed: {error}"),
        };
        jwk.crv = "P-256".to_string();
        assert!(jwk.validate().is_err());
    }

    #[test]
    fn provider_builds_document_and_exposes_kid() {
        let provider = match JwksProvider::from_es384_public_pem(TEST_ES384_PUBLIC_KEY_PEM) {
            Ok(provider) => provider,
            Err(error) => panic!("provider creation should succeed: {error}"),
        };

        assert_eq!(provider.document().keys.len(), 1);
        assert!(provider.key_id().is_some());
    }
}
