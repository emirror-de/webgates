//! JWT and token encoding/decoding infrastructure.
//!
//! This module provides the [`Codec`] trait for pluggable token encoding/decoding and
//! a complete JWT implementation via the [`jwt`] submodule. The codec system allows
//! axum-gate to work with different token formats while maintaining type safety.
//!
//! # JWT Implementation
//!
//! The primary implementation is [`jwt::JsonWebToken`], which provides secure JWT
//! encoding/decoding with customizable keys and validation:
//!
//! ```rust
//! use axum_gate::codecs::jwt::{JsonWebToken, JwtClaims, JsonWebTokenOptions};
//! use axum_gate::accounts::Account;
//! use axum_gate::prelude::{Role, Group};
//! use std::sync::Arc;
//!
//! // Use default (random key - development only)
//! let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//!
//! // Production: use persistent key
//! let options = JsonWebTokenOptions {
//!     enc_key: jsonwebtoken::EncodingKey::from_secret(b"your-secret-key"),
//!     dec_key: jsonwebtoken::DecodingKey::from_secret(b"your-secret-key"),
//!     header: None,
//!     validation: None,
//! };
//! let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::new_with_options(options));
//! ```
//!
//! # Custom Codec Implementation
//!
//! Implement the [`Codec`] trait for custom token formats:
//!
//! ```rust
//! use axum_gate::codecs::Codec;
//! use axum_gate::errors::Result;
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Clone)]
//! struct CustomCodec {
//!     secret: String,
//! }
//!
//! #[derive(Serialize, Deserialize)]
//! struct CustomPayload {
//!     data: String,
//! }
//!
//! impl Codec for CustomCodec {
//!     type Payload = CustomPayload;
//!
//!     fn encode(&self, payload: &Self::Payload) -> Result<Vec<u8>> {
//!         // Your encoding implementation
//!         # Ok(vec![])
//!     }
//!
//!     fn decode(&self, encoded: &[u8]) -> Result<Self::Payload> {
//!         // Your decoding implementation
//!         # Ok(CustomPayload { data: "".to_string() })
//!     }
//! }
//! ```
//!
//! # Security Requirements
//!
//! Codec implementations must:
//! - Validate integrity/authenticity in `decode` (verify signatures/MACs)
//! - Use secure key management practices
//! - Avoid leaking sensitive validation details in error messages
//! - Handle token expiration and validation consistently
use crate::errors::Result;
use serde::{Serialize, de::DeserializeOwned};

pub mod errors;
pub mod jwt;
pub use errors::{CodecOperation, CodecsError, JwtError, JwtOperation};

/// A pluggable payload encoder/decoder.
///
/// See the module-level documentation for detailed guidance and examples.
pub trait Codec
where
    Self: Clone,
    Self::Payload: Serialize + DeserializeOwned,
{
    /// Type of the payload being encoded/decoded.
    type Payload;

    /// Encode a payload into an opaque, implementation-defined byte vector.
    ///
    /// Implementations MUST:
    /// - Serialize + sign / encrypt (where applicable)
    /// - Return an error if encoding or cryptographic operations fail
    fn encode(&self, payload: &Self::Payload) -> Result<Vec<u8>>;

    /// Decode a previously encoded payload.
    ///
    /// Implementations MUST:
    /// - Fully validate integrity/authenticity (e.g. signature/MAC) before returning
    /// - Reject malformed or tampered data with an appropriate error
    fn decode(&self, encoded_value: &[u8]) -> Result<Self::Payload>;
}
