#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
/*!
# webgates-codecs

Framework-agnostic JWT codecs and validation helpers for the webgates ecosystem.

This crate provides:

- The [`Codec`] trait for pluggable payload encoding and decoding
- Structured codec and JWT error types
- JWT claim types and a JWT codec in [`jwt`]
- JWT validation helpers re-exported through [`jwt`]

The crate depends only on shared core types from `webgates-core` and does not
include HTTP, cookie, or framework-specific integration concerns.
*/

use serde::{Serialize, de::DeserializeOwned};

pub mod errors;
pub mod jwt;

pub use jsonwebtoken;

use errors::{CodecsError, JwtError};

/// Result type used by codec implementations.
pub type Result<T> = std::result::Result<T, Error>;

/// Root error type for this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Codec/serialization category errors.
    #[error(transparent)]
    Codecs(#[from] CodecsError),

    /// JWT processing category errors.
    #[error(transparent)]
    Jwt(#[from] JwtError),
}

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
    /// - Fully validate integrity/authenticity before returning
    /// - Reject malformed or tampered data with an appropriate error
    fn decode(&self, encoded_value: &[u8]) -> Result<Self::Payload>;
}
