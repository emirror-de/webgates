//! Auth-side authority bundle for ES384 JWT signing and JWKS publication.
//!
//! [`JwtAuthority`] is the single entry point for auth services that need to:
//! - Sign JWTs with an ES384 private key
//! - Publish the corresponding public key as a JWKS document
//!
//! It composes the existing [`JsonWebToken`] codec and [`JwksProvider`] from a
//! single pair of PEM-encoded key bytes, ensuring the `kid` is always consistent
//! between the signing header and the published JWKS document.
//!
//! # Example
//!
//! ```rust
//! use webgates_codecs::jwt::authority::JwtAuthority;
//! use webgates_codecs::jwt::JwtClaims;
//!
//! # const PRIVATE_PEM: &[u8] = br#"-----BEGIN PRIVATE KEY-----
//! # MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCFT7MfRqWZfNgVX/cH
//! # bxFTlPkBeCKqjsLkZXD/J3ZYHV1EtQksdrKtOzTr2hMs6pmhZANiAASyND9eQ5Qk
//! # 7ZteSEPMpExbVJenRWwyobExJMb62mmp3eA7Fszy8uBbLj8HRB16y3QbLcTxCBoo
//! # ldBXfNFzM133OuTV2bBWXq5h34l+A0h4gU/odZ678LfAgnrRYMG4ZjU=
//! # -----END PRIVATE KEY-----
//! # "#;
//! # const PUBLIC_PEM: &[u8] = br#"-----BEGIN PUBLIC KEY-----
//! # MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEsjQ/XkOUJO2bXkhDzKRMW1SXp0VsMqGx
//! # MSTG+tppqd3gOxbM8vLgWy4/B0Qdest0Gy3E8QgaKJXQV3zRczNd9zrk1dmwVl6u
//! # Yd+JfgNIeIFP6HWeu/C3wIJ60WDBuGY1
//! # -----END PUBLIC KEY-----
//! # "#;
//! let authority = JwtAuthority::<JwtClaims<()>>::from_es384_pem(PRIVATE_PEM, PUBLIC_PEM)
//!     .expect("valid ES384 key pair");
//!
//! // The kid is stable and shared between the codec and the JWKS provider.
//! assert_eq!(authority.key_id(), authority.jwks_provider().key_id().unwrap());
//! ```

use std::sync::Arc;

use crate::Result;
use crate::jwt::jwks::JwksProvider;
use crate::jwt::{JsonWebToken, JsonWebTokenOptions};

use serde::{Serialize, de::DeserializeOwned};

/// Auth-side authority bundle that owns an ES384 signing codec and a JWKS provider.
///
/// Construct once at startup with [`JwtAuthority::from_es384_pem`] and share via
/// `Arc<JwtAuthority<P>>` across handlers.
///
/// The `kid` embedded in every signed JWT header is guaranteed to match the `kid`
/// in the published JWKS document.
#[derive(Clone)]
pub struct JwtAuthority<P>
where
    P: Serialize + DeserializeOwned + Clone,
{
    codec: Arc<JsonWebToken<P>>,
    jwks_provider: JwksProvider,
    key_id: String,
}

impl<P> JwtAuthority<P>
where
    P: Serialize + DeserializeOwned + Clone,
{
    /// Build an authority bundle from PEM-encoded ES384 private and public keys.
    ///
    /// The `kid` is derived deterministically from the public key bytes so it is
    /// stable across restarts as long as the key pair does not change.
    ///
    /// # Errors
    ///
    /// Returns an error if either key cannot be parsed or the JWKS provider
    /// cannot be constructed from the public key.
    pub fn from_es384_pem(private_key_pem: &[u8], public_key_pem: &[u8]) -> Result<Self> {
        let options = JsonWebTokenOptions::from_es384_pem(private_key_pem, public_key_pem)?;
        let key_id = options.key_id().to_string();
        let jwks_provider =
            JwksProvider::from_es384_public_pem_with_kid(public_key_pem, key_id.clone())?;
        let codec = Arc::new(JsonWebToken::new_with_options(options));
        Ok(Self {
            codec,
            jwks_provider,
            key_id,
        })
    }

    /// Returns the signing codec.
    ///
    /// Use this to encode JWTs in login handlers.
    pub fn codec(&self) -> Arc<JsonWebToken<P>> {
        Arc::clone(&self.codec)
    }

    /// Returns the JWKS provider.
    ///
    /// Pass this to the JWKS publication route handler.
    pub fn jwks_provider(&self) -> &JwksProvider {
        &self.jwks_provider
    }

    /// Returns the active signing key id (`kid`).
    ///
    /// This value is identical to the `kid` in the published JWKS document.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl<P> std::fmt::Debug for JwtAuthority<P>
where
    P: Serialize + DeserializeOwned + Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtAuthority")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::Codec as _;
    use crate::jwt::{JwtClaims, RegisteredClaims};

    const PRIVATE_PEM: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCFT7MfRqWZfNgVX/cH
bxFTlPkBeCKqjsLkZXD/J3ZYHV1EtQksdrKtOzTr2hMs6pmhZANiAASyND9eQ5Qk
7ZteSEPMpExbVJenRWwyobExJMb62mmp3eA7Fszy8uBbLj8HRB16y3QbLcTxCBoo
ldBXfNFzM133OuTV2bBWXq5h34l+A0h4gU/odZ678LfAgnrRYMG4ZjU=
-----END PRIVATE KEY-----
"#;

    const PUBLIC_PEM: &[u8] = br#"-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEsjQ/XkOUJO2bXkhDzKRMW1SXp0VsMqGx
MSTG+tppqd3gOxbM8vLgWy4/B0Qdest0Gy3E8QgaKJXQV3zRczNd9zrk1dmwVl6u
Yd+JfgNIeIFP6HWeu/C3wIJ60WDBuGY1
-----END PUBLIC KEY-----
"#;

    #[test]
    fn authority_builds_from_es384_pem() {
        let authority = JwtAuthority::<JwtClaims<()>>::from_es384_pem(PRIVATE_PEM, PUBLIC_PEM)
            .expect("authority should be created from valid ES384 PEM");

        assert!(!authority.key_id().is_empty());
        assert_eq!(
            authority.key_id(),
            authority.jwks_provider().key_id().expect("kid must be set")
        );
        assert_eq!(authority.jwks_provider().document().keys.len(), 1);
    }

    #[test]
    fn authority_kid_is_stable_across_constructions() {
        let a1 = JwtAuthority::<JwtClaims<()>>::from_es384_pem(PRIVATE_PEM, PUBLIC_PEM)
            .expect("first construction");
        let a2 = JwtAuthority::<JwtClaims<()>>::from_es384_pem(PRIVATE_PEM, PUBLIC_PEM)
            .expect("second construction");

        assert_eq!(a1.key_id(), a2.key_id());
    }

    #[test]
    fn authority_codec_can_sign_and_verify() {
        use jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER as JWT_CRYPTO_PROVIDER;
        use webgates_core::accounts::Account;
        use webgates_core::groups::Group;
        use webgates_core::roles::Role;

        let _ = JWT_CRYPTO_PROVIDER.install_default();

        let authority = JwtAuthority::<JwtClaims<Account<Role, Group>>>::from_es384_pem(
            PRIVATE_PEM,
            PUBLIC_PEM,
        )
        .expect("authority should be created");

        let account = Account::<Role, Group>::new("test-user");
        let exp = chrono::Utc::now().timestamp() as u64 + 60;
        let claims = JwtClaims::new(account, RegisteredClaims::new("test-issuer", exp));

        let codec = authority.codec();
        let encoded = codec.encode(&claims).expect("encoding should succeed");
        let decoded = codec.decode(&encoded).expect("decoding should succeed");

        assert_eq!(decoded.registered_claims.issuer, "test-issuer");
    }
}
