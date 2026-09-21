//! Sign ES384 JWTs and publish the matching JWKS document.
//!
//! [`JwtAuthority`] is the main entry point when you need to:
//! - sign JWTs with an ES384 private key
//! - publish the corresponding public key as a JWKS document
//!
//! It composes [`JsonWebToken`] and [`JwksProvider`] from a single pair of
//! PEM-encoded key bytes, ensuring the `kid` is always consistent between the
//! signing header and the published JWKS document.
//!
//! # Example
//!
//! ```rust
//! use webgates_codecs::jwt::authority::JwtAuthority;
//! use webgates_codecs::jwt::JwtClaims;
//! use webgates_codecs::jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER as JWT_CRYPTO_PROVIDER;
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
//! let _ = JWT_CRYPTO_PROVIDER.install_default();
//! let authority = JwtAuthority::<JwtClaims<()>>::from_es384_pem(PRIVATE_PEM, PUBLIC_PEM)
//!     .expect("valid ES384 key pair");
//!
//! // The kid is stable and shared between the codec and the JWKS provider.
//! assert_eq!(authority.key_id(), authority.jwks_provider().key_id().unwrap());
//! ```

use std::sync::Arc;

use crate::Result;
use crate::jwt::jwks::JwksProvider;
use crate::jwt::{JsonWebToken, JsonWebTokenOptions, generate_es384_key_pair_pem};

use serde::{Serialize, de::DeserializeOwned};

/// Authority bundle that owns an ES384 signing codec and a JWKS provider.
///
/// Construct this type once at startup with [`JwtAuthority::from_es384_pem`]
/// and share it across handlers with `Arc<JwtAuthority<P>>`.
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

    /// Loads or generates an authority bundle from a private key file path.
    ///
    /// The public key path is derived by appending `.pub` to the private key path.
    ///
    /// # Behavior
    ///
    /// - **Both files exist**: Loads keys from disk
    /// - **Neither file exists**: Generates fresh keys and saves both files
    /// - **Only one file exists**: Returns an error
    ///
    /// # Example
    ///
    /// ```rust
    /// use webgates_codecs::jwt::JwtClaims;
    /// use webgates_codecs::jwt::authority::JwtAuthority;
    ///
    /// # let unique = std::time::SystemTime::now()
    /// #     .duration_since(std::time::UNIX_EPOCH)?
    /// #     .as_nanos();
    /// # let temp_dir = std::env::temp_dir().join(format!("webgates-authority-reuse-docs-{unique}"));
    /// # std::fs::create_dir_all(&temp_dir)?;
    /// # let key_path = temp_dir.join("jwt.key");
    /// # let public_key_path = temp_dir.join("jwt.key.pub");
    /// # let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    /// // First run: generates and saves keys.
    /// let first = runtime.block_on(async {
    ///     JwtAuthority::<JwtClaims<()>>::from_private_key_path(&key_path).await
    /// })?;
    ///
    /// // Subsequent runs: reuses existing keys.
    /// let second = runtime.block_on(async {
    ///     JwtAuthority::<JwtClaims<()>>::from_private_key_path(&key_path).await
    /// })?;
    ///
    /// assert_eq!(first.key_id(), second.key_id());
    /// assert!(key_path.is_file());
    /// assert!(public_key_path.is_file());
    /// # let _ = std::fs::remove_file(&public_key_path);
    /// # let _ = std::fs::remove_file(&key_path);
    /// # let _ = std::fs::remove_dir_all(&temp_dir);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Production Use
    ///
    /// Perfect for auth servers that publish JWKS:
    ///
    /// ```rust
    /// use webgates_codecs::jwt::JwtClaims;
    /// use webgates_codecs::jwt::authority::JwtAuthority;
    ///
    /// # let unique = std::time::SystemTime::now()
    /// #     .duration_since(std::time::UNIX_EPOCH)?
    /// #     .as_nanos();
    /// # let temp_dir = std::env::temp_dir().join(format!("webgates-authority-server-docs-{unique}"));
    /// # std::fs::create_dir_all(&temp_dir)?;
    /// # let key_path = temp_dir.join("server.key");
    /// # let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    /// // Loads or generates keys.
    /// let authority = runtime.block_on(async {
    ///     JwtAuthority::<JwtClaims<()>>::from_private_key_path(&key_path).await
    /// })?;
    ///
    /// let signing_codec = authority.codec();
    /// let jwks_provider = authority.jwks_provider();
    /// assert_eq!(jwks_provider.document().keys.len(), 1);
    /// assert_eq!(authority.key_id(), jwks_provider.key_id().unwrap());
    ///
    /// # let _ = signing_codec;
    /// # let _ = std::fs::remove_file(temp_dir.join("server.key.pub"));
    /// # let _ = std::fs::remove_file(&key_path);
    /// # let _ = std::fs::remove_dir_all(&temp_dir);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Only one key file exists
    /// - Files cannot be read/written/created
    /// - Invalid key material is found
    pub async fn from_private_key_path(
        private_key_path: impl Into<std::path::PathBuf>,
    ) -> Result<Self> {
        let loader = crate::jwt::Es384KeyPairLoader::from_private_key_path(private_key_path);
        let key_pair = loader.initialize_if_required().await?;
        Self::from_es384_pem(key_pair.private_key_pem(), key_pair.public_key_pem())
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

    /// Generates a fresh ES384 key pair and builds an authority bundle.
    ///
    /// This is a convenience method for testing and development that combines
    /// [`JsonWebTokenOptions::generate_for_testing`] with [`Self::from_es384_pem`].
    ///
    /// Each call produces a unique key pair, making it perfect for:
    /// - Unit/integration tests that need isolated key material
    /// - Quick development setups without key management
    /// - Examples and prototypes
    ///
    /// # Example
    ///
    /// ```rust
    /// use webgates_codecs::jwt::JwtClaims;
    /// use webgates_codecs::jwt::authority::JwtAuthority;
    ///
    /// let authority = JwtAuthority::<JwtClaims<()>>::generate_for_testing()?;
    /// let codec = authority.codec();
    /// let jwks = authority.jwks_provider();
    /// assert_eq!(jwks.document().keys.len(), 1);
    /// assert_eq!(authority.key_id(), jwks.key_id().unwrap());
    /// # let _ = codec;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if key generation or authority construction fails.
    pub fn generate_for_testing() -> Result<Self> {
        let (private_key_pem, public_key_pem) = generate_es384_key_pair_pem()?;
        Self::from_es384_pem(&private_key_pem, &public_key_pem)
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
