//! Token primitives for session issuance and renewal.
//!
//! This module defines the framework-agnostic token boundary types used by the
//! sessions crate. It intentionally avoids HTTP and cookie concerns so login,
//! renewal, and logout workflows can compose these values in higher layers.

use crate::errors::TokenError;
use rand::{Rng, distr::Alphanumeric, rng};
use sha2::{Digest, Sha256};
use webgates_codecs::Codec;

/// Short-lived authentication token returned to clients after login or renewal.
///
/// The concrete auth-token format is owned by the issuing implementation
/// (for example a JWT), while this type provides a stable boundary for the
/// session domain.
///
/// # Examples
///
/// ```
/// use webgates_sessions::tokens::AuthToken;
///
/// let token = AuthToken::new("eyJhbGciOiJIUzI1NiJ9.payload.sig").unwrap();
/// assert_eq!(token.as_str(), "eyJhbGciOiJIUzI1NiJ9.payload.sig");
///
/// let raw = token.into_inner();
/// assert_eq!(raw, "eyJhbGciOiJIUzI1NiJ9.payload.sig");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthToken {
    value: String,
}

impl AuthToken {
    /// Creates a new auth token wrapper from a raw token string.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::InvalidTokenMaterial`] when `value` is empty or
    /// contains only whitespace.
    pub fn new(value: impl Into<String>) -> Result<Self, TokenError> {
        let value = value.into();

        if value.trim().is_empty() {
            return Err(TokenError::InvalidTokenMaterial);
        }

        Ok(Self { value })
    }

    /// Returns the raw auth token string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Consumes the wrapper and returns the raw auth token string.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.value
    }
}

/// Plaintext refresh token presented by a client.
///
/// Callers should treat this value as sensitive. Persistence layers are expected
/// to store only a derived hash rather than this plaintext value.
///
/// # Examples
///
/// ```
/// use webgates_sessions::tokens::RefreshTokenPlaintext;
///
/// let token = RefreshTokenPlaintext::new("a".repeat(64)).unwrap();
/// assert_eq!(token.as_str().len(), 64);
///
/// // Empty or whitespace-only strings are rejected.
/// assert!(RefreshTokenPlaintext::new("   ").is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshTokenPlaintext {
    value: String,
}

impl RefreshTokenPlaintext {
    /// Creates a new plaintext refresh token wrapper from a raw token string.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::InvalidTokenMaterial`] when `value` is empty or
    /// contains only whitespace.
    pub fn new(value: impl Into<String>) -> Result<Self, TokenError> {
        let value = value.into();

        if value.trim().is_empty() {
            return Err(TokenError::InvalidTokenMaterial);
        }

        Ok(Self { value })
    }

    /// Returns the raw plaintext refresh token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Consumes the wrapper and returns the raw plaintext refresh token.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.value
    }
}

/// Stable hashed representation of a refresh token suitable for persistence.
///
/// The hashing algorithm is intentionally abstracted away from this type so the
/// sessions domain can depend on the hash value without committing to a
/// particular implementation strategy here.
///
/// # Examples
///
/// ```
/// use webgates_sessions::tokens::RefreshTokenHash;
///
/// let hash = RefreshTokenHash::new("abc123def456").unwrap();
/// assert_eq!(hash.as_str(), "abc123def456");
///
/// // Empty strings are rejected.
/// assert!(RefreshTokenHash::new("").is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshTokenHash {
    value: String,
}

impl RefreshTokenHash {
    /// Creates a new hashed refresh-token wrapper.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::InvalidTokenMaterial`] when `value` is empty or
    /// contains only whitespace.
    pub fn new(value: impl Into<String>) -> Result<Self, TokenError> {
        let value = value.into();

        if value.trim().is_empty() {
            return Err(TokenError::InvalidTokenMaterial);
        }

        Ok(Self { value })
    }

    /// Returns the persisted hash representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Consumes the wrapper and returns the persisted hash representation.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.value
    }
}

/// Borrowed view of a refresh-token hash.
pub type RefreshTokenHashRef<'a> = &'a str;

/// Minimum length accepted by [`RefreshTokenLength::new`].
pub const MIN_REFRESH_TOKEN_LENGTH: usize = 32;

/// Default length used by [`OpaqueRefreshTokenGenerator::default`].
pub const DEFAULT_REFRESH_TOKEN_LENGTH: usize = 64;

/// Validated refresh-token length used by [`OpaqueRefreshTokenGenerator`].
///
/// # Examples
///
/// ```
/// use webgates_sessions::tokens::{RefreshTokenLength, MIN_REFRESH_TOKEN_LENGTH};
///
/// let length = RefreshTokenLength::new(64).unwrap();
/// assert_eq!(length.get(), 64);
///
/// // Values shorter than the minimum are rejected.
/// assert!(RefreshTokenLength::new(MIN_REFRESH_TOKEN_LENGTH - 1).is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RefreshTokenLength(usize);

impl RefreshTokenLength {
    /// Creates a validated refresh-token length.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::InvalidRefreshTokenLength`] when `value` is shorter
    /// than [`MIN_REFRESH_TOKEN_LENGTH`].
    pub fn new(value: usize) -> Result<Self, TokenError> {
        if value < MIN_REFRESH_TOKEN_LENGTH {
            return Err(TokenError::InvalidRefreshTokenLength);
        }

        Ok(Self(value))
    }

    /// Returns the configured token length.
    #[must_use]
    pub fn get(self) -> usize {
        self.0
    }
}

impl Default for RefreshTokenLength {
    fn default() -> Self {
        Self(DEFAULT_REFRESH_TOKEN_LENGTH)
    }
}

/// Concrete refresh-token generator that emits opaque random token strings.
///
/// The generated tokens are intentionally high-entropy, framework-agnostic
/// values that can be returned to clients and later transformed into a
/// deterministic persisted fingerprint.
///
/// # Examples
///
/// ```
/// use webgates_sessions::tokens::{
///     OpaqueRefreshTokenGenerator, RefreshTokenGenerator, RefreshTokenLength,
/// };
///
/// # tokio_test::block_on(async {
/// let length = RefreshTokenLength::new(64).unwrap();
/// let generator = OpaqueRefreshTokenGenerator::new(length);
/// let token = generator.generate_refresh_token().await.unwrap();
///
/// assert_eq!(token.as_str().len(), 64);
/// # });
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpaqueRefreshTokenGenerator {
    length: RefreshTokenLength,
}

impl OpaqueRefreshTokenGenerator {
    /// Creates a generator with the provided token length.
    #[must_use]
    pub fn new(length: RefreshTokenLength) -> Self {
        Self { length }
    }

    /// Returns the configured plaintext token length.
    #[must_use]
    pub fn length(&self) -> RefreshTokenLength {
        self.length
    }
}

impl Default for OpaqueRefreshTokenGenerator {
    fn default() -> Self {
        Self::new(RefreshTokenLength::default())
    }
}

impl RefreshTokenGenerator for OpaqueRefreshTokenGenerator {
    type Error = TokenError;

    fn generate_refresh_token(
        &self,
    ) -> impl std::future::Future<Output = Result<RefreshTokenPlaintext, Self::Error>> + Send {
        let length = self.length.get();

        async move {
            let value: String = rng()
                .sample_iter(&Alphanumeric)
                .take(length)
                .map(char::from)
                .collect();

            RefreshTokenPlaintext::new(value)
        }
    }
}

/// Deterministic SHA-256 refresh-token hasher suitable for indexed lookups.
///
/// Unlike password hashing, refresh-token persistence in this crate needs a
/// stable lookup key so repositories can locate session state by presented
/// token material. This hasher therefore fingerprints only opaque,
/// high-entropy random refresh tokens and must not be reused for user-chosen
/// secrets such as passwords.
///
/// # Examples
///
/// ```
/// use webgates_sessions::tokens::{
///     RefreshTokenHasher, RefreshTokenPlaintext, Sha256RefreshTokenHasher,
/// };
///
/// # tokio_test::block_on(async {
/// let token = RefreshTokenPlaintext::new("a".repeat(64)).unwrap();
/// let hasher = Sha256RefreshTokenHasher;
/// let hash = hasher.hash_refresh_token(&token).await.unwrap();
///
/// // The same plaintext always produces the same hash.
/// let hash2 = hasher.hash_refresh_token(&token).await.unwrap();
/// assert_eq!(hash, hash2);
/// # });
/// ```
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Sha256RefreshTokenHasher;

impl RefreshTokenHasher for Sha256RefreshTokenHasher {
    type Error = TokenError;

    fn hash_refresh_token(
        &self,
        refresh_token: &RefreshTokenPlaintext,
    ) -> impl std::future::Future<Output = Result<RefreshTokenHash, Self::Error>> + Send {
        let bytes = refresh_token.as_str().as_bytes().to_owned();

        async move {
            let digest = Sha256::digest(&bytes);
            let mut encoded = String::with_capacity(digest.len() * 2);

            for byte in digest {
                use std::fmt::Write as _;

                write!(&mut encoded, "{byte:02x}").map_err(|_| TokenError::HashFailed)?;
            }

            RefreshTokenHash::new(encoded).map_err(|_| TokenError::HashFailed)
        }
    }
}

/// Full token material produced by a login or renewal issuance step.
///
/// This output keeps the client-facing token pair alongside the persisted
/// refresh-token hash that repositories need for lookup and rotation.
///
/// # Examples
///
/// ```
/// use webgates_sessions::tokens::{
///     AuthToken, IssuedSessionTokens, IssuedTokenPair, RefreshTokenHash,
///     RefreshTokenPlaintext,
/// };
///
/// let auth = AuthToken::new("eyJhbGciOiJIUzI1NiJ9.payload.sig").unwrap();
/// let refresh = RefreshTokenPlaintext::new("a".repeat(64)).unwrap();
/// let hash = RefreshTokenHash::new("abc123def456").unwrap();
/// let pair = IssuedTokenPair::new(auth, refresh);
/// let issued = IssuedSessionTokens::new(pair, hash.clone());
///
/// assert_eq!(issued.refresh_token_hash, hash);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedSessionTokens {
    /// Newly issued client-facing auth and refresh tokens.
    pub token_pair: IssuedTokenPair,
    /// Deterministic persisted fingerprint for the refresh token.
    pub refresh_token_hash: RefreshTokenHash,
}

impl IssuedSessionTokens {
    /// Creates a new issuance result from a token pair and persisted hash.
    #[must_use]
    pub fn new(token_pair: IssuedTokenPair, refresh_token_hash: RefreshTokenHash) -> Self {
        Self {
            token_pair,
            refresh_token_hash,
        }
    }
}

/// Auth and refresh tokens issued together for a session lifecycle step.
///
/// # Examples
///
/// ```
/// use webgates_sessions::tokens::{AuthToken, IssuedTokenPair, RefreshTokenPlaintext};
///
/// let auth = AuthToken::new("eyJhbGciOiJIUzI1NiJ9.payload.sig").unwrap();
/// let refresh = RefreshTokenPlaintext::new("a".repeat(64)).unwrap();
/// let pair = IssuedTokenPair::new(auth.clone(), refresh.clone());
///
/// assert_eq!(pair.auth_token, auth);
/// assert_eq!(pair.refresh_token, refresh);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedTokenPair {
    /// Newly issued short-lived auth token.
    pub auth_token: AuthToken,
    /// Newly issued long-lived refresh token.
    pub refresh_token: RefreshTokenPlaintext,
}

impl IssuedTokenPair {
    /// Creates a token pair from its component values.
    #[must_use]
    pub fn new(auth_token: AuthToken, refresh_token: RefreshTokenPlaintext) -> Self {
        Self {
            auth_token,
            refresh_token,
        }
    }
}

/// Framework-agnostic abstraction for issuing auth tokens for a session subject.
///
/// Implementations return a `Send` future so callers can compose issuance into
/// end-to-end async workflows on multi-threaded runtimes. Purely synchronous
/// implementations may wrap their result in `std::future::ready`.
pub trait AuthTokenIssuer<Subject>: Send + Sync {
    /// Error type returned when token issuance fails.
    type Error;

    /// Issues a new auth token for the provided subject.
    fn issue_auth_token(
        &self,
        subject: &Subject,
    ) -> impl std::future::Future<Output = Result<AuthToken, Self::Error>> + Send;
}

/// Framework-agnostic abstraction for generating opaque refresh tokens.
///
/// Implementations return a `Send` future so generation can be delegated to an
/// async-capable entropy or key-derivation backend without blocking the runtime.
/// Purely synchronous implementations may wrap their result in
/// `std::future::ready`.
pub trait RefreshTokenGenerator: Send + Sync {
    /// Error type returned when refresh-token generation fails.
    type Error;

    /// Generates a new plaintext refresh token.
    fn generate_refresh_token(
        &self,
    ) -> impl std::future::Future<Output = Result<RefreshTokenPlaintext, Self::Error>> + Send;
}

/// Framework-agnostic abstraction for hashing refresh tokens before storage.
///
/// Implementations return a `Send` future so hashing can be offloaded to an
/// async-capable backend without blocking the runtime. Purely synchronous
/// implementations may wrap their result in `std::future::ready`.
pub trait RefreshTokenHasher: Send + Sync {
    /// Error type returned when hashing fails.
    type Error;

    /// Hashes a plaintext refresh token into a stable persisted representation.
    fn hash_refresh_token(
        &self,
        refresh_token: &RefreshTokenPlaintext,
    ) -> impl std::future::Future<Output = Result<RefreshTokenHash, Self::Error>> + Send;
}

/// Auth-token issuer backed by a `webgates-codecs` payload codec.
///
/// Callers provide a claims factory so this issuer can stay generic over both
/// the subject type and the encoded claim shape.
///
/// # Examples
///
/// ```
/// use webgates_codecs::jwt::{JsonWebToken, JwtClaims, RegisteredClaims};
/// use webgates_sessions::tokens::{AuthTokenIssuer, CodecAuthTokenIssuer};
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Debug, Clone, Serialize, Deserialize)]
/// struct MyClaims {
///     sub: String,
/// }
///
/// // Install a crypto provider required by jsonwebtoken before using the codec.
/// webgates_codecs::jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER
///     .install_default()
///     .ok();
///
/// let codec = JsonWebToken::<JwtClaims<MyClaims>>::default();
/// let issuer = CodecAuthTokenIssuer::new(codec, |subject: &String| {
///     JwtClaims::new(
///         MyClaims { sub: subject.clone() },
///         RegisteredClaims::new("my-service", 4_102_444_800),
///     )
/// });
///
/// # tokio_test::block_on(async {
/// let token = issuer.issue_auth_token(&String::from("user-42")).await.unwrap();
/// assert!(!token.as_str().is_empty());
/// # });
/// ```
#[derive(Clone)]
pub struct CodecAuthTokenIssuer<C, F> {
    codec: C,
    claims_factory: F,
}

impl<C, F> CodecAuthTokenIssuer<C, F> {
    /// Creates a new codec-backed auth-token issuer.
    #[must_use]
    pub fn new(codec: C, claims_factory: F) -> Self {
        Self {
            codec,
            claims_factory,
        }
    }
}

impl<Subject, Claims, C, F> AuthTokenIssuer<Subject> for CodecAuthTokenIssuer<C, F>
where
    C: Codec<Payload = Claims> + Send + Sync,
    F: Fn(&Subject) -> Claims + Send + Sync,
    Subject: Send + Sync,
    Claims: Send + Sync,
{
    type Error = TokenError;

    fn issue_auth_token(
        &self,
        subject: &Subject,
    ) -> impl std::future::Future<Output = Result<AuthToken, Self::Error>> + Send {
        let claims = (self.claims_factory)(subject);
        let result = self
            .codec
            .encode(&claims)
            .map_err(|_| TokenError::AuthIssuanceFailed)
            .and_then(|encoded| {
                String::from_utf8(encoded).map_err(|_| TokenError::AuthIssuanceFailed)
            })
            .and_then(|token| AuthToken::new(token).map_err(|_| TokenError::AuthIssuanceFailed));

        std::future::ready(result)
    }
}

/// Cohesive token-pair issuance workflow for login and renewal services.
///
/// This type combines auth-token issuance, refresh-token generation, and
/// persisted refresh-token hashing behind one deterministic boundary.
///
/// # Examples
///
/// ```
/// use webgates_sessions::tokens::{
///     AuthToken, AuthTokenIssuer, OpaqueRefreshTokenGenerator, RefreshTokenGenerator,
///     RefreshTokenLength, Sha256RefreshTokenHasher, TokenPairIssuer,
/// };
///
/// #[derive(Debug, Clone, Copy)]
/// struct PrefixAuthTokenIssuer;
///
/// impl AuthTokenIssuer<String> for PrefixAuthTokenIssuer {
///     type Error = webgates_sessions::errors::TokenError;
///
///     fn issue_auth_token(
///         &self,
///         subject: &String,
///     ) -> impl std::future::Future<Output = Result<AuthToken, Self::Error>> + Send {
///         std::future::ready(AuthToken::new(format!("auth-{subject}")))
///     }
/// }
///
/// # tokio_test::block_on(async {
/// let length = RefreshTokenLength::new(64).unwrap();
/// let issuer = TokenPairIssuer::new(
///     PrefixAuthTokenIssuer,
///     OpaqueRefreshTokenGenerator::new(length),
///     Sha256RefreshTokenHasher,
/// );
///
/// let subject = String::from("user-42");
/// let issued = issuer.issue_for_subject(&subject).await.unwrap();
/// assert_eq!(issued.token_pair.auth_token.as_str(), "auth-user-42");
/// assert_eq!(issued.token_pair.refresh_token.as_str().len(), 64);
/// # });
/// ```
#[derive(Debug, Clone)]
pub struct TokenPairIssuer<A, G, H> {
    auth_token_issuer: A,
    refresh_token_generator: G,
    refresh_token_hasher: H,
}

impl<A, G, H> TokenPairIssuer<A, G, H> {
    /// Creates a new token-pair issuer from its component services.
    #[must_use]
    pub fn new(auth_token_issuer: A, refresh_token_generator: G, refresh_token_hasher: H) -> Self {
        Self {
            auth_token_issuer,
            refresh_token_generator,
            refresh_token_hasher,
        }
    }
}

impl<A, G, H> TokenPairIssuer<A, G, H> {
    /// Hashes an existing plaintext refresh token using the configured hasher.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::HashFailed`] when the configured refresh-token
    /// hasher cannot produce a persisted fingerprint.
    pub async fn hash_refresh_token(
        &self,
        refresh_token: &RefreshTokenPlaintext,
    ) -> Result<RefreshTokenHash, TokenError>
    where
        H: RefreshTokenHasher,
    {
        self.refresh_token_hasher
            .hash_refresh_token(refresh_token)
            .await
            .map_err(|_| TokenError::HashFailed)
    }

    /// Issues an auth token, refresh token, and persisted refresh-token hash.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::AuthIssuanceFailed`],
    /// [`TokenError::GenerationFailed`], or [`TokenError::HashFailed`] when one
    /// of the underlying issuance steps fails.
    pub async fn issue_for_subject<Subject>(
        &self,
        subject: &Subject,
    ) -> Result<IssuedSessionTokens, TokenError>
    where
        A: AuthTokenIssuer<Subject>,
        G: RefreshTokenGenerator,
        H: RefreshTokenHasher,
    {
        let auth_token = self
            .auth_token_issuer
            .issue_auth_token(subject)
            .await
            .map_err(|_| TokenError::AuthIssuanceFailed)?;
        let refresh_token = self
            .refresh_token_generator
            .generate_refresh_token()
            .await
            .map_err(|_| TokenError::GenerationFailed)?;
        let refresh_token_hash = self.hash_refresh_token(&refresh_token).await?;

        Ok(IssuedSessionTokens::new(
            IssuedTokenPair::new(auth_token, refresh_token),
            refresh_token_hash,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use webgates_codecs::jwt::{JsonWebToken, JwtClaims, RegisteredClaims};
    use webgates_codecs::{Codec, jsonwebtoken};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct TestClaims {
        session_id: String,
    }

    #[derive(Debug, Clone, Copy)]
    struct StaticAuthTokenIssuer;

    impl AuthTokenIssuer<String> for StaticAuthTokenIssuer {
        type Error = TokenError;

        fn issue_auth_token(
            &self,
            subject: &String,
        ) -> impl std::future::Future<Output = Result<AuthToken, Self::Error>> + Send {
            std::future::ready(AuthToken::new(format!("auth-{subject}")))
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct StaticRefreshTokenGenerator;

    impl RefreshTokenGenerator for StaticRefreshTokenGenerator {
        type Error = TokenError;

        fn generate_refresh_token(
            &self,
        ) -> impl std::future::Future<Output = Result<RefreshTokenPlaintext, Self::Error>> + Send
        {
            std::future::ready(RefreshTokenPlaintext::new("fixed-refresh-token"))
        }
    }

    #[test]
    fn auth_token_rejects_empty_value() {
        let error = match AuthToken::new("   ") {
            Ok(token) => panic!("expected invalid auth token, got {}", token.as_str()),
            Err(error) => error,
        };

        assert_eq!(error, TokenError::InvalidTokenMaterial);
    }

    #[test]
    fn refresh_token_plaintext_rejects_empty_value() {
        let error = match RefreshTokenPlaintext::new("") {
            Ok(token) => panic!("expected invalid refresh token, got {}", token.as_str()),
            Err(error) => error,
        };

        assert_eq!(error, TokenError::InvalidTokenMaterial);
    }

    #[test]
    fn refresh_token_hash_rejects_empty_value() {
        let error = match RefreshTokenHash::new(" ") {
            Ok(hash) => panic!("expected invalid refresh token hash, got {}", hash.as_str()),
            Err(error) => error,
        };

        assert_eq!(error, TokenError::InvalidTokenMaterial);
    }

    #[test]
    fn refresh_token_length_rejects_short_values() {
        let error = match RefreshTokenLength::new(MIN_REFRESH_TOKEN_LENGTH - 1) {
            Ok(length) => panic!("expected invalid length, got {}", length.get()),
            Err(error) => error,
        };

        assert_eq!(error, TokenError::InvalidRefreshTokenLength);
    }

    #[test]
    fn issued_token_pair_keeps_both_tokens() {
        let auth_token = match AuthToken::new("auth-token") {
            Ok(token) => token,
            Err(error) => panic!("expected valid auth token: {error}"),
        };
        let refresh_token = match RefreshTokenPlaintext::new("refresh-token") {
            Ok(token) => token,
            Err(error) => panic!("expected valid refresh token: {error}"),
        };

        let pair = IssuedTokenPair::new(auth_token.clone(), refresh_token.clone());

        assert_eq!(pair.auth_token, auth_token);
        assert_eq!(pair.refresh_token, refresh_token);
    }

    #[tokio::test]
    async fn opaque_refresh_token_generator_uses_requested_length() {
        let length = match RefreshTokenLength::new(48) {
            Ok(length) => length,
            Err(error) => panic!("expected valid refresh token length: {error}"),
        };
        let generator = OpaqueRefreshTokenGenerator::new(length);
        let token = match generator.generate_refresh_token().await {
            Ok(token) => token,
            Err(error) => panic!("expected generated refresh token: {error}"),
        };

        assert_eq!(token.as_str().len(), 48);
    }

    #[tokio::test]
    async fn sha256_refresh_token_hasher_is_deterministic() {
        let token = match RefreshTokenPlaintext::new("repeatable-refresh-token") {
            Ok(token) => token,
            Err(error) => panic!("expected valid refresh token: {error}"),
        };
        let hasher = Sha256RefreshTokenHasher;

        let first_hash = match hasher.hash_refresh_token(&token).await {
            Ok(hash) => hash,
            Err(error) => panic!("expected successful hash: {error}"),
        };
        let second_hash = match hasher.hash_refresh_token(&token).await {
            Ok(hash) => hash,
            Err(error) => panic!("expected successful hash: {error}"),
        };

        assert_eq!(first_hash, second_hash);
    }

    #[tokio::test]
    async fn codec_auth_token_issuer_encodes_claims_with_codec() {
        let _ = jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER.install_default();
        let codec = JsonWebToken::<JwtClaims<TestClaims>>::default();
        let issuer = CodecAuthTokenIssuer::new(codec.clone(), |subject: &String| {
            JwtClaims::new(
                TestClaims {
                    session_id: subject.clone(),
                },
                RegisteredClaims::new("tests", 4_102_444_800),
            )
        });
        let subject = String::from("session-123");

        let token = match issuer.issue_auth_token(&subject).await {
            Ok(token) => token,
            Err(error) => panic!("expected successful auth-token issuance: {error}"),
        };
        let decoded = match codec.decode(token.as_str().as_bytes()) {
            Ok(claims) => claims,
            Err(error) => panic!("expected decodable auth token: {error}"),
        };

        assert_eq!(decoded.custom_claims.session_id, subject);
    }

    #[tokio::test]
    async fn token_pair_issuer_returns_tokens_and_hash() {
        let issuer = TokenPairIssuer::new(
            StaticAuthTokenIssuer,
            StaticRefreshTokenGenerator,
            Sha256RefreshTokenHasher,
        );
        let subject = String::from("subject-123");

        let issued = match issuer.issue_for_subject(&subject).await {
            Ok(issued) => issued,
            Err(error) => panic!("expected successful token-pair issuance: {error}"),
        };
        let expected_hash = match Sha256RefreshTokenHasher
            .hash_refresh_token(&issued.token_pair.refresh_token)
            .await
        {
            Ok(hash) => hash,
            Err(error) => panic!("expected successful hash calculation: {error}"),
        };

        assert_eq!(issued.token_pair.auth_token.as_str(), "auth-subject-123");
        assert_eq!(issued.refresh_token_hash, expected_hash);
    }
}
