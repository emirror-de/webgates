//! Transport-agnostic remote JWKS verifier for consumer services.
//!
//! [`RemoteJwksVerifier`] fetches, caches, and refreshes a remote JWKS document
//! and exposes a [`RemoteJwksVerifier::verify_token`] method that both Axum and
//! Tonic integrations can depend on without duplicating fetch/cache/refresh logic.
//!
//! # Behavior
//!
//! - **Startup**: attempts a live JWKS fetch; falls back to a persistent cache if
//!   the fetch fails; fails closed (returns an error) when neither source provides
//!   valid ES384 keys.
//! - **Background refresh**: call [`RemoteJwksVerifier::start_background_refresh`]
//!   once after bootstrap to keep keys current.
//! - **Unknown-`kid` recovery**: on a first verification failure caused by an
//!   unknown `kid`, the verifier performs one bounded refresh before retrying.
//! - **Request-path verification**: all JWT validation is local; no per-request
//!   network I/O is performed.
//!
//! # Example
//!
//! ```rust,no_run
//! use webgates_codecs::jwt::remote_verifier::{RemoteJwksVerifier, RemoteJwksVerifierConfig};
//! use webgates_codecs::jwt::JwtClaims;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = RemoteJwksVerifierConfig::from_jwks_url(
//!     "https://auth.example.com/.well-known/jwks.json",
//! );
//! let verifier = RemoteJwksVerifier::<JwtClaims<()>>::bootstrap(config).await?;
//! let _refresh_handle = verifier.start_background_refresh();
//! # Ok(())
//! # }
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::Codec as _;
use crate::jwt::jwks::JwksDocument;
use crate::jwt::{JsonWebToken, JsonWebTokenOptions};

const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

type SharedVerifier<P> = Arc<RwLock<Option<Arc<JsonWebToken<P>>>>>;

/// Configuration for a [`RemoteJwksVerifier`].
#[derive(Clone, Debug)]
pub struct RemoteJwksVerifierConfig {
    /// URL of the remote JWKS endpoint.
    pub jwks_url: String,
    /// HTTP request timeout for JWKS fetches.
    pub http_timeout: Duration,
    /// Interval between background refresh attempts.
    pub refresh_interval: Duration,
    /// Optional path for persisting the JWKS document as a local cache.
    pub cache_path: Option<PathBuf>,
}

impl RemoteJwksVerifierConfig {
    /// Build a config from a JWKS URL with default timeout and refresh interval.
    pub fn from_jwks_url(jwks_url: impl Into<String>) -> Self {
        Self {
            jwks_url: jwks_url.into(),
            http_timeout: DEFAULT_HTTP_TIMEOUT,
            refresh_interval: DEFAULT_REFRESH_INTERVAL,
            cache_path: None,
        }
    }

    /// Override the HTTP request timeout.
    #[must_use]
    pub fn with_http_timeout(mut self, timeout: Duration) -> Self {
        self.http_timeout = timeout;
        self
    }

    /// Override the background refresh interval.
    #[must_use]
    pub fn with_refresh_interval(mut self, refresh_interval: Duration) -> Self {
        self.refresh_interval = refresh_interval;
        self
    }

    /// Enable a persistent local cache at the given path.
    #[must_use]
    pub fn with_cache_path(mut self, cache_path: impl Into<PathBuf>) -> Self {
        self.cache_path = Some(cache_path.into());
        self
    }
}

/// Errors produced by [`RemoteJwksVerifier`].
#[derive(thiserror::Error, Debug)]
pub enum RemoteJwksVerifierError {
    /// HTTP client construction failed.
    #[error("failed to build HTTP client: {0}")]
    HttpClientBuild(#[from] reqwest::Error),
    /// JWKS fetch failed.
    #[error("failed to fetch JWKS document from {url}: {message}")]
    Fetch {
        /// The URL that was fetched.
        url: String,
        /// The error message.
        message: String,
    },
    /// JWKS response could not be parsed.
    #[error("failed to parse JWKS response: {0}")]
    ParseResponse(String),
    /// No valid ES384 keys were found in the JWKS document.
    #[error("JWKS document did not contain any valid ES384 keys")]
    NoValidKeys,
    /// Cache write failed.
    #[error("failed to persist JWKS cache at {path}: {message}")]
    CacheWrite {
        /// The cache path.
        path: String,
        /// The error message.
        message: String,
    },
    /// Cache read failed.
    #[error("failed to read JWKS cache at {path}: {message}")]
    CacheRead {
        /// The cache path.
        path: String,
        /// The error message.
        message: String,
    },
    /// Token has no `kid` and no fallback key was available after refresh.
    #[error("missing JWT `kid` and refresh did not provide a fallback key")]
    MissingKidWithoutFallback,
    /// Token `kid` was not found even after a refresh.
    #[error("JWT key id `{kid}` not found after refresh")]
    UnknownKid {
        /// The unknown key id.
        kid: String,
    },
    /// Token verification failed.
    #[error("token verification failed: {0}")]
    Verify(String),
    /// Startup failed because no live or cached JWKS was available.
    #[error("startup failed because no live JWKS or cached JWKS was available")]
    StartupNoKeys,
}

/// Transport-agnostic remote JWKS verifier.
///
/// Clone-cheap: all state is behind `Arc`.
#[derive(Clone)]
pub struct RemoteJwksVerifier<P>
where
    P: Serialize + DeserializeOwned + Clone + Send + Sync + 'static,
{
    config: RemoteJwksVerifierConfig,
    client: Client,
    verifier: SharedVerifier<P>,
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
}

impl<P> RemoteJwksVerifier<P>
where
    P: Serialize + DeserializeOwned + Clone + Send + Sync + 'static,
{
    /// Bootstrap the verifier: attempt a live JWKS fetch, fall back to cache,
    /// fail closed when neither source provides valid ES384 keys.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteJwksVerifierError::StartupNoKeys`] when no keys are
    /// available from either the live endpoint or the persistent cache.
    pub async fn bootstrap(
        config: RemoteJwksVerifierConfig,
    ) -> Result<Self, RemoteJwksVerifierError> {
        let client = Client::builder().timeout(config.http_timeout).build()?;
        let verifier: SharedVerifier<P> = Arc::new(RwLock::new(None));

        let this = Self {
            config,
            client,
            verifier,
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
        };

        let mut has_cache = false;
        if let Some(cached) = this.load_cached_verifier().await? {
            *this.verifier.write().await = Some(cached);
            has_cache = true;
            tracing::warn!("starting with cached JWKS keys while attempting live refresh");
        }

        match this.refresh().await {
            Ok(()) => {}
            Err(error) if has_cache => {
                tracing::warn!(error = %error, "live JWKS refresh failed, continuing with cached keys");
            }
            Err(_) => return Err(RemoteJwksVerifierError::StartupNoKeys),
        }

        Ok(this)
    }

    /// Spawn a background task that refreshes the JWKS document on the configured interval.
    ///
    /// The returned [`JoinHandle`] should be kept alive for the lifetime of the service.
    /// Dropping it cancels the background refresh.
    pub fn start_background_refresh(&self) -> JoinHandle<()> {
        let refresh_interval = self.config.refresh_interval;
        let this = self.clone();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(refresh_interval);
            loop {
                ticker.tick().await;
                if let Err(error) = this.refresh().await {
                    tracing::warn!(error = %error, "background JWKS refresh failed");
                }
            }
        })
    }

    /// Perform a single JWKS refresh: fetch, parse, optionally persist, and swap in.
    ///
    /// # Errors
    ///
    /// Returns an error if the fetch, parse, or cache write fails.
    pub async fn refresh(&self) -> Result<(), RemoteJwksVerifierError> {
        let _lock = self.refresh_lock.lock().await;
        let jwks = self.fetch_jwks().await?;
        let codec = Arc::new(codec_from_jwks(&jwks)?);

        if let Some(cache_path) = &self.config.cache_path {
            persist_jwks_cache(cache_path, &jwks).await?;
        }

        *self.verifier.write().await = Some(codec);
        Ok(())
    }

    /// Verify a JWT token string against the current in-memory key set.
    ///
    /// On a first failure caused by an unknown `kid`, performs one bounded
    /// refresh before retrying. All verification is local; no per-request
    /// network I/O is performed on the happy path.
    ///
    /// # Errors
    ///
    /// Returns a [`RemoteJwksVerifierError`] when the token is invalid, the
    /// `kid` is unknown after refresh, or no keys are loaded.
    pub async fn verify_token(&self, token: &str) -> Result<P, RemoteJwksVerifierError> {
        match self.verify_once(token).await {
            Ok(claims) => Ok(claims),
            Err(RemoteJwksVerifierError::Verify(ref message))
                if message.contains("missing `kid`") || message.contains("not configured") =>
            {
                let message = message.clone();
                self.refresh().await?;
                match self.verify_once(token).await {
                    Ok(claims) => Ok(claims),
                    Err(RemoteJwksVerifierError::Verify(ref refreshed_message))
                        if refreshed_message.contains("missing `kid`") =>
                    {
                        Err(RemoteJwksVerifierError::MissingKidWithoutFallback)
                    }
                    Err(RemoteJwksVerifierError::Verify(ref refreshed_message)) => {
                        if let Some(kid) = kid_from_token_error(refreshed_message) {
                            Err(RemoteJwksVerifierError::UnknownKid { kid })
                        } else {
                            Err(RemoteJwksVerifierError::Verify(refreshed_message.clone()))
                        }
                    }
                    Err(error) => {
                        let _ = message;
                        Err(error)
                    }
                }
            }
            Err(error) => Err(error),
        }
    }

    async fn verify_once(&self, token: &str) -> Result<P, RemoteJwksVerifierError> {
        let verifier = self
            .verifier
            .read()
            .await
            .clone()
            .ok_or(RemoteJwksVerifierError::StartupNoKeys)?;
        verifier
            .decode(token.as_bytes())
            .map_err(|error: crate::Error| RemoteJwksVerifierError::Verify(error.to_string()))
    }

    async fn load_cached_verifier(
        &self,
    ) -> Result<Option<Arc<JsonWebToken<P>>>, RemoteJwksVerifierError> {
        let Some(cache_path) = &self.config.cache_path else {
            return Ok(None);
        };

        if !cache_path.exists() {
            return Ok(None);
        }

        let raw = tokio::fs::read_to_string(cache_path)
            .await
            .map_err(|error| RemoteJwksVerifierError::CacheRead {
                path: cache_path.display().to_string(),
                message: error.to_string(),
            })?;
        let jwks: JwksDocument = serde_json::from_str(&raw)
            .map_err(|error| RemoteJwksVerifierError::ParseResponse(error.to_string()))?;
        let codec = Arc::new(codec_from_jwks(&jwks)?);
        Ok(Some(codec))
    }

    async fn fetch_jwks(&self) -> Result<JwksDocument, RemoteJwksVerifierError> {
        let response = self
            .client
            .get(&self.config.jwks_url)
            .send()
            .await
            .map_err(|error| RemoteJwksVerifierError::Fetch {
                url: self.config.jwks_url.clone(),
                message: error.to_string(),
            })?;

        if !response.status().is_success() {
            return Err(RemoteJwksVerifierError::Fetch {
                url: self.config.jwks_url.clone(),
                message: format!("unexpected HTTP status {}", response.status()),
            });
        }

        response
            .json::<JwksDocument>()
            .await
            .map_err(|error| RemoteJwksVerifierError::ParseResponse(error.to_string()))
    }
}

fn kid_from_token_error(message: &str) -> Option<String> {
    let marker = "JWT `kid` `";
    let index = message.find(marker)? + marker.len();
    let rest = &message[index..];
    let end = rest.find('`')?;
    Some(rest[..end].to_string())
}

fn codec_from_jwks<P>(document: &JwksDocument) -> Result<JsonWebToken<P>, RemoteJwksVerifierError>
where
    P: Serialize + DeserializeOwned + Clone,
{
    let keys: Vec<_> = document
        .keys
        .iter()
        .filter(|key| {
            key.alg == "ES384" && key.crv == "P-384" && key.kty == "EC" && key.use_ == "sig"
        })
        .cloned()
        .collect();

    if keys.is_empty() {
        return Err(RemoteJwksVerifierError::NoValidKeys);
    }

    let options = JsonWebTokenOptions::for_es384_jwks_keys(&keys)
        .map_err(|error| RemoteJwksVerifierError::Verify(error.to_string()))?;
    Ok(JsonWebToken::new_with_options(options))
}

async fn persist_jwks_cache(
    cache_path: &PathBuf,
    jwks: &JwksDocument,
) -> Result<(), RemoteJwksVerifierError> {
    if let Some(parent) = cache_path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent).await.map_err(|error| {
            RemoteJwksVerifierError::CacheWrite {
                path: parent.display().to_string(),
                message: error.to_string(),
            }
        })?;
    }

    let raw = serde_json::to_string_pretty(jwks)
        .map_err(|error| RemoteJwksVerifierError::ParseResponse(error.to_string()))?;
    tokio::fs::write(cache_path, raw)
        .await
        .map_err(|error| RemoteJwksVerifierError::CacheWrite {
            path: cache_path.display().to_string(),
            message: error.to_string(),
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::jwt::jwks::EcP384Jwk;

    #[test]
    fn config_defaults_require_only_jwks_url() {
        let config = RemoteJwksVerifierConfig::from_jwks_url(
            "https://example.invalid/.well-known/jwks.json",
        );

        assert_eq!(
            config.jwks_url,
            "https://example.invalid/.well-known/jwks.json"
        );
        assert_eq!(config.http_timeout, Duration::from_secs(3));
        assert_eq!(config.refresh_interval, Duration::from_secs(60));
        assert!(config.cache_path.is_none());
    }

    #[test]
    fn jwks_document_rejects_empty_keys() {
        let document = JwksDocument { keys: vec![] };
        let result = codec_from_jwks::<crate::jwt::JwtClaims<()>>(&document);
        assert!(matches!(result, Err(RemoteJwksVerifierError::NoValidKeys)));
    }

    #[test]
    fn kid_parser_extracts_unknown_kid() {
        let message = "JWT `kid` `next-key` is not configured for verification";
        assert_eq!(kid_from_token_error(message).as_deref(), Some("next-key"));
    }

    #[test]
    fn codec_builds_from_valid_es384_jwks() {
        const TEST_ES384_PUBLIC_KEY_PEM: &[u8] = br#"-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEsjQ/XkOUJO2bXkhDzKRMW1SXp0VsMqGx
MSTG+tppqd3gOxbM8vLgWy4/B0Qdest0Gy3E8QgaKJXQV3zRczNd9zrk1dmwVl6u
Yd+JfgNIeIFP6HWeu/C3wIJ60WDBuGY1
-----END PUBLIC KEY-----
"#;

        let key = EcP384Jwk::from_public_key_pem("key-a", TEST_ES384_PUBLIC_KEY_PEM)
            .expect("jwk generation should succeed");
        let document = JwksDocument { keys: vec![key] };

        let codec = codec_from_jwks::<crate::jwt::JwtClaims<()>>(&document)
            .expect("codec should be created");
        assert_eq!(codec.verification_key_count(), 1);
    }
}
