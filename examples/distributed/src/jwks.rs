use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use webgates::accounts::Account;
use webgates::codecs::Codec;
use webgates::codecs::jwt::jwks::JwksDocument;
use webgates::codecs::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims};
use webgates::groups::Group;
use webgates::roles::Role;

type AppClaims = JwtClaims<Account<Role, Group>>;
type SharedVerifier = Arc<RwLock<Option<Arc<JsonWebToken<AppClaims>>>>>;

const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
pub struct JwksConsumerConfig {
    pub jwks_url: String,
    pub http_timeout: Duration,
    pub refresh_interval: Duration,
    pub cache_path: Option<PathBuf>,
}

impl JwksConsumerConfig {
    pub fn from_jwks_url(jwks_url: impl Into<String>) -> Self {
        Self {
            jwks_url: jwks_url.into(),
            http_timeout: DEFAULT_HTTP_TIMEOUT,
            refresh_interval: DEFAULT_REFRESH_INTERVAL,
            cache_path: None,
        }
    }

    pub fn with_http_timeout(mut self, timeout: Duration) -> Self {
        self.http_timeout = timeout;
        self
    }

    pub fn with_refresh_interval(mut self, refresh_interval: Duration) -> Self {
        self.refresh_interval = refresh_interval;
        self
    }

    pub fn with_cache_path(mut self, cache_path: impl Into<PathBuf>) -> Self {
        self.cache_path = Some(cache_path.into());
        self
    }
}

#[derive(thiserror::Error, Debug)]
pub enum JwksConsumerError {
    #[error("failed to build HTTP client: {0}")]
    HttpClientBuild(#[from] reqwest::Error),
    #[error("failed to fetch JWKS document from {url}: {message}")]
    Fetch { url: String, message: String },
    #[error("failed to parse JWKS response: {0}")]
    ParseResponse(String),
    #[error("JWKS document did not contain any valid ES384 keys")]
    NoValidKeys,
    #[error("failed to persist JWKS cache at {path}: {message}")]
    CacheWrite { path: String, message: String },
    #[error("failed to read JWKS cache at {path}: {message}")]
    CacheRead { path: String, message: String },
    #[error("missing JWT `kid` and refresh did not provide a fallback key")]
    MissingKidWithoutFallback,
    #[error("JWT key id `{kid}` not found after refresh")]
    UnknownKid { kid: String },
    #[error("token verification failed: {0}")]
    Verify(String),
    #[error("startup failed because no live JWKS or cached JWKS was available")]
    StartupNoKeys,
}

#[derive(Clone)]
pub struct JwksVerifier {
    config: JwksConsumerConfig,
    client: Client,
    verifier: SharedVerifier,
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
}

impl JwksVerifier {
    pub async fn bootstrap(config: JwksConsumerConfig) -> Result<Self, JwksConsumerError> {
        let client = Client::builder().timeout(config.http_timeout).build()?;
        let verifier = Arc::new(RwLock::new(None));

        let jwks_verifier = Self {
            config,
            client,
            verifier,
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
        };

        let mut has_cache = false;
        if let Some(cache) = jwks_verifier.load_cached_verifier().await? {
            *jwks_verifier.verifier.write().await = Some(cache);
            has_cache = true;
            tracing::warn!("starting with cached JWKS keys while attempting live refresh");
        }

        match jwks_verifier.refresh().await {
            Ok(()) => {}
            Err(error) if has_cache => {
                tracing::warn!(error = %error, "live JWKS refresh failed, continuing with cached keys");
            }
            Err(_) => return Err(JwksConsumerError::StartupNoKeys),
        }

        Ok(jwks_verifier)
    }

    pub fn start_background_refresh(&self) -> JoinHandle<()> {
        let refresh_interval = self.config.refresh_interval;
        let verifier = self.clone();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(refresh_interval);
            loop {
                ticker.tick().await;
                if let Err(error) = verifier.refresh().await {
                    tracing::warn!(error = %error, "background JWKS refresh failed");
                }
            }
        })
    }

    pub async fn refresh(&self) -> Result<(), JwksConsumerError> {
        let _lock = self.refresh_lock.lock().await;
        let jwks = self.fetch_jwks().await?;
        let codec = Arc::new(codec_from_jwks(&jwks)?);

        if let Some(cache_path) = &self.config.cache_path {
            persist_jwks_cache(cache_path, &jwks).await?;
        }

        *self.verifier.write().await = Some(codec);
        Ok(())
    }

    async fn load_cached_verifier(
        &self,
    ) -> Result<Option<Arc<JsonWebToken<AppClaims>>>, JwksConsumerError> {
        let Some(cache_path) = &self.config.cache_path else {
            return Ok(None);
        };

        if !cache_path.exists() {
            return Ok(None);
        }

        let raw = tokio::fs::read_to_string(cache_path)
            .await
            .map_err(|error| JwksConsumerError::CacheRead {
                path: cache_path.display().to_string(),
                message: error.to_string(),
            })?;
        let jwks: JwksDocument = serde_json::from_str(&raw)
            .map_err(|error| JwksConsumerError::ParseResponse(error.to_string()))?;
        let codec = Arc::new(codec_from_jwks(&jwks)?);
        Ok(Some(codec))
    }

    async fn fetch_jwks(&self) -> Result<JwksDocument, JwksConsumerError> {
        let response = self
            .client
            .get(&self.config.jwks_url)
            .send()
            .await
            .map_err(|error| JwksConsumerError::Fetch {
                url: self.config.jwks_url.clone(),
                message: error.to_string(),
            })?;

        if !response.status().is_success() {
            return Err(JwksConsumerError::Fetch {
                url: self.config.jwks_url.clone(),
                message: format!("unexpected HTTP status {}", response.status()),
            });
        }

        response
            .json::<JwksDocument>()
            .await
            .map_err(|error| JwksConsumerError::ParseResponse(error.to_string()))
    }

    async fn current_verifier(&self) -> Result<Arc<JsonWebToken<AppClaims>>, JwksConsumerError> {
        self.verifier
            .read()
            .await
            .clone()
            .ok_or(JwksConsumerError::StartupNoKeys)
    }

    async fn verify_once(&self, token: &str) -> Result<AppClaims, JwksConsumerError> {
        let verifier = self.current_verifier().await?;
        verifier
            .decode(token.as_bytes())
            .map_err(|error| JwksConsumerError::Verify(error.to_string()))
    }

    pub async fn verify_token(&self, token: &str) -> Result<AppClaims, JwksConsumerError> {
        match self.verify_once(token).await {
            Ok(claims) => Ok(claims),
            Err(JwksConsumerError::Verify(message))
                if message.contains("missing `kid`") || message.contains("not configured") =>
            {
                self.refresh().await?;
                match self.verify_once(token).await {
                    Ok(claims) => Ok(claims),
                    Err(JwksConsumerError::Verify(ref refreshed_message))
                        if refreshed_message.contains("missing `kid`") =>
                    {
                        Err(JwksConsumerError::MissingKidWithoutFallback)
                    }
                    Err(JwksConsumerError::Verify(ref refreshed_message)) => {
                        if let Some(kid) = kid_from_token_error(refreshed_message) {
                            Err(JwksConsumerError::UnknownKid { kid })
                        } else {
                            Err(JwksConsumerError::Verify(refreshed_message.clone()))
                        }
                    }
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    }
}

fn kid_from_token_error(message: &str) -> Option<String> {
    let marker = "JWT `kid` `";
    let index = message.find(marker)? + marker.len();
    let rest = &message[index..];
    let end = rest.find('`')?;
    Some(rest[..end].to_string())
}

fn codec_from_jwks(document: &JwksDocument) -> Result<JsonWebToken<AppClaims>, JwksConsumerError> {
    let mut keys = Vec::new();
    for key in &document.keys {
        if key.alg == "ES384" && key.crv == "P-384" && key.kty == "EC" && key.use_ == "sig" {
            keys.push(key.clone());
        }
    }

    if keys.is_empty() {
        return Err(JwksConsumerError::NoValidKeys);
    }

    let options = JsonWebTokenOptions::for_es384_jwks_keys(&keys)
        .map_err(|error| JwksConsumerError::Verify(error.to_string()))?;
    Ok(JsonWebToken::new_with_options(options))
}

async fn persist_jwks_cache(
    cache_path: &PathBuf,
    jwks: &JwksDocument,
) -> Result<(), JwksConsumerError> {
    if let Some(parent) = cache_path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|error| JwksConsumerError::CacheWrite {
                path: parent.display().to_string(),
                message: error.to_string(),
            })?;
    }

    let raw = serde_json::to_string_pretty(jwks)
        .map_err(|error| JwksConsumerError::ParseResponse(error.to_string()))?;
    tokio::fs::write(cache_path, raw)
        .await
        .map_err(|error| JwksConsumerError::CacheWrite {
            path: cache_path.display().to_string(),
            message: error.to_string(),
        })
}

pub struct JwksCookieGateVerifier {
    issuer: String,
    verifier: JwksVerifier,
}

impl JwksCookieGateVerifier {
    pub fn new(issuer: impl Into<String>, verifier: JwksVerifier) -> Self {
        Self {
            issuer: issuer.into(),
            verifier,
        }
    }

    pub async fn verify_token(&self, token: &str) -> Result<AppClaims, JwksConsumerError> {
        let claims = self.verifier.verify_token(token).await?;
        if claims.registered_claims.issuer != self.issuer {
            return Err(JwksConsumerError::Verify(format!(
                "token issuer mismatch: expected `{}`, got `{}`",
                self.issuer, claims.registered_claims.issuer
            )));
        }
        Ok(claims)
    }
}

pub fn parse_jwks_url() -> Option<String> {
    dotenvy::var("JWKS_URL").ok()
}

pub fn parse_jwks_refresh_secs() -> Duration {
    let secs = dotenvy::var("JWKS_REFRESH_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_REFRESH_INTERVAL.as_secs());
    Duration::from_secs(secs)
}

pub fn parse_jwks_timeout_millis() -> Duration {
    let millis = dotenvy::var("JWKS_HTTP_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_HTTP_TIMEOUT.as_millis() as u64);
    Duration::from_millis(millis)
}

pub fn parse_jwks_cache_path() -> Option<PathBuf> {
    dotenvy::var("JWKS_CACHE_PATH").ok().map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use webgates::codecs::jwt::jwks::EcP384Jwk;

    #[test]
    fn config_defaults_require_only_jwks_url() {
        let config =
            JwksConsumerConfig::from_jwks_url("https://example.invalid/.well-known/jwks.json");

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

        let result = codec_from_jwks(&document);
        assert!(matches!(result, Err(JwksConsumerError::NoValidKeys)));
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

        let codec = codec_from_jwks(&document).expect("codec should be created");
        assert_eq!(codec.verification_key_count(), 1);
    }
}
