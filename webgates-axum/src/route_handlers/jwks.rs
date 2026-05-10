//! JWKS publication handlers for auth authorities.
//!
//! Two handlers are provided:
//!
//! - `jwks` — low-level handler that accepts a `JwksProvider` value directly.
//! - `jwks_from_authority` — ergonomic handler that reads the provider from
//!   Axum [`State`](axum::extract::State) holding an `Arc<JwtAuthority<P>>`.
//!   This is the recommended entry point when using the authority bundle.
//!
//! # Minimal auth-node wiring with `jwks_from_authority`
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use axum::{Router, routing::get};
//! use webgates_codecs::jwt::authority::JwtAuthority;
//! use webgates_codecs::jwt::JwtClaims;
//! use webgates_axum::route_handlers::jwks::jwks_from_authority;
//!
//! # const PRIVATE_PEM: &[u8] = b"";
//! # const PUBLIC_PEM: &[u8] = b"";
//! let authority = Arc::new(
//!     JwtAuthority::<JwtClaims<()>>::from_es384_pem(PRIVATE_PEM, PUBLIC_PEM)
//!         .expect("valid ES384 key pair"),
//! );
//!
//! let app: Router<Arc<JwtAuthority<JwtClaims<()>>>> = Router::new()
//!     .route("/.well-known/jwks.json", get(jwks_from_authority::<JwtClaims<()>>))
//!     .with_state(Arc::clone(&authority));
//! ```

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::HeaderValue;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::IntoResponse;
use serde::{Serialize, de::DeserializeOwned};
use webgates::codecs::jwt::jwks::JwksProvider;
use webgates_codecs::jwt::authority::JwtAuthority;

/// Returns the canonical JWKS response for `GET /.well-known/jwks.json`.
///
/// The response includes only public verification key material and sets
/// cache-friendly headers.
pub async fn jwks(provider: JwksProvider) -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, HeaderValue::from_static("application/json")),
            (
                CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=60, stale-while-revalidate=30"),
            ),
        ],
        Json(provider.document().clone()),
    )
}

/// Returns the canonical JWKS response using a `JwtAuthority` held in Axum [`State`].
///
/// This is the recommended handler when using the authority bundle. Mount it with
/// `.with_state(Arc::clone(&authority))` on the router.
///
/// The type parameter `P` must match the claims type used by the authority.
pub async fn jwks_from_authority<P>(
    State(authority): State<Arc<JwtAuthority<P>>>,
) -> impl IntoResponse
where
    P: Serialize + DeserializeOwned + Clone + Send + Sync + 'static,
{
    jwks(authority.jwks_provider().clone()).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use webgates::codecs::jwt::jwks::JwksProvider;

    const TEST_ES384_PUBLIC_KEY_PEM: &[u8] = br#"-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEsjQ/XkOUJO2bXkhDzKRMW1SXp0VsMqGx
MSTG+tppqd3gOxbM8vLgWy4/B0Qdest0Gy3E8QgaKJXQV3zRczNd9zrk1dmwVl6u
Yd+JfgNIeIFP6HWeu/C3wIJ60WDBuGY1
-----END PUBLIC KEY-----
"#;

    #[tokio::test]
    async fn jwks_handler_returns_public_key_document() {
        let provider = match JwksProvider::from_es384_public_pem(TEST_ES384_PUBLIC_KEY_PEM) {
            Ok(provider) => provider,
            Err(error) => panic!("provider should be created: {error}"),
        };

        let response = jwks(provider).await.into_response();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let cache_control = response
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok());
        assert_eq!(
            cache_control,
            Some("public, max-age=60, stale-while-revalidate=30")
        );
    }

    #[tokio::test]
    async fn jwks_from_authority_returns_public_key_document() {
        use axum::extract::State;
        use std::sync::Arc;
        use webgates_codecs::jwt::JwtClaims;
        use webgates_codecs::jwt::authority::JwtAuthority;

        const PRIVATE_PEM: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCFT7MfRqWZfNgVX/cH
bxFTlPkBeCKqjsLkZXD/J3ZYHV1EtQksdrKtOzTr2hMs6pmhZANiAASyND9eQ5Qk
7ZteSEPMpExbVJenRWwyobExJMb62mmp3eA7Fszy8uBbLj8HRB16y3QbLcTxCBoo
ldBXfNFzM133OuTV2bBWXq5h34l+A0h4gU/odZ678LfAgnrRYMG4ZjU=
-----END PRIVATE KEY-----
"#;

        let authority = Arc::new(
            JwtAuthority::<JwtClaims<()>>::from_es384_pem(PRIVATE_PEM, TEST_ES384_PUBLIC_KEY_PEM)
                .expect("authority should be created"),
        );

        let response = jwks_from_authority::<JwtClaims<()>>(State(authority))
            .await
            .into_response();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let cache_control = response
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok());
        assert_eq!(
            cache_control,
            Some("public, max-age=60, stale-while-revalidate=30")
        );
    }
}
