//! Secure cookie template builder for authentication cookies.
//!
//! This module provides [`CookieTemplate`] for creating secure authentication
//! cookies with sensible secure defaults.
//! The builder keeps transport safety on by default and requires an explicit
//! opt-in for insecure local development.
//!
//! # Quick Start
//!
//! ```rust
//! use webgates::cookie_template::CookieTemplate;
//! use cookie::time::Duration;
//!
//! // Use secure defaults
//! let template = CookieTemplate::recommended()
//!     .name("auth-token")
//!     .persistent(Duration::hours(24));
//! ```
//!
//! # Security Features
//!
//! The builder automatically provides secure defaults:
//! - **HttpOnly**: Prevents JavaScript access (XSS protection)
//! - **Secure**: HTTPS-only by default
//! - **SameSite=Strict**: CSRF protection by default
//! - **Session cookies**: No persistence by default
//! - **Explicit local-dev opt-in**: Insecure cookies require an intentional builder call

use cookie::time::Duration;
use cookie::{Cookie, CookieBuilder, SameSite};
use std::borrow::Cow;

/// Default cookie name used by the gate when none is specified.
pub const DEFAULT_COOKIE_NAME: &str = "webgates";

/// Builder for secure authentication cookies used by `Gate`.
///
/// Provides secure defaults independent of build configuration:
/// - **All builds**: Secure=true, HttpOnly=true, SameSite=Strict, session cookie
///
/// # Security Best Practices
///
/// The recommended approach is to start with [`CookieTemplate::recommended()`] and
/// customize only what you need:
///
/// ```rust
/// use webgates::cookie_template::CookieTemplate;
/// use cookie::{time::Duration, SameSite};
///
/// // Secure defaults with custom name and expiration
/// let template = CookieTemplate::recommended()
///     .name("auth-token")
///     .persistent(Duration::hours(24));
///
/// // For OAuth/redirect flows that need cross-site navigation
/// let oauth_template = CookieTemplate::recommended()
///     .name("oauth-state")
///     .same_site(SameSite::Lax);  // Allow cross-site for redirects
/// ```
///
/// # Security Features
///
/// - **HttpOnly**: Prevents JavaScript access to auth cookies (XSS protection)
/// - **Secure**: HTTPS-only in production (MITM protection)
/// - **SameSite=Strict**: Prevents CSRF attacks in production
/// - **Session cookies**: No persistent storage by default (privacy)
///
/// # Production Safety
///
/// Recommended defaults always keep `Secure=true` and `SameSite=Strict` unless you
/// intentionally weaken them. For local HTTP development, call
/// [`CookieTemplate::insecure_dev_only`] explicitly and only in trusted environments.
/// Call [`CookieTemplate::assert_production_secure`] at application startup to detect
/// accidental insecure configuration before serving requests:
///
/// ```rust,no_run
/// use webgates::cookie_template::CookieTemplate;
///
/// let template = CookieTemplate::recommended().name("auth-token");
/// template.assert_production_secure();
/// ```
///
/// # Common Customizations
///
/// - `name("my-auth-cookie")` - Set custom cookie name
/// - `persistent(Duration::hours(24))` - Make cookie persist across browser sessions
/// - `same_site(SameSite::Lax)` - Allow cross-site navigation (OAuth flows)
/// - `domain(".example.com")` - Share cookies across subdomains
///
/// Convert to `cookie::Cookie` via [`CookieTemplate::builder`] then `.build()`,
/// or use [`CookieTemplate::validate_and_build`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CookieTemplate {
    name: Cow<'static, str>,
    value: Cow<'static, str>,
    path: Cow<'static, str>,
    domain: Option<Cow<'static, str>>,
    secure: bool,
    http_only: bool,
    same_site: SameSite,
    max_age: Option<Duration>,
}

impl Default for CookieTemplate {
    /// Returns transport-safe default cookie settings.
    ///
    /// All builds default to `Secure=true`, `SameSite=Strict`, `HttpOnly=true`, and a
    /// session-only lifetime. Local HTTP development must opt into insecure cookies
    /// explicitly via [`CookieTemplate::insecure_dev_only`].
    fn default() -> Self {
        Self {
            name: Cow::Borrowed(DEFAULT_COOKIE_NAME),
            value: Cow::Borrowed(""),
            path: Cow::Borrowed("/"),
            domain: None,
            secure: true,
            http_only: true,
            same_site: SameSite::Strict,
            max_age: None, // session cookie – safer by default
        }
    }
}

impl CookieTemplate {
    /// Secure recommended defaults.
    #[must_use]
    pub fn recommended() -> Self {
        Self::default()
    }

    /// Set / override the cookie name.
    ///
    /// Keep names short and avoid sensitive info.
    #[must_use]
    pub fn name(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        self.name = name.into();
        self
    }

    /// Provide an initial value (normally left empty – the login code will
    /// insert the JWT).
    #[must_use]
    pub fn value(mut self, value: impl Into<Cow<'static, str>>) -> Self {
        self.value = value.into();
        self
    }

    /// Set the cookie path (default `/`).
    #[must_use]
    pub fn path(mut self, path: impl Into<Cow<'static, str>>) -> Self {
        self.path = path.into();
        self
    }

    /// Set the cookie domain. Avoid setting for single‑domain apps
    /// to retain host-only semantics (slightly tighter).
    #[must_use]
    pub fn domain(mut self, domain: impl Into<Cow<'static, str>>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// Unset the previously configured domain (host-only cookie).
    #[must_use]
    pub fn clear_domain(mut self) -> Self {
        self.domain = None;
        self
    }

    /// Explicitly mark the cookie as secure (HTTPS only).
    #[must_use]
    pub fn secure(mut self, flag: bool) -> Self {
        self.secure = flag;
        self
    }

    /// Convenience: weaken transport cookie settings for local development only.
    ///
    /// This disables `Secure` and relaxes `SameSite` to `Lax` so cookies can work over
    /// `http://localhost` during intentional local testing. Do not use this in staging or
    /// production.
    #[must_use]
    pub fn insecure_dev_only(mut self) -> Self {
        self.secure = false;
        self.same_site = SameSite::Lax;
        self
    }

    /// Set / unset HttpOnly flag.
    #[must_use]
    pub fn http_only(mut self, flag: bool) -> Self {
        self.http_only = flag;
        self
    }

    /// Set the SameSite attribute (default `Strict`).
    ///
    /// Consider `Lax` for some OAuth / cross-site redirect flows. Only use
    /// `None` when you understand the CSRF implications and the need for
    /// `Secure`.
    #[must_use]
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = same_site;
        self
    }

    /// Make persistent with a specific `Max-Age`.
    #[must_use]
    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }

    /// Remove persistence (session cookie again).
    #[must_use]
    pub fn clear_max_age(mut self) -> Self {
        self.max_age = None;
        self
    }

    /// Convenience for setting a persistent cookie lifetime.
    #[must_use]
    pub fn persistent(self, duration: Duration) -> Self {
        self.max_age(duration)
    }

    /// Use a short-lived cookie (e.g. 15 minutes) – explicit for readability.
    #[must_use]
    pub fn short_lived(self) -> Self {
        self.max_age(Duration::minutes(15))
    }

    /// Asserts that the template is configured with production-safe cookie attributes.
    ///
    /// Panics if [`CookieTemplate::secure`] is `false`. Call this once at application startup
    /// before binding a listener to prevent accidental insecure cookie configuration in
    /// staging or production environments.
    ///
    /// If you explicitly opt into insecure local-development cookies, do not call this in
    /// that environment.
    ///
    /// # Panics
    ///
    /// Panics with a descriptive message when `Secure=false`.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use webgates::cookie_template::CookieTemplate;
    ///
    /// let auth_template = CookieTemplate::recommended().name("auth-token");
    /// auth_template.assert_production_secure();
    /// ```
    pub fn assert_production_secure(&self) {
        assert!(
            self.secure,
            "CookieTemplate '{}' has Secure=false. \
             This indicates an explicitly insecure cookie configuration. \
             Do NOT use insecure cookies in production or staging environments. \
             Remove `.insecure_dev_only()` or call `.secure(true)` after confirming \
             the deployment context.",
            self.name
        );
    }

    /// Validate the template configuration. Returns `Ok(())` if fine.
    pub fn validate(&self) -> Result<(), CookieTemplateBuilderError> {
        if self.same_site == SameSite::None && !self.secure {
            return Err(CookieTemplateBuilderError::InsecureNoneSameSite);
        }
        Ok(())
    }

    /// Convert into the underlying `cookie::CookieBuilder<'static>`.
    #[must_use]
    #[inline]
    pub fn builder(&self) -> CookieBuilder<'static> {
        let mut builder = CookieBuilder::new(self.name.clone(), self.value.clone())
            .secure(self.secure)
            .http_only(self.http_only)
            .same_site(self.same_site)
            .path(self.path.clone());

        if let Some(ref domain) = self.domain {
            builder = builder.domain(domain.clone());
        }

        if let Some(max_age) = self.max_age {
            builder = builder.max_age(max_age);
        }

        builder
    }

    /// Validate then build. Returns an error if invalid.
    pub fn validate_and_build(&self) -> Result<Cookie<'static>, CookieTemplateBuilderError> {
        self.validate()?;
        Ok(self.builder().build())
    }

    /// Build a cookie preserving all template attributes, having the name and value.
    #[must_use]
    #[inline]
    pub fn build_with_name_value(&self, name: &str, value: &str) -> Cookie<'static> {
        let mut builder = CookieBuilder::new(name.to_owned(), value.to_owned())
            .secure(self.secure)
            .http_only(self.http_only)
            .same_site(self.same_site)
            .path(self.path.clone());

        if let Some(ref domain) = self.domain {
            builder = builder.domain(domain.clone());
        }

        if let Some(max_age) = self.max_age {
            builder = builder.max_age(max_age);
        }

        builder.build()
    }

    /// Build a cookie preserving attributes, overriding only the value.
    #[must_use]
    #[inline]
    pub fn build_with_value(&self, value: &str) -> Cookie<'static> {
        self.build_with_name_value(self.name.as_ref(), value)
    }

    /// Build a cookie preserving attributes, overriding only the name.
    #[must_use]
    #[inline]
    pub fn build_with_name(&self, name: &str) -> Cookie<'static> {
        self.build_with_name_value(name, self.value.as_ref())
    }

    /// Build a removal cookie preserving attributes, overriding the name.
    #[must_use]
    pub fn build_removal(&self) -> Cookie<'static> {
        let mut cookie = self.builder().build();
        cookie.make_removal();
        cookie
    }

    /// Get a reference to the configured cookie name without allocating.
    ///
    /// Prefer this on hot paths (e.g., header extraction).
    #[must_use]
    #[inline]
    pub fn cookie_name_ref(&self) -> &str {
        self.name.as_ref()
    }
}

/// Possible configuration issues detected during validation.
#[derive(Debug, thiserror::Error)]
pub enum CookieTemplateBuilderError {
    #[error("SameSite=None requires Secure=true (browser enforcement & CSRF protection)")]
    /// SameSite=None requires Secure=true for browser security and CSRF protection.
    InsecureNoneSameSite,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recommended_defaults_are_secure_and_strict() {
        let template = CookieTemplate::recommended();
        let cookie = template.build_with_value("token");

        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Strict));
        assert_eq!(cookie.max_age(), None);
    }

    #[test]
    fn insecure_dev_only_is_explicit_and_relaxes_transport_settings() {
        let template = CookieTemplate::recommended().insecure_dev_only();
        let cookie = template.build_with_value("token");

        assert_eq!(cookie.secure(), Some(false));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[test]
    fn same_site_none_still_requires_secure_even_with_dev_override() {
        let Err(error) = CookieTemplate::recommended()
            .insecure_dev_only()
            .same_site(SameSite::None)
            .validate()
        else {
            return;
        };

        assert!(matches!(
            error,
            CookieTemplateBuilderError::InsecureNoneSameSite
        ));
    }

    #[test]
    fn production_assertion_rejects_explicit_insecure_configuration() {
        let template = CookieTemplate::recommended().insecure_dev_only();

        let panic = std::panic::catch_unwind(|| template.assert_production_secure());

        assert!(panic.is_err());
    }
}
