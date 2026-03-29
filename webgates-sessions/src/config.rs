//! Typed session configuration values.
//!
//! This module defines framework-agnostic configuration for session issuance,
//! renewal, refresh-token rotation, and lease coordination.

use std::time::Duration;

use crate::errors::ConfigError;
use crate::lease::LeaseTtl;

/// Result returned by session configuration validation.
pub type ConfigResult<T> = std::result::Result<T, ConfigError>;

/// Configuration for session issuance and renewal behavior.
///
/// This type intentionally stays free of HTTP-specific concerns such as cookie
/// names, headers, or response mutation. Adapter crates should translate these
/// values into transport-specific behavior at the system edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfig {
    /// Lifetime of the short-lived authentication token.
    pub auth_token_ttl: Duration,
    /// Lifetime of the long-lived refresh token.
    pub refresh_token_ttl: Duration,
    /// Window before auth-token expiry during which proactive renewal is
    /// allowed.
    pub proactive_renewal_window: Duration,
    /// Typed duration for which a renewal lease remains valid once acquired.
    pub renewal_lease_ttl: LeaseTtl,
    /// Maximum amount of clock skew tolerated by renewal decision logic.
    pub clock_skew_tolerance: Duration,
}

impl SessionConfig {
    /// Creates a configuration with explicit values.
    #[must_use]
    pub const fn new(
        auth_token_ttl: Duration,
        refresh_token_ttl: Duration,
        proactive_renewal_window: Duration,
        renewal_lease_ttl: LeaseTtl,
        clock_skew_tolerance: Duration,
    ) -> Self {
        Self {
            auth_token_ttl,
            refresh_token_ttl,
            proactive_renewal_window,
            renewal_lease_ttl,
            clock_skew_tolerance,
        }
    }

    /// Returns the configured lease TTL as a raw duration.
    #[must_use]
    pub fn renewal_lease_duration(&self) -> Duration {
        self.renewal_lease_ttl.duration()
    }

    /// Validates the configuration and returns the typed value when it is
    /// internally consistent.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when one of the required durations is
    /// zero or when the proactive renewal window exceeds the auth-token
    /// lifetime.
    pub fn validate(self) -> ConfigResult<Self> {
        if self.auth_token_ttl.is_zero()
            || self.refresh_token_ttl.is_zero()
            || self.renewal_lease_duration().is_zero()
        {
            return Err(ConfigError::Invalid);
        }

        if self.proactive_renewal_window > self.auth_token_ttl {
            return Err(ConfigError::Invalid);
        }

        Ok(self)
    }

    /// Returns `true` when the configuration is internally consistent.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.clone().validate().is_ok()
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            auth_token_ttl: Duration::from_secs(15 * 60),
            refresh_token_ttl: Duration::from_secs(30 * 24 * 60 * 60),
            proactive_renewal_window: Duration::from_secs(2 * 60),
            renewal_lease_ttl: LeaseTtl::default(),
            clock_skew_tolerance: Duration::from_secs(5),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SessionConfig;
    use crate::lease::LeaseTtl;
    use std::time::Duration;

    #[test]
    fn default_config_is_valid() {
        assert!(SessionConfig::default().is_valid());
    }

    #[test]
    fn config_exposes_typed_lease_duration() {
        let config = SessionConfig::default();

        assert_eq!(
            config.renewal_lease_duration(),
            LeaseTtl::default().duration()
        );
    }

    #[test]
    fn config_is_invalid_when_proactive_window_exceeds_auth_ttl() {
        let config = SessionConfig::new(
            Duration::from_secs(60),
            Duration::from_secs(3600),
            Duration::from_secs(61),
            LeaseTtl::new(Duration::from_secs(30)),
            Duration::from_secs(5),
        );

        assert!(!config.is_valid());
    }

    #[test]
    fn config_is_invalid_when_required_durations_are_zero() {
        let config = SessionConfig::new(
            Duration::ZERO,
            Duration::from_secs(3600),
            Duration::ZERO,
            LeaseTtl::new(Duration::from_secs(30)),
            Duration::from_secs(5),
        );

        assert!(!config.is_valid());
    }

    #[test]
    fn config_is_invalid_when_lease_ttl_is_zero() {
        let config = SessionConfig::new(
            Duration::from_secs(60),
            Duration::from_secs(3600),
            Duration::from_secs(30),
            LeaseTtl::new(Duration::ZERO),
            Duration::from_secs(5),
        );

        assert!(!config.is_valid());
    }
}
