//! Value hashing implementations.
//!
//! Provides a *single* configurable Argon2id password hashing service with security‑first defaults.
//!
//! Build mode defaults:
//! - Release builds (`debug_assertions` disabled): HighSecurity preset
//! - Debug builds (`debug_assertions` enabled):   DevFast preset (faster local iteration)
//!
//! You can override the default explicitly with presets or a custom configuration.
//!
//! # Example
//! ```rust
//! use axum_gate::hashing::argon2::Argon2Hasher;
//! use axum_gate::hashing::HashingService;
//!
//! // Default (build‑mode appropriate) hasher
//! let hasher = Argon2Hasher::new_recommended().unwrap();
//! let hash = hasher.hash_value("secret").unwrap();
//! assert!(hasher.verify_value("secret", &hash).is_ok());
//! ```
//!
//! ⚠ The `DevFast` preset MUST NOT be used in production; it exists only to keep debug builds
//! responsive. When you explicitly construct a hasher, choose an appropriate security profile.
use super::HashedValue;
use crate::errors::{Error, Result};
use crate::hashing::HashingService;
use crate::hashing::{HashingError, HashingOperation};
use crate::verification_result::VerificationResult;
use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordVerifier, Version};

/// Argon2 parameter configuration (memory in KiB).
#[derive(Debug, Clone, Copy)]
pub struct Argon2Config {
    /// Memory usage in KiB for the Argon2 algorithm.
    pub memory_kib: u32,
    /// Number of iterations (time cost) for the Argon2 algorithm.
    pub time_cost: u32,
    /// Number of parallel threads to use during hashing.
    pub parallelism: u32,
}

impl Argon2Config {
    /// High security configuration for production environments.
    ///
    /// Uses 64 MiB memory, 3 iterations, and 1 thread for maximum security.
    pub fn high_security() -> Self {
        Self {
            memory_kib: 64 * 1024, // 64 MiB
            time_cost: 3,
            parallelism: 1,
        }
    }
    /// Interactive configuration balanced for user-facing applications.
    ///
    /// Uses 32 MiB memory, 2 iterations, and 1 thread for reasonable performance.
    pub fn interactive() -> Self {
        Self {
            memory_kib: 32 * 1024,
            time_cost: 2,
            parallelism: 1,
        }
    }
    /// Fast configuration for development and testing.
    ///
    /// Uses minimal resources: 1 MiB memory, 1 iteration, and 1 thread.
    #[cfg(any(feature = "insecure-fast-hash", debug_assertions))]
    pub fn dev_fast() -> Self {
        Self {
            memory_kib: 4 * 1024,
            time_cost: 1,
            parallelism: 1,
        }
    }
    /// Override the memory usage in KiB.
    pub fn with_memory_kib(mut self, v: u32) -> Self {
        self.memory_kib = v;
        self
    }
    /// Override the time cost (number of iterations).
    pub fn with_time_cost(mut self, v: u32) -> Self {
        self.time_cost = v;
        self
    }
    /// Override the number of parallel threads.
    pub fn with_parallelism(mut self, v: u32) -> Self {
        self.parallelism = v;
        self
    }
}

impl Default for Argon2Config {
    fn default() -> Self {
        Argon2Config::high_security()
    }
}

/// Preset selector for convenience.
#[derive(Debug, Clone, Copy)]
pub enum Argon2Preset {
    /// High security preset for production environments (64 MiB memory, 3 iterations).
    HighSecurity,
    /// Interactive preset balanced for user-facing applications (32 MiB memory, 2 iterations).
    Interactive,
    /// Fast preset for development and testing (4 MiB memory, 1 iteration).
    #[cfg(any(feature = "insecure-fast-hash", debug_assertions))]
    DevFast,
}

impl Argon2Preset {
    /// Convert this preset to an `Argon2Config`.
    pub fn to_config(self) -> Argon2Config {
        match self {
            Self::HighSecurity => Argon2Config::high_security(),
            Self::Interactive => Argon2Config::interactive(),
            #[cfg(any(feature = "insecure-fast-hash", debug_assertions))]
            Self::DevFast => Argon2Config::dev_fast(),
        }
    }
}

/// Configurable Argon2id hasher.
#[derive(Clone)]
pub struct Argon2Hasher {
    config: Argon2Config,
    engine: Argon2<'static>,
}

impl Argon2Hasher {
    /// Creates a new instance with recommended settings based on the current build (dev/release).
    pub fn new_recommended() -> Result<Self> {
        if cfg!(debug_assertions) {
            #[cfg(any(feature = "insecure-fast-hash", debug_assertions))]
            {
                return Self::dev_fast();
            }
        }
        // Fallback / release: always high security
        Self::high_security()
    }
    /// Create from explicit configuration.
    pub fn from_config(config: Argon2Config) -> Result<Self> {
        let params = Params::new(
            config.memory_kib,
            config.time_cost,
            config.parallelism,
            None,
        )?;
        let engine = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        Ok(Self { config, engine })
    }

    /// Create from a preset.
    pub fn from_preset(preset: Argon2Preset) -> Result<Self> {
        Self::from_config(preset.to_config())
    }

    /// Return current configuration.
    pub fn config(&self) -> &Argon2Config {
        &self.config
    }

    /// Maximum security hasher for production environments.
    ///
    /// **Parameters:**
    /// - Memory: 64 MiB (65,536 KiB)
    /// - Time cost: 3 iterations
    /// - Parallelism: 1 thread
    ///
    /// **Use cases:**
    /// - Production servers with sufficient memory
    /// - High-value accounts requiring maximum security
    /// - Applications where authentication latency is acceptable (~100-200ms)
    ///
    /// **Security:** Provides excellent protection against brute-force attacks
    /// and rainbow tables, suitable for protecting sensitive user credentials.
    ///
    /// **Performance:** Slowest option, designed for security over speed.
    pub fn high_security() -> Result<Self> {
        Self::from_preset(Argon2Preset::HighSecurity)
    }

    /// Balanced hasher for interactive applications.
    ///
    /// **Parameters:**
    /// - Memory: 32 MiB (32,768 KiB)
    /// - Time cost: 2 iterations
    /// - Parallelism: 1 thread
    ///
    /// **Use cases:**
    /// - Web applications with user-facing login forms
    /// - Mobile applications where response time matters
    /// - Services with moderate security requirements
    /// - Memory-constrained production environments
    ///
    /// **Security:** Good security level, still resistant to most attacks
    /// while providing reasonable authentication response times.
    ///
    /// **Performance:** Moderate speed (~50-100ms), good balance of security and usability.
    pub fn interactive() -> Result<Self> {
        Self::from_preset(Argon2Preset::Interactive)
    }

    /// Fast hasher for development and testing only.
    ///
    /// **⚠️ WARNING: DO NOT USE IN PRODUCTION**
    ///
    /// **Parameters:**
    /// - Memory: 4 MiB (4,096 KiB)
    /// - Time cost: 1 iteration
    /// - Parallelism: 1 thread
    ///
    /// **Use cases:**
    /// - Local development to speed up test cycles
    /// - Unit tests that need fast password hashing
    /// - CI/CD pipelines to reduce build times
    /// - Debug builds (automatically used by `default()`)
    ///
    /// **Security:** ⚠️ Insufficient for production use - vulnerable to brute-force attacks
    ///
    /// **Performance:** Very fast (~5-20ms), prioritizes development speed over security.
    ///
    /// This preset is only available in debug builds or when the `insecure-fast-hash`
    /// feature is explicitly enabled.
    #[cfg(any(feature = "insecure-fast-hash", debug_assertions))]
    pub fn dev_fast() -> Result<Self> {
        Self::from_preset(Argon2Preset::DevFast)
    }
}

impl HashingService for Argon2Hasher {
    fn hash_value(&self, plain_value: &str) -> Result<HashedValue> {
        let salt = SaltString::generate(&mut OsRng);
        Ok(self
            .engine
            .hash_password(plain_value.as_bytes(), &salt)
            .map_err(|e| {
                Error::Hashing(HashingError::with_context(
                    HashingOperation::Hash,
                    format!("Could not hash secret: {e}"),
                    Some("Argon2id".to_string()),
                    Some("PHC".to_string()),
                ))
            })?
            .to_string())
    }

    fn verify_value(&self, plain_value: &str, hashed_value: &str) -> Result<VerificationResult> {
        let hash = PasswordHash::new(hashed_value).map_err(|e| {
            Error::Hashing(HashingError::with_context(
                HashingOperation::Verify,
                format!("Could not parse stored hash: {e}"),
                Some("Argon2id".to_string()),
                Some("PHC".to_string()),
            ))
        })?;
        Ok(VerificationResult::from(
            self.engine
                .verify_password(plain_value.as_bytes(), &hash)
                .is_ok(),
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::hashing::HashingService;

    #[test]
    fn default_build_mode() {
        let hasher = Argon2Hasher::new_recommended().unwrap();
        let hash = hasher.hash_value("pw").unwrap();
        assert!(matches!(
            hasher.verify_value("pw", &hash),
            Ok(VerificationResult::Ok)
        ));
    }

    #[test]
    fn presets_work() {
        for preset in [
            Argon2Preset::HighSecurity,
            Argon2Preset::Interactive,
            #[cfg(any(feature = "insecure-fast-hash", debug_assertions))]
            Argon2Preset::DevFast,
        ] {
            let hasher = Argon2Hasher::from_preset(preset).unwrap();
            let h = hasher.hash_value("secret").unwrap();
            assert_eq!(
                VerificationResult::Ok,
                hasher.verify_value("secret", &h).unwrap()
            );
            assert_eq!(
                VerificationResult::Unauthorized,
                hasher.verify_value("other", &h).unwrap()
            );
        }
    }

    #[test]
    fn custom_config() {
        let cfg = Argon2Config::default()
            .with_memory_kib(48 * 1024)
            .with_time_cost(2)
            .with_parallelism(1);
        let hasher = Argon2Hasher::from_config(cfg).unwrap();
        let h = hasher.hash_value("abc").unwrap();
        assert!(matches!(
            hasher.verify_value("abc", &h),
            Ok(VerificationResult::Ok)
        ));
    }
}
