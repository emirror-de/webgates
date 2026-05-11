//! Argon2id hashing implementation.
//!
//! This module provides the default [`HashingService`] implementation for
//! `webgates-secrets`.
//!
//! [`Argon2Hasher`] uses explicit, reviewable presets and produces PHC-formatted
//! hash strings that can be stored directly.
//!
//! # Examples
//!
//! ```rust
//! use webgates_core::verification_result::VerificationResult;
//! use webgates_secrets::hashing::argon2::Argon2Hasher;
//! use webgates_secrets::hashing::hashing_service::HashingService;
//!
//! let hasher = Argon2Hasher::new_recommended().unwrap();
//! let hash = hasher.hash_value("secret").unwrap();
//!
//! assert_eq!(
//!     hasher.verify_value("secret", &hash).unwrap(),
//!     VerificationResult::Ok
//! );
//! assert_eq!(
//!     hasher.verify_value("other", &hash).unwrap(),
//!     VerificationResult::Unauthorized
//! );
//! ```
use super::HashedValue;
use crate::Result;
use crate::hashing::errors::{HashingError, HashingOperation};
use crate::hashing::hashing_service::HashingService;
use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordVerifier, Version};
use webgates_core::verification_result::VerificationResult;

/// Configures the Argon2id memory, time, and parallelism parameters.
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
    /// Returns a high-security configuration for production environments.
    ///
    /// This preset uses 64 MiB of memory, 3 iterations, and 1 thread.
    pub fn high_security() -> Self {
        Self {
            memory_kib: 64 * 1024, // 64 MiB
            time_cost: 3,
            parallelism: 1,
        }
    }
    /// Returns an interactive configuration for user-facing applications.
    ///
    /// This preset uses 32 MiB of memory, 2 iterations, and 1 thread.
    pub fn interactive() -> Self {
        Self {
            memory_kib: 32 * 1024,
            time_cost: 2,
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

/// Preset selector for common Argon2id configurations.
#[derive(Debug, Clone, Copy)]
pub enum Argon2Preset {
    /// High security preset for production environments (64 MiB memory, 3 iterations).
    HighSecurity,
    /// Interactive preset balanced for user-facing applications (32 MiB memory, 2 iterations).
    Interactive,
}

impl Argon2Preset {
    /// Convert this preset to an `Argon2Config`.
    pub fn to_config(self) -> Argon2Config {
        match self {
            Self::HighSecurity => Argon2Config::high_security(),
            Self::Interactive => Argon2Config::interactive(),
        }
    }
}

/// Argon2id hasher with explicit, reviewable configuration.
///
/// This is the default hashing implementation provided by the crate.
#[derive(Clone)]
pub struct Argon2Hasher {
    config: Argon2Config,
    engine: Argon2<'static>,
}

impl Argon2Hasher {
    /// Creates a new hasher using the crate's recommended preset.
    pub fn new_recommended() -> Result<Self> {
        Self::high_security()
    }
    /// Creates a hasher from explicit configuration.
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

    /// Creates a hasher from a preset.
    pub fn from_preset(preset: Argon2Preset) -> Result<Self> {
        Self::from_config(preset.to_config())
    }

    /// Returns the current configuration.
    pub fn config(&self) -> &Argon2Config {
        &self.config
    }

    /// Creates a high-security hasher for production environments.
    ///
    /// # Defaults
    ///
    /// - memory: 64 MiB
    /// - time cost: 3 iterations
    /// - parallelism: 1 thread
    pub fn high_security() -> Result<Self> {
        Self::from_preset(Argon2Preset::HighSecurity)
    }

    /// Creates an interactive hasher for user-facing applications.
    ///
    /// # Defaults
    ///
    /// - memory: 32 MiB
    /// - time cost: 2 iterations
    /// - parallelism: 1 thread
    pub fn interactive() -> Result<Self> {
        Self::from_preset(Argon2Preset::Interactive)
    }
}

impl HashingService for Argon2Hasher {
    fn hash_value(&self, plain_value: &str) -> Result<HashedValue, HashingError> {
        let salt = SaltString::generate(&mut OsRng);
        Ok(self
            .engine
            .hash_password(plain_value.as_bytes(), &salt)
            .map_err(|e| {
                HashingError::with_context(
                    HashingOperation::Hash,
                    format!("Could not hash secret: {e}"),
                    Some("Argon2id".to_string()),
                    Some("PHC".to_string()),
                )
            })?
            .to_string())
    }

    fn verify_value(
        &self,
        plain_value: &str,
        hashed_value: &str,
    ) -> Result<VerificationResult, HashingError> {
        let hash = PasswordHash::new(hashed_value).map_err(|e| {
            HashingError::with_context(
                HashingOperation::Verify,
                format!("Could not parse stored hash: {e}"),
                Some("Argon2id".to_string()),
                Some("PHC".to_string()),
            )
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
    use crate::hashing::hashing_service::HashingService;

    #[test]
    fn recommended_hasher_verifies_matching_secret() {
        let hasher = Argon2Hasher::new_recommended().unwrap();
        let hash = hasher.hash_value("pw").unwrap();
        assert!(matches!(
            hasher.verify_value("pw", &hash),
            Ok(VerificationResult::Ok)
        ));
    }

    #[test]
    fn presets_verify_matching_and_non_matching_secrets() {
        for preset in [Argon2Preset::HighSecurity, Argon2Preset::Interactive] {
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
    fn custom_config_verifies_matching_secret() {
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
