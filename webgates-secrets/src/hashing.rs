//! Password hashing and verification services.
//!
//! This module contains the hashing-facing API of `webgates-secrets`.
//!
//! It provides the hashing abstraction, the default Argon2id implementation, and
//! the `HashedValue` type used for stored hashes.
//!
//! # Key Components
//!
//! - [`hashing_service::HashingService`] - Service for hashing and verifying passwords
//! - [`HashedValue`] - Represents a hashed password with algorithm metadata
//! - [`argon2`] - Argon2 algorithm implementation with secure defaults
//!
//! # Quick Start
//!
//! ```rust
//! use webgates_core::verification_result::VerificationResult;
//! use webgates_secrets::hashing::argon2::Argon2Hasher;
//! use webgates_secrets::hashing::hashing_service::HashingService;
//!
//! let hasher = Argon2Hasher::new_recommended().unwrap();
//!
//! // Hash a password
//! let hashed = hasher.hash_value("user_password").unwrap();
//! println!("Hashed password: {}", hashed);
//!
//! // Verify a password
//! let result = hasher.verify_value("user_password", &hashed).unwrap();
//! assert_eq!(result, VerificationResult::Ok);
//! ```
//!
//! # Canonical Public Paths
//!
//! Each public item in this module has a single canonical path through its owning
//! submodule:
//!
//! - [`crate::hashing::argon2::Argon2Hasher`]
//! - [`crate::hashing::hashing_service::HashingService`]
//! - [`crate::hashing::errors::HashingError`]
//! - [`crate::hashing::errors::HashingOperation`]
//! - [`crate::hashing::HashedValue`]
//!
//! # Security Features
//!
//! - **Argon2id algorithm** - Recommended by password hashing competition
//! - **Configurable parameters** - Memory cost, time cost, and parallelism
//! - **Built-in salt generation** - Each password gets a unique random salt
//! - **Constant-time verification** - Prevents timing attacks
//! - **Development vs production profiles** - Fast hashing in debug builds, secure in release
//!
//! # Performance Considerations
//!
//! The hashing service automatically adjusts parameters based on build configuration:
//! - **Debug builds**: Fast parameters for development efficiency
//! - **Release builds**: Secure parameters for production security
//! - **Custom parameters**: Override via `Argon2Hasher::from_config()`

pub mod argon2;
pub mod errors;
/// Hashing service traits and public contracts.
///
/// Use the canonical path [`crate::hashing::hashing_service::HashingService`]
/// to import the hashing trait.
pub mod hashing_service;

/// A hashed value produced by password hashing algorithms.
///
/// This is the stored representation returned by hashing implementations.
/// It usually contains the algorithm identifier, parameters, salt, and hash in
/// a standardized format.
///
/// ## Format
///
/// For Argon2id hashes, the format follows the PHC (Password Hashing Competition) standard:
/// ```text
/// $argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>
/// ```
///
/// Where:
/// - `argon2id` - Algorithm identifier
/// - `v=19` - Algorithm version
/// - `m=65536,t=3,p=1` - Memory cost, time cost, parallelism parameters
/// - `<salt>` - Base64-encoded random salt
/// - `<hash>` - Base64-encoded password hash
///
/// ## Security Properties
///
/// - **Self-contained**: Includes all information needed for verification
/// - **Salt included**: Each hash has a unique random salt to prevent rainbow table attacks
/// - **Parameter embedded**: Hash contains the parameters used, enabling verification
/// - **Future-proof**: Format supports algorithm upgrades and parameter changes
///
/// ## Usage
///
/// ```rust
/// use webgates_secrets::hashing::argon2::Argon2Hasher;
/// use webgates_secrets::hashing::hashing_service::HashingService;
/// use webgates_secrets::hashing::HashedValue;
///
/// let hasher = Argon2Hasher::new_recommended().unwrap();
/// let hashed: HashedValue = hasher.hash_value("my_password").unwrap();
///
/// // The hashed value is self-contained and can be stored directly
/// println!("Hashed password: {}", hashed);
///
/// // Later, verify against the stored hash
/// use webgates_core::verification_result::VerificationResult;
/// let result = hasher.verify_value("my_password", &hashed).unwrap();
/// assert_eq!(result, VerificationResult::Ok);
/// ```
///
/// ## Storage Considerations
///
/// - **Database storage**: Store as TEXT/VARCHAR with sufficient length (≥100 characters recommended)
/// - **No additional encoding needed**: The string is already in a safe, printable format
/// - **Indexing**: Generally should not be indexed as hashes are not used for lookups
/// - **Migration**: Hash format changes require re-hashing passwords during user login
pub type HashedValue = String;
