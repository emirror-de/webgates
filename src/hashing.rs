//! Password hashing and verification services.
//!
//! This module provides secure password hashing functionality using industry-standard
//! algorithms. The primary implementation uses Argon2, which is recommended by security
//! experts for password hashing due to its resistance to both brute-force and side-channel
//! attacks.
//!
//! # Key Components
//!
//! - [`HashingService`] - Service for hashing and verifying passwords
//! - [`HashedValue`] - Represents a hashed password with algorithm metadata
//! - [`argon2`] - Argon2 algorithm implementation with secure defaults
//!
//! # Quick Start
//!
//! ```rust
//! use axum_gate::hashing::{HashingService, argon2::Argon2Hasher};
//! use axum_gate::verification_result::VerificationResult;
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
//! - **Custom parameters**: Override via `Argon2Hasher::with_params()`

pub mod argon2;
mod hashing_service;

pub use hashing_service::HashingService;

pub mod errors;
pub use errors::{HashingError, HashingOperation};

/// A hashed value produced by password hashing algorithms.
///
/// This type represents the output of cryptographic password hashing functions,
/// typically containing the algorithm identifier, parameters, salt, and hash in
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
/// use axum_gate::hashing::{argon2::Argon2Hasher, HashingService, HashedValue};
///
/// let hasher = Argon2Hasher::new_recommended().unwrap();
/// let hashed: HashedValue = hasher.hash_value("my_password").unwrap();
///
/// // The hashed value is self-contained and can be stored directly
/// println!("Hashed password: {}", hashed);
///
/// // Later, verify against the stored hash
/// use axum_gate::verification_result::VerificationResult;
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
