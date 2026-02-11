use super::Secret;

use crate::errors::Result;
use std::future::Future;
use uuid::Uuid;

/// Repository abstraction for persisting authentication [`Secret`]s (hashed credentials).
///
/// Secrets are intentionally stored separately from account metadata to allow:
/// - Split persistence (e.g. different database / schema / encryption domain)
/// - Principle of least privilege for services that only need account profile data
/// - Defense-in-depth (compartmentalization if one store is compromised)
///
/// # Semantics
///
/// | Method            | Success Value                | Special `false` / `None` Meaning                | Error (`Err`) Meaning                          |
/// |-------------------|------------------------------|------------------------------------------------|-----------------------------------------------|
/// | `store_secret`    | `true` (inserted)            | `false` = secret already exists for account_id | Backend / persistence failure                 |
/// | `update_secret`   | `()`                         | —                                              | Backend / persistence failure                 |
/// | `delete_secret`   | `Some(secret)` = removed     | `None` = no secret for that id                 | Backend / persistence failure                 |
///
/// # Implementation Guidelines
///
/// - `store_secret` SHOULD perform an atomic insert (do not overwrite existing secret).
/// - `update_secret` SHOULD replace the stored hash (e.g. after password change / rehash).
/// - `delete_secret` MUST (where possible) remove and return atomically to enable callers
///   to perform compensating actions if subsequent logic fails.
/// - All methods should avoid leaking timing that distinguishes “exists vs not” where the
///   caller relies on indistinguishability (e.g. during login flows with enumeration resistance).
///
/// # Error vs Absence
///
/// Use:
/// - `Ok(false)` (only for `store_secret`) to indicate a duplicate attempt.
/// - `Ok(None)` for expected absence (`delete_secret`).
/// - `Err(..)` strictly for exceptional conditions (I/O, serialization, constraint violation).
///
/// # Example (rotate secret)
/// ```rust
/// use axum_gate::secrets::{Secret, SecretRepository};
/// use axum_gate::hashing::argon2::Argon2Hasher;
/// use axum_gate::repositories::memory::MemorySecretRepository;
/// use uuid::Uuid;
///
/// fn rotate_secret(
///     repo: &MemorySecretRepository,
///     new_secret: Secret
/// ) -> axum_gate::errors::Result<()> {
///     tokio_test::block_on(repo.update_secret(new_secret))
/// }
///
/// // Usage
/// let repo = MemorySecretRepository::new_with_argon2_hasher().unwrap();
/// let account_id = Uuid::now_v7();
/// let hasher = Argon2Hasher::new_recommended().unwrap();
/// let secret = Secret::new(&account_id, "new_password", hasher).unwrap();
/// rotate_secret(&repo, secret).unwrap();
/// ```
///
/// # Security Note
///
/// Callers MUST ensure the `Secret` they pass was created using a secure hashing
/// service (e.g. Argon2 via `Secret::new`). This repository trait does not verify
/// hash format; it treats the value opaquely.
///
/// Avoid adding a read/list-all API to this trait; derive any necessary audit logging
/// at a different layer to minimize accidental exposure of hashed credentials.
pub trait SecretRepository
where
    Self: Send + Sync,
{
    /// Store a newly created secret.
    ///
    /// Returns:
    /// - `Ok(true)` if inserted
    /// - `Ok(false)` if a secret already exists for the associated account (no change)
    /// - `Err(e)` on backend failure
    fn store_secret(&self, secret: Secret) -> impl Future<Output = Result<bool>> + Send;

    /// Update (replace) an existing secret.
    ///
    /// Use this for password change flows or adaptive rehashing. Implementations
    /// may choose to return an error if the secret does not already exist; if so
    /// that should be documented by the implementation. This trait treats absence
    /// as exceptional for updates (hence no `Option`).
    fn update_secret(&self, secret: Secret) -> impl Future<Output = Result<()>> + Send;

    /// Remove and return a secret by its owning account id.
    ///
    /// Returns:
    /// - `Ok(Some(secret))` if a secret existed and was removed
    /// - `Ok(None)` if no secret existed (idempotent)
    /// - `Err(e)` on backend failure
    ///
    /// SHOULD be atomic (retrieve + delete) to allow callers to retry / rollback
    /// higher-level operations safely.
    fn delete_secret(&self, id: &Uuid) -> impl Future<Output = Result<Option<Secret>>> + Send;
}
