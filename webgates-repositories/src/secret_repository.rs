use webgates_secrets::Secret;

use std::future::Future;
use uuid::Uuid;

/// Persists authentication [`Secret`] values.
///
/// Secrets are intentionally stored separately from account metadata to support
/// split persistence, least-privilege designs, and defense-in-depth.
///
/// # Semantics
///
/// | Method            | Success Value                | Special `false` / `None` Meaning                | Error (`Err`) Meaning                          |
/// |-------------------|------------------------------|------------------------------------------------|-----------------------------------------------|
/// | `store_secret`    | `true` (inserted)            | `false` = secret already exists for account_id | Backend / persistence failure                 |
/// | `update_secret`   | `()`                         | —                                              | Backend / persistence failure                 |
/// | `delete_secret`   | `Some(secret)` = removed     | `None` = no secret for that id                 | Backend / persistence failure                 |
///
/// # Behavior
///
/// - `store_secret` should perform an atomic insert and avoid overwriting an existing secret.
/// - `update_secret` should replace the stored hash, for example after a password change or rehash.
/// - `delete_secret` should remove and return the secret atomically where possible.
/// - Methods should avoid leaking timing differences between existence and absence when callers rely on indistinguishability.
///
/// # Error vs. absence
///
/// Use:
/// - `Ok(false)` (only for `store_secret`) to indicate a duplicate attempt.
/// - `Ok(None)` for expected absence (`delete_secret`).
/// - `Err(..)` strictly for exceptional conditions (I/O, serialization, constraint violation).
///
/// # Examples
/// ```rust
/// use webgates_repositories::memory::secret::MemorySecretRepository;
/// use webgates_repositories::secret_repository::SecretRepository;
/// use webgates_secrets::hashing::argon2::Argon2Hasher;
/// use webgates_secrets::Secret;
/// use uuid::Uuid;
///
/// fn rotate_secret(
///     repo: &MemorySecretRepository,
///     new_secret: Secret
/// ) -> webgates_repositories::errors::Result<()> {
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
/// # Security notes
///
/// Callers must ensure the `Secret` they pass was created using a secure
/// hashing service such as `Secret::new`. This trait treats stored hashes as
/// opaque values.
///
/// This trait intentionally avoids read-all style APIs so higher layers do not
/// accidentally expose hashed credentials.
pub trait SecretRepository
where
    Self: Send + Sync,
{
    /// Backend-specific error type for repository operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Bootstraps the repository backend.
    ///
    /// This method allows implementations to prepare required storage objects
    /// before normal repository operations begin, for example by creating
    /// database tables if they do not exist yet.
    fn bootstrap(&self) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores a newly created secret.
    fn store_secret(
        &self,
        secret: Secret,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    /// Updates (replaces) an existing secret.
    ///
    /// Use this for password change flows or adaptive rehashing. Implementations
    /// may choose to return an error if the secret does not already exist; if so
    /// that should be documented by the implementation. This trait treats absence
    /// as exceptional for updates (hence no `Option`).
    fn update_secret(&self, secret: Secret)
    -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Removes and returns a secret by its owning account id.
    ///
    /// Implementations should make this operation atomic where possible so
    /// callers can safely apply retry or compensating logic.
    fn delete_secret(
        &self,
        id: &Uuid,
    ) -> impl Future<Output = Result<Option<Secret>, Self::Error>> + Send;
}
