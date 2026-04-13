use webgates_core::permissions::mapping::PermissionMapping;
use webgates_core::permissions::permission_id::PermissionId;

use std::future::Future;

/// Repository abstraction for persisting and retrieving [`PermissionMapping`] entities.
///
/// This trait enables the optional registry pattern for permission string mappings,
/// allowing reverse lookup from permission IDs back to their normalized string
/// representations. This is implemented alongside the existing bitmap-based
/// permission system without replacing it.
///
/// # Purpose
///
/// The permission mapping repository provides optional functionality for:
/// - Debugging and logging with human-readable permission names
/// - Administrative interfaces showing permission details
/// - Audit trails with readable permission descriptions
/// - Permission reporting and analysis
///
/// # Usage Pattern
///
/// This repository is intended to be used optionally alongside the existing
/// `Permissions` struct. When permission strings need to be recoverable:
///
/// ```rust
/// # use webgates_core::permissions::mapping::PermissionMapping;
/// # use webgates_core::permissions::Permissions;
/// # use webgates_repositories::memory::permission_mapping::MemoryPermissionMappingRepository;
/// # use webgates_repositories::permission_mapping_repository::PermissionMappingRepository;
///
/// let repo = MemoryPermissionMappingRepository::default();
///
/// let mapping = PermissionMapping::from("read:api");
/// let mut permissions = Permissions::new();
/// permissions.grant(mapping.normalized_string());
///
/// let stored = tokio_test::block_on(repo.store_mapping(mapping.clone())).unwrap();
/// assert!(stored.is_some());
///
/// let fetched = tokio_test::block_on(repo.query_mapping_by_id(mapping.permission_id())).unwrap();
/// assert!(matches!(fetched, Some(m) if m.normalized_string() == "read:api"));
/// ```
///
/// # Consistency Guarantees
///
/// Implementations SHOULD:
/// - Enforce uniqueness of both permission IDs and normalized strings
/// - Validate mapping consistency before storage (use `PermissionMapping::validate()`)
/// - Handle concurrent access safely
/// - Provide atomic operations where possible
///
/// # Performance Considerations
///
/// Since this is an optional feature for human-readable lookups:
/// - Implementations may prioritize consistency over performance
/// - Caching strategies are encouraged for frequently accessed mappings
/// - Bulk operations are not required but may be added via extension traits
///
/// # Error Handling
///
/// Return `Err` for exceptional backend failures (connectivity, serialization,
/// constraint violations). Use `Ok(None)` for "not found" / "no-op" outcomes.
/// Validation errors should be caught early using `PermissionMapping::validate()`.
///
/// # Example Implementation Patterns
///
/// ```rust
/// use webgates_core::permissions::mapping::PermissionMapping;
/// use webgates_core::permissions::Permissions;
/// use webgates_repositories::memory::permission_mapping::MemoryPermissionMappingRepository;
/// use webgates_repositories::permission_mapping_repository::PermissionMappingRepository;
///
/// async fn grant_permission_with_registry(
///     permissions: &mut Permissions,
///     registry: &MemoryPermissionMappingRepository,
///     permission_str: &str,
/// ) -> Result<(), webgates_repositories::errors::Error> {
///     let mapping = PermissionMapping::from(permission_str);
///     permissions.grant(mapping.normalized_string());
///     registry.store_mapping(mapping).await?;
///     Ok(())
/// }
///
/// # #[tokio::test]
/// # async fn usage() {
/// let repo = MemoryPermissionMappingRepository::default();
/// let mut permissions = Permissions::new();
/// grant_permission_with_registry(&mut permissions, &repo, "read:api").await.unwrap();
/// assert!(permissions.has("read:api"));
/// # }
/// ```
pub trait PermissionMappingRepository {
    /// Backend-specific error type for repository operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Initialize the repository backend.
    ///
    /// Implementations may use this hook to create tables, indexes, permissions,
    /// or other backend-specific storage prerequisites if they do not exist yet.
    ///
    /// Returns:
    /// - `Ok(())` if the repository is ready for use
    /// - `Err(e)` on backend initialization failure
    fn bootstrap(&self) -> impl Future<Output = Result<(), Self::Error>>;

    /// Store a permission mapping.
    ///
    /// Implementations SHOULD enforce uniqueness of both the permission ID
    /// and the normalized string.
    ///
    /// Idempotent backends MAY treat storing an already-existing unchanged
    /// mapping as a successful no-op and return `Ok(Some(mapping))`.
    /// Backends that distinguish between newly inserted and unchanged existing
    /// mappings MAY return `Ok(None)` to indicate no change.
    ///
    /// The mapping will be validated for internal consistency before storage.
    ///
    /// Returns:
    /// - `Ok(Some(mapping))` if successfully stored or accepted as an idempotent no-op
    /// - `Ok(None)` if the backend explicitly reports that the mapping already exists unchanged
    /// - `Err(e)` on backend error or validation failure
    fn store_mapping(
        &self,
        mapping: PermissionMapping,
    ) -> impl Future<Output = Result<Option<PermissionMapping>, Self::Error>>;

    /// Remove a permission mapping by its permission ID.
    ///
    /// Returns:
    /// - `Ok(Some(mapping))` if the mapping existed and was removed
    /// - `Ok(None)` if no mapping matched the ID
    /// - `Err(e)` on backend error
    fn remove_mapping_by_id(
        &self,
        id: PermissionId,
    ) -> impl Future<Output = Result<Option<PermissionMapping>, Self::Error>>;

    /// Remove a permission mapping by its permission string.
    ///
    /// The string will be normalized before lookup, so this will match
    /// regardless of case or whitespace differences.
    ///
    /// Returns:
    /// - `Ok(Some(mapping))` if the mapping existed and was removed
    /// - `Ok(None)` if no mapping matched the string
    /// - `Err(e)` on backend error
    fn remove_mapping_by_string(
        &self,
        permission: &str,
    ) -> impl Future<Output = Result<Option<PermissionMapping>, Self::Error>>;

    /// Query a permission mapping by its permission ID.
    ///
    /// This is the primary lookup method for reverse resolution of
    /// permission IDs back to their string representations.
    ///
    /// Returns:
    /// - `Ok(Some(mapping))` if found
    /// - `Ok(None)` if not found
    /// - `Err(e)` on backend failure
    fn query_mapping_by_id(
        &self,
        id: PermissionId,
    ) -> impl Future<Output = Result<Option<PermissionMapping>, Self::Error>>;

    /// Query a permission mapping by its permission string.
    ///
    /// The string will be normalized before lookup, so this will match
    /// regardless of case or whitespace differences.
    ///
    /// Returns:
    /// - `Ok(Some(mapping))` if found
    /// - `Ok(None)` if not found
    /// - `Err(e)` on backend failure
    fn query_mapping_by_string(
        &self,
        permission: &str,
    ) -> impl Future<Output = Result<Option<PermissionMapping>, Self::Error>>;

    /// List all stored permission mappings.
    ///
    /// This method is useful for administrative interfaces, debugging,
    /// and generating permission reports. For large numbers of mappings,
    /// consider implementing pagination via an extension trait.
    ///
    /// Returns:
    /// - `Ok(mappings)` - Vector of all mappings (empty if none exist)
    /// - `Err(e)` on backend failure
    fn list_all_mappings(
        &self,
    ) -> impl Future<Output = Result<Vec<PermissionMapping>, Self::Error>>;

    /// Check if a mapping exists for the given permission ID.
    ///
    /// This is a convenience method that may be more efficient than
    /// `query_mapping_by_id` when you only need to check existence.
    ///
    /// Returns:
    /// - `Ok(true)` if a mapping exists
    /// - `Ok(false)` if no mapping exists
    /// - `Err(e)` on backend failure
    fn has_mapping_for_id(
        &self,
        id: PermissionId,
    ) -> impl Future<Output = Result<bool, Self::Error>> {
        async move {
            match self.query_mapping_by_id(id).await {
                Ok(Some(_)) => Ok(true),
                Ok(None) => Ok(false),
                Err(e) => Err(e),
            }
        }
    }

    /// Check if a mapping exists for the given permission string.
    ///
    /// This is a convenience method that may be more efficient than
    /// `query_mapping_by_string` when you only need to check existence.
    ///
    /// Returns:
    /// - `Ok(true)` if a mapping exists
    /// - `Ok(false)` if no mapping exists
    /// - `Err(e)` on backend failure
    fn has_mapping_for_string(
        &self,
        permission: &str,
    ) -> impl Future<Output = Result<bool, Self::Error>> {
        async move {
            match self.query_mapping_by_string(permission).await {
                Ok(Some(_)) => Ok(true),
                Ok(None) => Ok(false),
                Err(e) => Err(e),
            }
        }
    }
}

/// Extension trait for bulk operations on permission mappings.
///
/// This trait provides optional bulk operations that may be more efficient
/// for implementations that support batch processing. Implementations are
/// not required to implement this trait unless they want to provide
/// optimized bulk operations.
pub trait PermissionMappingRepositoryBulk: PermissionMappingRepository {
    /// Store multiple permission mappings in a single operation.
    ///
    /// This may be more efficient than multiple individual `store_mapping` calls.
    /// Each mapping is validated before storage.
    ///
    /// Returns:
    /// - `Ok(stored_mappings)` - Vector of mappings accepted by the backend
    /// - `Err(e)` on backend error
    ///
    /// Note: Depending on backend semantics, this may include newly inserted
    /// mappings and unchanged mappings accepted as idempotent no-ops. Backends
    /// that distinguish duplicates may still skip existing mappings, similar to
    /// `store_mapping` returning `None`.
    fn store_mappings(
        &self,
        mappings: Vec<PermissionMapping>,
    ) -> impl Future<Output = Result<Vec<PermissionMapping>, Self::Error>>;

    /// Remove multiple permission mappings by their IDs.
    ///
    /// Returns:
    /// - `Ok(removed_mappings)` - Vector of successfully removed mappings
    /// - `Err(e)` on backend error
    ///
    /// Mappings that don't exist are silently ignored.
    fn remove_mappings_by_ids(
        &self,
        ids: Vec<PermissionId>,
    ) -> impl Future<Output = Result<Vec<PermissionMapping>, Self::Error>>;

    /// Query multiple permission mappings by their IDs.
    ///
    /// Returns:
    /// - `Ok(mappings)` - Vector of found mappings
    /// - `Err(e)` on backend error
    ///
    /// IDs that don't exist are silently ignored.
    fn query_mappings_by_ids(
        &self,
        ids: Vec<PermissionId>,
    ) -> impl Future<Output = Result<Vec<PermissionMapping>, Self::Error>>;
}
