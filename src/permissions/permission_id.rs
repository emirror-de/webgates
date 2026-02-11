use super::AsPermissionName;

use const_crypto::sha2::Sha256;
use serde::{Deserialize, Serialize};

/// A deterministic 64-bit permission identifier computed from normalized permission names.
///
/// Normalization strategy:
/// - Trim ASCII whitespace
/// - Convert to lowercase
///
/// # Examples
///
/// ```rust
/// use axum_gate::permissions::PermissionId;
///
/// let read_id = PermissionId::from("read:file");
/// let write_id = PermissionId::from("write:file");
///
/// assert_ne!(read_id, write_id);
/// assert_eq!(read_id, PermissionId::from("READ:FILE")); // Case-insensitive normalization
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PermissionId(u64);

impl std::fmt::Display for PermissionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PermissionId {
    /// Returns the underlying u64 value for use in bitmap/treemap structures.
    pub fn as_u64(self) -> u64 {
        self.0
    }

    /// Creates a PermissionId from a raw u64 value (primarily for deserialization).
    pub fn from_u64(value: u64) -> Self {
        Self(value)
    }
}

impl From<u64> for PermissionId {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl From<PermissionId> for u64 {
    fn from(id: PermissionId) -> u64 {
        id.as_u64()
    }
}

impl From<&str> for PermissionId {
    fn from(name: &str) -> Self {
        let norm = normalize_permission(name);
        Self(const_sha256_u64(&norm))
    }
}

impl From<String> for PermissionId {
    fn from(name: String) -> Self {
        Self::from(name.as_str())
    }
}

impl<T: AsPermissionName> From<&T> for PermissionId {
    fn from(permission: &T) -> Self {
        let norm = normalize_permission(&permission.as_permission_name());
        Self(const_sha256_u64(&norm))
    }
}

/// Normalize a permission name (current policy: trim + lowercase).
fn normalize_permission(input: &str) -> String {
    input.trim().to_lowercase()
}

/// Computes a deterministic u64 hash from a string using the first 8 bytes of SHA-256.
///
/// This is intentionally a `const fn` so it can be used in compile-time contexts
/// similar to the former 32-bit variant.
pub const fn const_sha256_u64(input: &str) -> u64 {
    let hash = Sha256::new().update(input.as_bytes()).finalize();
    u64::from_be_bytes([
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_id_different_names() {
        let read_id = PermissionId::from("read:file");
        let write_id = PermissionId::from("write:file");
        assert_ne!(read_id, write_id);
    }

    #[test]
    fn permission_id_case_normalization() {
        let id_lower = PermissionId::from("read:file");
        let id_upper = PermissionId::from("READ:FILE");
        assert_eq!(id_lower, id_upper);
    }

    #[test]
    fn permission_id_conversions() {
        let id = PermissionId::from("test:permission");
        let raw = id.as_u64();
        let from_u64 = PermissionId::from_u64(raw);
        assert_eq!(id, from_u64);
    }

    #[test]
    fn permission_id_from_string_types() {
        let name = "test:permission";
        let string_name = name.to_string();

        let from_str = PermissionId::from(name);
        let from_str_ref: PermissionId = name.into();
        let from_string: PermissionId = string_name.into();

        assert_eq!(from_str, from_str_ref);
        assert_eq!(from_str, from_string);
    }

    #[test]
    fn permission_id_from_permission_trait() {
        #[derive(Debug)]
        enum TestPermission {
            Read,
            Write,
        }

        impl AsPermissionName for TestPermission {
            fn as_permission_name(&self) -> String {
                format!("Test:{:?}", self)
            }
        }

        let read_perm = TestPermission::Read;
        let write_perm = TestPermission::Write;

        let read_id = PermissionId::from(&read_perm);
        let write_id = PermissionId::from(&write_perm);
        let read_id_from_trait = PermissionId::from(&read_perm);

        assert_ne!(read_id, write_id);
        assert_eq!(read_id, read_id_from_trait);

        // Case normalization (Test:Read vs test:read)
        assert_eq!(read_id, PermissionId::from("test:read"));
        assert_eq!(write_id, PermissionId::from("test:write"));
    }

    #[test]
    fn permission_id_deterministic() {
        let id1 = PermissionId::from("read:file");
        let id2 = PermissionId::from("read:file");
        assert_eq!(id1, id2);
    }

    #[test]
    fn permission_id_nested_enum_example() {
        #[derive(Debug)]
        enum AppPermission {
            Repository(RepositoryPermission),
            Api(ApiPermission),
        }

        #[derive(Debug)]
        enum RepositoryPermission {
            Read,
        }

        #[derive(Debug)]
        enum ApiPermission {
            Read,
        }

        impl AsPermissionName for AppPermission {
            fn as_permission_name(&self) -> String {
                match self {
                    AppPermission::Repository(perm) => {
                        format!("repository:{:?}", perm)
                    }
                    AppPermission::Api(perm) => format!("api:{:?}", perm),
                }
            }
        }

        let repo_read = AppPermission::Repository(RepositoryPermission::Read);
        let api_read = AppPermission::Api(ApiPermission::Read);

        let repo_read_id = PermissionId::from(&repo_read);
        let api_read_id = PermissionId::from(&api_read);

        assert_ne!(repo_read_id, api_read_id);
        assert_eq!(repo_read_id, PermissionId::from("repository:read"));
        assert_eq!(api_read_id, PermissionId::from("api:read"));
    }

    #[test]
    fn permission_id_integrates_with_permissions_struct() {
        use crate::permissions::Permissions;

        #[derive(Debug)]
        enum TestPermission {
            Read,
            Write,
        }

        impl AsPermissionName for TestPermission {
            fn as_permission_name(&self) -> String {
                format!("test:{:?}", self)
            }
        }

        let read_perm = TestPermission::Read;
        let write_perm = TestPermission::Write;

        let mut permissions = Permissions::new();

        permissions.grant(&read_perm);
        permissions.grant(&write_perm);

        assert!(permissions.has(&read_perm));
        assert!(permissions.has(&write_perm));

        assert!(permissions.has("test:read"));
        assert!(permissions.has("test:write"));

        assert!(permissions.has_all([&read_perm, &write_perm]));
        assert!(permissions.has_any([&read_perm]));
    }
}
