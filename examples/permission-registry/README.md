# Permission Mapping Registry Example

This example demonstrates the optional permission mapping registry pattern in axum-gate, which enables reverse lookup from permission IDs back to their normalized string representations.

## Overview

The axum-gate permission system uses a high-performance bitmap-based storage approach where permission strings are normalized and hashed to 64-bit IDs. While this provides excellent performance for permission checking, it means the original permission strings cannot be recovered from the stored IDs.

The permission mapping registry provides an optional solution that allows you to:

- Store mappings between permission IDs and their normalized strings
- Perform reverse lookups for debugging and logging
- Build administrative interfaces with human-readable permission names
- Generate audit trails with meaningful permission names

Note: The mapping stores the normalized string and the computed ID. If you need to retain original formatting or separate descriptions, store them separately (e.g., in your database) or encode them in your own structure.

## Key Features

- Optional: Works alongside the existing bitmap system without replacing it
- Performance: Core permission checking performance is unaffected
- Flexible: Encapsulates normalized strings and computed IDs
- Thread-safe: Async-friendly repository implementations
- Validation: Ensures consistency between strings and IDs

## Running the Example

```bash
# From the axum-gate root directory
cargo run -p permission-registry-example
```

## What the Example Demonstrates

1) Basic Registry Operations
- Creating permission mappings from strings
- Storing mappings in the repository
- Reverse lookup by permission ID
- Forward lookup by permission string (with normalization)
- Listing all stored mappings

2) Integration with Permissions
- Granting permissions using the bitmap system
- Storing corresponding mappings for reverse lookup
- Retrieving human-readable names for granted permissions

3) Account Integration
- Creating accounts and granting permissions
- Storing mappings to enable reverse lookup
- Displaying account permissions with readable names

4) Repository Operations
- Removing mappings by ID or string
- Checking for mapping existence
- Listing all mappings
- (Optional) Bulk traits exist for future implementations; the in-memory repo does not implement them

## Core Types

### `PermissionMapping`

Represents the mapping between a normalized permission string and its computed 64-bit ID.

```rust
use axum_gate::permissions::mapping::PermissionMapping;

// Create from string (normalizes by trim + lowercase)
let mapping = PermissionMapping::from("read:api");

// Access components
println!("Normalized: {}", mapping.normalized_string()); // "read:api"
println!("ID: {}", mapping.id_as_u64());                 // e.g., 4432869890453236604
```

### `PermissionMappingRepository`

Repository trait for storing and retrieving mappings.

```rust
use axum_gate::permissions::mapping::{PermissionMapping, PermissionMappingRepository};
use axum_gate::repositories::memory::MemoryPermissionMappingRepository;
use axum_gate::prelude::PermissionId;

# async fn demo() -> axum_gate::errors::Result<()> {
let repo = MemoryPermissionMappingRepository::default();

// Store a mapping
let mapping = PermissionMapping::from("write:file");
repo.store_mapping(mapping.clone()).await?;

// Query by ID
let found = repo.query_mapping_by_id(mapping.permission_id()).await?;

// Query by string (with normalization)
let found2 = repo.query_mapping_by_string("WRITE:FILE").await?; // Case-insensitive

// Existence checks
let has_id = repo.has_mapping_for_id(PermissionId::from("write:file")).await?;
let has_str = repo.has_mapping_for_string("write:file").await?;
# Ok(()) }
```

## Usage Patterns

### Service Layer Integration

```rust
use axum_gate::permissions::Permissions;
use axum_gate::permissions::mapping::{PermissionMapping, PermissionMappingRepository};

async fn grant_permission_with_registry<Repo>(
    permissions: &mut Permissions,
    registry: &Repo,
    permission_str: &str,
) -> axum_gate::errors::Result<()>
where
    Repo: PermissionMappingRepository,
{
    let mapping = PermissionMapping::from(permission_str);

    // Grant the permission (primary operation)
    permissions.grant(mapping.normalized_string());

    // Store the mapping for reverse lookup (optional)
    // Do not fail the grant on a registry error; handle/log as appropriate.
    registry.store_mapping(mapping).await?;

    Ok(())
}
```

### Debugging and Logging

```rust
use axum_gate::permissions::mapping::PermissionMappingRepository;
use axum_gate::prelude::PermissionId;
use tracing::{info, warn, error};

// Log granted permissions with human-readable names
async fn log_permissions<R: PermissionMappingRepository>(
    registry: &R,
    granted_ids: impl Iterator<Item = u64>,
) -> axum_gate::errors::Result<()> {
    for permission_id in granted_ids {
        let id = PermissionId::from_u64(permission_id);
        match registry.query_mapping_by_id(id).await {
            Ok(Some(mapping)) => info!("User has permission: {}", mapping.normalized_string()),
            Ok(None) => warn!("Unknown permission ID: {}", permission_id),
            Err(e) => error!("Failed to lookup permission {}: {}", permission_id, e),
        }
    }
    Ok(())
}
```

## Available Implementations

- In-Memory (`MemoryPermissionMappingRepository`)
  - Path: `axum_gate::repositories::memory::MemoryPermissionMappingRepository`
  - Intended for development and small deployments
  - Lookups are O(n) (linear scan) in the in-memory implementation

For production, implement `PermissionMappingRepository` for your chosen backend:
- SQL databases (PostgreSQL, MySQL, SQLite) with unique indexes on ID and normalized string
- NoSQL databases (MongoDB, DynamoDB)
- Key-value stores (Redis, etc.)

## Performance Considerations

- The registry is optional; core permission checking uses roaring bitmaps and is unaffected
- The in-memory implementation is simple and uses linear scans; suitable for development or small datasets
- For higher scale, implement a repository with indexed lookups (e.g., DB indexes or in-memory hash maps)
- Caching strategies can improve read performance

## Error Handling

- Mapping creation validates consistency between normalized strings and IDs
- Repository failures should not block core permission operations; handle gracefully and log as needed

## When to Use

Use the permission mapping registry when you need:
- Debugging/logging with human-readable permission names
- Administrative UIs that display permission names
- Audit trails and reporting

If you want to carry human-written descriptions, store them alongside your mapping (e.g., separate field/table). The example also demonstrates a simple “comment suffix” technique for demos, but a separate data structure is recommended for production.