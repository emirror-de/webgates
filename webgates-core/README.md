# webgates-core

Framework-agnostic domain types and authorization primitives for the `webgates` ecosystem.

`webgates-core` provides the foundational building blocks for authentication and authorization without depending on any specific web framework, HTTP implementation, or runtime.

## What this crate provides

- **Account, role, and group domain types** for representing users and their capabilities
- **Authorization policies and evaluation services** for access control decisions
- **Credential boundary types and verification contracts** for authentication workflows
- **Deterministic permission identifiers, sets, and validation helpers** for fine-grained access control
- **Shared error traits and verification result types** for consistent error handling

## When to use this crate

Use `webgates-core` when you:

- Need only the core domain types without HTTP dependencies
- Want to build custom integrations with frameworks not yet supported
- Are implementing authorization logic in non-web contexts
- Want the smallest possible dependency footprint

For web applications, consider using `webgates` (which re-exports this crate) or framework-specific integrations like `webgates-axum`.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
webgates-core = "0.1"
```

Minimum supported Rust version: 1.91

## Core concepts

### Accounts

Accounts represent users with roles, groups, and individual permissions:

```rust
use webgates_core::prelude::*;

// Create an account (default role is applied automatically)
let account = Account::<Role, Group>::new("user123");

// Create an account with explicit roles and groups
let account = Account::<Role, Group>::new("user123")
    .with_roles(vec![Role::Admin])
    .with_groups(vec![Group::new("developers".to_string())]);

// Grant individual permissions
let mut account = Account::<Role, Group>::new("user123");
account.grant_permission("api:read");
assert!(account.has_permission(&PermissionId::from("api:read")));
```

### Authorization policies

Define access requirements declaratively:

```rust
use webgates_core::authz::AccessPolicy;
use webgates_core::prelude::*;

// Require admin role exactly
let policy = AccessPolicy::require_role(Role::Admin);

// Require admin role or any role that supervises it in the hierarchy
let policy = AccessPolicy::require_role_or_supervisor(Role::Admin);

// Require specific permission
let policy = AccessPolicy::require_permission("admin:users:delete");

// Require group membership
let policy = AccessPolicy::require_group(Group::new("approvers".to_string()));

// Combine multiple requirements (any match grants access)
let policy = AccessPolicy::require_role(Role::Admin)
    .or_require_permission("special:access");
```

### Authorization service

Evaluate policies against accounts:

```rust
use webgates_core::authz::{AccessPolicy, AuthorizationService};
use webgates_core::prelude::*;

let account = Account::<Role, Group>::new("user123")
    .with_roles(vec![Role::Admin]);

let policy = AccessPolicy::require_role(Role::Admin);
let auth_service = AuthorizationService::new(policy);

assert!(auth_service.is_authorized(&account));
```

### Permissions

Work with deterministic permission identifiers:

```rust
use webgates_core::prelude::*;

// Create permission from string
let perm_id = PermissionId::from("api:users:read");

// Create permission set
let mut perms = Permissions::new();
perms.grant("api:users:read");
perms.grant("api:users:write");

// Check permissions
assert!(perms.has(&PermissionId::from("api:users:read")));
assert!(perms.has_all(&["api:users:read", "api:users:write"]));

// Set operations
let other_perms = Permissions::from_iter(["api:posts:read"]);
let combined = perms.union(&other_perms);
```

### Permission validation

Validate permission definitions at build or test time:

```rust
use webgates_core::validate_permissions;

validate_permissions![
    "api:users:read",
    "api:users:write",
    "api:posts:read",
];
```

Implement `AsPermissionName` on your own permission enum to map structured types to string names:

```rust
use webgates_core::permissions::{AsPermissionName, Permissions};

enum AppPermission {
    UsersRead,
    UsersWrite,
}

impl AsPermissionName for AppPermission {
    fn as_permission_name(&self) -> String {
        match self {
            AppPermission::UsersRead => "api:users:read".to_string(),
            AppPermission::UsersWrite => "api:users:write".to_string(),
        }
    }
}
```

### Credentials

Handle authentication boundaries:

```rust
use webgates_core::credentials::Credentials;

// Create credentials for verification
let creds = Credentials::new("username", "password");

// In your authentication service, implement CredentialsVerifier
// to handle the actual verification logic
```

## Features

This crate has no optional features and minimal dependencies. It provides only the core types and authorization logic.

For additional capabilities like JWT codecs, HTTP cookie handling, or framework integration, use:

- `webgates` - adds JWT, cookies, sessions, and higher-level services
- `webgates-axum` - Axum framework integration
- `webgates-repositories` - persistence layer implementations
- `webgates-sessions` - session management primitives

## Error handling

The crate uses structured error types for different failure modes:

```rust
use webgates_core::errors::Result;
use webgates_core::authz::AuthzError;

// Authorization errors provide context about access failures
fn check_access() -> Result<(), AuthzError> {
    // Your authorization logic here
    Ok(())
}
```

## WASM compatibility

This crate supports WebAssembly targets. The minimal dependency set and framework-agnostic design make it suitable for client-side authorization logic.

## Testing

```rust
use webgates_core::prelude::*;

#[test]
fn account_permissions() {
    let mut account = Account::<Role, Group>::new("test");
    account.grant_permission("test:permission");

    assert!(account.has_permission(&PermissionId::from("test:permission")));
}
```

## Related crates

- `webgates` - user-facing composition crate with optional features
- `webgates-axum` - Axum framework integration
- `webgates-repositories` - persistence implementations
- `webgates-sessions` - session lifecycle management
- `webgates-codecs` - JWT and other codec implementations
- `webgates-secrets` - secret handling and hashing utilities

## License

MIT
