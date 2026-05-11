# webgates-core

User-focused Rust building blocks for authentication and authorization.

`webgates-core` is the smallest crate in the `webgates` ecosystem. It gives you the domain model and authorization primitives without pulling in HTTP, cookies, JWT handling, sessions, database adapters, or framework integrations.

If you want to understand how `webgates` works at its foundation, or you want to build your own adapter around another framework, this is the crate to start with.

## Who this crate is for

Use `webgates-core` when you want to:

- model users as accounts with roles, groups, and direct permissions
- make authorization decisions in pure Rust domain code
- build your own authentication or authorization services on top of the core types
- integrate with a framework that does not yet have a `webgates` adapter
- keep dependencies minimal and avoid transport-specific concerns

If you are building a typical web application and want batteries included, you will usually want `webgates` instead.

## What you learn in this crate

Most developers only need to internalize a small core loop:

- `Account` represents the current user and their assigned capabilities
- `AccessPolicy` expresses what a protected action requires
- `AuthorizationService` evaluates whether the account satisfies that policy
- `Permissions` add fine-grained capability checks when roles or groups are too broad
- `Credentials` and `CredentialsVerifier` define the authentication boundary without committing you to one transport or backend

## What this crate does not do

This crate intentionally does **not** include:

- HTTP middleware
- framework integrations
- JWT encoding or decoding
- cookies
- session issuance or renewal
- password hashing implementations
- repository implementations

Those concerns live in sibling crates such as `webgates`, `webgates-axum`, `webgates-codecs`, `webgates-repositories`, `webgates-secrets`, and `webgates-sessions`.

## Install

Add this to your `Cargo.toml`:

```toml
[dependencies]
webgates-core = "0.1"
```

Minimum supported Rust version: `1.91`.

## The mental model

If you are onboarding to the crate, this is the simplest way to think about it:

1. You represent the current user as an `Account`.
2. You express access requirements as an `AccessPolicy`.
3. You ask `AuthorizationService` whether the account satisfies that policy.
4. You optionally use `Credentials` and `CredentialsVerifier` to plug in your own login flow.

That is the core loop.

## Quick start

This example shows the main flow you will use in application code.

```rust
use webgates_core::accounts::Account;
use webgates_core::authz::access_policy::AccessPolicy;
use webgates_core::authz::authorization_service::AuthorizationService;
use webgates_core::groups::Group;
use webgates_core::roles::Role;

let account = Account::<Role, Group>::new("user-123")
    .with_roles(vec![Role::Admin])
    .with_groups(vec![Group::new("engineering")]);

let policy = AccessPolicy::<Role, Group>::require_role(Role::Admin)
    .or_require_group(Group::new("support-override"));

let authz = AuthorizationService::new(policy);

assert!(authz.is_authorized(&account));
```

## Core concepts

### 1. Accounts represent the current user

`Account<R, G>` is the central domain type. It stores:

- a generated `account_id`
- your application-level `user_id`
- assigned roles
- assigned groups
- direct permissions

Example:

```rust
use webgates_core::accounts::Account;
use webgates_core::groups::Group;
use webgates_core::permissions::Permissions;
use webgates_core::roles::Role;

let permissions: Permissions = ["projects:read", "projects:write"].into_iter().collect();

let account = Account::<Role, Group>::new("alice@example.com")
    .with_roles(vec![Role::Moderator])
    .with_groups(vec![Group::new("engineering")])
    .with_permissions(permissions);

assert_eq!(account.user_id, "alice@example.com");
assert!(account.has_role(&Role::Moderator));
assert!(account.is_member_of(&Group::new("engineering")));
```

A useful onboarding detail: `Account::new(...)` automatically assigns the default role for your role type. With the built-in `Role` enum, that default is `Role::User`.

### 2. Roles model hierarchical privilege

The built-in `Role` type is ordered from least privileged to most privileged:

- `Role::User`
- `Role::Reporter`
- `Role::Moderator`
- `Role::Admin`

That ordering matters when you use `require_role_or_supervisor(...)`.

Example:

```rust
use webgates_core::authz::access_policy::AccessPolicy;
use webgates_core::groups::Group;
use webgates_core::roles::Role;

let exact = AccessPolicy::<Role, Group>::require_role(Role::Moderator);
let hierarchical = AccessPolicy::<Role, Group>::require_role_or_supervisor(Role::Moderator);

assert!(exact.has_requirements());
assert!(hierarchical.has_requirements());
```

If your application needs its own role hierarchy, define your own enum in least-to-most privileged order and implement `AccessHierarchy` for it.

### 3. Groups model exact membership

Groups are useful for non-hierarchical membership such as departments, tenants, teams, or project assignments.

```rust
use webgates_core::groups::Group;

let engineering = Group::new("engineering");
let billing = Group::new("billing");

assert_eq!(engineering.name(), "engineering");
assert_eq!(billing.name(), "billing");
```

Use groups when access depends on *belonging to something*, not on privilege level.

### 4. Permissions model fine-grained capabilities

Permissions are string-based capabilities such as `projects:read` or `admin:users:delete`.

`webgates-core` converts them into deterministic `PermissionId` values internally, so you can do fast checks without maintaining a central numeric registry.

```rust
use webgates_core::permissions::Permissions;
use webgates_core::permissions::permission_id::PermissionId;

let mut permissions = Permissions::new();
permissions
    .grant("projects:read")
    .grant(PermissionId::from("projects:write"));

assert!(permissions.has("projects:read"));
assert!(permissions.has_all(["projects:read", "projects:write"]));
assert!(!permissions.has("projects:delete"));
```

Use permissions when a role is too broad and you need feature-level control.

### 5. Policies declare what access requires

`AccessPolicy<R, G>` is how you describe who should be allowed through.

Important onboarding note: policy requirements use **OR semantics**.
If any configured role, group, or permission requirement matches, authorization succeeds.

```rust
use webgates_core::authz::access_policy::AccessPolicy;
use webgates_core::groups::Group;
use webgates_core::roles::Role;

let policy = AccessPolicy::<Role, Group>::require_role(Role::Admin)
    .or_require_role_or_supervisor(Role::Moderator)
    .or_require_group(Group::new("security"))
    .or_require_permission("audit:read");

assert!(policy.has_requirements());
```

This is a good fit for rules like:

- admins may enter
- moderators and above may enter
- members of a specific emergency group may enter
- anybody with a dedicated override permission may enter

### 6. The authorization service evaluates the policy

`AuthorizationService` turns the policy into an authorization decision for a specific account.

```rust
use webgates_core::accounts::Account;
use webgates_core::authz::access_policy::AccessPolicy;
use webgates_core::authz::authorization_service::AuthorizationService;
use webgates_core::groups::Group;
use webgates_core::roles::Role;

let account = Account::<Role, Group>::new("bob")
    .with_roles(vec![Role::Reporter]);

let policy = AccessPolicy::<Role, Group>::require_role(Role::Admin)
    .or_require_role(Role::Reporter);

let service = AuthorizationService::new(policy);
assert!(service.is_authorized(&account));
```

## A practical onboarding example

This example shows a realistic setup for an internal admin page.

```rust
use webgates_core::accounts::Account;
use webgates_core::authz::access_policy::AccessPolicy;
use webgates_core::authz::authorization_service::AuthorizationService;
use webgates_core::groups::Group;
use webgates_core::roles::Role;

let mut account = Account::<Role, Group>::new("carol@example.com")
    .with_roles(vec![Role::User])
    .with_groups(vec![Group::new("support")]);

account.grant_permission("tickets:read");
account.grant_permission("tickets:escalate");

let policy = AccessPolicy::<Role, Group>::require_role(Role::Admin)
    .or_require_group(Group::new("support"))
    .or_require_permission("tickets:escalate");

let authz = AuthorizationService::new(policy);

assert!(authz.is_authorized(&account));
```

Here access succeeds even though the user is not an admin, because the policy accepts **any** matching requirement and the account belongs to the `support` group.

## Authentication boundary: credentials and verification

`webgates-core` does not implement password hashing or login services for you. Instead, it gives you a clean boundary:

- `Credentials<Id>` holds user-supplied identifier + plaintext secret
- `CredentialsVerifier` is the trait you implement to check those credentials against your own backend

```rust
use webgates_core::credentials::Credentials;

let credentials = Credentials::new(&"alice@example.com".to_string(), "correct horse battery staple");

assert_eq!(credentials.id, "alice@example.com");
```

This separation is useful because it keeps your domain model independent from:

- which database you use
- how you hash passwords
- which framework handles the request
- whether login happens over HTTP, gRPC, CLI, or background jobs

## Validate permissions during tests

If your application defines many permission strings, validate them in tests so collisions or duplicate definitions are caught early.

```rust
use webgates_core::validate_permissions;

validate_permissions![
    "projects:read",
    "projects:write",
    "projects:delete",
    "admin:users:read",
    "admin:users:write",
    "admin:users:delete",
];
```

This is especially helpful when your permission surface grows over time or is shared across multiple modules.

## Recommended onboarding path

If you are new to the crate, I recommend learning it in this order:

1. `accounts::Account`
2. `roles::Role` and `groups::Group`
3. `permissions::Permissions`
4. `authz::access_policy::AccessPolicy`
5. `authz::authorization_service::AuthorizationService`
6. `credentials::Credentials` and `credentials_verifier::CredentialsVerifier`

That sequence mirrors how most applications adopt the crate.

## Which crate should you use?

Choose based on how much infrastructure you want out of the box:

- use `webgates-core` when you only want domain types and authorization primitives
- use `webgates` when you want the main user-facing composition crate
- use `webgates-axum` when you want Axum integration
- use `webgates-sessions` when you want framework-agnostic session lifecycle primitives
- use `webgates-codecs` when you need JWT and codec support
- use `webgates-repositories` when you want repository contracts and storage integrations
- use `webgates-secrets` when you need hashing and secret handling helpers

## Design goals

This crate is intentionally designed to be:

- framework-agnostic
- transport-agnostic
- easy to test
- small in dependency footprint
- usable in server and WASM contexts
- explicit about authorization behavior

## Security notes

A few important things to keep in mind:

- `Credentials` contains plaintext secrets and should be short-lived
- do not log secrets, tokens, or raw credential data
- use secure transport when credentials cross a process or network boundary
- treat permission names as application API and keep them stable once adopted
- validate your permission set in CI if your app depends heavily on string permissions

## Related crates

- `webgates` - the main composition crate for most applications
- `webgates-axum` - Axum integration
- `webgates-codecs` - JWT and codec support
- `webgates-repositories` - repository traits and backends
- `webgates-secrets` - secret and hashing helpers
- `webgates-sessions` - session lifecycle and renewal primitives
- `webgates-tonic` - tonic integration

## License

MIT
