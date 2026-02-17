//! Commonly used types for convenient imports.
//!
//! This prelude intentionally excludes any web-framework integrations.
//! For axum integration, use the `webgates-axum` crate.

pub use crate::accounts::Account;
#[cfg(feature = "server")]
pub use crate::authz::AccessPolicy;
#[cfg(feature = "server")]
pub use crate::codecs::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims, RegisteredClaims};
#[cfg(feature = "server")]
pub use crate::cookie_template::CookieTemplate;
pub use crate::credentials::Credentials;
#[cfg(feature = "server")]
pub use crate::gate::Gate;
pub use crate::groups::Group;
pub use crate::permissions::{PermissionId, Permissions};
pub use crate::roles::Role;
