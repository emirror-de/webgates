//! Commonly used types for convenient imports.
//!
//! This prelude intentionally excludes any web-framework integrations.
//! For axum integration, use the `webgates-axum` crate.

pub use crate::accounts::Account;
pub use crate::authz::AccessPolicy;
pub use crate::codecs::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims, RegisteredClaims};
pub use crate::credentials::Credentials;
#[cfg(feature = "server")]
pub use crate::cookie_template::CookieTemplate;
pub use crate::groups::Group;
pub use crate::permissions::{PermissionId, Permissions};
pub use crate::roles::Role;
