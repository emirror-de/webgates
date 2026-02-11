//! Common types and functions for quick imports.

#[cfg(feature = "server")]
mod server_impl {
    pub use crate::authz::AccessPolicy;
    pub use crate::codecs::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims, RegisteredClaims};
    pub use crate::cookie_template::CookieTemplate;
    pub use crate::gate::Gate;
}

#[cfg(feature = "server")]
pub use server_impl::*;

pub use crate::accounts::Account;
pub use crate::credentials::Credentials;
pub use crate::groups::Group;
pub use crate::permissions::{PermissionId, Permissions};
pub use crate::roles::Role;
