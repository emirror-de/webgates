//! Typed request-extension models for handler-visible authentication context.
//!
//! These types are inserted into [`tonic::Request`] extensions by the bearer
//! gate middleware and retrieved by gRPC handlers. Each type represents a
//! specific authentication state so that handlers can use Rust's type system
//! to distinguish between authenticated, optional, and static-token flows.
//!
//! # Strict JWT mode
//!
//! On success, the middleware inserts:
//! - `JwtAuthContext` — wraps the decoded account and registered claims.
//!
//! Retrieve it in a handler:
//!
//! ```rust,ignore
//! use webgates_tonic::context::JwtAuthContext;
//! use webgates::accounts::Account;
//! use webgates::roles::Role;
//! use webgates::groups::Group;
//! use tonic::{Request, Response, Status};
//!
//! async fn my_handler(
//!     req: Request<MyRequest>,
//! ) -> Result<Response<MyResponse>, Status> {
//!     let ctx = req.extensions().get::<JwtAuthContext<Role, Group>>()
//!         .ok_or_else(|| Status::unauthenticated("missing auth context"))?;
//!     // ctx.account() and ctx.registered_claims() are now available
//!     todo!()
//! }
//! ```
//!
//! # Optional JWT mode
//!
//! The middleware inserts `OptionalJwtAuthContext`, which wraps
//! `Option<Account>` and `Option<RegisteredClaims>`.
//!
//! # Static-token mode
//!
//! The middleware inserts `StaticTokenAuthorized`, which carries a `bool`
//! indicating whether the provided token matched the configured static token.

use webgates::accounts::Account;
use webgates::authz::access_hierarchy::AccessHierarchy;
use webgates::codecs::jwt::RegisteredClaims;

/// Authentication context inserted by the strict JWT bearer gate.
///
/// Handlers in strict JWT mode can retrieve this type from request extensions
/// after the gate has validated the bearer token and enforced the access
/// policy.
#[derive(Debug, Clone)]
pub struct JwtAuthContext<R, G>
where
    R: AccessHierarchy + Eq + std::fmt::Display + Clone,
    G: Eq + Clone,
{
    /// The decoded, policy-verified account from the JWT payload.
    account: Account<R, G>,
    /// The registered JWT claims (issuer, expiry, etc.) from the token.
    registered_claims: RegisteredClaims,
}

impl<R, G> JwtAuthContext<R, G>
where
    R: AccessHierarchy + Eq + std::fmt::Display + Clone,
    G: Eq + Clone,
{
    /// Create a new auth context from a decoded account and its registered claims.
    pub fn new(account: Account<R, G>, registered_claims: RegisteredClaims) -> Self {
        Self {
            account,
            registered_claims,
        }
    }

    /// Return a reference to the authenticated account.
    pub fn account(&self) -> &Account<R, G> {
        &self.account
    }

    /// Return a reference to the registered JWT claims.
    pub fn registered_claims(&self) -> &RegisteredClaims {
        &self.registered_claims
    }
}

/// Authentication context inserted by the optional JWT bearer gate.
///
/// Handlers in optional JWT mode can retrieve this type from request
/// extensions. When a valid token is present, `account` and `registered_claims`
/// are `Some`. When no valid token is present, both are `None`.
///
/// In optional mode the gate does not enforce the access policy automatically.
/// Handlers must perform any required access checks themselves.
#[derive(Debug, Clone)]
pub struct OptionalJwtAuthContext<R, G>
where
    R: AccessHierarchy + Eq + std::fmt::Display + Clone,
    G: Eq + Clone,
{
    /// The decoded account, or `None` when the request is unauthenticated.
    account: Option<Account<R, G>>,
    /// The registered JWT claims, or `None` when the request is unauthenticated.
    registered_claims: Option<RegisteredClaims>,
}

impl<R, G> OptionalJwtAuthContext<R, G>
where
    R: AccessHierarchy + Eq + std::fmt::Display + Clone,
    G: Eq + Clone,
{
    /// Create a context for an authenticated request.
    pub fn authenticated(account: Account<R, G>, registered_claims: RegisteredClaims) -> Self {
        Self {
            account: Some(account),
            registered_claims: Some(registered_claims),
        }
    }

    /// Create a context for an unauthenticated (anonymous) request.
    pub fn anonymous() -> Self {
        Self {
            account: None,
            registered_claims: None,
        }
    }

    /// Return a reference to the account if the request is authenticated.
    pub fn account(&self) -> Option<&Account<R, G>> {
        self.account.as_ref()
    }

    /// Return a reference to the registered claims if the request is
    /// authenticated.
    pub fn registered_claims(&self) -> Option<&RegisteredClaims> {
        self.registered_claims.as_ref()
    }

    /// Return `true` if the request was authenticated with a valid JWT.
    pub fn is_authenticated(&self) -> bool {
        self.account.is_some()
    }
}

/// Authorization marker inserted by the static-token bearer gate.
///
/// Handlers using static-token mode retrieve this type from request extensions.
/// In strict mode, only authorized requests reach the handler and this is
/// always `true`. In optional mode, all requests reach the handler; check
/// [`StaticTokenAuthorized::is_authorized`] to determine whether the provided
/// token matched.
#[derive(Debug, Clone, Copy)]
pub struct StaticTokenAuthorized(bool);

impl StaticTokenAuthorized {
    /// Create a new instance with the given authorization state.
    pub fn new(authorized: bool) -> Self {
        Self(authorized)
    }

    /// Return `true` if the request token matched the configured static token.
    pub fn is_authorized(&self) -> bool {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webgates::accounts::Account;
    use webgates::codecs::jwt::RegisteredClaims;
    use webgates::groups::Group;
    use webgates::roles::Role;

    /// Strict JWT context preserves account and claims.
    #[test]
    fn jwt_auth_context_accessors() {
        let account = Account::<Role, Group>::new("user");
        let claims = RegisteredClaims::new("issuer", 9999);
        let ctx = JwtAuthContext::new(account.clone(), claims.clone());
        assert_eq!(ctx.account().user_id, account.user_id);
        assert_eq!(ctx.registered_claims().issuer, "issuer");
    }

    /// Optional context correctly identifies authenticated vs. anonymous.
    #[test]
    fn optional_jwt_auth_context_authenticated() {
        let account = Account::<Role, Group>::new("user");
        let claims = RegisteredClaims::new("issuer", 9999);
        let ctx = OptionalJwtAuthContext::authenticated(account, claims);
        assert!(ctx.is_authenticated());
        assert!(ctx.account().is_some());
        assert!(ctx.registered_claims().is_some());
    }

    /// Anonymous optional context returns None for both fields.
    #[test]
    fn optional_jwt_auth_context_anonymous() {
        let ctx = OptionalJwtAuthContext::<Role, Group>::anonymous();
        assert!(!ctx.is_authenticated());
        assert!(ctx.account().is_none());
        assert!(ctx.registered_claims().is_none());
    }

    /// StaticTokenAuthorized exposes the authorization bool faithfully.
    #[test]
    fn static_token_authorized_true() {
        assert!(StaticTokenAuthorized::new(true).is_authorized());
    }

    /// StaticTokenAuthorized with false is correctly reported.
    #[test]
    fn static_token_authorized_false() {
        assert!(!StaticTokenAuthorized::new(false).is_authorized());
    }
}
