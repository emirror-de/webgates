//! Session context types shared across issuance, renewal, and revocation flows.
//!
//! This module defines framework-agnostic request context data used by the
//! session layer to record who initiated a session change and under which
//! runtime conditions it happened.
//!
//! The initial scaffold intentionally keeps the model small and transport-free.
//! Additional fields can be added as concrete persistence and audit needs become
//! clearer during later checklist items.

use std::collections::BTreeMap;

/// Immutable metadata describing the caller and environment for a session
/// operation.
///
/// This type is transport agnostic by design. Adapters may derive values from
/// HTTP requests, RPC metadata, CLI invocations, or background jobs before
/// passing them into session services.
///
/// # Examples
///
/// ```
/// use webgates_sessions::context::{SessionActor, SessionClientContext, SessionContext};
///
/// let context = SessionContext::new()
///     .with_actor(SessionActor::Subject {
///         subject_id: "user-42".to_string(),
///     })
///     .with_correlation_id("req-abc-123")
///     .with_client(
///         SessionClientContext::new()
///             .with_ip_address("203.0.113.5")
///             .with_user_agent("MyApp/2.0"),
///     )
///     .with_attribute("entrypoint", "login");
///
/// assert!(!context.is_empty());
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionContext {
    /// Stable identifier for the logical actor that initiated the operation.
    pub actor: Option<SessionActor>,
    /// Correlation identifier used to trace a session workflow across layers.
    pub correlation_id: Option<String>,
    /// Client environment metadata collected at the boundary.
    pub client: SessionClientContext,
    /// Additional non-sensitive attributes associated with the operation.
    pub attributes: BTreeMap<String, String>,
}

impl SessionContext {
    /// Creates an empty context with no actor or client metadata.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the actor that initiated the session operation.
    #[must_use]
    pub fn with_actor(mut self, actor: SessionActor) -> Self {
        self.actor = Some(actor);
        self
    }

    /// Sets the correlation identifier for the current workflow.
    #[must_use]
    pub fn with_correlation_id(mut self, correlation_id: impl Into<String>) -> Self {
        self.correlation_id = Some(correlation_id.into());
        self
    }

    /// Replaces the client metadata associated with the current workflow.
    #[must_use]
    pub fn with_client(mut self, client: SessionClientContext) -> Self {
        self.client = client;
        self
    }

    /// Inserts a single non-sensitive attribute into the context.
    #[must_use]
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Returns `true` when the context contains no actor, correlation id,
    /// client metadata, or attributes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.actor.is_none()
            && self.correlation_id.is_none()
            && self.client.is_empty()
            && self.attributes.is_empty()
    }
}

/// Describes the principal that triggered a session change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionActor {
    /// The authenticated account or subject that owns the session.
    Subject {
        /// Stable identifier of the authenticated subject.
        subject_id: String,
    },
    /// An administrator or operator acting on behalf of another subject.
    Delegate {
        /// Stable identifier of the acting principal.
        actor_id: String,
        /// Free-form reason or source for the delegated operation.
        reason: Option<String>,
    },
    /// A system-initiated background process.
    System {
        /// Stable name of the service or component.
        service: String,
    },
}

/// Client-origin metadata captured at a trust boundary.
///
/// Fields are optional because not every adapter or runtime can provide every
/// value safely or reliably.
///
/// # Examples
///
/// ```
/// use webgates_sessions::context::SessionClientContext;
///
/// let client = SessionClientContext::new()
///     .with_ip_address("203.0.113.5")
///     .with_user_agent("MyApp/2.0")
///     .with_device_id("device-abc");
///
/// assert!(!client.is_empty());
/// assert_eq!(client.ip_address.as_deref(), Some("203.0.113.5"));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionClientContext {
    /// User agent or equivalent client identifier.
    pub user_agent: Option<String>,
    /// Source IP address recorded as text to avoid transport-specific types.
    pub ip_address: Option<String>,
    /// Stable device identifier when the outer system provides one.
    pub device_id: Option<String>,
}

impl SessionClientContext {
    /// Creates an empty client context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the user agent value.
    #[must_use]
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Sets the source IP address.
    #[must_use]
    pub fn with_ip_address(mut self, ip_address: impl Into<String>) -> Self {
        self.ip_address = Some(ip_address.into());
        self
    }

    /// Sets the stable device identifier.
    #[must_use]
    pub fn with_device_id(mut self, device_id: impl Into<String>) -> Self {
        self.device_id = Some(device_id.into());
        self
    }

    /// Returns `true` when no client metadata is present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.user_agent.is_none() && self.ip_address.is_none() && self.device_id.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionActor, SessionClientContext, SessionContext};

    #[test]
    fn empty_context_reports_empty() {
        let context = SessionContext::new();

        assert!(context.is_empty());
    }

    #[test]
    fn populated_context_reports_not_empty() {
        let context = SessionContext::new()
            .with_actor(SessionActor::Subject {
                subject_id: "user-123".to_string(),
            })
            .with_correlation_id("req-456")
            .with_client(
                SessionClientContext::new()
                    .with_user_agent("test-agent")
                    .with_ip_address("127.0.0.1"),
            )
            .with_attribute("entrypoint", "login");

        assert!(!context.is_empty());
    }

    #[test]
    fn empty_client_context_reports_empty() {
        let client = SessionClientContext::new();

        assert!(client.is_empty());
    }

    #[test]
    fn populated_client_context_reports_not_empty() {
        let client = SessionClientContext::new().with_device_id("device-123");

        assert!(!client.is_empty());
    }
}
