//! Audit logging utilities for sensitive operations.
//!
//! This module is intentionally minimal and only defines functions when the
//! `audit-logging` feature is enabled. All call sites are also feature-gated,
//! so there is no need for separate enabled/disabled submodules or no-op
//! fallbacks here.
//!
//! Security notes:
//! - Never log secrets, passwords, raw tokens, or JWT contents.
//! - Prefer stable identifiers (UUID/user_id), reason codes, and support codes.
//! - Keep spans/events coarse and avoid leaking internal state.
//!
//! Enable via Cargo features (in the depending crate):
//! - `axum-gate = { version = "1", features = ["audit-logging"] }`
//!
//! Environment and subscriber configuration are left to the application.

use tracing::{Level, Span, event, span};
use uuid::Uuid;

#[cfg(feature = "prometheus")]
use std::time::Instant;

const TARGET: &str = "axum_gate::audit";

/// Creates a request-scoped span with basic HTTP metadata.
///
/// Fields:
/// - method: HTTP method (e.g., GET)
/// - path: Request path (no query string)
/// - request_id: Optional stable identifier for correlation (header/correlation id)
pub fn request_span(method: &str, path: &str, request_id: Option<&str>) -> Span {
    match request_id {
        Some(id) => span!(target: TARGET, Level::INFO, "request", %method, %path, request_id = %id),
        None => span!(target: TARGET, Level::INFO, "request", %method, %path),
    }
}

/// Creates a span for authorization checks.
///
/// Fields:
/// - account_id: Optional internal stable identifier
/// - role: Optional active role label
pub fn authorization_span(account_id: Option<&Uuid>, role: Option<&str>) -> Span {
    match (account_id, role) {
        (Some(id), Some(role)) => {
            span!(target: TARGET, Level::INFO, "authz.check", account_id = %id, role = %role)
        }
        (Some(id), None) => span!(target: TARGET, Level::INFO, "authz.check", account_id = %id),
        (None, Some(role)) => span!(target: TARGET, Level::INFO, "authz.check", role = %role),
        (None, None) => span!(target: TARGET, Level::INFO, "authz.check"),
    }
}

/// Records an authorization success decision.
pub fn authorized(account_id: &Uuid, role: Option<&str>) {
    match role {
        Some(r) => {
            event!(target: TARGET, Level::INFO, account_id = %account_id, role = %r, "authorized")
        }
        None => event!(target: TARGET, Level::INFO, account_id = %account_id, "authorized"),
    }

    #[cfg(feature = "prometheus")]
    if let Some(m) = prometheus_metrics::metrics() {
        m.authz_authorized.inc();
    }
}

/// Records an authorization denial decision with a coarse-grained reason code.
///
/// Avoid logging sensitive policy internals; prefer stable reason codes.
pub fn denied(account_id: Option<&Uuid>, reason_code: &str) {
    match account_id {
        Some(id) => {
            event!(target: TARGET, Level::WARN, account_id = %id, reason = %reason_code, "denied")
        }
        None => event!(target: TARGET, Level::WARN, reason = %reason_code, "denied"),
    }

    #[cfg(feature = "prometheus")]
    if let Some(m) = prometheus_metrics::metrics() {
        m.authz_denied.with_label_values(&[reason_code]).inc();
    }
}

/// Records that a JWT had an invalid issuer.
pub fn jwt_invalid_issuer(expected: &str, actual: &str) {
    event!(
        target: TARGET,
        Level::WARN,
        expected_issuer = %expected,
        actual_issuer = %actual,
        "jwt_invalid_issuer"
    );

    #[cfg(feature = "prometheus")]
    if let Some(m) = prometheus_metrics::metrics() {
        m.jwt_invalid
            .with_label_values(&[prometheus_metrics::JwtInvalidKind::Issuer.as_ref()])
            .inc();
    }
}

/// Records that a JWT token was otherwise invalid (expired, signature, etc.).
pub fn jwt_invalid_token(summary: &str) {
    event!(target: TARGET, Level::WARN, error = %summary, "jwt_invalid_token");

    #[cfg(feature = "prometheus")]
    if let Some(m) = prometheus_metrics::metrics() {
        m.jwt_invalid
            .with_label_values(&[prometheus_metrics::JwtInvalidKind::Token.as_ref()])
            .inc();
    }
}

/// Records the start of an account deletion workflow.
pub fn account_delete_start(user_id: &str, account_id: &Uuid) {
    event!(
        target: TARGET,
        Level::INFO,
        %user_id,
        account_id = %account_id,
        "account_delete_start"
    );

    #[cfg(feature = "prometheus")]
    if let Some(m) = prometheus_metrics::metrics() {
        m.account_delete_outcome
            .with_label_values(&[
                prometheus_metrics::AccountDeleteOutcome::Start.as_ref(),
                prometheus_metrics::SecretRestored::None_.as_ref(),
            ])
            .inc();
    }
}

/// Records a successful account deletion.
pub fn account_delete_success(user_id: &str, account_id: &Uuid) {
    event!(
        target: TARGET,
        Level::INFO,
        %user_id,
        account_id = %account_id,
        "account_delete_success"
    );

    #[cfg(feature = "prometheus")]
    if let Some(m) = prometheus_metrics::metrics() {
        m.account_delete_outcome
            .with_label_values(&[
                prometheus_metrics::AccountDeleteOutcome::Success.as_ref(),
                prometheus_metrics::SecretRestored::None_.as_ref(),
            ])
            .inc();
    }
}

/// Records an account deletion failure and the outcome of any compensating action.
pub fn account_delete_failure(
    user_id: &str,
    account_id: &Uuid,
    secret_restored: Option<bool>,
    error_summary: &str,
) {
    match secret_restored {
        Some(true) => event!(
            target: TARGET,
            Level::ERROR,
            %user_id,
            account_id = %account_id,
            error = %error_summary,
            secret_restored = true,
            "account_delete_failure"
        ),
        Some(false) => event!(
            target: TARGET,
            Level::ERROR,
            %user_id,
            account_id = %account_id,
            error = %error_summary,
            secret_restored = false,
            "account_delete_failure"
        ),
        None => event!(
            target: TARGET,
            Level::ERROR,
            %user_id,
            account_id = %account_id,
            error = %error_summary,
            "account_delete_failure"
        ),
    }

    #[cfg(feature = "prometheus")]
    if let Some(m) = prometheus_metrics::metrics() {
        use prometheus_metrics::{AccountDeleteOutcome, SecretRestored};
        let sr = match secret_restored {
            Some(true) => SecretRestored::True,
            Some(false) => SecretRestored::False,
            None => SecretRestored::None_,
        };
        m.account_delete_outcome
            .with_label_values(&[AccountDeleteOutcome::Failure.as_ref(), sr.as_ref()])
            .inc();
    }
}

/// Records a newly created account.
pub fn account_created(user_id: &str, account_id: &Uuid) {
    event!(
        target: TARGET,
        Level::INFO,
        %user_id,
        account_id = %account_id,
        "account_created"
    );

    #[cfg(feature = "prometheus")]
    if let Some(m) = prometheus_metrics::metrics() {
        m.account_insert_outcome
            .with_label_values(&[
                prometheus_metrics::AccountInsertOutcome::Success.as_ref(),
                "none",
            ])
            .inc();
    }
}

/// Records an account insertion failure with a coarse-grained reason code.
///
/// The reason should be a low-cardinality, stable code (e.g., "duplicate_user_id",
/// "repo_error") to keep Prometheus label cardinality under control.
pub fn account_insert_failure(user_id: &str, reason_code: &str) {
    event!(
        target: TARGET,
        Level::ERROR,
        %user_id,
        reason = %reason_code,
        "account_insert_failure"
    );

    #[cfg(feature = "prometheus")]
    if let Some(m) = prometheus_metrics::metrics() {
        m.account_insert_outcome
            .with_label_values(&[
                prometheus_metrics::AccountInsertOutcome::Failure.as_ref(),
                reason_code,
            ])
            .inc();
    }
}

// ---------------------------------------------------------------------------
// Authorization latency histogram helper
// ---------------------------------------------------------------------------

#[cfg(feature = "prometheus")]
/// Outcome of an authorization decision for latency observation.
#[derive(Copy, Clone, Debug)]
pub enum AuthzOutcome {
    /// Authorization succeeded.
    Authorized,
    /// Authorization was denied.
    Denied,
}

#[cfg(feature = "prometheus")]
impl AuthzOutcome {
    fn as_label(&self) -> &'static str {
        match self {
            AuthzOutcome::Authorized => "authorized",
            AuthzOutcome::Denied => "denied",
        }
    }
}

#[cfg(feature = "prometheus")]
/// Observes the elapsed time between `start` and now for an authorization decision.
///
/// Typical usage pattern at a call site:
/// ```ignore
/// let start = Instant::now();
/// // ... perform authz logic ...
/// audit::authorized(account_id, role);
/// audit::observe_authz_latency(start, AuthzOutcome::Authorized);
/// ```
pub fn observe_authz_latency(start: Instant, outcome: AuthzOutcome) {
    if let Some(m) = prometheus_metrics::metrics() {
        let elapsed = start.elapsed().as_secs_f64();
        m.authz_decision_latency
            .with_label_values(&[outcome.as_label()])
            .observe(elapsed);
    }
}

#[cfg(feature = "prometheus")]
/// Prometheus metrics integration for axum-gate authentication events.
///
/// This module provides Prometheus metrics collection for monitoring authentication
/// and authorization events. Metrics include authorization decisions, JWT validation
/// failures, account management operations, and authorization decision latency.
///
/// # Features
///
/// This module is only available when the `prometheus` feature is enabled.
///
/// # Usage
///
/// ```rust
/// use axum_gate::audit::prometheus_metrics;
/// # fn main() -> Result<(), prometheus::Error> {
/// // Install metrics into the default registry
/// prometheus_metrics::install_prometheus_metrics()?;
///
/// // Access metrics for custom instrumentation
/// if let Some(metrics) = prometheus_metrics::metrics() {
///     metrics.authz_authorized.inc();
/// }
/// # Ok(())
/// # }
/// ```
pub mod prometheus_metrics {
    use prometheus::{Counter, CounterVec, HistogramOpts, HistogramVec, Registry};
    use std::sync::OnceLock;
    use strum::AsRefStr;

    /// Categories of JWT validation failures for metrics labeling.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, AsRefStr)]
    pub enum JwtInvalidKind {
        /// JWT issuer validation failed.
        Issuer,
        /// JWT token format or signature validation failed.
        Token,
    }

    /// Outcomes of account deletion operations for metrics labeling.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, AsRefStr)]
    pub enum AccountDeleteOutcome {
        /// Account deletion operation started.
        Start,
        /// Account deletion completed successfully.
        Success,
        /// Account deletion failed.
        Failure,
    }

    /// Whether account secrets were restored during operations for metrics labeling.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, AsRefStr)]
    pub enum SecretRestored {
        /// Secret was restored during the operation.
        True,
        /// Secret was not restored during the operation.
        False,
        /// Secret restoration status not applicable or unknown.
        #[strum(serialize = "none")]
        None_,
    }

    /// Outcomes of account insertion operations for metrics labeling.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, AsRefStr)]
    pub enum AccountInsertOutcome {
        /// Account insertion completed successfully.
        Success,
        /// Account insertion failed.
        Failure,
    }

    /// Outcomes of JWT validation for latency labeling.
    #[derive(Copy, Clone, Debug)]
    pub enum JwtValidationOutcome {
        #[doc = "JWT was successfully validated."]
        Valid,
        #[doc = "JWT failed issuer validation (issuer mismatch)."]
        InvalidIssuer,
        #[doc = "JWT was invalid for other reasons (decode failure, signature, format, etc.)."]
        InvalidToken,
    }

    impl JwtValidationOutcome {
        #[doc = "Returns the stable label value used in `axum_gate_jwt_validation_seconds`."]
        pub fn as_label(&self) -> &'static str {
            match self {
                JwtValidationOutcome::Valid => "valid",
                JwtValidationOutcome::InvalidIssuer => "invalid_issuer",
                JwtValidationOutcome::InvalidToken => "invalid_token",
            }
        }
    }

    /// Collection of Prometheus metrics for axum-gate operations.
    pub struct Metrics {
        /// Counter for successful authorization decisions.
        pub authz_authorized: Counter,
        /// Counter for denied authorization attempts, labeled by reason.
        pub authz_denied: CounterVec,
        /// Counter for invalid JWT tokens, labeled by failure kind.
        pub jwt_invalid: CounterVec,
        /// Counter for account deletion operations, labeled by outcome and secret restoration status.
        pub account_delete_outcome: CounterVec,
        /// Counter for account insertion operations, labeled by outcome and reason.
        pub account_insert_outcome: CounterVec,
        /// Histogram for authorization decision latency, labeled by outcome.
        pub authz_decision_latency: HistogramVec,
        /// Histogram for JWT validation latency, labeled by outcome.
        pub jwt_validation_latency: HistogramVec,
    }

    static METRICS: OnceLock<Metrics> = OnceLock::new();

    /// Returns a reference to the installed metrics, if any.
    ///
    /// Returns `None` if metrics have not been installed via [`install_prometheus_metrics`]
    /// or [`install_prometheus_metrics_with_registry`].
    pub fn metrics() -> Option<&'static Metrics> {
        METRICS.get()
    }

    /// Installs Prometheus metrics into the default registry.
    ///
    /// Safe to call multiple times; metrics are only registered once.
    pub fn install_prometheus_metrics() -> Result<(), prometheus::Error> {
        install_prometheus_metrics_with_registry(prometheus::default_registry())
    }

    /// Installs Prometheus metrics into the provided registry.
    ///
    /// Safe to call multiple times; metrics are only registered once.
    pub fn install_prometheus_metrics_with_registry(
        registry: &Registry,
    ) -> Result<(), prometheus::Error> {
        if METRICS.get().is_some() {
            return Ok(()); // Already installed
        }

        let authz_authorized = Counter::new(
            "axum_gate_authz_authorized_total",
            "Total number of successful authorization decisions",
        )?;

        let authz_denied = CounterVec::new(
            prometheus::Opts::new(
                "axum_gate_authz_denied_total",
                "Total number of denied authorization attempts",
            ),
            &["reason"],
        )?;

        let jwt_invalid = CounterVec::new(
            prometheus::Opts::new(
                "axum_gate_jwt_invalid_total",
                "Total number of invalid JWT tokens",
            ),
            &["kind"],
        )?;

        let account_delete_outcome = CounterVec::new(
            prometheus::Opts::new(
                "axum_gate_account_delete_outcome_total",
                "Total number of account deletion operations",
            ),
            &["outcome", "secret_restored"],
        )?;

        let account_insert_outcome = CounterVec::new(
            prometheus::Opts::new(
                "axum_gate_account_insert_outcome_total",
                "Total number of account insertion operations",
            ),
            &["outcome", "reason"],
        )?;

        let authz_decision_latency = HistogramVec::new(
            HistogramOpts::new(
                "axum_gate_authz_decision_seconds",
                "Authorization decision latency in seconds",
            )
            .buckets(vec![
                0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
            ]),
            &["outcome"],
        )?;

        let jwt_validation_latency = HistogramVec::new(
            HistogramOpts::new(
                "axum_gate_jwt_validation_seconds",
                "JWT validation latency in seconds",
            )
            .buckets(vec![
                0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5,
            ]),
            &["outcome"],
        )?;

        // Register metrics with the provided registry
        registry.register(Box::new(authz_authorized.clone()))?;
        registry.register(Box::new(authz_denied.clone()))?;
        registry.register(Box::new(jwt_invalid.clone()))?;
        registry.register(Box::new(account_delete_outcome.clone()))?;
        registry.register(Box::new(account_insert_outcome.clone()))?;
        registry.register(Box::new(authz_decision_latency.clone()))?;
        registry.register(Box::new(jwt_validation_latency.clone()))?;

        // Store metrics in static for global access
        let metrics = Metrics {
            authz_authorized,
            authz_denied,
            jwt_invalid,
            account_delete_outcome,
            account_insert_outcome,
            authz_decision_latency,
            jwt_validation_latency,
        };

        let _ = METRICS.set(metrics);
        Ok(())
    }

    /// Observe JWT validation latency with an outcome label.
    ///
    /// Capture `let start = Instant::now();` immediately before decoding/validating
    /// and call this after the validation result is known.
    pub fn observe_jwt_validation_latency(
        start: std::time::Instant,
        outcome: JwtValidationOutcome,
    ) {
        if let Some(m) = metrics() {
            let elapsed = start.elapsed().as_secs_f64();
            m.jwt_validation_latency
                .with_label_values(&[outcome.as_label()])
                .observe(elapsed);
        }
    }
}
