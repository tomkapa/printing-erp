//! Delivery of password-reset tokens.
//!
//! The token lifecycle (mint, store-hash, expire, consume) is fully implemented
//! and tested; *delivery* is stubbed behind this trait until the Notifications
//! service (issue #36) provides real email/Zalo transport. The reset token is
//! never returned in an API response — it leaves the system only through a
//! notifier.

use crate::domain::Email;

/// Sends a password-reset token to a user out of band.
///
/// Implementations must be cheap/non-blocking from the request path (the
/// production one will enqueue to the Redis-backed job queue, SPEC.md §Retry).
pub(crate) trait PasswordResetNotifier: Send + Sync + std::fmt::Debug {
    /// Delivers `token` (the raw routable reset token) to `email`.
    fn notify_reset(&self, email: &Email, token: &str);
}

/// Development stub: logs that a reset was requested. The token is PII-adjacent
/// secret material, so it is emitted at `DEBUG` only (stripped by production
/// exporters, CLAUDE.md §2) and never returned to the caller.
#[derive(Debug, Default)]
pub(crate) struct LoggingNotifier;

impl PasswordResetNotifier for LoggingNotifier {
    fn notify_reset(&self, email: &Email, token: &str) {
        tracing::debug!(
            event = "auth.password_reset.dispatch",
            email = email.as_str(),
            token = token,
            "password reset token issued (dev stub; real delivery is #36)",
        );
    }
}
