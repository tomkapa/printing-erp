//! Time access abstraction.
//!
//! CLAUDE.md §11: production code never calls `Instant::now` / `Utc::now`
//! directly. Instead it takes a [`Clock`]. [`SystemClock`] is the single
//! adapter to the operating-system clock; tests substitute a deterministic
//! fake. Wall-clock (`now_utc`) is added here once code writes timestamps
//! itself rather than relying on database defaults.

use std::time::Instant;

/// Source of monotonic time.
pub(crate) trait Clock: std::fmt::Debug + Send + Sync + 'static {
    /// Monotonic instant, for measuring elapsed durations.
    fn now(&self) -> Instant;
}

/// Production [`Clock`] backed by the operating system.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}
