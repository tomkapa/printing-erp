//! Time access abstraction.
//!
//! CLAUDE.md §11: production code never calls `Instant::now` / `Utc::now`
//! directly. Instead it takes a [`Clock`]. [`SystemClock`] is the single
//! adapter to the operating-system clock; tests substitute a deterministic
//! fake. Two axes are exposed: [`Clock::now`] (monotonic, for measuring elapsed
//! durations) and [`Clock::now_utc`] (wall clock, for timestamps the app writes
//! itself — token `iat`/`exp`, refresh/reset expiry — rather than relying on
//! database `now()` defaults).

use chrono::{DateTime, Utc};
use std::time::Instant;

/// Source of time, both monotonic and wall-clock.
pub(crate) trait Clock: std::fmt::Debug + Send + Sync + 'static {
    /// Monotonic instant, for measuring elapsed durations.
    fn now(&self) -> Instant;

    /// Wall-clock time, for timestamps the application persists or signs.
    fn now_utc(&self) -> DateTime<Utc>;
}

/// Production [`Clock`] backed by the operating system.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn now_utc(&self) -> DateTime<Utc> {
        // The single `Utc::now()` call site in the tree (CLAUDE.md §11).
        Utc::now()
    }
}

#[cfg(test)]
pub(crate) mod test_clock {
    //! Deterministic [`Clock`] for tests (CLAUDE.md §11). Shared via `Arc`, both
    //! axes advance together so elapsed-duration and wall-clock assertions stay
    //! consistent. Lives here, exported `pub(crate)`, because the crate is a
    //! single binary with no separate test-support crate.

    use super::Clock;
    use chrono::{DateTime, Utc};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// A clock whose time only changes when a test calls [`TestClock::advance`].
    #[derive(Debug)]
    pub(crate) struct TestClock {
        // `Instant` has no public constructor from a wall time, so we anchor one
        // at construction and step both axes by the same `Duration`.
        state: Mutex<(Instant, DateTime<Utc>)>,
    }

    impl TestClock {
        /// Creates a shared clock fixed at `start_utc` until advanced.
        pub(crate) fn new(start_utc: DateTime<Utc>) -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new((Instant::now(), start_utc)),
            })
        }

        /// Moves both the monotonic and wall-clock axes forward by `by`.
        pub(crate) fn advance(&self, by: Duration) {
            let step =
                chrono::Duration::from_std(by).expect("invariant: advance fits chrono::Duration");
            let mut guard = self
                .state
                .lock()
                .expect("invariant: test clock mutex not poisoned");
            guard.0 += by;
            guard.1 += step;
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> Instant {
            self.state
                .lock()
                .expect("invariant: test clock mutex not poisoned")
                .0
        }

        fn now_utc(&self) -> DateTime<Utc> {
            self.state
                .lock()
                .expect("invariant: test clock mutex not poisoned")
                .1
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{Clock as _, TestClock};
        use chrono::{TimeZone as _, Utc};
        use std::time::Duration;

        #[test]
        fn advance_moves_both_axes_by_the_same_delta() {
            let start = Utc.timestamp_opt(1_700_000_000, 0).single().expect("epoch");
            let clock = TestClock::new(start);

            let mono_before = clock.now();
            let utc_before = clock.now_utc();
            assert_eq!(utc_before, start, "fresh clock reads its start time");

            clock.advance(Duration::from_secs(60));

            assert_eq!(
                clock.now_utc(),
                start + chrono::Duration::seconds(60),
                "wall clock advanced by 60s"
            );
            assert_eq!(
                clock.now().saturating_duration_since(mono_before),
                Duration::from_secs(60),
                "monotonic clock advanced by the same 60s"
            );
        }

        #[test]
        fn time_is_frozen_until_advanced() {
            let start = Utc.timestamp_opt(1_700_000_000, 0).single().expect("epoch");
            let clock = TestClock::new(start);
            let first = clock.now_utc();
            let second = clock.now_utc();
            assert_eq!(first, second, "wall clock does not move on its own");
        }
    }
}
