//! Hybrid logical clock for cross-machine Last-Writer-Wins ordering.
//!
//! HLCs are how Cairn orders events across machines: when folding two
//! machines' log entries into the materialized projection, the entry with
//! the higher HLC wins, with [`MachineId`](crate::MachineId) breaking ties.
//! The clock guarantees strict monotonicity within a process and `witness`es
//! remote values so subsequent local ticks always exceed anything seen.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A hybrid logical clock combining wall-clock time with a logical counter.
///
/// Produces monotonically increasing timestamps (nanoseconds since UNIX epoch)
/// that are always at least as large as the wall clock and strictly increasing
/// even when the wall clock hasn't advanced. Thread-safe via [`AtomicU64`].
pub struct HybridClock {
    last: AtomicU64,
}

impl HybridClock {
    /// Create a new clock initialised to the current wall-clock time.
    pub fn new() -> Self {
        Self {
            last: AtomicU64::new(wall_clock_nanos()),
        }
    }

    /// Create a new clock initialised to `start`, useful for tests and for
    /// restoring a clock from a persisted tip.
    pub fn from_value(start: u64) -> Self {
        Self {
            last: AtomicU64::new(start),
        }
    }

    /// Advance and return a new unique timestamp.
    ///
    /// The returned value is `max(wall_clock, last) + 1`, guaranteeing strict
    /// monotonicity even under rapid successive calls or backward clock skew.
    pub fn tick(&self) -> u64 {
        loop {
            let prev = self.last.load(Ordering::SeqCst);
            let now = wall_clock_nanos();
            let candidate = prev.max(now) + 1;

            if self
                .last
                .compare_exchange(prev, candidate, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return candidate;
            }
        }
    }

    /// Witness a remote HLC, advancing the local clock if necessary.
    ///
    /// After witnessing, `current() >= remote_hlc`. The next [`tick`](Self::tick)
    /// will return a value strictly greater than both the previous local value
    /// and `remote_hlc`.
    pub fn witness(&self, remote_hlc: u64) {
        self.last.fetch_max(remote_hlc, Ordering::SeqCst);
    }

    /// Return the current clock value without advancing it.
    pub fn current(&self) -> u64 {
        self.last.load(Ordering::SeqCst)
    }
}

impl Default for HybridClock {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for HybridClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridClock")
            .field("last", &self.last.load(Ordering::SeqCst))
            .finish()
    }
}

fn wall_clock_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;

    #[test]
    fn tick_is_strictly_monotonic() {
        let clock = HybridClock::new();
        let mut prev = clock.tick();
        for _ in 0..1_000 {
            let next = clock.tick();
            assert!(next > prev, "tick must be strictly increasing");
            prev = next;
        }
    }

    #[test]
    fn tick_advances_beyond_wall_clock() {
        let clock = HybridClock::new();
        let t1 = clock.tick();
        let t2 = clock.tick();
        let t3 = clock.tick();
        assert!(t1 < t2 && t2 < t3);
    }

    #[test]
    fn witness_advances_past_future_remote_value() {
        let clock = HybridClock::new();
        let far_future = clock.current() + 1_000_000_000;
        clock.witness(far_future);
        assert!(clock.current() >= far_future);
        let next = clock.tick();
        assert!(next > far_future, "tick after witness exceeds remote");
    }

    #[test]
    fn witness_with_past_value_does_not_retreat() {
        let clock = HybridClock::new();
        let current = clock.tick();
        let past = current.saturating_sub(1_000_000);
        clock.witness(past);
        assert!(clock.current() >= current);
    }

    #[test]
    fn concurrent_ticks_are_unique() {
        let clock = Arc::new(HybridClock::new());
        let n_threads = 4;
        let ticks_per_thread = 1_000;
        let mut handles = Vec::new();

        for _ in 0..n_threads {
            let clock = clock.clone();
            handles.push(std::thread::spawn(move || {
                let mut values = Vec::with_capacity(ticks_per_thread);
                for _ in 0..ticks_per_thread {
                    values.push(clock.tick());
                }
                values
            }));
        }

        let mut all = HashSet::new();
        for h in handles {
            for v in h.join().unwrap() {
                assert!(all.insert(v), "duplicate tick value across threads");
            }
        }
        assert_eq!(all.len(), n_threads * ticks_per_thread);
    }

    #[test]
    fn default_constructs_a_clock() {
        let _ = HybridClock::default();
    }

    #[test]
    fn from_value_seeds_the_clock() {
        let clock = HybridClock::from_value(1_000_000);
        assert!(clock.current() >= 1_000_000);
        let next = clock.tick();
        assert!(next > 1_000_000);
    }

    #[test]
    fn debug_renders_with_last_field() {
        let clock = HybridClock::from_value(42);
        let d = format!("{clock:?}");
        assert!(d.contains("HybridClock"));
        assert!(d.contains("42"));
    }
}
