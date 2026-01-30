#[cfg(feature = "fuzz")]
mod inner {
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    static FUZZ_ENABLED: AtomicBool = AtomicBool::new(false);
    static SIMULATED_NANOS: AtomicU64 = AtomicU64::new(0);
    static WAKE_NEEDED: AtomicBool = AtomicBool::new(false);
    static BASE_INSTANT: OnceLock<Instant> = OnceLock::new();

    pub fn now() -> Instant {
        if FUZZ_ENABLED.load(Ordering::Relaxed) {
            let base = *BASE_INSTANT.get().unwrap();
            let nanos = SIMULATED_NANOS.load(Ordering::Relaxed);
            base + Duration::from_nanos(nanos)
        } else {
            Instant::now()
        }
    }

    pub fn enable_fuzz() {
        BASE_INSTANT.get_or_init(Instant::now);
        FUZZ_ENABLED.store(true, Ordering::Release);
    }

    pub fn is_fuzz() -> bool {
        FUZZ_ENABLED.load(Ordering::Relaxed)
    }

    /// Advances simulated time by `nanos` nanoseconds.
    /// Returns the previous value of WAKE_NEEDED (true means the event loop
    /// was waiting on a timed condition and should be woken).
    pub fn advance(nanos: u64) -> bool {
        SIMULATED_NANOS.fetch_add(nanos, Ordering::Relaxed);
        WAKE_NEEDED.swap(false, Ordering::AcqRel)
    }

    pub fn set_wake_needed(needed: bool) {
        WAKE_NEEDED.store(needed, Ordering::Release);
    }

    pub fn simulated_nanos() -> u64 {
        SIMULATED_NANOS.load(Ordering::Relaxed)
    }
}

#[cfg(feature = "fuzz")]
pub use inner::*;

#[cfg(not(feature = "fuzz"))]
pub fn now() -> std::time::Instant {
    std::time::Instant::now()
}

#[cfg(not(feature = "fuzz"))]
pub fn is_fuzz() -> bool {
    false
}

#[cfg(not(feature = "fuzz"))]
pub fn set_wake_needed(_needed: bool) {}
