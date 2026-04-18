//! Per-client token-bucket rate limiter.
//!
//! Used by the offer poller to cap how often a single client's
//! offer-ingest path consumes CPU. Semantics:
//!
//! - Each bucket holds up to `burst_cap` tokens.
//! - On `try_consume`, the bucket is refilled proportional to the
//!   elapsed time since the last refill at `refill_per_sec` tokens per
//!   second, capped at `burst_cap`.
//! - If at least one token is available, one is consumed and the call
//!   returns `true`; otherwise the bucket is untouched and the call
//!   returns `false`.
//!
//! The implementation is deliberately synchronous and tokio-free: the
//! caller threads an explicit `now: Instant` in. That lets the offer
//! poller reuse its per-cycle `Instant::now()` and makes unit tests
//! deterministic without `tokio::time::pause`.

use std::time::Instant;

/// One per-client token bucket.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    /// Current token count. Fractional so refill math is exact.
    tokens: f64,
    /// When `tokens` was last refilled.
    last_refill: Instant,
    /// Maximum token count. `tokens` is clamped to this on every refill.
    burst_cap: f64,
    /// Refill rate in tokens per second.
    refill_per_sec: f64,
}

impl TokenBucket {
    /// Build a new bucket starting full (`tokens = burst_cap`).
    ///
    /// # Panics
    ///
    /// Panics if `burst_cap <= 0.0`, `refill_per_sec <= 0.0`, or either
    /// argument is not finite. Callers are expected to validate config
    /// values before construction.
    #[must_use]
    pub fn new(burst_cap: u32, refill_per_sec: f64, now: Instant) -> Self {
        assert!(
            burst_cap > 0 && refill_per_sec.is_finite() && refill_per_sec > 0.0,
            "TokenBucket requires burst_cap > 0 and finite, positive refill_per_sec",
        );
        let cap = f64::from(burst_cap);
        Self {
            tokens: cap,
            last_refill: now,
            burst_cap: cap,
            refill_per_sec,
        }
    }

    /// Attempt to consume one token. Returns `true` on success.
    ///
    /// Refills the bucket first based on elapsed wall time since the
    /// previous refill, clamped to `burst_cap`.
    pub fn try_consume(&mut self, now: Instant) -> bool {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.burst_cap);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn starts_full_burst_cap_then_empties() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(3, 1.0, t0);
        assert!(b.try_consume(t0));
        assert!(b.try_consume(t0));
        assert!(b.try_consume(t0));
        // Fourth consume in the same instant is rejected.
        assert!(!b.try_consume(t0));
    }

    #[test]
    fn refills_on_elapsed_time() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(2, 1.0, t0);
        assert!(b.try_consume(t0));
        assert!(b.try_consume(t0));
        assert!(!b.try_consume(t0));
        // 2 seconds later, two tokens' worth have refilled.
        let t1 = t0 + Duration::from_secs(2);
        assert!(b.try_consume(t1));
        assert!(b.try_consume(t1));
        assert!(!b.try_consume(t1));
    }

    #[test]
    fn refill_caps_at_burst() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(3, 1.0, t0);
        // Drain.
        for _ in 0..3 {
            assert!(b.try_consume(t0));
        }
        // A huge gap refills but caps at burst.
        let t_far = t0 + Duration::from_secs(10_000);
        for _ in 0..3 {
            assert!(b.try_consume(t_far));
        }
        assert!(!b.try_consume(t_far));
    }

    #[test]
    fn fractional_refill_accumulates() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(1, 1.0, t0);
        // Drain.
        assert!(b.try_consume(t0));
        // 0.4 s → 0.4 tokens — not enough.
        let t_half = t0 + Duration::from_millis(400);
        assert!(!b.try_consume(t_half));
        // Another 0.7 s on top → 1.1 accumulated, enough.
        let t_full = t_half + Duration::from_millis(700);
        assert!(b.try_consume(t_full));
    }

    #[test]
    #[should_panic]
    fn rejects_zero_burst() {
        let _ = TokenBucket::new(0, 1.0, Instant::now());
    }

    #[test]
    #[should_panic]
    fn rejects_non_finite_refill() {
        let _ = TokenBucket::new(3, f64::NAN, Instant::now());
    }
}
