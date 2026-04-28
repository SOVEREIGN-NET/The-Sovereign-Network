//! Per-observer / per-sponsor rate-limit primitives (observer-admission-8).
//!
//! Provides a deterministic token-bucket suitable for ingress
//! gating in `lib-network` and the HTTP API. Capacities derive
//! from the canonical [`ObserverRateLimitTier`] in `lib-types`.
//!
//! # Scope
//!
//! This module is **policy + math only**. It does not own any
//! mutable global state and performs no I/O. Callers (network
//! layer, API handlers) own the bucket instances they consume.
//!
//! # Sponsor aggregation
//!
//! A sponsor's *aggregate* quota is the sum of their admitted
//! observers' tier capacities, scaled by [`SPONSOR_AGGREGATE_FACTOR`].
//! The factor is < 1.0 so that one rogue observer cannot consume the
//! entire sponsor budget.

use lib_types::ObserverRateLimitTier;

/// Scaling factor applied to the sum of per-observer quotas when
/// computing a sponsor's aggregate ingress budget.
pub const SPONSOR_AGGREGATE_FACTOR: f64 = 0.75;

/// Deterministic token-bucket rate limiter.
///
/// All time inputs are unix seconds. The bucket starts full.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: u32,
    refill_per_sec: f64,
    tokens: f64,
    last_refill: u64,
}

impl TokenBucket {
    /// Construct a bucket with explicit capacity / refill rate.
    pub fn new(capacity: u32, refill_per_sec: f64, now: u64) -> Self {
        Self {
            capacity,
            refill_per_sec,
            tokens: f64::from(capacity),
            last_refill: now,
        }
    }

    /// Construct a bucket sized for the given per-observer tier.
    pub fn for_tier(tier: ObserverRateLimitTier, now: u64) -> Self {
        Self::new(tier.quota_per_minute(), tier.refill_per_second(), now)
    }

    /// Construct a bucket sized for a sponsor's aggregate budget.
    ///
    /// Sums the per-observer quotas across all admitted children and
    /// applies [`SPONSOR_AGGREGATE_FACTOR`].
    pub fn for_sponsor(child_tiers: &[ObserverRateLimitTier], now: u64) -> Self {
        let total: u32 = child_tiers
            .iter()
            .map(|t| t.quota_per_minute())
            .sum::<u32>();
        let scaled = (f64::from(total) * SPONSOR_AGGREGATE_FACTOR).round() as u32;
        let refill = f64::from(scaled) / 60.0;
        Self::new(scaled, refill, now)
    }

    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    pub fn available_tokens(&self) -> f64 {
        self.tokens
    }

    /// Try to consume `n` tokens at time `now`. Refills the bucket
    /// by elapsed seconds * refill rate, capped at capacity, before
    /// the consumption check. Returns `true` iff tokens were debited.
    pub fn try_consume(&mut self, now: u64, n: u32) -> bool {
        self.refill_to(now);
        let cost = f64::from(n);
        if self.tokens + 1e-9 >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }

    fn refill_to(&mut self, now: u64) {
        if now > self.last_refill {
            let elapsed = (now - self.last_refill) as f64;
            self.tokens =
                (self.tokens + elapsed * self.refill_per_sec).min(f64::from(self.capacity));
            self.last_refill = now;
        }
    }
}

/// Compute the aggregate per-minute quota a sponsor may consume across
/// all of their admitted observers, without instantiating a bucket.
///
/// Useful for diagnostics / API responses that expose the budget.
pub fn sponsor_aggregate_quota_per_minute(child_tiers: &[ObserverRateLimitTier]) -> u32 {
    let total: u32 = child_tiers
        .iter()
        .map(|t| t.quota_per_minute())
        .sum::<u32>();
    (f64::from(total) * SPONSOR_AGGREGATE_FACTOR).round() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_tier_capacity_matches_spec() {
        let bucket = TokenBucket::for_tier(ObserverRateLimitTier::Standard, 0);
        assert_eq!(bucket.capacity(), 60);
    }

    #[test]
    fn elevated_tier_capacity_matches_spec() {
        let bucket = TokenBucket::for_tier(ObserverRateLimitTier::Elevated, 0);
        assert_eq!(bucket.capacity(), 300);
    }

    #[test]
    fn organizational_tier_capacity_matches_spec() {
        let bucket = TokenBucket::for_tier(ObserverRateLimitTier::Organizational, 0);
        assert_eq!(bucket.capacity(), 1_200);
    }

    #[test]
    fn bucket_starts_full_and_drains() {
        let mut bucket = TokenBucket::for_tier(ObserverRateLimitTier::Standard, 100);
        // Consume the full capacity at the same instant
        for _ in 0..60 {
            assert!(bucket.try_consume(100, 1));
        }
        // Next request at the same instant must fail (no refill yet).
        assert!(!bucket.try_consume(100, 1));
    }

    #[test]
    fn bucket_refills_over_time() {
        let mut bucket = TokenBucket::for_tier(ObserverRateLimitTier::Standard, 100);
        // Drain
        for _ in 0..60 {
            assert!(bucket.try_consume(100, 1));
        }
        // 60 seconds later the bucket has refilled to capacity.
        assert!(bucket.try_consume(160, 60));
        assert!(!bucket.try_consume(160, 1));
    }

    #[test]
    fn bucket_caps_at_capacity_after_long_idle() {
        let mut bucket = TokenBucket::for_tier(ObserverRateLimitTier::Standard, 0);
        // After an hour of idleness, available tokens cap at capacity.
        assert!(bucket.try_consume(3_600, 60));
        assert!(!bucket.try_consume(3_600, 1));
    }

    #[test]
    fn try_consume_zero_is_always_ok() {
        let mut bucket = TokenBucket::for_tier(ObserverRateLimitTier::Standard, 0);
        assert!(bucket.try_consume(0, 0));
    }

    #[test]
    fn try_consume_more_than_capacity_fails() {
        let mut bucket = TokenBucket::for_tier(ObserverRateLimitTier::Standard, 0);
        assert!(!bucket.try_consume(0, 61));
    }

    #[test]
    fn sponsor_aggregate_sums_and_scales() {
        // 60 + 300 = 360, scaled by 0.75 = 270.
        let q = sponsor_aggregate_quota_per_minute(&[
            ObserverRateLimitTier::Standard,
            ObserverRateLimitTier::Elevated,
        ]);
        assert_eq!(q, 270);
    }

    #[test]
    fn sponsor_bucket_uses_aggregate_capacity() {
        let bucket = TokenBucket::for_sponsor(
            &[
                ObserverRateLimitTier::Standard,
                ObserverRateLimitTier::Elevated,
            ],
            0,
        );
        assert_eq!(bucket.capacity(), 270);
    }

    #[test]
    fn sponsor_bucket_with_no_children_has_zero_capacity() {
        let bucket = TokenBucket::for_sponsor(&[], 0);
        assert_eq!(bucket.capacity(), 0);
        // And cannot serve even one request.
        let mut b = bucket;
        assert!(!b.try_consume(0, 1));
    }
}
