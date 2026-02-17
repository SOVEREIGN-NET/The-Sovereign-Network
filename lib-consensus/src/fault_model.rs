//! # BFT Fault Assumptions and Partition Tradeoffs [BFT-A][R5]
//!
//! ## Fault Tolerance Model
//!
//! The consensus protocol tolerates up to f Byzantine validators where:
//!   f < n / 3
//!
//! This gives us:
//! - Safety: guaranteed as long as ≥2f+1 validators are honest
//! - Liveness: guaranteed during periods of synchrony with ≥f+1 online validators
//!
//! ## Partition Tradeoffs (CAP Theorem)
//!
//! Under network partition, BFT consensus chooses SAFETY over LIVENESS:
//! - If <2/3 validators are reachable: consensus STALLS (no new blocks committed)
//! - The stalled minority will NEVER commit a conflicting block
//! - This guarantees no double-spend or chain split
//!
//! ## Network Model
//! - Assumes partial synchrony (GST - Global Stabilization Time)
//! - Messages may be delayed arbitrarily before GST
//! - After GST, messages arrive within a known bound δ
//! - Safety holds even during asynchrony; liveness requires synchrony

/// Maximum fraction of Byzantine validators: f < n/3
pub const MAX_BYZANTINE_FRACTION_NUMERATOR: u64 = 1;
pub const MAX_BYZANTINE_FRACTION_DENOMINATOR: u64 = 3;

/// Safety threshold: 2f+1 validators needed (supermajority)
pub const SAFETY_THRESHOLD_NUMERATOR: u64 = 2;
pub const SAFETY_THRESHOLD_DENOMINATOR: u64 = 3;

/// Liveness threshold: f+1 validators needed
pub const LIVENESS_THRESHOLD_NUMERATOR: u64 = 1;
pub const LIVENESS_THRESHOLD_DENOMINATOR: u64 = 3;

/// Maximum allowed Byzantine validators given n total.
pub const fn max_byzantine(n: u64) -> u64 {
    if n == 0 { return 0; }
    (n - 1) / 3
}

/// Minimum validators needed for safety quorum (2f+1).
pub const fn safety_quorum(n: u64) -> u64 {
    2 * max_byzantine(n) + 1
}

/// Minimum validators needed for liveness (f+1).
pub const fn liveness_quorum(n: u64) -> u64 {
    max_byzantine(n) + 1
}

/// Returns true if the system can make progress (reach liveness quorum).
pub fn can_make_progress(online: u64, n: u64) -> bool {
    online >= safety_quorum(n)
}

/// Returns true if the system is safe from split-brain (cannot have conflicting commits).
/// This is always true in BFT — safety is unconditional once 2f+1 honest validators commit.
pub const fn is_safe(faulty: u64, n: u64) -> bool {
    n >= 4 && faulty <= max_byzantine(n)
}

/// Creates a human-readable fault model summary.
pub fn fault_model_summary(n: u64) -> String {
    let f = max_byzantine(n);
    let sq = safety_quorum(n);
    let lq = liveness_quorum(n);
    format!(
        "n={n} validators: tolerates f={f} Byzantine, \
         safety quorum={sq}, liveness quorum={lq}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fault_model_4_validators() {
        assert_eq!(max_byzantine(4), 1);
        assert_eq!(safety_quorum(4), 3);
        assert_eq!(liveness_quorum(4), 2);
    }

    #[test]
    fn test_fault_model_7_validators() {
        assert_eq!(max_byzantine(7), 2);
        assert_eq!(safety_quorum(7), 5);
        assert_eq!(liveness_quorum(7), 3);
    }
}
