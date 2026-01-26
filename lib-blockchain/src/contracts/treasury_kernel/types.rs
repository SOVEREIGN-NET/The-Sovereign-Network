//! Treasury Kernel Core Types
//!
//! Defines the fundamental data structures for the Treasury Kernel:
//! - KernelState: Dedup maps, pool tracking, last processed epoch
//! - RejectionReason: 5-check validation failure codes
//! - KernelStats: Monitoring statistics

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Rejection reason codes for UBI claims (5 checks)
///
/// When a claim fails validation, the Kernel emits UbiClaimRejected with one of these codes.
/// Citizens never see error details (silent failure for privacy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RejectionReason {
    /// Check 1 failed: Citizen not in registry
    NotACitizen = 1,

    /// Check 2 failed: Citizen has been revoked
    AlreadyRevoked = 2,

    /// Check 4 failed: Citizen already claimed this epoch
    AlreadyClaimedEpoch = 3,

    /// Check 5 failed: Pool exhausted for this epoch
    PoolExhausted = 4,

    /// Check 3 failed: Citizenship epoch hasn't arrived yet
    EligibilityNotMet = 5,
}

impl std::fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotACitizen => write!(f, "Not a citizen"),
            Self::AlreadyRevoked => write!(f, "Citizen revoked"),
            Self::AlreadyClaimedEpoch => write!(f, "Already claimed this epoch"),
            Self::PoolExhausted => write!(f, "Pool exhausted"),
            Self::EligibilityNotMet => write!(f, "Eligibility not met"),
        }
    }
}

/// Kernel state tracking for UBI distribution
///
/// **Consensus-Critical**: All fields must be persisted for crash recovery.
/// Dedup state prevents double-minting if Kernel crashes mid-distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelState {
    /// Deduplication tracking: citizen_id -> {epoch -> bool}
    /// Prevents double-minting after crashes
    /// Key: citizen_id [u8; 32]
    /// Value: HashMap<epoch, claimed_flag>
    pub already_claimed: HashMap<[u8; 32], HashMap<u64, bool>>,

    /// Pool distribution tracking: epoch -> total_distributed
    /// Enforces 1,000,000 SOV hard cap per epoch
    /// Key: epoch
    /// Value: cumulative SOV distributed in that epoch
    pub total_distributed: HashMap<u64, u64>,

    /// Last processed epoch (for idempotency and recovery)
    /// If current_epoch == last_processed_epoch, skip distribution
    pub last_processed_epoch: Option<u64>,

    /// Monitoring statistics
    pub stats: KernelStats,
}

/// Statistics for monitoring Kernel health
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KernelStats {
    /// Total claims processed
    pub total_claims_processed: u64,

    /// Total rejections (any reason)
    pub total_rejections: u64,

    /// Total SOV distributed
    pub total_sov_distributed: u64,

    /// Rejections by reason code
    pub rejections_by_reason: [u64; 5],
}

impl KernelState {
    /// Create new empty kernel state
    pub fn new() -> Self {
        Self {
            already_claimed: HashMap::new(),
            total_distributed: HashMap::new(),
            last_processed_epoch: None,
            stats: KernelStats::default(),
        }
    }

    /// Check if citizen has claimed in this epoch
    ///
    /// # Arguments
    /// * `citizen_id` - Citizen identifier
    /// * `epoch` - Epoch to check
    ///
    /// # Returns
    /// true if citizen has already claimed in this epoch
    pub fn has_claimed(&self, citizen_id: &[u8; 32], epoch: u64) -> bool {
        self.already_claimed
            .get(citizen_id)
            .and_then(|epochs| epochs.get(&epoch))
            .copied()
            .unwrap_or(false)
    }

    /// Mark citizen as claimed in this epoch
    ///
    /// # Arguments
    /// * `citizen_id` - Citizen identifier
    /// * `epoch` - Epoch to mark
    ///
    /// # Panics
    /// If citizen was already marked as claimed (indicates logic error)
    pub fn mark_claimed(&mut self, citizen_id: [u8; 32], epoch: u64) {
        let epochs = self
            .already_claimed
            .entry(citizen_id)
            .or_insert_with(HashMap::new);

        assert!(
            !epochs.contains_key(&epoch),
            "Citizen already marked claimed in epoch (logic error)"
        );

        epochs.insert(epoch, true);
    }

    /// Get total amount distributed in an epoch
    ///
    /// # Arguments
    /// * `epoch` - Epoch to query
    ///
    /// # Returns
    /// Total SOV distributed in this epoch (0 if none)
    pub fn get_distributed(&self, epoch: u64) -> u64 {
        self.total_distributed.get(&epoch).copied().unwrap_or(0)
    }

    /// Check if adding amount would exceed pool capacity
    ///
    /// # Arguments
    /// * `epoch` - Epoch to check
    /// * `amount` - Amount attempting to distribute
    ///
    /// # Returns
    /// true if amount can be distributed (capacity available)
    /// false if pool would be exceeded
    pub fn check_pool_capacity(&self, epoch: u64, amount: u64) -> bool {
        const POOL_CAP_PER_EPOCH: u64 = 1_000_000;
        let current = self.get_distributed(epoch);

        current
            .checked_add(amount)
            .map(|total| total <= POOL_CAP_PER_EPOCH)
            .unwrap_or(false)
    }

    /// Add to distributed amount for an epoch
    ///
    /// # Arguments
    /// * `epoch` - Epoch to update
    /// * `amount` - Amount to add
    ///
    /// # Returns
    /// Ok(()) if successful
    /// Err if addition would overflow or exceed pool
    pub fn add_distributed(&mut self, epoch: u64, amount: u64) -> Result<(), String> {
        const POOL_CAP_PER_EPOCH: u64 = 1_000_000;

        let current = self.get_distributed(epoch);
        let new_total = current
            .checked_add(amount)
            .ok_or("Distribution overflow".to_string())?;

        if new_total > POOL_CAP_PER_EPOCH {
            return Err("Pool exhausted".to_string());
        }

        self.total_distributed.insert(epoch, new_total);
        self.stats.total_sov_distributed = self
            .stats
            .total_sov_distributed
            .checked_add(amount)
            .ok_or("Stats overflow".to_string())?;

        Ok(())
    }

    /// Record a rejection
    ///
    /// # Arguments
    /// * `reason` - Rejection reason code
    pub fn record_rejection(&mut self, reason: RejectionReason) {
        self.stats.total_rejections += 1;
        let reason_idx = (reason as u8) - 1; // Convert 1-5 to 0-4
        if (reason_idx as usize) < self.stats.rejections_by_reason.len() {
            self.stats.rejections_by_reason[reason_idx as usize] += 1;
        }
    }

    /// Record a successful distribution
    pub fn record_success(&mut self) {
        self.stats.total_claims_processed += 1;
    }
}

impl Default for KernelState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_state_new() {
        let state = KernelState::new();
        assert_eq!(state.already_claimed.len(), 0);
        assert_eq!(state.total_distributed.len(), 0);
        assert_eq!(state.last_processed_epoch, None);
        assert_eq!(state.stats.total_claims_processed, 0);
    }

    #[test]
    fn test_has_claimed_empty_state() {
        let state = KernelState::new();
        let citizen_id = [1u8; 32];
        assert!(!state.has_claimed(&citizen_id, 100));
    }

    #[test]
    fn test_mark_claimed() {
        let mut state = KernelState::new();
        let citizen_id = [1u8; 32];

        state.mark_claimed(citizen_id, 100);
        assert!(state.has_claimed(&citizen_id, 100));
    }

    #[test]
    fn test_mark_claimed_different_epochs() {
        let mut state = KernelState::new();
        let citizen_id = [1u8; 32];

        state.mark_claimed(citizen_id, 100);
        state.mark_claimed(citizen_id, 101);

        assert!(state.has_claimed(&citizen_id, 100));
        assert!(state.has_claimed(&citizen_id, 101));
    }

    #[test]
    fn test_get_distributed_empty() {
        let state = KernelState::new();
        assert_eq!(state.get_distributed(100), 0);
    }

    #[test]
    fn test_add_distributed_success() {
        let mut state = KernelState::new();
        let result = state.add_distributed(100, 500_000);
        assert!(result.is_ok());
        assert_eq!(state.get_distributed(100), 500_000);
    }

    #[test]
    fn test_add_distributed_multiple_times() {
        let mut state = KernelState::new();
        state.add_distributed(100, 300_000).unwrap();
        state.add_distributed(100, 700_000).unwrap();
        assert_eq!(state.get_distributed(100), 1_000_000);
    }

    #[test]
    fn test_add_distributed_exceeds_cap() {
        let mut state = KernelState::new();
        state.add_distributed(100, 900_000).unwrap();
        let result = state.add_distributed(100, 200_000);
        assert!(result.is_err());
        assert_eq!(state.get_distributed(100), 900_000);
    }

    #[test]
    fn test_check_pool_capacity_success() {
        let mut state = KernelState::new();
        state.add_distributed(100, 500_000).unwrap();
        assert!(state.check_pool_capacity(100, 500_000));
    }

    #[test]
    fn test_check_pool_capacity_at_limit() {
        let mut state = KernelState::new();
        state.add_distributed(100, 1_000_000).unwrap();
        assert!(!state.check_pool_capacity(100, 1));
    }

    #[test]
    fn test_check_pool_capacity_different_epochs() {
        let mut state = KernelState::new();
        state.add_distributed(100, 1_000_000).unwrap();
        assert!(state.check_pool_capacity(101, 1_000_000));
    }

    #[test]
    fn test_record_rejection() {
        let mut state = KernelState::new();
        state.record_rejection(RejectionReason::NotACitizen);
        assert_eq!(state.stats.total_rejections, 1);
        assert_eq!(state.stats.rejections_by_reason[0], 1);
    }

    #[test]
    fn test_record_multiple_rejections() {
        let mut state = KernelState::new();
        state.record_rejection(RejectionReason::NotACitizen);
        state.record_rejection(RejectionReason::AlreadyRevoked);
        state.record_rejection(RejectionReason::PoolExhausted);
        assert_eq!(state.stats.total_rejections, 3);
    }

    #[test]
    fn test_record_success() {
        let mut state = KernelState::new();
        state.record_success();
        assert_eq!(state.stats.total_claims_processed, 1);
    }

    #[test]
    #[should_panic]
    fn test_mark_claimed_duplicate_panics() {
        let mut state = KernelState::new();
        let citizen_id = [1u8; 32];
        state.mark_claimed(citizen_id, 100);
        state.mark_claimed(citizen_id, 100);
    }

    #[test]
    fn test_rejection_reason_display() {
        assert_eq!(RejectionReason::NotACitizen.to_string(), "Not a citizen");
        assert_eq!(
            RejectionReason::AlreadyRevoked.to_string(),
            "Citizen revoked"
        );
        assert_eq!(
            RejectionReason::EligibilityNotMet.to_string(),
            "Eligibility not met"
        );
    }
}
