use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::contracts::treasury_kernel::types::KernelStats;

/// Kernel state: dedup tracking, pool capacity, and last processed epoch
///
/// This state is persisted to prevent double-minting after crashes.
/// Deduplication works by tracking which citizens have already claimed in each epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelState {
    /// Deduplication map: citizen_id -> {epoch -> bool}
    /// Prevents double-minting even after crashes
    claimed_map: HashMap<[u8; 32], HashMap<u64, bool>>,

    /// Pool tracking: epoch -> total_distributed
    /// Enforces 1,000,000 SOV cap per epoch
    epoch_distributions: HashMap<u64, u64>,

    /// Last successfully processed epoch
    /// Used to detect if we've already processed an epoch
    last_processed_epoch: Option<u64>,

    /// Statistics for monitoring and debugging
    stats: KernelStats,
}

impl KernelState {
    /// Create a new, empty kernel state
    pub fn new() -> Self {
        Self {
            claimed_map: HashMap::new(),
            epoch_distributions: HashMap::new(),
            last_processed_epoch: None,
            stats: KernelStats::new(),
        }
    }

    /// Check if a citizen has already claimed UBI in a specific epoch
    pub fn has_claimed(&self, citizen_id: &[u8; 32], epoch: u64) -> bool {
        self.claimed_map
            .get(citizen_id)
            .and_then(|epochs| epochs.get(&epoch))
            .copied()
            .unwrap_or(false)
    }

    /// Mark a citizen as having claimed UBI in a specific epoch
    pub fn mark_claimed(&mut self, citizen_id: [u8; 32], epoch: u64) {
        self.claimed_map
            .entry(citizen_id)
            .or_insert_with(HashMap::new)
            .insert(epoch, true);
    }

    /// Get the total amount distributed in an epoch
    pub fn get_distributed(&self, epoch: u64) -> u64 {
        self.epoch_distributions.get(&epoch).copied().unwrap_or(0)
    }

    /// Check if adding an amount would exceed the pool cap
    /// Returns true if the distribution would fit within the 1,000,000 SOV cap
    pub fn check_pool_capacity(&self, epoch: u64, amount: u64) -> bool {
        const POOL_CAP: u64 = 1_000_000;
        let current_distributed = self.get_distributed(epoch);
        current_distributed + amount <= POOL_CAP
    }

    /// Add an amount to the epoch distribution total
    pub fn add_distributed(&mut self, epoch: u64, amount: u64) -> Result<(), String> {
        const POOL_CAP: u64 = 1_000_000;
        let current = self.get_distributed(epoch);

        if current + amount > POOL_CAP {
            return Err("Pool would exceed capacity".to_string());
        }

        self.epoch_distributions.insert(epoch, current + amount);
        Ok(())
    }

    /// Get the last processed epoch
    pub fn last_processed_epoch(&self) -> Option<u64> {
        self.last_processed_epoch
    }

    /// Set the last processed epoch
    pub fn set_last_processed_epoch(&mut self, epoch: u64) {
        self.last_processed_epoch = Some(epoch);
    }

    /// Get mutable reference to stats
    pub fn stats_mut(&mut self) -> &mut KernelStats {
        &mut self.stats
    }

    /// Get reference to stats
    pub fn stats(&self) -> &KernelStats {
        &self.stats
    }

    /// Get the number of citizens who have claimed in a specific epoch
    pub fn get_claimed_count(&self, epoch: u64) -> u64 {
        self.claimed_map
            .values()
            .filter(|epochs| epochs.get(&epoch).copied().unwrap_or(false))
            .count() as u64
    }

    /// Clear old dedup entries (optional optimization for old epochs)
    /// This is an optional memory optimization - can be called periodically
    pub fn prune_old_epochs(&mut self, threshold_epoch: u64) {
        for claimed_epochs in self.claimed_map.values_mut() {
            claimed_epochs.retain(|epoch, _| *epoch >= threshold_epoch);
        }
        self.epoch_distributions.retain(|epoch, _| *epoch >= threshold_epoch);
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
    fn test_new_state() {
        let state = KernelState::new();
        assert_eq!(state.last_processed_epoch(), None);
        assert_eq!(state.get_distributed(0), 0);
    }

    #[test]
    fn test_dedup_marking() {
        let mut state = KernelState::new();
        let citizen_id = [1u8; 32];
        let epoch = 100;

        assert!(!state.has_claimed(&citizen_id, epoch));

        state.mark_claimed(citizen_id, epoch);
        assert!(state.has_claimed(&citizen_id, epoch));

        // Different epoch should not be marked
        assert!(!state.has_claimed(&citizen_id, 101));
    }

    #[test]
    fn test_pool_capacity_check() {
        let mut state = KernelState::new();
        let epoch = 0;

        // Initially should allow 1,000,000
        assert!(state.check_pool_capacity(epoch, 1_000_000));

        // Add 500,000
        state.add_distributed(epoch, 500_000).unwrap();
        assert!(state.get_distributed(epoch) == 500_000);

        // Should allow another 500,000
        assert!(state.check_pool_capacity(epoch, 500_000));

        // Should not allow 500,001
        assert!(!state.check_pool_capacity(epoch, 500_001));
    }

    #[test]
    fn test_pool_exhaustion() {
        let mut state = KernelState::new();
        let epoch = 0;

        // Fill to capacity
        state.add_distributed(epoch, 1_000_000).unwrap();

        // Should reject any additional amount
        assert!(!state.check_pool_capacity(epoch, 1));

        // Add should also fail
        let result = state.add_distributed(epoch, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_citizens() {
        let mut state = KernelState::new();
        let epoch = 50;

        let citizen1 = [1u8; 32];
        let citizen2 = [2u8; 32];
        let citizen3 = [3u8; 32];

        state.mark_claimed(citizen1, epoch);
        state.mark_claimed(citizen2, epoch);
        state.mark_claimed(citizen3, epoch);

        assert!(state.has_claimed(&citizen1, epoch));
        assert!(state.has_claimed(&citizen2, epoch));
        assert!(state.has_claimed(&citizen3, epoch));

        // Different citizen should not be marked
        let citizen4 = [4u8; 32];
        assert!(!state.has_claimed(&citizen4, epoch));
    }

    #[test]
    fn test_epoch_isolation() {
        let mut state = KernelState::new();
        let citizen_id = [1u8; 32];

        // Claim in epoch 1
        state.mark_claimed(citizen_id, 1);
        assert!(state.has_claimed(&citizen_id, 1));
        assert!(!state.has_claimed(&citizen_id, 2));

        // Claim in epoch 2
        state.mark_claimed(citizen_id, 2);
        assert!(state.has_claimed(&citizen_id, 1));
        assert!(state.has_claimed(&citizen_id, 2));
        assert!(!state.has_claimed(&citizen_id, 3));
    }

    #[test]
    fn test_last_processed_epoch() {
        let mut state = KernelState::new();

        assert_eq!(state.last_processed_epoch(), None);

        state.set_last_processed_epoch(100);
        assert_eq!(state.last_processed_epoch(), Some(100));

        state.set_last_processed_epoch(101);
        assert_eq!(state.last_processed_epoch(), Some(101));
    }

    #[test]
    fn test_claimed_count() {
        let mut state = KernelState::new();
        let epoch = 50;

        assert_eq!(state.get_claimed_count(epoch), 0);

        let citizen1 = [1u8; 32];
        let citizen2 = [2u8; 32];

        state.mark_claimed(citizen1, epoch);
        assert_eq!(state.get_claimed_count(epoch), 1);

        state.mark_claimed(citizen2, epoch);
        assert_eq!(state.get_claimed_count(epoch), 2);

        // Mark same citizen again - should still be 2
        state.mark_claimed(citizen1, epoch);
        assert_eq!(state.get_claimed_count(epoch), 2);
    }

    #[test]
    fn test_multiple_epoch_distributions() {
        let mut state = KernelState::new();

        state.add_distributed(1, 100_000).unwrap();
        state.add_distributed(2, 200_000).unwrap();
        state.add_distributed(1, 50_000).unwrap();

        assert_eq!(state.get_distributed(1), 150_000);
        assert_eq!(state.get_distributed(2), 200_000);
        assert_eq!(state.get_distributed(3), 0);
    }

    #[test]
    fn test_stats_tracking() {
        let mut state = KernelState::new();

        assert_eq!(state.stats().total_processed, 0);

        state.stats_mut().record_success();
        assert_eq!(state.stats().total_processed, 1);
        assert_eq!(state.stats().successful_distributions, 1);

        state.stats_mut().record_rejection();
        assert_eq!(state.stats().total_processed, 2);
        assert_eq!(state.stats().rejected_claims, 1);
    }

    #[test]
    fn test_prune_old_epochs() {
        let mut state = KernelState::new();
        let citizen = [1u8; 32];

        // Add claims and distributions for epochs 1-10
        for epoch in 1..=10 {
            state.mark_claimed(citizen, epoch);
            state.add_distributed(epoch, 100_000).unwrap();
        }

        // Prune epochs older than 5
        state.prune_old_epochs(5);

        // Old epochs should be gone
        assert!(!state.has_claimed(&citizen, 1));
        assert_eq!(state.get_distributed(1), 0);

        // Newer epochs should remain
        assert!(state.has_claimed(&citizen, 5));
        assert!(state.has_claimed(&citizen, 10));
        assert_eq!(state.get_distributed(5), 100_000);
        assert_eq!(state.get_distributed(10), 100_000);
    }
}
