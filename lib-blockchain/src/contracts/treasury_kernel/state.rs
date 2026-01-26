//! Treasury Kernel State Management
//!
//! State tracking for UBI distribution with crash recovery guarantees.
//! All state is consensus-critical and must be persisted.

use super::types::{KernelState, RejectionReason};

/// State management for crash recovery
impl KernelState {
    /// Get current state for persistence
    /// 
    /// # Returns
    /// Reference to kernel state (for serialization)
    pub fn state(&self) -> &KernelState {
        self
    }

    /// Get mutable state for updates
    /// 
    /// # Returns
    /// Mutable reference to kernel state
    pub fn state_mut(&mut self) -> &mut KernelState {
        self
    }

    /// Clear old epoch data to save memory
    /// 
    /// Only call after epoch is fully processed and can be archived.
    /// Keep last_processed_epoch for crash recovery.
    /// 
    /// # Arguments
    /// * `cutoff_epoch` - Remove data for epochs < cutoff_epoch
    pub fn prune_old_epochs(&mut self, cutoff_epoch: u64) {
        // Keep dedup data for recent epochs (don't clear)
        // Citizens shouldn't claim twice across epochs anyway
        
        // Remove old distribution data
        self.total_distributed.retain(|epoch, _| *epoch >= cutoff_epoch);
    }

    /// Get statistics snapshot
    pub fn get_stats(&self) -> crate::contracts::treasury_kernel::types::KernelStats {
        self.stats.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_methods() {
        let mut state = KernelState::new();
        
        // Test state() accessor
        let ref_state = state.state();
        assert_eq!(ref_state.stats.total_claims_processed, 0);
        
        // Test state_mut() accessor
        let mut_state = state.state_mut();
        mut_state.record_success();
        
        assert_eq!(state.stats.total_claims_processed, 1);
    }

    #[test]
    fn test_prune_old_epochs() {
        let mut state = KernelState::new();
        
        // Add distribution data for epochs 100-104
        for epoch in 100..105 {
            state.add_distributed(epoch, 500_000).unwrap();
        }
        
        // Prune epochs before 102
        state.prune_old_epochs(102);
        
        // Epochs 100-101 should be gone
        assert_eq!(state.get_distributed(100), 0);
        assert_eq!(state.get_distributed(101), 0);
        
        // Epochs 102-104 should remain
        assert_eq!(state.get_distributed(102), 500_000);
        assert_eq!(state.get_distributed(103), 500_000);
        assert_eq!(state.get_distributed(104), 500_000);
    }

    #[test]
    fn test_get_stats() {
        let mut state = KernelState::new();
        state.record_success();
        state.record_rejection(RejectionReason::NotACitizen);
        
        let stats = state.get_stats();
        assert_eq!(stats.total_claims_processed, 1);
        assert_eq!(stats.total_rejections, 1);
    }
}
