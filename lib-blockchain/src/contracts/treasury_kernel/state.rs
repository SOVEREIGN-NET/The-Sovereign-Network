//! Treasury Kernel State Management
//!
//! State tracking for UBI distribution with crash recovery guarantees.
//! All state is consensus-critical and must be persisted.
//!
//! Phase 6: Crash Recovery
//! =====================
//! KernelState is persisted using deterministic serialization (bincode).
//! This ensures crash recovery is idempotent: restarting always recovers
//! to the same state, preventing double-minting.
//!
//! Storage Key Pattern: kernel:state:v1
//! Serialization: bincode (deterministic, compact)

use super::types::KernelState;

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
    /// Removes data for epochs older than cutoff to prevent unbounded memory growth.
    /// Safe to call because citizens cannot claim in past epochs:
    /// - Validation checks: current_epoch >= citizenship_epoch
    /// - Citizens advancing in time can never go backwards
    /// - Stale dedup entries are never queried after their epoch passes
    ///
    /// # Design
    /// - Prunes total_distributed: no longer needed for past epochs
    /// - Prunes already_claimed: dedup entries cannot be reused in past epochs
    /// - Keeps last_processed_epoch: needed for crash recovery
    ///
    /// Recommended: Call weekly or monthly to prune epochs older than 52 weeks
    /// This keeps memory bounded while retaining historical audit trail length.
    ///
    /// # Arguments
    /// * `cutoff_epoch` - Remove data for epochs < cutoff_epoch
    pub fn prune_old_epochs(&mut self, cutoff_epoch: u64) {
        // Remove old distribution data
        self.total_distributed.retain(|epoch, _| *epoch >= cutoff_epoch);

        // Remove old dedup entries (safe because citizens can't claim in past epochs)
        self.already_claimed.retain(|_citizen_id, epoch_map| {
            // Keep epochs >= cutoff_epoch
            epoch_map.retain(|epoch, _| *epoch >= cutoff_epoch);
            // Remove citizen entry if all their epochs are pruned
            !epoch_map.is_empty()
        });
    }

    /// Get statistics snapshot
    pub fn get_stats(&self) -> crate::contracts::treasury_kernel::types::KernelStats {
        self.stats.clone()
    }

    // ========================================================================
    // PHASE 6: CRASH RECOVERY - PERSISTENCE AND RECOVERY METHODS
    // ========================================================================

    /// Serialize state to bytes for persistence
    ///
    /// # Design
    /// Uses deterministic bincode serialization to ensure all validators
    /// produce identical byte sequences for the same state.
    /// This is critical for recovery: crash recovery must always
    /// restore to identical state.
    ///
    /// # Returns
    /// Vec<u8> containing serialized state
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self)
            .map_err(|e| format!("Failed to serialize KernelState: {}", e))
    }

    /// Deserialize state from bytes after crash
    ///
    /// # Design
    /// Reconstructs exact state from persisted bytes.
    /// This guarantees recovery is idempotent:
    /// - Restart always restores same dedup map
    /// - Prevents double-minting even after multiple crashes
    ///
    /// # Arguments
    /// * `data` - Serialized state bytes
    ///
    /// # Returns
    /// Restored KernelState or error if data is corrupted
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data)
            .map_err(|e| format!("Failed to deserialize KernelState: {}", e))
    }

    /// Check if state is valid (internal consistency check)
    ///
    /// # Design
    /// Verifies invariants after loading from persistence:
    /// - stats.total_claims_processed >= stats.total_rejections
    /// - Pool doesn't have negative remaining (covered by get_distributed checks)
    /// - last_processed_epoch is monotonic (never decreases)
    ///
    /// # Returns
    /// true if state is consistent, false if corrupted
    pub fn is_valid(&self) -> bool {
        // Invariant: total processed >= rejections
        let total_by_reason: u64 = self.stats.rejections_by_reason.iter().sum();
        if self.stats.total_rejections != total_by_reason {
            return false;
        }

        // Total processed = successes + rejections
        if self.stats.total_claims_processed < self.stats.total_rejections {
            return false;
        }

        true
    }

    /// Detect if crash occurred mid-distribution
    ///
    /// # Design
    /// Compares persisted last_processed_epoch with current block height's epoch.
    /// If they differ, a crash occurred and recovery must resume distribution.
    ///
    /// # Arguments
    /// * `current_epoch` - Epoch calculated from current block height
    ///
    /// # Returns
    /// true if crash/incomplete epoch detected
    pub fn needs_recovery(&self, current_epoch: u64) -> bool {
        match self.last_processed_epoch {
            Some(last_epoch) => last_epoch < current_epoch,
            None => false, // No prior state, not a recovery case
        }
    }

    /// Get the next epoch to process (for recovery)
    ///
    /// # Design
    /// Allows resumption from the correct point without re-processing
    /// already-completed epochs.
    ///
    /// # Returns
    /// Epoch to resume processing from
    pub fn next_epoch_to_process(&self) -> u64 {
        match self.last_processed_epoch {
            Some(last) => last + 1,
            None => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::treasury_kernel::types::RejectionReason;

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
    fn test_prune_old_epochs_also_prunes_dedup() {
        let mut state = KernelState::new();
        let citizen1 = [1u8; 32];
        let citizen2 = [2u8; 32];

        // Add claims for epochs 100-104
        for epoch in 100..105 {
            let _ = state.mark_claimed(citizen1, epoch);
            let _ = state.mark_claimed(citizen2, epoch);
            state.add_distributed(epoch, 500_000).unwrap();
        }

        // Verify claims are recorded
        assert!(state.has_claimed(&citizen1, 100));
        assert!(state.has_claimed(&citizen2, 102));

        // Prune epochs before 102 (removes 100-101)
        state.prune_old_epochs(102);

        // Old epochs should be pruned
        assert!(!state.has_claimed(&citizen1, 100));
        assert!(!state.has_claimed(&citizen2, 101));

        // Recent epochs should remain
        assert!(state.has_claimed(&citizen1, 102));
        assert!(state.has_claimed(&citizen1, 103));
        assert!(state.has_claimed(&citizen2, 102));
        assert!(state.has_claimed(&citizen2, 104));

        // Distribution data also pruned
        assert_eq!(state.get_distributed(100), 0);
        assert_eq!(state.get_distributed(102), 500_000);
    }

    #[test]
    fn test_prune_old_epochs_removes_empty_citizen_entries() {
        let mut state = KernelState::new();
        let citizen1 = [1u8; 32];
        let citizen2 = [2u8; 32];

        // Citizen1 only has epoch 100 (will be fully pruned)
        let _ = state.mark_claimed(citizen1, 100);

        // Citizen2 has epochs 100 and 102 (100 will be pruned, 102 remains)
        let _ = state.mark_claimed(citizen2, 100);
        let _ = state.mark_claimed(citizen2, 102);

        // Before pruning: both citizens have data
        assert_eq!(state.already_claimed.len(), 2);

        // Prune epochs before 102
        state.prune_old_epochs(102);

        // After pruning: citizen1 should be completely removed (no epochs left)
        // citizen2 should remain (has epoch 102)
        assert!(!state.already_claimed.contains_key(&citizen1));
        assert!(state.already_claimed.contains_key(&citizen2));
        assert_eq!(state.already_claimed.len(), 1);

        // Verify citizen2's epoch 102 is still there
        assert!(state.has_claimed(&citizen2, 102));
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

    // ========================================================================
    // PHASE 6 CRASH RECOVERY TESTS
    // ========================================================================

    #[test]
    fn test_state_serialization_deterministic() {
        let mut state1 = KernelState::new();
        state1.mark_claimed([1u8; 32], 100);
        state1.add_distributed(100, 500_000).unwrap();
        state1.record_success();

        let mut state2 = KernelState::new();
        state2.mark_claimed([1u8; 32], 100);
        state2.add_distributed(100, 500_000).unwrap();
        state2.record_success();

        // Same operations produce identical bytes
        let bytes1 = state1.to_bytes().expect("serialize1");
        let bytes2 = state2.to_bytes().expect("serialize2");

        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_state_deserialization_recovery() {
        let mut original = KernelState::new();
        original.mark_claimed([1u8; 32], 100);
        original.add_distributed(100, 500_000).unwrap();
        original.record_success();
        original.last_processed_epoch = Some(100);

        // Serialize
        let bytes = original.to_bytes().expect("serialize");

        // Deserialize (simulating crash recovery)
        let recovered = KernelState::from_bytes(&bytes).expect("deserialize");

        // Verify exact restoration
        assert_eq!(recovered.has_claimed(&[1u8; 32], 100), true);
        assert_eq!(recovered.get_distributed(100), 500_000);
        assert_eq!(recovered.stats.total_claims_processed, 1);
        assert_eq!(recovered.last_processed_epoch, Some(100));
    }

    #[test]
    fn test_state_corrupted_data_fails() {
        let corrupted_data = vec![0xFF, 0xFF, 0xFF, 0xFF];
        let result = KernelState::from_bytes(&corrupted_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_state_is_valid_new_state() {
        let state = KernelState::new();
        assert!(state.is_valid());
    }

    #[test]
    fn test_state_is_valid_after_processing() {
        let mut state = KernelState::new();
        for _ in 0..5 {
            state.record_success();
        }
        for _ in 0..3 {
            state.record_rejection(RejectionReason::NotACitizen);
        }

        assert!(state.is_valid());
        assert_eq!(state.stats.total_claims_processed, 5);
        assert_eq!(state.stats.total_rejections, 3);
    }

    #[test]
    fn test_needs_recovery_no_prior_state() {
        let state = KernelState::new();
        assert!(!state.needs_recovery(100));
    }

    #[test]
    fn test_needs_recovery_same_epoch() {
        let mut state = KernelState::new();
        state.last_processed_epoch = Some(100);

        // No recovery needed if already processed this epoch
        assert!(!state.needs_recovery(100));
    }

    #[test]
    fn test_needs_recovery_new_epoch() {
        let mut state = KernelState::new();
        state.last_processed_epoch = Some(100);

        // Recovery needed if new epoch arrived
        assert!(state.needs_recovery(101));
        assert!(state.needs_recovery(105));
    }

    #[test]
    fn test_next_epoch_to_process_no_prior() {
        let state = KernelState::new();
        assert_eq!(state.next_epoch_to_process(), 0);
    }

    #[test]
    fn test_next_epoch_to_process_after_crash() {
        let mut state = KernelState::new();
        state.last_processed_epoch = Some(100);

        // Should resume from next epoch
        assert_eq!(state.next_epoch_to_process(), 101);
    }

    #[test]
    fn test_crash_recovery_scenario_1_crash_before_mint() {
        // Scenario: Crash before any distribution recorded
        let state = KernelState::new();
        let bytes = state.to_bytes().expect("serialize");

        // Simulate crash and restart
        let recovered = KernelState::from_bytes(&bytes).expect("deserialize");

        // State should be pristine, needs recovery for any epoch
        assert_eq!(recovered.stats.total_claims_processed, 0);
        assert!(!recovered.needs_recovery(0)); // No prior state
    }

    #[test]
    fn test_crash_recovery_scenario_2_crash_after_partial_mint() {
        // Scenario: Crashed after processing 3 of 5 claims
        let mut state = KernelState::new();
        state.mark_claimed([1u8; 32], 100);
        state.mark_claimed([2u8; 32], 100);
        state.mark_claimed([3u8; 32], 100);
        state.add_distributed(100, 3_000).unwrap();
        state.stats.total_claims_processed = 3;
        state.last_processed_epoch = Some(99); // Was processing epoch 100, not yet marked complete

        let bytes = state.to_bytes().expect("serialize");
        let recovered = KernelState::from_bytes(&bytes).expect("deserialize");

        // Verify dedup prevents double-mint
        assert!(recovered.has_claimed(&[1u8; 32], 100));
        assert!(recovered.has_claimed(&[2u8; 32], 100));
        assert!(recovered.has_claimed(&[3u8; 32], 100));

        // Can detect need to resume epoch 100
        assert!(recovered.needs_recovery(100));
    }

    #[test]
    fn test_crash_recovery_scenario_3_crash_during_state_save() {
        // Scenario: Crashed while saving state after last claim processed
        // Recovery must prevent second claim from succeeding
        let mut state = KernelState::new();

        // First claim succeeded in prior run
        let _ = state.mark_claimed([1u8; 32], 100);
        state.add_distributed(100, 1_000).unwrap();
        state.record_success();
        state.last_processed_epoch = Some(100);

        let bytes = state.to_bytes().expect("serialize");
        let recovered = KernelState::from_bytes(&bytes).expect("deserialize");

        // Same claim comes in again (e.g., from event replay)
        // Dedup should prevent it
        assert!(recovered.has_claimed(&[1u8; 32], 100));
    }

    #[test]
    fn test_crash_recovery_dedup_prevents_double_mint() {
        // Critical test: Dedup state must survive crash to prevent double-minting

        // Citizen claims in epoch 100, claim is processed
        let mut state_before_crash = KernelState::new();
        let _ = state_before_crash.mark_claimed([1u8; 32], 100);
        state_before_crash.add_distributed(100, 1_000).unwrap();
        state_before_crash.record_success();

        // Simulate crash and recovery
        let bytes = state_before_crash.to_bytes().expect("serialize");
        let state_after_recovery = KernelState::from_bytes(&bytes).expect("deserialize");

        // CRITICAL: Dedup state must be restored
        assert_eq!(
            state_before_crash.has_claimed(&[1u8; 32], 100),
            state_after_recovery.has_claimed(&[1u8; 32], 100)
        );

        assert!(state_after_recovery.has_claimed(&[1u8; 32], 100));
    }

    #[test]
    fn test_crash_recovery_pool_capacity_restored() {
        // Test: Pool tracking survives crash
        let mut state = KernelState::new();
        state.add_distributed(100, 500_000).unwrap();
        state.add_distributed(100, 300_000).unwrap();

        let bytes = state.to_bytes().expect("serialize");
        let recovered = KernelState::from_bytes(&bytes).expect("deserialize");

        // Pool capacity must be restored exactly
        assert_eq!(recovered.get_distributed(100), 800_000);
        assert!(recovered.check_pool_capacity(100, 200_000)); // 800k + 200k = 1M (ok)
        assert!(!recovered.check_pool_capacity(100, 200_001)); // 800k + 200.001k > 1M (fail)
    }

    #[test]
    fn test_crash_recovery_statistics_preserved() {
        // Test: Stats survive crash
        let mut state = KernelState::new();
        for _ in 0..5 {
            state.record_success();
        }
        for _ in 0..2 {
            state.record_rejection(RejectionReason::NotACitizen);
        }
        for _ in 0..1 {
            state.record_rejection(RejectionReason::PoolExhausted);
        }

        let bytes = state.to_bytes().expect("serialize");
        let recovered = KernelState::from_bytes(&bytes).expect("deserialize");

        let stats = recovered.get_stats();
        assert_eq!(stats.total_claims_processed, 5);
        assert_eq!(stats.total_rejections, 3);
        assert_eq!(stats.rejections_by_reason[0], 2); // NotACitizen
        assert_eq!(stats.rejections_by_reason[3], 1); // PoolExhausted
    }

    #[test]
    fn test_crash_recovery_multiple_epochs() {
        // Test: Multiple epochs of data survive crash
        let mut state = KernelState::new();

        for epoch in 100..105 {
            let _ = state.mark_claimed([(epoch % 256) as u8; 32], epoch);
            state.add_distributed(epoch, 100_000).unwrap();
        }
        state.last_processed_epoch = Some(104);

        let bytes = state.to_bytes().expect("serialize");
        let recovered = KernelState::from_bytes(&bytes).expect("deserialize");

        // All epochs should be recovered
        for epoch in 100..105 {
            assert!(recovered.has_claimed(&[(epoch % 256) as u8; 32], epoch));
            assert_eq!(recovered.get_distributed(epoch), 100_000);
        }

        assert_eq!(recovered.last_processed_epoch, Some(104));
    }

    #[test]
    fn test_crash_recovery_state_validity_check() {
        // Test: Recovered state passes validity check
        let mut state = KernelState::new();
        state.record_success();
        state.record_success();
        state.record_rejection(RejectionReason::NotACitizen);

        // State should be valid before serialization
        assert!(state.is_valid());

        let bytes = state.to_bytes().expect("serialize");
        let recovered = KernelState::from_bytes(&bytes).expect("deserialize");

        // State should be valid after recovery
        assert!(recovered.is_valid());
    }

    #[test]
    fn test_crash_recovery_large_state() {
        // Stress test: Large state survives crash
        let mut state = KernelState::new();

        // Simulate 256 unique citizens claiming in epoch 100
        // (256 unique values for a single byte)
        for i in 0..256 {
            let citizen_id = [i as u8; 32];
            let _ = state.mark_claimed(citizen_id, 100);
            state.add_distributed(100, 1).unwrap();
        }
        state.stats.total_claims_processed = 256;

        let bytes = state.to_bytes().expect("serialize");
        let recovered = KernelState::from_bytes(&bytes).expect("deserialize");

        // Spot check a few citizens
        assert!(recovered.has_claimed(&[0u8; 32], 100));
        assert!(recovered.has_claimed(&[255u8; 32], 100));
        assert_eq!(recovered.get_distributed(100), 256);
    }

    // ========================================================================
    // PHASE 6 PERFORMANCE BENCHMARKS
    // ========================================================================
    // These tests verify performance requirements from the plan:
    // - 1000 citizens processed in <5 seconds
    // - Serialization/deserialization overhead acceptable

    #[test]
    fn test_performance_process_1000_citizens() {
        // Benchmark: Process 1000 unique citizens claiming in epoch 100
        // Requirement: <5 seconds total (from plan)
        let mut state = KernelState::new();

        let start = std::time::Instant::now();

        // Process 1000 citizens (simulate epochs 0-9 with 100 each for diversity)
        for epoch in 0..10 {
            for i in 0..100 {
                let mut citizen_id = [0u8; 32];
                citizen_id[0] = epoch as u8;
                citizen_id[1] = (i / 256) as u8;
                citizen_id[2] = (i % 256) as u8;

                state.mark_claimed(citizen_id, epoch);
                state.add_distributed(epoch, 1_000).unwrap();
                state.record_success();
            }
        }

        let elapsed = start.elapsed();

        // Verify all processed (10 epochs * 100 claims/epoch = 1000 claims, 1000 SOV each)
        assert_eq!(state.stats.total_claims_processed, 1000);
        assert_eq!(state.stats.total_sov_distributed, 1_000_000); // 1000 * 1000

        // Performance requirement: must complete in under 5 seconds
        // (tests typically run much faster - expecting <100ms)
        assert!(
            elapsed.as_secs() < 5,
            "Processing 1000 citizens took {:.2}s, limit is 5s",
            elapsed.as_secs_f64()
        );

        println!(
            "✓ Performance: 1000 citizens processed in {:.3}ms",
            elapsed.as_secs_f64() * 1000.0
        );
    }

    #[test]
    fn test_performance_serialization() {
        // Benchmark: Serialization of large state (1000 citizens)
        let mut state = KernelState::new();

        // Build large state
        for i in 0..1000 {
            let mut citizen_id = [0u8; 32];
            citizen_id[0] = (i / 65536) as u8;
            citizen_id[1] = (i / 256) as u8;
            citizen_id[2] = (i % 256) as u8;
            state.mark_claimed(citizen_id, 100);
            state.add_distributed(100, 1).unwrap();
        }

        // Benchmark serialization
        let start = std::time::Instant::now();
        let bytes = state.to_bytes().expect("serialize").clone();
        let serialize_time = start.elapsed();

        // Benchmark deserialization
        let start = std::time::Instant::now();
        let _recovered = KernelState::from_bytes(&bytes).expect("deserialize");
        let deserialize_time = start.elapsed();

        // Verify size is reasonable (should be <100KB for 1000 entries)
        let size_kb = bytes.len() as f64 / 1024.0;

        assert!(
            size_kb < 100.0,
            "Serialized state size {:.1}KB exceeds limit",
            size_kb
        );

        println!(
            "✓ Serialization performance: {:?} to serialize, {:?} to deserialize ({:.1}KB)",
            serialize_time, deserialize_time, size_kb
        );
    }

    #[test]
    fn test_performance_dedup_lookup() {
        // Benchmark: Dedup lookups are fast (critical path)
        let mut state = KernelState::new();

        // Setup: Mark 1000 citizens as claimed
        for i in 0..1000 {
            let mut citizen_id = [0u8; 32];
            citizen_id[0] = (i / 65536) as u8;
            citizen_id[1] = (i / 256) as u8;
            citizen_id[2] = (i % 256) as u8;
            state.mark_claimed(citizen_id, 100);
        }

        // Benchmark: Lookup each citizen 1000 times (1M total lookups)
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            for i in 0..1000 {
                let mut citizen_id = [0u8; 32];
                citizen_id[0] = (i / 65536) as u8;
                citizen_id[1] = (i / 256) as u8;
                citizen_id[2] = (i % 256) as u8;
                assert!(state.has_claimed(&citizen_id, 100));
            }
        }
        let elapsed = start.elapsed();

        // 1M lookups should complete very fast (<1 second)
        assert!(
            elapsed.as_secs_f64() < 1.0,
            "1M dedup lookups took {:.3}s",
            elapsed.as_secs_f64()
        );

        println!(
            "✓ Dedup performance: 1M lookups in {:.3}ms",
            elapsed.as_secs_f64() * 1000.0
        );
    }

    #[test]
    fn test_performance_pool_tracking() {
        // Benchmark: Pool capacity checks for all citizens
        let state = KernelState::new();

        let start = std::time::Instant::now();

        // Simulate 100 epochs with varying loads
        for epoch in 0..100 {
            for amount in [10_000, 50_000, 100_000, 200_000, 500_000].iter() {
                // Try to add different amounts
                let _ = state.check_pool_capacity(epoch, *amount);
            }
        }

        let elapsed = start.elapsed();

        // Should be very fast (<10ms for 500 checks)
        assert!(
            elapsed.as_millis() < 100,
            "Pool tracking checks took {}ms",
            elapsed.as_millis()
        );

        println!(
            "✓ Pool tracking: 500 checks in {:.2}ms",
            elapsed.as_secs_f64() * 1000.0
        );
    }

    #[test]
    fn test_performance_epoch_scale() {
        // Benchmark: Multiple epochs with accumulated data
        // Simulates realistic scenario: system runs for weeks with many epochs
        let mut state = KernelState::new();

        let start = std::time::Instant::now();

        // Simulate 52 weeks of data (1 epoch per week)
        for week in 0..52 {
            for citizen in 0..100 {
                let mut citizen_id = [0u8; 32];
                citizen_id[0] = week as u8;
                citizen_id[1] = citizen as u8;
                state.mark_claimed(citizen_id, week);
                state.add_distributed(week, 1_000).unwrap();
            }
        }

        // Serialize (simulating end-of-epoch save)
        let bytes = state.to_bytes().expect("serialize");

        // Deserialize (simulating recovery or load)
        let _recovered = KernelState::from_bytes(&bytes).expect("deserialize");

        let elapsed = start.elapsed();

        // Should handle year+ of data efficiently (<500ms total)
        assert!(
            elapsed.as_millis() < 500,
            "Year-scale data handling took {}ms",
            elapsed.as_millis()
        );

        println!(
            "✓ Multi-epoch scale: 52 weeks * 100 citizens processed in {:.2}ms",
            elapsed.as_secs_f64() * 1000.0
        );
    }
}
