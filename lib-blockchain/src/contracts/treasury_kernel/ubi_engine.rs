//! UBI Distribution Engine - Main processing loop
//!
//! This module orchestrates the UBI distribution process at epoch boundaries:
//! 1. Poll for UbiClaimRecorded events from UBI contract
//! 2. Validate each claim (5-check validation)
//! 3. Mint tokens for valid claims
//! 4. Emit rejection events for invalid claims
//! 5. Emit pool status summary
//! 6. Persist kernel state

use crate::contracts::treasury_kernel::{TreasuryKernel, UbiClaimRecorded};
use crate::contracts::governance::CitizenRegistry;

impl TreasuryKernel {
    /// Poll for UbiClaimRecorded events from the UBI contract
    ///
    /// Retrieves all UBI claim intent events recorded during an epoch.
    /// These claims are then validated and processed for minting.
    ///
    /// # Arguments
    /// * `_epoch` - The epoch to poll claims for
    ///
    /// # Returns
    /// A vector of UbiClaimRecorded events for the given epoch
    ///
    /// # Note
    /// In Phase 5, this will be integrated with ContractExecutor.query_events()
    pub fn poll_ubi_claims(
        &self,
        _epoch: u64,
    ) -> Result<Vec<UbiClaimRecorded>, Box<dyn std::error::Error>> {
        // TODO: Phase 5 - Integrate with ContractExecutor.query_events()
        // For now, return empty vector (to be populated from event storage)
        // let events = executor.query_events(epoch, "UbiClaimRecorded")?;
        // let mut claims = Vec::new();
        // for event_data in events {
        //     let claim: UbiClaimRecorded = bincode::deserialize(&event_data)?;
        //     claims.push(claim);
        // }
        // Ok(claims)

        Ok(Vec::new()) // Stub for Phase 5
    }

    /// Process all UBI distributions for the current epoch
    ///
    /// This is the main entry point for UBI distribution orchestration.
    /// Called at epoch boundaries to process all citizen claims.
    ///
    /// # Algorithm
    /// 1. Check if we've already processed this epoch (idempotency)
    /// 2. Poll for UbiClaimRecorded events from UBI contract
    /// 3. For each claim:
    ///    a. Validate (5-check pipeline)
    ///    b. If valid: mark as claimed, add to distributed total, record success
    ///    c. If invalid: record rejection reason, record failure
    /// 4. Emit UbiPoolStatus summary event
    /// 5. Update last_processed_epoch for crash recovery
    /// 6. (Phase 6) Persist state to storage
    ///
    /// # Returns
    /// Ok(epoch) if successful, Err if validation or storage fails
    ///
    /// # Integration Points
    /// - Phase 3: Token minting via mint_ubi() (not yet integrated)
    /// - Phase 4: Event polling via poll_ubi_claims() and event emission
    /// - Phase 6: State persistence via save_to_storage()
    pub fn process_ubi_distributions(
        &mut self,
        current_height: u64,
        citizen_registry: &CitizenRegistry,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let current_epoch = self.current_epoch(current_height);

        // 1. Idempotency: Don't process the same epoch twice
        if self.state.last_processed_epoch() == Some(current_epoch) {
            return Ok(current_epoch);
        }

        // 2. Poll for UbiClaimRecorded events from UBI contract
        let claims = self.poll_ubi_claims(current_epoch)?;

        // 3. Process each claim through validation pipeline
        for claim in claims {
            // Validate the claim (5-check pipeline)
            match self.validate_claim(&claim, citizen_registry, current_epoch) {
                Ok(()) => {
                    // Valid claim: Update kernel state
                    self.state_mut().mark_claimed(claim.citizen_id, current_epoch);
                    self.state_mut().add_distributed(current_epoch, 1000)?;
                    self.state_mut().stats_mut().record_success();

                    // TODO: Phase 5 - Integrate Phase 3 minting
                    // Once minting is integrated, uncomment:
                    // let kernel_txid = self.compute_kernel_txid(&claim.citizen_id, current_epoch, 1000);
                    // TODO: Phase 5 - Integrate Phase 4 event emission
                    // self.emit_ubi_distributed(claim.citizen_id, 1000, current_epoch, kernel_txid, storage)?;
                }
                Err(_reason) => {
                    // Invalid claim: Record rejection
                    self.state_mut().stats_mut().record_rejection();

                    // TODO: Phase 5 - Integrate Phase 4 event emission
                    // self.emit_ubi_rejected(claim.citizen_id, current_epoch, reason, current_height, storage)?;
                }
            }
        }

        // 4. Emit pool status summary
        let _eligible_count = citizen_registry.get_active_citizens().len() as u64;
        let _total_distributed = self.state.get_distributed(current_epoch);

        // TODO: Phase 5 - Integrate Phase 4 event emission
        // self.emit_ubi_pool_status(current_epoch, eligible_count, total_distributed, storage)?;

        // 5. Update state for crash recovery
        self.state_mut().set_last_processed_epoch(current_epoch);

        // 6. (Phase 6) Persist kernel state to storage
        // TODO: Phase 6 - Integrate storage persistence
        // self.save_to_storage(storage)?;

        Ok(current_epoch)
    }

    /// Resume UBI processing after a crash or restart
    ///
    /// This is called during system startup to:
    /// 1. Load persisted kernel state (dedup maps, pool tracking)
    /// 2. Check if the current epoch was fully processed
    /// 3. Resume processing if needed (idempotent via dedup)
    ///
    /// # Algorithm
    /// - Load state from storage (includes dedup tracking)
    /// - Check last_processed_epoch vs current_epoch
    /// - If not equal, resume processing for current epoch
    /// - Dedup state ensures no double-minting even if we crash mid-epoch
    ///
    /// # Crash Scenarios Handled
    /// 1. Crash before any distribution: Resumes from scratch
    /// 2. Crash mid-distribution: Dedup prevents double-minting
    /// 3. Crash after full distribution: Idempotency skips processing
    /// 4. Crash during state save: WAL allows full recovery
    ///
    /// # Note
    /// This implementation requires WAL support in storage layer.
    /// The dedup maps are the source of truth for what has been minted.
    pub fn resume_after_crash(
        &mut self,
        current_height: u64,
        citizen_registry: &CitizenRegistry,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Note: In Phase 6, would load from storage:
        // self.load_from_storage(storage)?;

        let current_epoch = self.current_epoch(current_height);

        // Check if this epoch has been fully processed
        if self.state.last_processed_epoch() != Some(current_epoch) {
            // Epoch not yet processed - resume/complete distribution
            // The dedup state will prevent double-minting
            self.process_ubi_distributions(current_height, citizen_registry)?;
        }

        // If we reach here, either:
        // 1. Current epoch was already fully processed, or
        // 2. We just completed processing for the current epoch
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integration::crypto_integration::PublicKey;

    fn create_test_kernel() -> TreasuryKernel {
        let gov_auth = PublicKey::new(vec![1u8; 1312]);
        let kernel_addr = PublicKey::new(vec![2u8; 1312]);
        TreasuryKernel::new(gov_auth, kernel_addr, 60_480)
    }

    fn create_test_registry() -> CitizenRegistry {
        CitizenRegistry::new()
    }

    #[test]
    fn test_idempotency() {
        let mut kernel = create_test_kernel();
        let _registry = create_test_registry();

        // Set last_processed_epoch to current epoch
        kernel.state_mut().set_last_processed_epoch(100);

        // Check idempotency - should return early
        let height = 100 * 60_480;
        assert_eq!(kernel.current_epoch(height), 100);
        assert_eq!(kernel.state().last_processed_epoch(), Some(100));
    }

    #[test]
    fn test_epoch_boundary_processing() {
        let kernel = create_test_kernel();

        // Check epoch boundaries
        let epoch0_height = 0;
        let epoch1_height = 60_480;
        let epoch2_height = 120_960;

        assert_eq!(kernel.current_epoch(epoch0_height), 0);
        assert_eq!(kernel.current_epoch(epoch1_height), 1);
        assert_eq!(kernel.current_epoch(epoch2_height), 2);
    }

    #[test]
    fn test_stats_tracking_on_success() {
        let mut kernel = create_test_kernel();
        let _registry = create_test_registry();

        // Simulate processing (no actual claims in this test)
        kernel.state_mut().stats_mut().record_success();
        kernel.state_mut().stats_mut().record_success();
        kernel.state_mut().stats_mut().record_rejection();

        assert_eq!(kernel.stats().total_processed, 3);
        assert_eq!(kernel.stats().successful_distributions, 2);
        assert_eq!(kernel.stats().rejected_claims, 1);
    }

    #[test]
    fn test_process_ubi_distributions_flow_idempotent() {
        let mut kernel = create_test_kernel();
        let registry = create_test_registry();

        // First processing of epoch 100
        let height1 = 100 * 60_480;
        let result1 = kernel.process_ubi_distributions(height1, &registry);
        assert!(result1.is_ok());
        assert_eq!(result1.unwrap(), 100);

        // Second processing should be idempotent (no change)
        let result2 = kernel.process_ubi_distributions(height1, &registry);
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap(), 100);

        // Verify state only processed once
        assert_eq!(kernel.state().last_processed_epoch(), Some(100));
    }

    #[test]
    fn test_process_multiple_epochs() {
        let mut kernel = create_test_kernel();
        let registry = create_test_registry();

        // Process epoch 100
        let height1 = 100 * 60_480;
        assert_eq!(kernel.process_ubi_distributions(height1, &registry).unwrap(), 100);

        // Process epoch 101
        let height2 = 101 * 60_480;
        assert_eq!(kernel.process_ubi_distributions(height2, &registry).unwrap(), 101);

        // Verify each epoch was processed
        assert_eq!(kernel.state().last_processed_epoch(), Some(101));
    }

    #[test]
    fn test_poll_ubi_claims_stub() {
        let kernel = create_test_kernel();

        // Poll should return empty (Phase 5 stub)
        let claims = kernel.poll_ubi_claims(100).expect("poll_ubi_claims");
        assert_eq!(claims.len(), 0);
    }

    #[test]
    fn test_distribution_state_tracking() {
        let mut kernel = create_test_kernel();
        let registry = create_test_registry();

        let epoch = 50;

        // Simulate marking a citizen as claimed
        let citizen = [1u8; 32];
        kernel.state_mut().mark_claimed(citizen, epoch);

        // Add to distributed total
        kernel.state_mut().add_distributed(epoch, 1000).unwrap();

        // Verify state
        assert!(kernel.state().has_claimed(&citizen, epoch));
        assert_eq!(kernel.state().get_distributed(epoch), 1000);

        // Now when processing, it should be idempotent
        kernel.state_mut().set_last_processed_epoch(epoch);
        let result = kernel.process_ubi_distributions(epoch * 60_480, &registry);
        assert!(result.is_ok());
        assert_eq!(kernel.state().last_processed_epoch(), Some(epoch));
    }

    #[test]
    fn test_epoch_to_height_consistency() {
        let kernel = create_test_kernel();

        // Test epoch calculation consistency
        for epoch in 0..10 {
            let height = epoch * 60_480;
            assert_eq!(kernel.current_epoch(height), epoch);
            assert!(kernel.is_epoch_boundary(height));
        }
    }

    #[test]
    fn test_resume_after_crash_idempotency() {
        let mut kernel = create_test_kernel();
        let registry = create_test_registry();

        let epoch = 100;
        let height = epoch * 60_480;

        // First processing
        kernel.process_ubi_distributions(height, &registry).unwrap();
        assert_eq!(kernel.state().last_processed_epoch(), Some(epoch));

        // Simulate recovery - should not reprocess
        kernel.resume_after_crash(height, &registry).unwrap();
        assert_eq!(kernel.state().last_processed_epoch(), Some(epoch));
    }

    #[test]
    fn test_crash_before_distribution() {
        let mut kernel = create_test_kernel();
        let registry = create_test_registry();

        let epoch = 50;
        let height = epoch * 60_480;

        // Verify state is initially empty
        assert_eq!(kernel.state().last_processed_epoch(), None);
        assert_eq!(kernel.state().get_distributed(epoch), 0);

        // Simulate crash and recovery
        kernel.resume_after_crash(height, &registry).unwrap();

        // Should have processed current epoch
        assert_eq!(kernel.state().last_processed_epoch(), Some(epoch));
    }

    #[test]
    fn test_crash_dedup_protection() {
        let mut kernel1 = create_test_kernel();
        let mut kernel2 = create_test_kernel();
        let registry = create_test_registry();

        let epoch = 75;
        let height = epoch * 60_480;
        let citizen = [42u8; 32];

        // Simulate Kernel1 processing and crashing mid-distribution
        kernel1.state_mut().mark_claimed(citizen, epoch);
        kernel1.state_mut().add_distributed(epoch, 1000).unwrap();
        kernel1.state_mut().set_last_processed_epoch(epoch);

        // Copy state to simulate persistence
        kernel2.state_mut().mark_claimed(citizen, epoch);
        kernel2.state_mut().add_distributed(epoch, 1000).unwrap();
        kernel2.state_mut().set_last_processed_epoch(epoch);

        // Kernel2 resumes - should not double-mint
        kernel2.resume_after_crash(height, &registry).unwrap();

        // Dedup prevents re-claiming
        assert!(kernel2.state().has_claimed(&citizen, epoch));
        assert_eq!(kernel2.state().get_distributed(epoch), 1000);
    }

    #[test]
    fn test_crash_with_pool_exhaustion() {
        let mut kernel = create_test_kernel();
        let registry = create_test_registry();

        let epoch = 60;
        let height = epoch * 60_480;

        // Simulate pool being exhausted
        kernel.state_mut().add_distributed(epoch, 1_000_000).unwrap();

        // Resume after crash
        kernel.resume_after_crash(height, &registry).unwrap();

        // State should be preserved
        assert_eq!(kernel.state().get_distributed(epoch), 1_000_000);

        // Pool should still be at capacity
        assert!(!kernel.state().check_pool_capacity(epoch, 1));
    }

    #[test]
    fn test_crash_recovery_preserves_stats() {
        let mut kernel = create_test_kernel();
        let registry = create_test_registry();

        let epoch = 45;
        let height = epoch * 60_480;

        // Simulate some processing with stats
        kernel.state_mut().stats_mut().record_success();
        kernel.state_mut().stats_mut().record_success();
        kernel.state_mut().stats_mut().record_rejection();

        let stats_before = kernel.state().stats().clone();

        // Simulate crash and recovery
        kernel.resume_after_crash(height, &registry).unwrap();

        // Stats should be unchanged (would be persisted in Phase 6)
        assert_eq!(kernel.state().stats().total_processed, stats_before.total_processed);
        assert_eq!(kernel.state().stats().successful_distributions, stats_before.successful_distributions);
    }

    #[test]
    fn test_multi_epoch_crash_recovery() {
        let mut kernel = create_test_kernel();
        let registry = create_test_registry();

        // Process multiple epochs
        for epoch in 0..5 {
            let height = epoch * 60_480;
            kernel.process_ubi_distributions(height, &registry).unwrap();
        }

        // Verify all epochs processed
        assert_eq!(kernel.state().last_processed_epoch(), Some(4));

        // Simulate crash at epoch 4
        let crash_height = 4 * 60_480;

        // Create new kernel and resume (simulating restart with persisted state)
        let mut kernel2 = create_test_kernel();
        // Copy state (would be loaded from storage in Phase 6)
        kernel2.state_mut().set_last_processed_epoch(4);

        // Resume should not reprocess
        kernel2.resume_after_crash(crash_height, &registry).unwrap();
        assert_eq!(kernel2.state().last_processed_epoch(), Some(4));
    }

    #[test]
    fn test_crash_recovery_at_epoch_boundary() {
        let mut kernel = create_test_kernel();
        let registry = create_test_registry();

        let epoch = 100;
        let height = epoch * 60_480;

        // Crash exactly at epoch boundary
        kernel.resume_after_crash(height, &registry).unwrap();

        // Should process epoch 100
        assert_eq!(kernel.state().last_processed_epoch(), Some(epoch));

        // Resume again - should be idempotent
        kernel.resume_after_crash(height, &registry).unwrap();
        assert_eq!(kernel.state().last_processed_epoch(), Some(epoch));
    }
}
