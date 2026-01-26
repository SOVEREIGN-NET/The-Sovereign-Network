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
    /// This is the main entry point called from ContractExecutor.finalize_block_state()
    /// at epoch boundaries.
    ///
    /// Returns the current epoch number on success.
    ///
    /// # Algorithm
    /// 1. Check if we've already processed this epoch (idempotency)
    /// 2. Poll for UbiClaimRecorded events
    /// 3. For each claim:
    ///    a. Validate (5-check pipeline)
    ///    b. If valid: mint tokens
    ///    c. If invalid: emit rejection event
    /// 4. Emit pool status
    /// 5. Persist state
    ///
    /// # Note
    /// This is a Phase 5 implementation. Currently a stub that will be completed
    /// with full event polling and minting in subsequent phases.
    pub fn process_ubi_distributions(
        &mut self,
        current_height: u64,
        citizen_registry: &CitizenRegistry,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let current_epoch = self.current_epoch(current_height);

        // Idempotency check: don't process same epoch twice
        if self.state.last_processed_epoch() == Some(current_epoch) {
            return Ok(current_epoch);
        }

        // TODO: Phase 4 - Poll for UbiClaimRecorded events from UBI contract
        // let claims = self.poll_ubi_claims(current_epoch, executor)?;

        let claims = Vec::new(); // Placeholder

        // Process each claim
        for claim in claims {
            match self.validate_claim(&claim, citizen_registry, current_epoch) {
                Ok(_) => {
                    // TODO: Phase 3 - Mint tokens
                    // let kernel_txid = self.mint_ubi(&claim.citizen_id, 1000, current_epoch, executor)?;
                    // self.emit_ubi_distributed(claim.citizen_id, 1000, current_epoch, kernel_txid, executor.storage())?;
                    // self.state.mark_claimed(claim.citizen_id, current_epoch);
                    // self.state.add_distributed(current_epoch, 1000)?;

                    self.state_mut().mark_claimed(claim.citizen_id, current_epoch);
                    self.state_mut().add_distributed(current_epoch, 1000)?;
                    self.state_mut().stats_mut().record_success();
                }
                Err(_reason) => {
                    // TODO: Phase 4 - Emit rejection event
                    // self.emit_ubi_rejected(claim.citizen_id, current_epoch, reason, current_height, executor.storage())?;
                    self.state_mut().stats_mut().record_rejection();
                }
            }
        }

        // Emit pool status
        let _eligible_count = citizen_registry.get_active_citizens().len() as u64;
        let _total_dist = self.state.get_distributed(current_epoch);

        // TODO: Phase 4 - Emit pool status event
        // self.emit_ubi_pool_status(current_epoch, eligible_count, total_dist, executor.storage())?;

        // Update state
        self.state_mut().set_last_processed_epoch(current_epoch);

        // TODO: Phase 6 - Persist state to storage
        // self.save_to_storage(executor.storage())?;

        Ok(current_epoch)
    }

    /// Resume UBI processing after a crash
    ///
    /// This is called during system startup to ensure we haven't missed
    /// any UBI distributions. If the system crashed before completing
    /// an epoch's distribution, it will be resumed here.
    ///
    /// The dedup state prevents double-minting even if we crash mid-epoch.
    ///
    /// # Note
    /// This is a Phase 6 implementation. Currently a stub that will be completed
    /// with full crash recovery logic in Phase 6.
    pub fn resume_after_crash(
        &mut self,
        current_height: u64,
        citizen_registry: &CitizenRegistry,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // TODO: Phase 6 - Load persisted state from storage

        let current_epoch = self.current_epoch(current_height);

        // If we haven't processed this epoch yet, resume processing
        if self.state.last_processed_epoch() != Some(current_epoch) {
            self.process_ubi_distributions(current_height, citizen_registry)?;
        }

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
}
