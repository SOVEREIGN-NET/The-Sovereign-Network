//! Treasury Kernel UBI Distribution Engine
//!
//! Main processing loop for UBI distribution:
//! 1. Poll for UbiClaimRecorded events
//! 2. Validate each claim (5 checks)
//! 3. Mint or reject with reason code
//! 4. Emit events (UbiDistributed, UbiClaimRejected, UbiPoolStatus)
//! 5. Update kernel state

use super::types::{KernelState, RejectionReason};
use crate::contracts::UbiClaimRecorded;
use crate::contracts::governance::CitizenRegistry;

/// UBI Distribution Engine
impl KernelState {
    /// Process all UBI distributions for current epoch
    ///
    /// Main orchestration loop that:
    /// 1. Retrieves all UbiClaimRecorded events for the epoch
    /// 2. Validates each claim against 5 checks (delegated to validation module)
    /// 3. Attempts minting (in production)
    /// 4. Records results (success/rejection)
    /// 5. Emits corresponding events
    ///
    /// # Arguments
    /// * `claims` - All UbiClaimRecorded events for this epoch
    /// * `citizen_registry` - For eligibility checks
    /// * `current_epoch` - Current epoch
    ///
    /// # Returns
    /// (successes, rejections) tuple
    pub fn process_ubi_claims(
        &mut self,
        claims: &[UbiClaimRecorded],
        citizen_registry: &CitizenRegistry,
        current_epoch: u64,
    ) -> (u64, u64) {
        let mut successes = 0u64;
        let mut rejections = 0u64;

        for claim in claims {
            // Delegated to validation module (defined in validation.rs)
            match self.validate_claim(claim, citizen_registry, current_epoch) {
                Ok(()) => {
                    // Claim passed all 5 checks
                    // In production, would call mint_ubi() here
                    self.mark_claimed(claim.citizen_id, current_epoch);
                    if let Ok(()) = self.add_distributed(current_epoch, claim.amount) {
                        self.record_success();
                        successes += 1;
                    }
                }
                Err(reason) => {
                    // Claim failed validation
                    self.record_rejection(reason);
                    rejections += 1;
                    // In production, would emit_claim_rejected() here
                }
            }
        }

        (successes, rejections)
    }

    /// Get processing statistics
    ///
    /// # Returns
    /// Tuple of (claims_processed, rejections, total_distributed)
    pub fn get_processing_stats(&self) -> (u64, u64, u64) {
        (
            self.stats.total_claims_processed,
            self.stats.total_rejections,
            self.stats.total_sov_distributed,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::governance::CitizenRole;

    fn create_test_claim(
        citizen_id: [u8; 32],
        epoch: u64,
        amount: u64,
    ) -> UbiClaimRecorded {
        UbiClaimRecorded {
            citizen_id,
            amount,
            epoch,
            timestamp: 0,
        }
    }

    fn create_test_registry() -> CitizenRegistry {
        CitizenRegistry::new()
    }

    #[test]
    fn test_process_single_claim_success() {
        let mut state = KernelState::new();
        let mut registry = create_test_registry();

        let citizen_id = [1u8; 32];
        let citizen = CitizenRole::new(citizen_id, 100, 100);
        registry.register(citizen).expect("register citizen");

        let claims = vec![create_test_claim(citizen_id, 100, 1000)];

        let (successes, rejections) = state.process_ubi_claims(&claims, &registry, 100);

        assert_eq!(successes, 1);
        assert_eq!(rejections, 0);
        assert_eq!(state.stats.total_claims_processed, 1);
    }

    #[test]
    fn test_process_multiple_claims_mixed_results() {
        let mut state = KernelState::new();
        let mut registry = create_test_registry();

        // Citizen 1: valid
        let citizen_id1 = [1u8; 32];
        let citizen1 = CitizenRole::new(citizen_id1, 100, 100);
        registry.register(citizen1).expect("register citizen 1");

        // Citizen 2: not registered (will fail)
        let citizen_id2 = [2u8; 32];

        // Citizen 3: valid
        let citizen_id3 = [3u8; 32];
        let citizen3 = CitizenRole::new(citizen_id3, 100, 100);
        registry.register(citizen3).expect("register citizen 3");

        let claims = vec![
            create_test_claim(citizen_id1, 100, 1000), // Should succeed
            create_test_claim(citizen_id2, 100, 1000), // Should fail (not citizen)
            create_test_claim(citizen_id3, 100, 1000), // Should succeed
        ];

        let (successes, rejections) = state.process_ubi_claims(&claims, &registry, 100);

        assert_eq!(successes, 2);
        assert_eq!(rejections, 1);
        assert_eq!(state.stats.total_rejections, 1);
    }

    #[test]
    fn test_process_dedup_enforcement() {
        let mut state = KernelState::new();
        let mut registry = create_test_registry();

        let citizen_id = [1u8; 32];
        let citizen = CitizenRole::new(citizen_id, 100, 100);
        registry.register(citizen).expect("register citizen");

        // First claim
        let claims1 = vec![create_test_claim(citizen_id, 100, 1000)];
        let (successes1, rejections1) = state.process_ubi_claims(&claims1, &registry, 100);

        assert_eq!(successes1, 1);
        assert_eq!(rejections1, 0);

        // Second claim same citizen same epoch (duplicate)
        let claims2 = vec![create_test_claim(citizen_id, 100, 1000)];
        let (successes2, rejections2) = state.process_ubi_claims(&claims2, &registry, 100);

        assert_eq!(successes2, 0);
        assert_eq!(rejections2, 1);
    }

    #[test]
    fn test_process_pool_exhaustion() {
        let mut state = KernelState::new();
        let mut registry = create_test_registry();

        // Register 2 citizens
        let citizen_id1 = [1u8; 32];
        let citizen1 = CitizenRole::new(citizen_id1, 100, 100);
        registry.register(citizen1).expect("register citizen 1");

        let citizen_id2 = [2u8; 32];
        let citizen2 = CitizenRole::new(citizen_id2, 100, 100);
        registry.register(citizen2).expect("register citizen 2");

        // Exhaust pool with first citizen
        state.add_distributed(100, 1_000_000).unwrap();

        // Second citizen tries to claim
        let claims = vec![create_test_claim(citizen_id2, 100, 1)];
        let (successes, rejections) = state.process_ubi_claims(&claims, &registry, 100);

        assert_eq!(successes, 0);
        assert_eq!(rejections, 1);
    }

    #[test]
    fn test_process_eligibility_gate() {
        let mut state = KernelState::new();
        let mut registry = create_test_registry();

        // Citizen becomes eligible at epoch 150
        let citizen_id = [1u8; 32];
        let citizen = CitizenRole::new(citizen_id, 150, 150);
        registry.register(citizen).expect("register citizen");

        // Claim at epoch 149 (too early)
        let claims = vec![create_test_claim(citizen_id, 149, 1000)];
        let (successes, rejections) = state.process_ubi_claims(&claims, &registry, 149);

        assert_eq!(successes, 0);
        assert_eq!(rejections, 1);

        // Claim at epoch 150 (now eligible)
        let claims2 = vec![create_test_claim(citizen_id, 150, 1000)];
        let (successes2, rejections2) = state.process_ubi_claims(&claims2, &registry, 150);

        assert_eq!(successes2, 1);
        assert_eq!(rejections2, 0);
    }

    #[test]
    fn test_get_processing_stats() {
        let mut state = KernelState::new();
        let mut registry = create_test_registry();

        let citizen_id = [1u8; 32];
        let citizen = CitizenRole::new(citizen_id, 100, 100);
        registry.register(citizen).expect("register citizen");

        // Process 5 claims
        for i in 0..5 {
            let claims = vec![create_test_claim([i as u8; 32], 100 + i as u64, 1000)];
            let _result = state.process_ubi_claims(&claims, &registry, 100 + i as u64);
        }

        let (processed, rejections, distributed) = state.get_processing_stats();

        assert!(processed > 0);
        assert_eq!(rejections, 4); // 4 citizens not registered
        assert!(distributed > 0);
    }

    #[test]
    fn test_process_large_batch() {
        let mut state = KernelState::new();
        let mut registry = create_test_registry();

        // Register 100 citizens
        for i in 0..100 {
            let citizen_id = [(i as u8); 32];
            let citizen = CitizenRole::new(citizen_id, 100, 100);
            registry.register(citizen).expect("register citizen");
        }

        // Create claims for all 100
        let mut claims = Vec::new();
        for i in 0..100 {
            claims.push(create_test_claim([(i as u8); 32], 100, 1000));
        }

        let (successes, rejections) = state.process_ubi_claims(&claims, &registry, 100);

        assert_eq!(successes, 100);
        assert_eq!(rejections, 0);
        assert_eq!(state.stats.total_claims_processed, 100);
    }

    #[test]
    fn test_process_zero_claims() {
        let mut state = KernelState::new();
        let registry = create_test_registry();

        let claims = vec![];
        let (successes, rejections) = state.process_ubi_claims(&claims, &registry, 100);

        assert_eq!(successes, 0);
        assert_eq!(rejections, 0);
    }
}
