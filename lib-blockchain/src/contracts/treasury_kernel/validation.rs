//! Validation Pipeline - 5-Check UBI Claim Validation
//!
//! Implements the core validation logic for UBI claims.
//!
//! # The 5-Check Validation Pipeline
//!
//! Every UBI claim passes through this deterministic validation sequence:
//!
//! 1. **Citizenship Check** (`NotACitizen`)
//!    - Look up citizen in CitizenRegistry
//!    - Fails if citizen is not registered
//!    - Requirement: citizen must exist in registry
//!
//! 2. **Revocation Check** (`AlreadyRevoked`)
//!    - Check `citizen.revoked` flag
//!    - Fails if citizen has been revoked
//!    - Irreversible: revocation is permanent within an epoch
//!
//! 3. **Eligibility Check** (`EligibilityNotMet`)
//!    - Compare `current_epoch >= citizen.citizenship_epoch`
//!    - Fails if claiming before becoming eligible
//!    - Prevents retroactive claims from new citizens
//!
//! 4. **Deduplication Check** (`AlreadyClaimedEpoch`)
//!    - Check `already_claimed[citizen_id][epoch]`
//!    - Fails if citizen already claimed in this epoch
//!    - Persisted across crashes: dedup map is serialized state
//!
//! 5. **Pool Capacity Check** (`PoolExhausted`)
//!    - Check if `total_distributed[epoch] + amount <= 1,000,000`
//!    - Fails if distribution would exceed epoch limit
//!    - Hard cap enforced: no exceptions
//!
//! # Check Ordering
//!
//! Checks run in strict order. The first failure short-circuits and returns.
//! This ordering prioritizes rejecting invalid/revoked citizens before
//! checking dedup and capacity, reducing unnecessary state mutations.
//!
//! # Privacy
//!
//! Rejected claims are silent failures from the citizen's perspective.
//! The citizen receives no feedback about which check failed.
//! This prevents information leakage about governance decisions.

use super::types::{KernelState, RejectionReason};
use crate::contracts::governance::CitizenRegistry;
use crate::contracts::UbiClaimRecorded;

impl KernelState {
    /// Validate a UBI claim against all 5 checks
    ///
    /// Returns Ok(()) if the claim passes validation, or Err(RejectionReason)
    /// if it fails any of the 5 checks.
    ///
    /// # Validation Checks
    /// 1. Citizen lookup: Does the citizen exist in registry?
    /// 2. Revocation: Is the citizen revoked?
    /// 3. Eligibility: Is current_epoch >= citizenship_epoch?
    /// 4. Dedup: Has citizen already claimed in this epoch?
    /// 5. Pool capacity: Will this distribution exceed the pool cap?
    pub fn validate_claim(
        &self,
        claim: &UbiClaimRecorded,
        citizen_registry: &CitizenRegistry,
        current_epoch: u64,
    ) -> Result<(), RejectionReason> {
        // CHECK 1: CitizenRegistry lookup
        let citizen = citizen_registry
            .get(&claim.citizen_id)
            .ok_or(RejectionReason::NotACitizen)?;

        // CHECK 2: Revocation check
        if citizen.revoked {
            return Err(RejectionReason::AlreadyRevoked);
        }

        // CHECK 3: Eligibility check (citizenship_epoch must be <= current_epoch)
        if current_epoch < citizen.citizenship_epoch() {
            return Err(RejectionReason::EligibilityNotMet);
        }

        // CHECK 4: Dedup check (has citizen already claimed in this epoch?)
        if self.has_claimed(&claim.citizen_id, current_epoch) {
            return Err(RejectionReason::AlreadyClaimedEpoch);
        }

        // CHECK 5: Pool capacity check
        if !self.check_pool_capacity(current_epoch, claim.amount) {
            return Err(RejectionReason::PoolExhausted);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::governance::CitizenRole;

    fn create_test_claim(citizen_id: [u8; 32], epoch: u64, amount: u64) -> UbiClaimRecorded {
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
    fn test_validation_passes() {
        let state = KernelState::new();
        let mut registry = create_test_registry();

        let citizen_id = [1u8; 32];
        let citizen = CitizenRole::new(citizen_id, 100, 100);

        registry.register(citizen).expect("register citizen");

        let claim = create_test_claim(citizen_id, 100, 1000);

        let result = state.validate_claim(&claim, &registry, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check1_not_a_citizen() {
        let state = KernelState::new();
        let registry = create_test_registry();

        let claim = create_test_claim([1u8; 32], 100, 1000);

        let result = state.validate_claim(&claim, &registry, 100);
        assert_eq!(result, Err(RejectionReason::NotACitizen));
    }

    #[test]
    fn test_check2_citizen_revoked() {
        let state = KernelState::new();
        let mut registry = create_test_registry();

        let citizen_id = [1u8; 32];
        let mut citizen = CitizenRole::new(citizen_id, 100, 100);
        citizen.revoke(100).expect("revocation should succeed");

        registry.register(citizen).expect("register citizen");

        let claim = create_test_claim(citizen_id, 100, 1000);

        let result = state.validate_claim(&claim, &registry, 100);
        assert_eq!(result, Err(RejectionReason::AlreadyRevoked));
    }

    #[test]
    fn test_check3_eligibility_not_met() {
        let state = KernelState::new();
        let mut registry = create_test_registry();

        let citizen_id = [1u8; 32];
        let citizen = CitizenRole::new(citizen_id, 150, 150); // Becomes citizen at epoch 150

        registry.register(citizen).expect("register citizen");

        let claim = create_test_claim(citizen_id, 149, 1000); // Claiming before becoming citizen

        let result = state.validate_claim(&claim, &registry, 149);
        assert_eq!(result, Err(RejectionReason::EligibilityNotMet));
    }

    #[test]
    fn test_check4_already_claimed() {
        let mut state = KernelState::new();
        let mut registry = create_test_registry();

        let citizen_id = [1u8; 32];
        let citizen = CitizenRole::new(citizen_id, 100, 100);

        registry.register(citizen).expect("register citizen");

        // Mark as already claimed
        let _ = state.mark_claimed(citizen_id, 100);

        let claim = create_test_claim(citizen_id, 100, 1000);

        let result = state.validate_claim(&claim, &registry, 100);
        assert_eq!(result, Err(RejectionReason::AlreadyClaimedEpoch));
    }

    #[test]
    fn test_check5_pool_exhausted() {
        let mut state = KernelState::new();
        let mut registry = create_test_registry();

        let citizen_id = [1u8; 32];
        let citizen = CitizenRole::new(citizen_id, 100, 100);

        registry.register(citizen).expect("register citizen");

        // Exhaust the pool
        state.add_distributed(100, 1_000_000).unwrap();

        let claim = create_test_claim(citizen_id, 100, 1);

        let result = state.validate_claim(&claim, &registry, 100);
        assert_eq!(result, Err(RejectionReason::PoolExhausted));
    }

    #[test]
    fn test_validation_sequence() {
        // Test that validation checks are run in order
        // and returns first applicable error

        let state = KernelState::new();
        let mut registry = create_test_registry();

        let citizen_id = [1u8; 32];
        let mut citizen = CitizenRole::new(citizen_id, 100, 100);
        citizen.revoke(100).expect("revocation should succeed"); // Revoked but claim is before citizenship epoch

        registry.register(citizen).expect("register citizen");

        let claim = create_test_claim(citizen_id, 50, 1000); // Before citizenship and revocation

        // Note: Revocation check (check 2) is performed before eligibility check (check 3)
        // So this should fail on revocation, not eligibility
        let result = state.validate_claim(&claim, &registry, 50);
        assert_eq!(result, Err(RejectionReason::AlreadyRevoked));
    }

    #[test]
    fn test_validation_with_multiple_citizens() {
        let state = KernelState::new();
        let mut registry = create_test_registry();

        // Register 3 different citizens
        for i in 1..=3 {
            let citizen_id = [i as u8; 32];
            let citizen = CitizenRole::new(citizen_id, 100, 100);
            registry.register(citizen).expect("register citizen");
        }

        // All should pass validation
        for i in 1..=3 {
            let citizen_id = [i as u8; 32];
            let claim = create_test_claim(citizen_id, 100, 1000);
            let result = state.validate_claim(&claim, &registry, 100);
            assert!(result.is_ok(), "Citizen {} should pass validation", i);
        }
    }

    #[test]
    fn test_validation_different_epochs() {
        let state = KernelState::new();
        let mut registry = create_test_registry();

        let citizen_id = [1u8; 32];
        let citizen = CitizenRole::new(citizen_id, 100, 100);
        registry.register(citizen).expect("register citizen");

        // Same citizen can claim in different epochs
        for epoch in 100..105 {
            let claim = create_test_claim(citizen_id, epoch, 1000);
            let result = state.validate_claim(&claim, &registry, epoch);
            assert!(
                result.is_ok(),
                "Citizen should pass validation in epoch {}",
                epoch
            );
        }
    }

    #[test]
    fn test_validation_pool_capacity_boundary() {
        let mut state = KernelState::new();
        let mut registry = create_test_registry();

        let citizen_id = [1u8; 32];
        let citizen = CitizenRole::new(citizen_id, 100, 100);
        registry.register(citizen).expect("register citizen");

        // Distribute 999,000
        state.add_distributed(100, 999_000).unwrap();

        // Claim of 1,000 should succeed (999,000 + 1,000 = 1,000,000)
        let claim = create_test_claim(citizen_id, 100, 1_000);
        let result = state.validate_claim(&claim, &registry, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validation_pool_capacity_exhausted_exact() {
        let mut state = KernelState::new();
        let mut registry = create_test_registry();

        let citizen_id = [1u8; 32];
        let citizen = CitizenRole::new(citizen_id, 100, 100);
        registry.register(citizen).expect("register citizen");

        // Exhaust the pool exactly
        state.add_distributed(100, 1_000_000).unwrap();

        // Even a claim of 1 should fail (already at cap)
        let claim = create_test_claim(citizen_id, 100, 1);
        let result = state.validate_claim(&claim, &registry, 100);
        assert_eq!(result, Err(RejectionReason::PoolExhausted));
    }
}
