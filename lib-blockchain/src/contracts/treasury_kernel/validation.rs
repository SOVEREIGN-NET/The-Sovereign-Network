//! UBI Validation Pipeline - 5-check eligibility validation
//!
//! This module implements the core validation logic for UBI claims:
//! 1. CitizenRegistry lookup
//! 2. Revocation status check
//! 3. Eligibility period check
//! 4. Deduplication check
//! 5. Pool capacity check

use crate::contracts::treasury_kernel::{RejectionReason, UbiClaimRecorded, TreasuryKernel};
use crate::contracts::governance::CitizenRegistry;

impl TreasuryKernel {
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
        if self.state.has_claimed(&claim.citizen_id, current_epoch) {
            return Err(RejectionReason::AlreadyClaimedEpoch);
        }

        // CHECK 5: Pool capacity check
        let ubi_amount = self.config().ubi_per_citizen;
        if !self.state.check_pool_capacity(current_epoch, ubi_amount) {
            return Err(RejectionReason::PoolExhausted);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::governance::CitizenRole;

    fn create_test_kernel() -> TreasuryKernel {
        use crate::integration::crypto_integration::PublicKey;
        let gov_auth = PublicKey::new(vec![1u8; 1312]);
        let kernel_addr = PublicKey::new(vec![2u8; 1312]);
        TreasuryKernel::new(gov_auth, kernel_addr, 60_480)
    }

    fn create_test_registry() -> CitizenRegistry {
        CitizenRegistry::new()
    }

    #[test]
    fn test_validation_passes() {
        let kernel = create_test_kernel();
        let mut registry = create_test_registry();

        let citizen_id = [1u8; 32];
        let citizen = CitizenRole::new(citizen_id, 100, 100);

        registry.register(citizen).expect("register citizen");

        let claim = UbiClaimRecorded {
            citizen_id,
            epoch: 100,
            block_height: 100,
        };

        let result = kernel.validate_claim(&claim, &registry, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check1_not_a_citizen() {
        let kernel = create_test_kernel();
        let registry = create_test_registry();

        let claim = UbiClaimRecorded {
            citizen_id: [1u8; 32],
            epoch: 100,
            block_height: 100,
        };

        let result = kernel.validate_claim(&claim, &registry, 100);
        assert_eq!(result, Err(RejectionReason::NotACitizen));
    }

    #[test]
    fn test_check2_citizen_revoked() {
        let kernel = create_test_kernel();
        let mut registry = create_test_registry();

        let citizen_id = [1u8; 32];
        let mut citizen = CitizenRole::new(citizen_id, 100, 100);
        citizen.revoke(100).expect("revocation should succeed");

        registry.register(citizen).expect("register citizen");

        let claim = UbiClaimRecorded {
            citizen_id,
            epoch: 100,
            block_height: 100,
        };

        let result = kernel.validate_claim(&claim, &registry, 100);
        assert_eq!(result, Err(RejectionReason::AlreadyRevoked));
    }

    #[test]
    fn test_check3_eligibility_not_met() {
        let kernel = create_test_kernel();
        let mut registry = create_test_registry();

        let citizen_id = [1u8; 32];
        let citizen = CitizenRole::new(citizen_id, 150, 150); // Becomes citizen at epoch 150

        registry.register(citizen).expect("register citizen");

        let claim = UbiClaimRecorded {
            citizen_id,
            epoch: 149, // Claiming before becoming citizen
            block_height: 149,
        };

        let result = kernel.validate_claim(&claim, &registry, 149);
        assert_eq!(result, Err(RejectionReason::EligibilityNotMet));
    }

    #[test]
    fn test_check4_already_claimed() {
        let mut kernel = create_test_kernel();
        let mut registry = create_test_registry();

        let citizen_id = [1u8; 32];
        let citizen = CitizenRole::new(citizen_id, 100, 100);

        registry.register(citizen).expect("register citizen");

        // Mark as already claimed
        kernel.state_mut().mark_claimed(citizen_id, 100);

        let claim = UbiClaimRecorded {
            citizen_id,
            epoch: 100,
            block_height: 100,
        };

        let result = kernel.validate_claim(&claim, &registry, 100);
        assert_eq!(result, Err(RejectionReason::AlreadyClaimedEpoch));
    }

    #[test]
    fn test_check5_pool_exhausted() {
        let mut kernel = create_test_kernel();
        let mut registry = create_test_registry();

        let citizen_id = [1u8; 32];
        let citizen = CitizenRole::new(citizen_id, 100, 100);

        registry.register(citizen).expect("register citizen");

        // Exhaust the pool
        kernel.state_mut().add_distributed(100, 1_000_000).unwrap();

        let claim = UbiClaimRecorded {
            citizen_id,
            epoch: 100,
            block_height: 100,
        };

        let result = kernel.validate_claim(&claim, &registry, 100);
        assert_eq!(result, Err(RejectionReason::PoolExhausted));
    }

    #[test]
    fn test_validation_sequence() {
        // Test that validation checks are run in order
        // and returns first applicable error

        let kernel = create_test_kernel();
        let mut registry = create_test_registry();

        let citizen_id = [1u8; 32];
        let mut citizen = CitizenRole::new(citizen_id, 100, 100);
        citizen.revoke(100).expect("revocation should succeed"); // Revoked but claim is before citizenship epoch

        registry.register(citizen).expect("register citizen");

        let claim = UbiClaimRecorded {
            citizen_id,
            epoch: 50, // Before citizenship and revocation
            block_height: 50,
        };

        // Note: Revocation check (check 2) is performed before eligibility check (check 3)
        // So this should fail on revocation, not eligibility
        let result = kernel.validate_claim(&claim, &registry, 50);
        assert_eq!(result, Err(RejectionReason::AlreadyRevoked));
    }
}
