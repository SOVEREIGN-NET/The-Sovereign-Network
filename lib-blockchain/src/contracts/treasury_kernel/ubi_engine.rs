//! Treasury Kernel UBI Distribution Engine
//!
//! Main processing loop for UBI distribution that executes at epoch boundaries.
//!
//! # Processing Pipeline
//!
//! The engine implements a deterministic pipeline that runs once per epoch:
//!
//! 1. **Poll for Claims**: Retrieve all UbiClaimRecorded events from UBI contract
//! 2. **Validate Each Claim**: Run 5-check validation (delegation to validation module)
//! 3. **Mint or Reject**:
//!    - Success: Mark citizen as claimed, update pool, record success
//!    - Failure: Record rejection with specific reason code
//! 4. **Emit Events**:
//!    - UbiDistributed (for successes)
//!    - UbiClaimRejected (for failures with reason)
//!    - UbiPoolStatus (epoch summary)
//! 5. **Update State**: Persist dedup and pool tracking for crash recovery
//!
//! # Execution Frequency
//!
//! The engine runs at epoch boundaries (block height % 60_480 == 0):
//! - **Weekly**: One execution per week (60,480 blocks ≈ 7 days)
//! - **Deterministic**: Same block height always produces same epoch
//! - **Idempotent**: Processing same epoch twice has no effect
//!
//! # Failure Handling
//!
//! ## Validation Failures (Expected)
//! If validation returns `Err(reason)`, the engine:
//! - Records the rejection with the reason code
//! - Continues processing next claim
//! - Does not mutate state
//!
//! ## Processing Failures (Rare)
//! If minting or event emission fails, the engine stops immediately.
//! The partially-updated state is persisted, and recovery picks up at restart.
//!
//! # Statistics
//!
//! The engine tracks:
//! - `total_claims_processed`: Count of validated claims
//! - `total_rejections`: Count of failed claims
//! - `total_sov_distributed`: Total SOV minted
//! - `rejections_by_reason`: Breakdown by rejection reason
//!
//! These are exposed via `get_processing_stats()` for governance monitoring.

use super::types::KernelState;
use crate::contracts::UbiClaimRecorded;
use crate::contracts::governance::CitizenRegistry;
use crate::contracts::TokenContract;
use crate::integration::crypto_integration::PublicKey;

/// UBI Distribution Engine
impl KernelState {
    fn compute_ubi_kernel_txid(citizen_id: &[u8; 32], epoch: u64, amount: u64) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(32 + 8 + 8 + 16);
        bytes.extend_from_slice(b"ubi:distributed:v1");
        bytes.extend_from_slice(citizen_id);
        bytes.extend_from_slice(&epoch.to_le_bytes());
        bytes.extend_from_slice(&amount.to_le_bytes());
        let hash = lib_crypto::hash_blake3(&bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash[..32]);
        out
    }

    /// Process all UBI distributions for current epoch
    ///
    /// Main orchestration loop that:
    /// 1. Retrieves all UbiClaimRecorded events for the epoch
    /// 2. Validates each claim against 5 checks (delegated to validation module)
    /// 3. Mints tokens to recipient (Issue #1017: now actually mints!)
    /// 4. Records results (success/rejection)
    /// 5. Emits corresponding events
    ///
    /// # Arguments
    /// * `claims` - All UbiClaimRecorded events for this epoch
    /// * `citizen_registry` - For eligibility checks
    /// * `current_epoch` - Current epoch
    /// * `token` - SOV token contract for minting (optional for backward compat)
    /// * `kernel_address` - Treasury Kernel's public key for mint authorization
    ///
    /// # Returns
    /// (successes, rejections) tuple
    pub fn process_ubi_claims(
        &mut self,
        claims: &[UbiClaimRecorded],
        citizen_registry: &CitizenRegistry,
        current_epoch: u64,
    ) -> (u64, u64) {
        // Call the new version without token (backward compatibility)
        self.process_ubi_claims_with_minting(claims, citizen_registry, current_epoch, None, None)
    }

    /// Process all UBI distributions with actual token minting (Issue #1017)
    ///
    /// This is the full implementation that actually mints tokens to recipients.
    /// Use this method when you have access to the TokenContract.
    ///
    /// # Arguments
    /// * `claims` - All UbiClaimRecorded events for this epoch
    /// * `citizen_registry` - For eligibility checks
    /// * `current_epoch` - Current epoch
    /// * `token` - SOV token contract for minting (if None, only tracks distribution)
    /// * `kernel_address` - Treasury Kernel's public key for mint authorization
    ///
    /// # Returns
    /// (successes, rejections) tuple
    pub fn process_ubi_claims_with_minting(
        &mut self,
        claims: &[UbiClaimRecorded],
        citizen_registry: &CitizenRegistry,
        current_epoch: u64,
        mut token: Option<&mut TokenContract>,
        kernel_address: Option<&PublicKey>,
    ) -> (u64, u64) {
        let mut successes = 0u64;
        let mut rejections = 0u64;

        // Check if we can mint (both token and kernel address available)
        let can_mint = token.is_some() && kernel_address.is_some();

        for claim in claims {
            // Delegated to validation module (defined in validation.rs)
            match self.validate_claim(claim, citizen_registry, current_epoch) {
                Ok(()) => {
                    // Claim passed all 5 checks
                    // Mark claimed in dedup map (should always succeed after validation)
                    match self.mark_claimed(claim.citizen_id, current_epoch) {
                        Ok(()) => {
                            // Issue #1017: Actually mint tokens if token contract is available
                            let mint_success = if can_mint {
                                // Create recipient PublicKey from citizen_id
                                // The citizen_id is used as the key_id for balance tracking
                                //
                                // ARCHITECTURAL NOTE: This creates a "synthetic" PublicKey with only key_id populated.
                                // The dilithium_pk and kyber_pk fields are left empty because:
                                // 1. TokenContract uses PublicKey as HashMap key (via PartialEq which checks all fields)
                                // 2. CitizenRegistry currently only stores citizen_id ([u8; 32]), not full PublicKeys
                                // 3. Balance tracking doesn't require cryptographic operations on the key
                                //
                                // Future improvement: Either refactor TokenContract to use key_id-only lookups,
                                // or extend CitizenRegistry to store full PublicKeys for each citizen.
                                // See PR#1019 review comments for discussion.
                                let recipient = PublicKey {
                                    dilithium_pk: vec![], // Empty - not needed for balance tracking
                                    kyber_pk: vec![],     // Empty - not needed for balance tracking
                                    key_id: claim.citizen_id,
                                };

                                // SAFETY: We verified token.is_some() and kernel_address.is_some() above
                                let kernel_addr = kernel_address.unwrap();
                                match token.as_mut().unwrap().mint_kernel_only(kernel_addr, &recipient, claim.amount) {
                                    Ok(()) => {
                                        tracing::debug!(
                                            "UBI minted: {} to citizen {:?}",
                                            claim.amount,
                                            &claim.citizen_id[..4]
                                        );
                                        true
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "UBI mint failed for citizen {:?}: {}",
                                            &claim.citizen_id[..4],
                                            e
                                        );
                                        false
                                    }
                                }
                            } else {
                                // No token contract - just track distribution (backward compat)
                                true
                            };

                            if mint_success {
                                if let Ok(()) = self.add_distributed(current_epoch, claim.amount) {
                                    let kernel_txid = Self::compute_ubi_kernel_txid(
                                        &claim.citizen_id,
                                        current_epoch,
                                        claim.amount,
                                    );
                                    if self.emit_distributed(
                                        claim.citizen_id,
                                        claim.amount,
                                        current_epoch,
                                        kernel_txid,
                                    ).is_err() {
                                        self.record_rejection(crate::contracts::treasury_kernel::types::RejectionReason::MintFailed);
                                        rejections += 1;
                                        continue;
                                    }
                                    self.record_success();
                                    successes += 1;
                                }
                            } else {
                                // Mint failed - record as rejection
                                let _ = self.emit_claim_rejected(
                                    claim.citizen_id,
                                    current_epoch,
                                    crate::contracts::treasury_kernel::types::RejectionReason::MintFailed,
                                    current_epoch,
                                );
                                self.record_rejection(crate::contracts::treasury_kernel::types::RejectionReason::MintFailed);
                                rejections += 1;
                            }
                        }
                        Err(_) => {
                            // Duplicate detected (shouldn't happen after validation passes)
                            // Treat as rejection rather than panic
                            let _ = self.emit_claim_rejected(
                                claim.citizen_id,
                                current_epoch,
                                crate::contracts::treasury_kernel::types::RejectionReason::AlreadyClaimedEpoch,
                                current_epoch,
                            );
                            self.record_rejection(crate::contracts::treasury_kernel::types::RejectionReason::AlreadyClaimedEpoch);
                            rejections += 1;
                        }
                    }
                }
                Err(reason) => {
                    // Claim failed validation
                    let _ = self.emit_claim_rejected(claim.citizen_id, current_epoch, reason, current_epoch);
                    self.record_rejection(reason);
                    rejections += 1;
                }
            }
        }

        let total_distributed = self.get_distributed(current_epoch);
        let remaining_capacity = 1_000_000u64.saturating_sub(total_distributed);
        let _ = self.emit_pool_status(
            current_epoch,
            claims.len() as u64,
            total_distributed,
            remaining_capacity,
        );

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
    use crate::contracts::TokenContract;

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

    #[test]
    fn test_process_claim_with_actual_minting() {
        // Issue #1017: Verify that tokens are actually minted when TokenContract is provided
        let mut state = KernelState::new();
        let mut registry = create_test_registry();

        // Create kernel authority using PublicKey::new to derive key_id from dilithium_pk
        let kernel_authority = PublicKey::new(vec![99u8; 32]);

        // Create SOV token with kernel authority
        let mut token = TokenContract::new_sov_with_kernel_authority(kernel_authority.clone());

        // Register citizen
        let citizen_id = [1u8; 32];
        let citizen = CitizenRole::new(citizen_id, 100, 100);
        registry.register(citizen).expect("register citizen");

        // Verify citizen has no balance initially
        let citizen_pubkey = PublicKey {
            dilithium_pk: vec![],
            kyber_pk: vec![],
            key_id: citizen_id,
        };
        assert_eq!(token.balance_of(&citizen_pubkey), 0);

        // Create claim
        let ubi_amount = 1000u64;
        let claims = vec![create_test_claim(citizen_id, 100, ubi_amount)];

        // Process with minting
        let (successes, rejections) = state.process_ubi_claims_with_minting(
            &claims,
            &registry,
            100,
            Some(&mut token),
            Some(&kernel_authority),
        );

        // Verify results
        assert_eq!(successes, 1, "Should have 1 success");
        assert_eq!(rejections, 0, "Should have 0 rejections");

        // Verify tokens were actually minted to citizen's balance
        let balance_after = token.balance_of(&citizen_pubkey);
        assert_eq!(
            balance_after, ubi_amount,
            "Citizen should have {} SOV after UBI mint, got {}",
            ubi_amount, balance_after
        );

        // Verify total supply increased
        assert_eq!(
            token.total_supply, ubi_amount,
            "Total supply should be {} after mint",
            ubi_amount
        );

        // Distributed + pool status events are emitted deterministically.
        assert_eq!(state.ubi_events().len(), 2);
    }

    #[test]
    fn test_process_claim_minting_fails_without_authority() {
        // Verify that minting fails gracefully when kernel authority doesn't match
        let mut state = KernelState::new();
        let mut registry = create_test_registry();

        // Create kernel authority
        let kernel_authority = PublicKey {
            dilithium_pk: vec![99u8; 32],
            kyber_pk: vec![99u8; 32],
            key_id: [99u8; 32],
        };

        // Create different authority (wrong key)
        let wrong_authority = PublicKey {
            dilithium_pk: vec![88u8; 32],
            kyber_pk: vec![88u8; 32],
            key_id: [88u8; 32],
        };

        // Create SOV token with kernel authority
        let mut token = TokenContract::new_sov_with_kernel_authority(kernel_authority);

        // Register citizen
        let citizen_id = [1u8; 32];
        let citizen = CitizenRole::new(citizen_id, 100, 100);
        registry.register(citizen).expect("register citizen");

        // Create claim
        let claims = vec![create_test_claim(citizen_id, 100, 1000)];

        // Process with wrong authority - should fail mint
        let (successes, rejections) = state.process_ubi_claims_with_minting(
            &claims,
            &registry,
            100,
            Some(&mut token),
            Some(&wrong_authority), // Wrong authority!
        );

        // Verify mint failed
        assert_eq!(successes, 0, "Should have 0 successes (mint failed)");
        assert_eq!(rejections, 1, "Should have 1 rejection (MintFailed)");

        // Verify no tokens were minted
        let citizen_pubkey = PublicKey {
            dilithium_pk: vec![],
            kyber_pk: vec![],
            key_id: citizen_id,
        };
        assert_eq!(
            token.balance_of(&citizen_pubkey),
            0,
            "Citizen should have 0 balance (mint failed)"
        );

        // Rejection + pool status events should be present.
        assert_eq!(state.ubi_events().len(), 2);
    }

    #[test]
    fn test_ubi_events_and_dedup_persist_across_state_recovery() {
        let mut state = KernelState::new();
        let mut registry = create_test_registry();
        let kernel_authority = PublicKey::new(vec![99u8; 32]);
        let mut token = TokenContract::new_sov_with_kernel_authority(kernel_authority.clone());

        let citizen_id = [1u8; 32];
        let citizen = CitizenRole::new(citizen_id, 100, 100);
        registry.register(citizen).expect("register citizen");

        let claims = vec![create_test_claim(citizen_id, 100, 1000)];
        let (successes, rejections) = state.process_ubi_claims_with_minting(
            &claims,
            &registry,
            100,
            Some(&mut token),
            Some(&kernel_authority),
        );
        assert_eq!(successes, 1);
        assert_eq!(rejections, 0);
        assert!(state.has_claimed(&citizen_id, 100));
        assert_eq!(state.ubi_events().len(), 2);

        let bytes = state.to_bytes().expect("serialize state");
        let restored = KernelState::from_bytes(&bytes).expect("deserialize state");

        assert!(restored.has_claimed(&citizen_id, 100));
        assert_eq!(restored.ubi_events().len(), 2);
        assert!(restored.is_valid());
    }
}
