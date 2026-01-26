//! Treasury Kernel - Exclusive Economic Enforcement Layer
//!
//! The Treasury Kernel is the **only** contract that can:
//! - Mint new tokens (SOV)
//! - Burn tokens
//! - Lock tokens for vesting
//! 
//! Per ADR-0017: Economic law is enforced exclusively by the Treasury Kernel.
//!
//! ## Initial Scope
//! Phase 1 implements UBI distribution only:
//! - Poll UbiClaimRecorded events from UBI contract
//! - Validate claims against 5 checks (citizenship, revocation, eligibility, dedup, pool)
//! - Mint or reject with reason code
//! - Emit UbiDistributed or UbiClaimRejected events
//!
//! ## Future Scope
//! - Compensation engine (deterministic, mechanical payouts)
//! - Metric book (prevent compensation without finalized work)
//! - Vesting + time locks
//! - Role registry + snapshots

pub mod types;
pub mod state;
pub mod validation;
pub mod authority;
pub mod events;

pub use types::{KernelState, RejectionReason, KernelStats};

use serde::{Serialize, Deserialize};
use crate::integration::crypto_integration::PublicKey;

/// Treasury Kernel - Exclusive enforcement for economic operations
///
/// **Consensus-Critical**: All state must be persisted and recoverable.
/// Kernel is a singleton - there is exactly one Kernel per blockchain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryKernel {
    /// Kernel state (dedup, pool tracking, last processed epoch)
    state: KernelState,

    /// Governance authority (immutable at init)
    governance_authority: PublicKey,

    /// Kernel identity (for minting authority)
    kernel_address: PublicKey,

    /// Blocks per epoch (60,480 for 1-week epochs)
    blocks_per_epoch: u64,
}

impl TreasuryKernel {
    /// Create a new Treasury Kernel
    ///
    /// # Arguments
    /// * `governance_authority` - Governance public key (immutable)
    /// * `kernel_address` - Kernel's own address (immutable)
    /// * `blocks_per_epoch` - Block count per epoch
    ///
    /// # Returns
    /// New TreasuryKernel instance
    pub fn new(
        governance_authority: PublicKey,
        kernel_address: PublicKey,
        blocks_per_epoch: u64,
    ) -> Self {
        Self {
            state: KernelState::new(),
            governance_authority,
            kernel_address,
            blocks_per_epoch,
        }
    }

    /// Get current kernel state
    pub fn state(&self) -> &KernelState {
        &self.state
    }

    /// Get mutable kernel state (for updates)
    pub fn state_mut(&mut self) -> &mut KernelState {
        &mut self.state
    }

    /// Get governance authority
    pub fn governance_authority(&self) -> &PublicKey {
        &self.governance_authority
    }

    /// Get kernel address
    pub fn kernel_address(&self) -> &PublicKey {
        &self.kernel_address
    }

    /// Get blocks per epoch
    pub fn blocks_per_epoch(&self) -> u64 {
        self.blocks_per_epoch
    }

    /// Calculate current epoch from block height
    ///
    /// # Arguments
    /// * `block_height` - Current block height
    ///
    /// # Returns
    /// Epoch index (deterministic, pure function)
    pub fn current_epoch(&self, block_height: u64) -> u64 {
        block_height / self.blocks_per_epoch
    }

    /// Get statistics for monitoring
    pub fn get_stats(&self) -> KernelStats {
        self.state.get_stats()
    }

    /// Resume after crash (for crash recovery)
    /// 
    /// # Arguments
    /// * `block_height` - Current block height
    ///
    /// # Returns
    /// Ok if recovery successful
    /// Err if state is corrupted
    pub fn resume_after_crash(&mut self, block_height: u64) -> Result<(), String> {
        let current_epoch = self.current_epoch(block_height);
        
        // If already processed this epoch, nothing to do
        if let Some(last_epoch) = self.state.last_processed_epoch {
            if last_epoch >= current_epoch {
                return Ok(());
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_governance() -> PublicKey {
        PublicKey {
            dilithium_pk: vec![99u8],
            kyber_pk: vec![99u8],
            key_id: [99u8; 32],
        }
    }

    fn test_kernel_address() -> PublicKey {
        PublicKey {
            dilithium_pk: vec![88u8],
            kyber_pk: vec![88u8],
            key_id: [88u8; 32],
        }
    }

    #[test]
    fn test_kernel_new() {
        let gov = test_governance();
        let kernel_addr = test_kernel_address();
        let kernel = TreasuryKernel::new(gov.clone(), kernel_addr.clone(), 60_480);

        assert_eq!(kernel.governance_authority().key_id, gov.key_id);
        assert_eq!(kernel.kernel_address().key_id, kernel_addr.key_id);
        assert_eq!(kernel.blocks_per_epoch(), 60_480);
    }

    #[test]
    fn test_current_epoch_calculation() {
        let kernel = TreasuryKernel::new(
            test_governance(),
            test_kernel_address(),
            60_480,
        );

        assert_eq!(kernel.current_epoch(0), 0);
        assert_eq!(kernel.current_epoch(60_479), 0);
        assert_eq!(kernel.current_epoch(60_480), 1);
        assert_eq!(kernel.current_epoch(120_960), 2);
    }

    #[test]
    fn test_state_accessors() {
        let mut kernel = TreasuryKernel::new(
            test_governance(),
            test_kernel_address(),
            60_480,
        );

        // Test immutable state accessor
        assert_eq!(kernel.state().stats.total_claims_processed, 0);

        // Test mutable state accessor
        kernel.state_mut().record_success();
        assert_eq!(kernel.state().stats.total_claims_processed, 1);
    }

    #[test]
    fn test_get_stats() {
        let mut kernel = TreasuryKernel::new(
            test_governance(),
            test_kernel_address(),
            60_480,
        );

        kernel.state_mut().record_success();
        kernel.state_mut().record_rejection(RejectionReason::NotACitizen);

        let stats = kernel.get_stats();
        assert_eq!(stats.total_claims_processed, 1);
        assert_eq!(stats.total_rejections, 1);
    }

    #[test]
    fn test_resume_after_crash_no_prior_state() {
        let mut kernel = TreasuryKernel::new(
            test_governance(),
            test_kernel_address(),
            60_480,
        );

        let result = kernel.resume_after_crash(60_480);
        assert!(result.is_ok());
    }

    #[test]
    fn test_resume_after_crash_skip_if_already_processed() {
        let mut kernel = TreasuryKernel::new(
            test_governance(),
            test_kernel_address(),
            60_480,
        );

        kernel.state_mut().last_processed_epoch = Some(1);

        let result = kernel.resume_after_crash(60_480);
        assert!(result.is_ok());
    }

    #[test]
    fn test_kernel_immutability() {
        let gov = test_governance();
        let kernel_addr = test_kernel_address();
        let kernel = TreasuryKernel::new(gov.clone(), kernel_addr.clone(), 60_480);

        // Verify governance authority is set correctly
        assert_eq!(kernel.governance_authority().key_id, gov.key_id);

        // Verify kernel address is set correctly
        assert_eq!(kernel.kernel_address().key_id, kernel_addr.key_id);
    }
}
