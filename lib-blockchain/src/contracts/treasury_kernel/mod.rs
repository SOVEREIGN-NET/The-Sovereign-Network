//! Treasury Kernel: Exclusive enforcement layer for economic operations
//!
//! This module implements the Treasury Kernel as specified in ADR-0017.
//! The Kernel is the sole authority for minting tokens and enforcing economic rules.
//!
//! ## Architecture
//!
//! The Treasury Kernel enforces economic law through:
//! - **Claim Validation**: 5-check validation pipeline for UBI eligibility
//! - **Deterministic Minting**: Token creation with Kernel authority enforcement
//! - **Deduplication**: Prevents double-minting after crashes
//! - **Pool Management**: Hard caps on total distributions per epoch
//! - **Event Emission**: Audit trail of all distributions and rejections
//!
//! ## UBI Distribution Flow
//!
//! ```text
//! Intent Recording → Storage Layer → Treasury Kernel → Economic Effects
//!    (UBI Contract)     (#841 WAL)    (This Module)   (Mint/Lock)
//! ```
//!
//! ## Minimal Viable Implementation
//!
//! This Kernel initially supports **UBI distribution only**:
//! - 1,000 SOV per citizen per epoch
//! - Hard pool cap of 1,000,000 SOV per epoch
//! - Automatic processing at epoch boundaries (every 60,480 blocks)

pub mod types;
pub mod state;
pub mod validation;
pub mod authority;
pub mod events;
pub mod ubi_engine;

pub use types::{
    RejectionReason, UbiClaimRecorded, UbiDistributed, UbiClaimRejected, UbiPoolStatus, KernelStats, KernelConfig,
};
pub use state::KernelState;

use serde::{Deserialize, Serialize};
use crate::contracts::executor::ContractStorage;
use crate::integration::crypto_integration::PublicKey;

/// The Treasury Kernel - exclusive enforcement of economic operations
///
/// The Kernel is initialized with:
/// - Reference to CitizenRegistry (for eligibility checks)
/// - Governance authority (for governance operations)
/// - Storage backend (for state persistence)
/// - Kernel address (for minting authority)
///
/// The Kernel maintains state across epochs and prevents double-minting
/// through deduplication, even in the case of crashes and restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryKernel {
    /// Kernel state (dedup, pool tracking, last processed epoch)
    state: KernelState,

    /// Citizen registry (read-only reference) - for eligibility checks
    /// NOTE: This is loaded from storage, not held as Arc<>
    /// Will be passed as parameter during processing
    citizen_registry_loaded: bool,

    /// Governance authority for future kernel operations
    governance_authority: PublicKey,

    /// Epoch parameters
    blocks_per_epoch: u64,

    /// Kernel identity (public key used for minting authority)
    kernel_address: PublicKey,

    /// Configuration parameters
    config: KernelConfig,
}

impl TreasuryKernel {
    /// Create a new Treasury Kernel
    ///
    /// # Arguments
    /// * `governance_authority` - The authority making governance decisions
    /// * `kernel_address` - The Kernel's public key (used for minting authority)
    /// * `blocks_per_epoch` - Number of blocks per epoch (typically 60,480)
    ///
    /// # Example
    /// ```ignore
    /// let kernel = TreasuryKernel::new(
    ///     governance_authority,
    ///     kernel_address,
    ///     60_480, // blocks per epoch
    /// );
    /// ```
    pub fn new(
        governance_authority: PublicKey,
        kernel_address: PublicKey,
        blocks_per_epoch: u64,
    ) -> Self {
        Self {
            state: KernelState::new(),
            citizen_registry_loaded: false,
            governance_authority,
            blocks_per_epoch,
            kernel_address,
            config: KernelConfig::default(),
        }
    }

    /// Load kernel state from storage
    ///
    /// This is called during initialization or after a crash to restore
    /// the kernel's state, including dedup maps and pool tracking.
    pub fn load_from_storage(
        &mut self,
        storage: &dyn ContractStorage,
    ) -> Result<(), Box<dyn std::error::Error>> {
        const KERNEL_KEY: &[u8] = b"kernel:treasury:v1";
        if let Some(data) = storage.get(KERNEL_KEY)? {
            self.state = bincode::deserialize(&data)?;
        }
        Ok(())
    }

    /// Save kernel state to storage
    ///
    /// This persists the dedup maps, pool tracking, and other state to
    /// ensure crash recovery is possible.
    pub fn save_to_storage(
        &self,
        storage: &dyn ContractStorage,
    ) -> Result<(), Box<dyn std::error::Error>> {
        const KERNEL_KEY: &[u8] = b"kernel:treasury:v1";
        let state_data = bincode::serialize(&self.state)?;
        storage.set(KERNEL_KEY, &state_data)?;
        Ok(())
    }

    /// Get the kernel's current state
    pub fn state(&self) -> &KernelState {
        &self.state
    }

    /// Get mutable reference to kernel state
    pub fn state_mut(&mut self) -> &mut KernelState {
        &mut self.state
    }

    /// Get the kernel's governance authority
    pub fn governance_authority(&self) -> &PublicKey {
        &self.governance_authority
    }

    /// Get the kernel's address (used for minting authority)
    pub fn kernel_address(&self) -> &PublicKey {
        &self.kernel_address
    }

    /// Get blocks per epoch configuration
    pub fn blocks_per_epoch(&self) -> u64 {
        self.blocks_per_epoch
    }

    /// Calculate the current epoch from block height
    pub fn current_epoch(&self, block_height: u64) -> u64 {
        block_height / self.blocks_per_epoch
    }

    /// Check if we're at an epoch boundary (should trigger UBI distribution)
    pub fn is_epoch_boundary(&self, block_height: u64) -> bool {
        block_height % self.blocks_per_epoch == 0
    }

    /// Get kernel configuration
    pub fn config(&self) -> &KernelConfig {
        &self.config
    }

    /// Get kernel statistics
    pub fn stats(&self) -> &KernelStats {
        self.state.stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_kernel() -> TreasuryKernel {
        let gov_auth = PublicKey::new(vec![1u8; 1312]);
        let kernel_addr = PublicKey::new(vec![2u8; 1312]);
        TreasuryKernel::new(gov_auth, kernel_addr, 60_480)
    }

    #[test]
    fn test_new_kernel() {
        let kernel = create_test_kernel();
        assert_eq!(kernel.blocks_per_epoch(), 60_480);
        assert_eq!(kernel.state().last_processed_epoch(), None);
    }

    #[test]
    fn test_epoch_calculation() {
        let kernel = create_test_kernel();

        assert_eq!(kernel.current_epoch(0), 0);
        assert_eq!(kernel.current_epoch(60_479), 0);
        assert_eq!(kernel.current_epoch(60_480), 1);
        assert_eq!(kernel.current_epoch(120_960), 2);
    }

    #[test]
    fn test_epoch_boundary_detection() {
        let kernel = create_test_kernel();

        assert!(kernel.is_epoch_boundary(0));
        assert!(!kernel.is_epoch_boundary(1));
        assert!(!kernel.is_epoch_boundary(60_479));
        assert!(kernel.is_epoch_boundary(60_480));
        assert!(kernel.is_epoch_boundary(120_960));
    }

    #[test]
    fn test_config_defaults() {
        let kernel = create_test_kernel();
        let config = kernel.config();

        assert_eq!(config.blocks_per_epoch, 60_480);
        assert_eq!(config.ubi_per_citizen, 1_000);
        assert_eq!(config.pool_cap_per_epoch, 1_000_000);
    }

    #[test]
    fn test_kernel_addresses() {
        let gov_auth = PublicKey::new(vec![1u8; 1312]);
        let kernel_addr = PublicKey::new(vec![2u8; 1312]);
        let kernel = TreasuryKernel::new(gov_auth.clone(), kernel_addr.clone(), 60_480);

        assert_eq!(kernel.governance_authority(), &gov_auth);
        assert_eq!(kernel.kernel_address(), &kernel_addr);
    }

    #[test]
    fn test_state_mutability() {
        let mut kernel = create_test_kernel();
        let citizen = [1u8; 32];
        let epoch = 100;

        kernel.state_mut().mark_claimed(citizen, epoch);
        assert!(kernel.state().has_claimed(&citizen, epoch));
    }
}
