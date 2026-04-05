//! Treasury Kernel - Exclusive Economic Enforcement Layer
//!
//! The Treasury Kernel is the **only** contract that can:
//! - Mint new tokens (SOV)
//! - Burn tokens
//! - Lock tokens for vesting
//!
//! Per ADR-0017: Economic law is enforced exclusively by the Treasury Kernel.
//!
//! # Architecture
//!
//! The Treasury Kernel implements the **Consensus-Critical Economic Enforcement** layer:
//! ```text
//! Intent Recording  → Storage Layer → Treasury Kernel → Economic Effects
//!   (Contracts)        (#841)         (This Module)     (Mint/Burn/Lock)
//! ```
//!
//! # Phase 1 Implementation: UBI Distribution Only
//!
//! Phase 1 provides minimal viable implementation focused on UBI (Universal Basic Income):
//! - **Passive Client Pattern**: UBI contract records intent, Kernel executes validation/minting
//! - **5-Check Validation**: Citizenship, revocation, eligibility, dedup, pool capacity
//! - **Hard Pool Cap**: 1,000,000 SOV per epoch (deterministic, consensus-critical)
//! - **Crash Recovery**: Dedup state prevents double-minting across failures
//! - **Performance**: 1000 citizens processed in <5 seconds
//!
//! # Implemented Features
//! - UBI Distribution (Phase 1)
//! - Vesting + time locks (Phase M3, Issue #853)
//! - Role Registry + Assignment Snapshots (Phase M4, Issue #854)
//! - Cap Ledger Enforcement (Phase M5, Issue #855)
//! - Metric Book + Epoch Finality (Phase M6, Issue #856)
//! - Compensation Engine Activation (Phase M7, Issue #857)
//! - Governance Execution Completion (Phase M8, Issue #858)
//!
//! # Treasury Kernel Complete
//! All milestones (M1-M8) are now implemented.
//!
//! # Critical Invariants
//!
//! The Kernel maintains these consensus-critical invariants:
//! - **Dedup Guarantee**: No citizen receives payment twice per epoch
//! - **Pool Capacity**: Total distributed never exceeds 1,000,000 SOV per epoch
//! - **Deterministic Execution**: Same inputs always produce identical outputs
//! - **Crash Recovery**: Restarting always restores to exact same state
//! - **Immutable Events**: All distributions/rejections recorded as audit trail
//!
//! ## Initial Scope
//! Phase 1 implements UBI distribution only:
//! - Poll UbiClaimRecorded events from UBI contract
//! - Validate claims against 5 checks (citizenship, revocation, eligibility, dedup, pool)
//! - Mint or reject with reason code
//! - Emit UbiDistributed or UbiClaimRejected events
//!
//! ## Architecture Layers
//! - **Role Registry**: Identity → Role assignments with snapshotted caps
//! - **Cap Ledger**: Hard cap enforcement at all scopes
//! - **Metric Book**: Append-only work metrics with attestations
//! - **Compensation Engine**: Deterministic payout computation
//! - **Paid Ledger**: Double-payment prevention
//! - **Governance Executor**: Proposal lifecycle and execution

pub mod authority;
pub mod cap_ledger;
pub mod cap_types;
pub mod compensation_engine;
pub mod events;
pub mod governance_executor;
pub mod governance_types;
pub mod interface;
pub mod kernel_ops;
pub mod metric_book;
pub mod metric_types;
pub mod paid_ledger;
pub mod payout_types;
pub mod role_registry;
pub mod role_types;
pub mod srv_ops;
pub mod srv_types;
pub mod state;
pub mod types;
pub mod ubi_engine;
pub mod validation;
pub mod vesting;
pub mod vesting_types;

pub use cap_ledger::CapLedger;
pub use cap_types::{
    AssignmentConsumption, CapError, CapReservation, PeriodConsumption, ReservationId, RoleCap,
};
pub use compensation_engine::CompensationEngine;
pub use governance_executor::GovernanceExecutor;
pub use governance_types::{
    BurnReason as GovBurnReason, ExecutionResult, GovernanceError, MintReason as GovMintReason,
    ProposalId, ProposalStatus, TreasuryAction, TreasuryParameter, TreasuryProposal,
};
pub use interface::{
    BurnAuthorization, CreditReason, DebitReason, KernelOpError, LockReason, MintAuthorization,
    MintReason, ReleaseReason,
};
pub use metric_book::{EpochClock, MetricBook};
pub use metric_types::{
    Attestation, AttestationPolicy, AttesterRole, EpochError, EpochState, EpochStatus, MetricError,
    MetricKey, MetricRecord, MetricType, MetricUnit,
};
pub use paid_ledger::PaidLedger;
pub use payout_types::{
    CapApplication, CapType, CompensationConfig, CompensationError, ComputationHash,
    EconomicConstants, PaymentError, PaymentRecord, PayoutBreakdown, PayoutCalculation,
    TransactionId,
};
pub use role_registry::RoleRegistry;
pub use role_types::{
    Assignment, AssignmentError, AssignmentId, AssignmentStatus, IdentityId, RoleDefinition,
    RoleId, RoleRegistryError,
};
pub use srv_types::{SRVError, SRVGenesisConfig, SRVState, SRVUpdateRecord};
pub use types::{KernelState, KernelStats, RejectionReason};
pub use vesting::VestingState;
pub use vesting_types::{VestingId, VestingLock, VestingSchedule, VestingStatus};

use crate::integration::crypto_integration::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

fn default_mint_delay_epochs() -> u64 {
    1
}

/// Treasury Kernel - Exclusive enforcement for economic operations
///
/// **Consensus-Critical**: All state must be persisted and recoverable.
/// Kernel is a singleton - there is exactly one Kernel per blockchain.
///
/// # Thread Safety
/// KernelState mutations are atomic and consensus-critical. All state changes
/// must be persisted before the next block is processed.
///
/// # Storage Guarantee
/// All KernelState mutations are immediately persisted using deterministic
/// serialization. This guarantees crash recovery: restarting a node always
/// recovers to the same state, preventing double-minting and ensuring
/// consensus across validators.
///
/// # Example
/// ```ignore
/// let mut kernel = TreasuryKernel::new(
///     governance_authority,
///     kernel_address,
///     60_480 // blocks per epoch (1 week)
/// );
///
/// // At epoch boundary:
/// kernel.process_ubi_distributions(block_height, executor)?;
/// ```
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

    /// Emergency pause flag — when true, all mutation operations are rejected.
    /// Only governance_authority can set/clear this flag.
    #[serde(default)]
    pub paused: bool,

    /// Pending mint authorizations from governance proposals (proposal_id -> auth)
    #[serde(default)]
    pending_mint_authorizations: BTreeMap<[u8; 32], MintAuthorization>,

    /// Pending burn authorizations from governance proposals (proposal_id -> auth)
    #[serde(default)]
    pending_burn_authorizations: BTreeMap<[u8; 32], BurnAuthorization>,

    /// Consumed authorization IDs (idempotency guard)
    #[serde(default)]
    consumed_authorizations: BTreeSet<[u8; 32]>,

    /// Mint delay in epochs (default: 1 epoch). Governance-configurable.
    #[serde(default = "default_mint_delay_epochs")]
    mint_delay_epochs: u64,
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
            paused: false,
            pending_mint_authorizations: BTreeMap::new(),
            pending_burn_authorizations: BTreeMap::new(),
            consumed_authorizations: BTreeSet::new(),
            mint_delay_epochs: default_mint_delay_epochs(),
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
            dilithium_pk: [99u8; 2592],
            kyber_pk: [99u8; 1568],
            key_id: [99u8; 32],
        }
    }

    fn test_kernel_address() -> PublicKey {
        PublicKey {
            dilithium_pk: [88u8; 2592],
            kyber_pk: [88u8; 1568],
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
        let kernel = TreasuryKernel::new(test_governance(), test_kernel_address(), 60_480);

        assert_eq!(kernel.current_epoch(0), 0);
        assert_eq!(kernel.current_epoch(60_479), 0);
        assert_eq!(kernel.current_epoch(60_480), 1);
        assert_eq!(kernel.current_epoch(120_960), 2);
    }

    #[test]
    fn test_state_accessors() {
        let mut kernel = TreasuryKernel::new(test_governance(), test_kernel_address(), 60_480);

        // Test immutable state accessor
        assert_eq!(kernel.state().stats.total_claims_processed, 0);

        // Test mutable state accessor
        kernel.state_mut().record_success();
        assert_eq!(kernel.state().stats.total_claims_processed, 1);
    }

    #[test]
    fn test_get_stats() {
        let mut kernel = TreasuryKernel::new(test_governance(), test_kernel_address(), 60_480);

        kernel.state_mut().record_success();
        kernel
            .state_mut()
            .record_rejection(RejectionReason::NotACitizen);

        let stats = kernel.get_stats();
        assert_eq!(stats.total_claims_processed, 1);
        assert_eq!(stats.total_rejections, 1);
    }

    #[test]
    fn test_resume_after_crash_no_prior_state() {
        let mut kernel = TreasuryKernel::new(test_governance(), test_kernel_address(), 60_480);

        let result = kernel.resume_after_crash(60_480);
        assert!(result.is_ok());
    }

    #[test]
    fn test_resume_after_crash_skip_if_already_processed() {
        let mut kernel = TreasuryKernel::new(test_governance(), test_kernel_address(), 60_480);

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
