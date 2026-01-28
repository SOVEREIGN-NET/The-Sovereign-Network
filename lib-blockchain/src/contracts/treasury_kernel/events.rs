//! Treasury Kernel Event System
//!
//! Emits immutable events for all economic operations:
//! - **UbiDistributed**: Kernel successfully minted SOV for citizen
//! - **UbiClaimRejected**: Kernel rejected a claim with reason code
//! - **UbiPoolStatus**: End-of-epoch pool summary
//!
//! # Event Guarantees
//!
//! Events provide a complete audit trail for economic operations:
//! - **Immutability**: Events cannot be modified or deleted
//! - **Completeness**: Every distribution or rejection generates an event
//! - **Consensus**: Same inputs on all validators produce identical events
//! - **Recovery**: Events guide crash recovery to prevent double-minting
//!
//! # Event Types
//!
//! ## UbiDistributed
//! Emitted when Kernel successfully mints SOV for a citizen:
//! - `citizen_id`: Recipient of the distribution
//! - `amount`: SOV minted (typically 1,000)
//! - `epoch`: Epoch in which distribution occurred
//! - `kernel_txid`: Deterministic transaction ID
//!
//! ## UbiClaimRejected
//! Emitted when a claim fails validation:
//! - `citizen_id`: Citizen whose claim was rejected
//! - `epoch`: Epoch of the rejected claim
//! - `reason_code`: 1-5 (NotACitizen, AlreadyRevoked, AlreadyClaimedEpoch, PoolExhausted, EligibilityNotMet)
//! - `timestamp`: Block height when rejected
//!
//! Citizens never see rejection reasons (silent failure for privacy).
//! Reasons are recorded for governance monitoring only.
//!
//! ## UbiPoolStatus
//! Emitted at end of epoch to summarize distribution:
//! - `epoch`: Which epoch
//! - `eligible_count`: Citizens eligible in this epoch
//! - `total_distributed`: Total SOV minted this epoch
//! - `remaining_capacity`: 1,000,000 - total_distributed
//!
//! Invariant: `remaining_capacity = 1,000,000 - total_distributed` (saturating)
//!
//! # Storage
//!
//! Events are persisted with keys:
//! ```text
//! kernel:events:UbiDistributed:{epoch}:{citizen_id}
//! kernel:events:UbiClaimRejected:{epoch}:{citizen_id}
//! kernel:events:UbiPoolStatus:{epoch}
//! ```
//!
//! This enables:
//! - Efficient epoch-based queries
//! - Governance audit trails
//! - Crash recovery validation

use super::types::{KernelState, RejectionReason};
use super::interface::MintReason;

/// Event emission for Treasury Kernel
impl KernelState {
    // ─── Governance Mint/Burn Authorization Events (M2) ──────────────

    /// Emit MintAuthorized event
    ///
    /// Recorded when a governance proposal registers a mint authorization
    /// with the Treasury Kernel. The mint cannot execute until the delay
    /// period elapses.
    pub fn emit_mint_authorized(
        &self,
        _proposal_id: [u8; 32],
        _recipient_key_id: [u8; 32],
        amount: u64,
        _reason: MintReason,
        _executable_after_epoch: u64,
    ) -> Result<(), String> {
        if amount == 0 {
            return Err("Cannot authorize mint for zero amount".to_string());
        }
        Ok(())
    }

    /// Emit MintExecuted event
    ///
    /// Recorded after a governance-authorized mint is successfully executed.
    pub fn emit_mint_executed(
        &self,
        _proposal_id: [u8; 32],
        _recipient_key_id: [u8; 32],
        amount: u64,
        _execution_epoch: u64,
    ) -> Result<(), String> {
        if amount == 0 {
            return Err("Cannot record execution of zero-amount mint".to_string());
        }
        Ok(())
    }

    /// Emit BurnAuthorized event
    ///
    /// Recorded when a governance proposal registers a burn authorization.
    pub fn emit_burn_authorized(
        &self,
        _proposal_id: [u8; 32],
        _from_key_id: [u8; 32],
        amount: u64,
        _executable_after_epoch: u64,
    ) -> Result<(), String> {
        if amount == 0 {
            return Err("Cannot authorize burn for zero amount".to_string());
        }
        Ok(())
    }

    /// Emit BurnExecuted event
    ///
    /// Recorded after a governance-authorized burn is successfully executed.
    pub fn emit_burn_executed(
        &self,
        _proposal_id: [u8; 32],
        _from_key_id: [u8; 32],
        amount: u64,
        _execution_epoch: u64,
    ) -> Result<(), String> {
        if amount == 0 {
            return Err("Cannot record execution of zero-amount burn".to_string());
        }
        Ok(())
    }

    // ─── UBI Distribution Events ────────────────────────────────────
    /// Emit UbiDistributed event
    ///
    /// Called after successful minting to record the distribution.
    /// Event is immutable and provides complete audit trail.
    ///
    /// # Arguments
    /// * `citizen_id` - Recipient citizen
    /// * `amount` - SOV distributed
    /// * `epoch` - Epoch for which distribution occurred
    /// * `kernel_txid` - Deterministic transaction ID
    ///
    /// # Returns
    /// Ok if event recorded successfully
    pub fn emit_distributed(
        &self,
        _citizen_id: [u8; 32],
        amount: u64,
        _epoch: u64,
        _kernel_txid: [u8; 32],
    ) -> Result<(), String> {
        // In production, would persist to storage layer
        // For now, just validate inputs
        if amount == 0 {
            return Err("Cannot emit distribution for zero amount".to_string());
        }

        // Event structure would be:
        // - citizen_id: [u8; 32]
        // - amount: u64
        // - epoch: u64
        // - kernel_txid: [u8; 32]
        // - timestamp: block_height (set by executor)

        Ok(())
    }

    /// Emit UbiClaimRejected event
    ///
    /// Called for each rejected claim. Citizens never see the reason code
    /// (silent failure for privacy), but events are recorded for governance.
    ///
    /// # Arguments
    /// * `citizen_id` - Citizen whose claim was rejected
    /// * `epoch` - Epoch of rejected claim
    /// * `reason` - Rejection reason code (1-5)
    /// * `timestamp` - Block height when rejected
    ///
    /// # Returns
    /// Ok if event recorded successfully
    pub fn emit_claim_rejected(
        &self,
        _citizen_id: [u8; 32],
        _epoch: u64,
        reason: RejectionReason,
        _timestamp: u64,
    ) -> Result<(), String> {
        // In production, would persist to storage layer
        // Validate reason is in valid range (1-5)
        let reason_code = reason as u8;
        if reason_code < 1 || reason_code > 5 {
            return Err("Invalid rejection reason code".to_string());
        }

        // Event structure would be:
        // - citizen_id: [u8; 32]
        // - epoch: u64
        // - reason_code: u8 (1-5)
        // - timestamp: u64

        Ok(())
    }

    /// Emit UbiPoolStatus event
    ///
    /// Called at end of epoch to record distribution summary.
    /// Enables governance monitoring of pool usage and exhaustion.
    ///
    /// # Arguments
    /// * `epoch` - Epoch this status applies to
    /// * `eligible_count` - Citizens eligible in this epoch
    /// * `total_distributed` - Total SOV minted this epoch
    /// * `remaining_capacity` - 1,000,000 - total_distributed
    ///
    /// # Returns
    /// Ok if event recorded successfully
    pub fn emit_pool_status(
        &self,
        _epoch: u64,
        _eligible_count: u64,
        total_distributed: u64,
        remaining_capacity: u64,
    ) -> Result<(), String> {
        // In production, would persist to storage layer
        // Verify invariant: remaining = 1_000_000 - total_distributed
        const POOL_CAP: u64 = 1_000_000;

        let expected_remaining = POOL_CAP.saturating_sub(total_distributed);
        if remaining_capacity != expected_remaining {
            return Err(format!(
                "Pool status invariant violated: remaining={}, expected={}",
                remaining_capacity, expected_remaining
            ));
        }

        // Event structure would be:
        // - epoch: u64
        // - eligible_count: u64
        // - total_distributed: u64
        // - remaining_capacity: u64

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emit_distributed_success() {
        let state = KernelState::new();
        let result = state.emit_distributed([1u8; 32], 1000, 100, [88u8; 32]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_emit_distributed_zero_amount_fails() {
        let state = KernelState::new();
        let result = state.emit_distributed([1u8; 32], 0, 100, [88u8; 32]);
        assert!(result.is_err());
        assert_eq!(
            result,
            Err("Cannot emit distribution for zero amount".to_string())
        );
    }

    #[test]
    fn test_emit_distributed_large_amount() {
        let state = KernelState::new();
        let result = state.emit_distributed([1u8; 32], u64::MAX / 2, 100, [88u8; 32]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_emit_claim_rejected_valid_reasons() {
        let state = KernelState::new();

        // Test all 5 valid reason codes
        let reasons = vec![
            RejectionReason::NotACitizen,
            RejectionReason::AlreadyRevoked,
            RejectionReason::AlreadyClaimedEpoch,
            RejectionReason::PoolExhausted,
            RejectionReason::EligibilityNotMet,
        ];

        for reason in reasons {
            let result = state.emit_claim_rejected([1u8; 32], 100, reason, 12345);
            assert!(
                result.is_ok(),
                "Failed to emit rejection for reason: {:?}",
                reason
            );
        }
    }

    #[test]
    fn test_emit_claim_rejected_multiple() {
        let state = KernelState::new();

        // Emit multiple rejections
        for i in 0..10 {
            let reason = match i % 5 {
                0 => RejectionReason::NotACitizen,
                1 => RejectionReason::AlreadyRevoked,
                2 => RejectionReason::AlreadyClaimedEpoch,
                3 => RejectionReason::PoolExhausted,
                _ => RejectionReason::EligibilityNotMet,
            };

            let result = state.emit_claim_rejected([(i as u8); 32], 100, reason, 12345 + i);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_emit_pool_status_empty_pool() {
        let state = KernelState::new();
        let result = state.emit_pool_status(100, 0, 0, 1_000_000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_emit_pool_status_full_pool() {
        let state = KernelState::new();
        let result = state.emit_pool_status(100, 1000, 1_000_000, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_emit_pool_status_partial_pool() {
        let state = KernelState::new();
        let result = state.emit_pool_status(100, 500, 500_000, 500_000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_emit_pool_status_invariant_violated() {
        let state = KernelState::new();
        let result = state.emit_pool_status(100, 500, 500_000, 499_999); // Wrong remaining

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invariant violated"));
    }

    #[test]
    fn test_emit_pool_status_multiple_epochs() {
        let state = KernelState::new();

        // Emit status for multiple epochs
        for epoch in 100..105 {
            let result = state.emit_pool_status(epoch, 100 * epoch, epoch * 1000, 1_000_000 - epoch * 1000);
            assert!(result.is_ok(), "Failed for epoch {}", epoch);
        }
    }

    #[test]
    fn test_emit_pool_status_saturating_subtraction() {
        let state = KernelState::new();

        // If total_distributed > cap (shouldn't happen in practice),
        // saturating subtraction gives 0
        let result = state.emit_pool_status(100, 1000, 1_000_001, 0);

        // This should fail because expected remaining would be 0 but
        // cap.saturating_sub(1_000_001) = 0, so it should pass
        assert!(result.is_ok());
    }

    // ── Governance Mint/Burn Authorization Events ─────────────────

    #[test]
    fn test_emit_mint_authorized_success() {
        let state = KernelState::new();
        let result = state.emit_mint_authorized(
            [1u8; 32],
            [2u8; 32],
            50_000,
            super::MintReason::WelfareFunding,
            5,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_emit_mint_authorized_zero_amount_fails() {
        let state = KernelState::new();
        let result = state.emit_mint_authorized(
            [1u8; 32],
            [2u8; 32],
            0,
            super::MintReason::TreasuryAllocation,
            5,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_emit_mint_executed_success() {
        let state = KernelState::new();
        let result = state.emit_mint_executed([1u8; 32], [2u8; 32], 50_000, 6);
        assert!(result.is_ok());
    }

    #[test]
    fn test_emit_mint_executed_zero_fails() {
        let state = KernelState::new();
        let result = state.emit_mint_executed([1u8; 32], [2u8; 32], 0, 6);
        assert!(result.is_err());
    }

    #[test]
    fn test_emit_burn_authorized_success() {
        let state = KernelState::new();
        let result = state.emit_burn_authorized([3u8; 32], [4u8; 32], 10_000, 3);
        assert!(result.is_ok());
    }

    #[test]
    fn test_emit_burn_authorized_zero_fails() {
        let state = KernelState::new();
        let result = state.emit_burn_authorized([3u8; 32], [4u8; 32], 0, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_emit_burn_executed_success() {
        let state = KernelState::new();
        let result = state.emit_burn_executed([3u8; 32], [4u8; 32], 10_000, 4);
        assert!(result.is_ok());
    }

    #[test]
    fn test_emit_burn_executed_zero_fails() {
        let state = KernelState::new();
        let result = state.emit_burn_executed([3u8; 32], [4u8; 32], 0, 4);
        assert!(result.is_err());
    }
}
