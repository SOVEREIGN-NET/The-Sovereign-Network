//! Mempool Admission Logic
//!
//! The `admit` function performs pre-consensus validation for mempool admission.
//!
//! Note: The canonical type definitions have moved to lib-types.
//! This module provides the admission logic while the data types
//! (AdmitResult, AdmitTx, etc.) live in lib-types.

use lib_fees::model_v2::TxKindExt;
use lib_fees::{compute_fee_v2, FeeInput, FeeParams};
use lib_types::mempool::{AdmitErrorKind, AdmitResult, AdmitTx};
use lib_types::{Amount, BlockHeight};

use crate::config::{MempoolConfig, MempoolConfigExt};
use crate::state::{MempoolState, MempoolStateExt};

/// Extension trait for AdmitResult with convenience methods
pub trait AdmitResultExt {
    /// Check if transaction was accepted
    fn is_accepted(&self) -> bool;
    /// Check if transaction was rejected
    fn is_rejected(&self) -> bool;
}

impl AdmitResultExt for AdmitResult {
    fn is_accepted(&self) -> bool {
        matches!(self, AdmitResult::Accepted)
    }

    fn is_rejected(&self) -> bool {
        matches!(self, AdmitResult::Rejected(_))
    }
}

/// Perform mempool admission check
///
/// Validates a transaction against mempool limits and fee requirements.
/// Returns AdmitResult::Accepted if the transaction can be admitted,
/// or AdmitResult::Rejected with the specific reason.
///
/// # Arguments
///
/// * `tx` - The transaction to check
/// * `fee_params` - Fee calculation parameters
/// * `config` - Mempool configuration limits
/// * `state` - Current mempool state
/// * `current_block` - Current block height for rate limit calculations
pub fn admit(
    tx: &AdmitTx,
    fee_params: &FeeParams,
    config: &MempoolConfig,
    state: &MempoolState,
    current_block: BlockHeight,
) -> AdmitResult {
    // Check mempool capacity
    if !state.has_tx_capacity(config.max_tx_count) {
        return AdmitResult::Rejected(AdmitErrorKind::MempoolFull);
    }

    // Check byte capacity, accounting for the incoming transaction size
    let prospective_bytes = state.total_bytes.saturating_add(tx.tx_bytes as u64);

    if prospective_bytes > config.max_mempool_bytes {
        return AdmitResult::Rejected(AdmitErrorKind::MempoolBytesFull {
            // Report the would-be size if this transaction were admitted
            prospective_total_bytes: prospective_bytes,
            max: config.max_mempool_bytes,
        });
    }

    // Check transaction size limits
    if tx.tx_bytes > config.max_tx_bytes {
        return AdmitResult::Rejected(AdmitErrorKind::TxTooLarge {
            size: tx.tx_bytes,
            max: config.max_tx_bytes,
        });
    }

    if tx.witness_bytes > config.max_witness_bytes {
        return AdmitResult::Rejected(AdmitErrorKind::WitnessTooLarge {
            size: tx.witness_bytes,
            max: config.max_witness_bytes,
        });
    }

    // Check per-TxKind witness cap (DoS mitigation)
    // The effective cap is the minimum of global config and TxKind-specific cap
    let kind_witness_cap = tx.tx_kind.witness_cap();
    let effective_witness_cap = config.max_witness_bytes.min(kind_witness_cap);
    if tx.witness_bytes > effective_witness_cap {
        return AdmitResult::Rejected(AdmitErrorKind::WitnessTooLarge {
            size: tx.witness_bytes,
            max: effective_witness_cap,
        });
    }

    // Check input/output limits
    if tx.input_count > config.max_inputs {
        return AdmitResult::Rejected(AdmitErrorKind::TooManyInputs {
            count: tx.input_count,
            max: config.max_inputs,
        });
    }

    if tx.output_count > config.max_outputs {
        return AdmitResult::Rejected(AdmitErrorKind::TooManyOutputs {
            count: tx.output_count,
            max: config.max_outputs,
        });
    }

    if tx.sig_count > config.max_signatures {
        return AdmitResult::Rejected(AdmitErrorKind::TooManySignatures {
            count: tx.sig_count,
            max: config.max_signatures,
        });
    }

    // Check per-sender limits
    let sender_count = state.sender_pending_count(&tx.sender);
    if sender_count >= config.max_per_sender {
        return AdmitResult::Rejected(AdmitErrorKind::SenderLimitReached {
            sender: tx.sender,
            count: sender_count,
            max: config.max_per_sender,
        });
    }

    // Check rate limiting
    let period_count =
        state.sender_period_count(&tx.sender, current_block, config.rate_limit_period_blocks);
    if period_count >= config.max_per_sender_per_period {
        return AdmitResult::Rejected(AdmitErrorKind::RateLimited {
            sender: tx.sender,
            period_count,
            max: config.max_per_sender_per_period,
        });
    }

    // Calculate minimum fee
    let fee_input = FeeInput {
        kind: tx.tx_kind,
        sig_scheme: tx.sig_scheme,
        sig_count: tx.sig_count,
        envelope_bytes: 100,
        payload_bytes: tx.tx_bytes.saturating_sub(tx.witness_bytes),
        witness_bytes: tx.witness_bytes,
        exec_units: tx.compute_units,
        state_reads: tx.state_reads,
        state_writes: tx.state_writes,
        state_write_bytes: tx.state_write_bytes,
        // Each input carries one ZkTransactionProof (currently 3 sub-proofs).
        // We charge 50 units per input to match the executor fee model.
        zk_verify_units: tx.input_count as u32 * 50,
    };

    let min_fee = compute_fee_v2(&fee_input, fee_params);

    // Apply fee multiplier using MempoolConfigExt for consistency
    let required_fee = config.effective_min_fee(min_fee as Amount);

    if tx.fee < required_fee {
        return AdmitResult::Rejected(AdmitErrorKind::InsufficientFee {
            required: required_fee,
            provided: tx.fee,
        });
    }

    AdmitResult::Accepted
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_fees::{SigScheme, TxKind};
    use lib_types::Address;

    fn create_test_tx(fee: u64) -> AdmitTx {
        AdmitTx {
            fee: fee as Amount,
            tx_bytes: 500,
            witness_bytes: 200,
            input_count: 2,
            output_count: 2,
            sig_count: 1,
            tx_kind: TxKind::NativeTransfer,
            sig_scheme: SigScheme::Dilithium5,
            sender: Address::default(),
            compute_units: 100,
            state_reads: 5,
            state_writes: 2,
            state_write_bytes: 100,
        }
    }

    #[test]
    fn test_admit_result_is_accepted() {
        assert!(AdmitResult::Accepted.is_accepted());
        assert!(!AdmitResult::Accepted.is_rejected());

        let rejected = AdmitResult::Rejected(AdmitErrorKind::MempoolFull);
        assert!(!rejected.is_accepted());
        assert!(rejected.is_rejected());
    }

    #[test]
    fn test_admit_accepts_valid_tx() {
        let tx = create_test_tx(100_000u64);
        let fee_params = FeeParams::default();
        let config = MempoolConfig::default();
        let state = MempoolState::default();

        let result = admit(&tx, &fee_params, &config, &state, 100);
        assert!(result.is_accepted());
    }

    #[test]
    fn test_admit_rejects_oversized_tx() {
        let mut tx = create_test_tx(100_000u64);
        tx.tx_bytes = 1_000_000;

        let fee_params = FeeParams::default();
        let config = MempoolConfig::default();
        let state = MempoolState::default();

        let result = admit(&tx, &fee_params, &config, &state, 100);
        assert!(matches!(
            result,
            AdmitResult::Rejected(AdmitErrorKind::TxTooLarge { .. })
        ));
    }

    #[test]
    fn test_admit_rejects_insufficient_fee() {
        let tx = create_test_tx(1u64);

        let fee_params = FeeParams::default();
        let config = MempoolConfig::default();
        let state = MempoolState::default();

        let result = admit(&tx, &fee_params, &config, &state, 100);
        assert!(matches!(
            result,
            AdmitResult::Rejected(AdmitErrorKind::InsufficientFee { .. })
        ));
    }

    #[test]
    fn test_admit_rejects_txkind_witness_cap() {
        // Create a transaction that exceeds the NativeTransfer witness cap
        // but is within the global max_witness_bytes
        let mut tx = create_test_tx(100_000u64);
        tx.tx_kind = TxKind::NativeTransfer; // witness_cap = 1024 bytes
        tx.witness_bytes = 2000; // Exceeds 1024 but under default max_witness_bytes (50_000)

        let fee_params = FeeParams::default();
        let config = MempoolConfig::default();
        let state = MempoolState::default();

        let result = admit(&tx, &fee_params, &config, &state, 100);
        assert!(matches!(
            result,
            AdmitResult::Rejected(AdmitErrorKind::WitnessTooLarge { .. })
        ));
    }

    #[test]
    fn test_admit_accepts_within_txkind_witness_cap() {
        // Create a transaction that is within the NativeTransfer witness cap
        let mut tx = create_test_tx(100_000u64);
        tx.tx_kind = TxKind::NativeTransfer; // witness_cap = 1024 bytes
        tx.witness_bytes = 500; // Well under 1024

        let fee_params = FeeParams::default();
        let config = MempoolConfig::default();
        let state = MempoolState::default();

        let result = admit(&tx, &fee_params, &config, &state, 100);
        // Should be accepted (fee is sufficient, within all limits)
        // Note: fee might not be sufficient for this tx, so we just check it doesn't fail on witness
        assert!(!matches!(
            result,
            AdmitResult::Rejected(AdmitErrorKind::WitnessTooLarge { .. })
        ));
    }
}
