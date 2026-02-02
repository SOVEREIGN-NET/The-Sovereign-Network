//! Mempool Admission Logic
//!
//! The `admit` function performs pre-consensus validation for mempool admission.

use lib_types::{Address, Amount, BlockHeight};
use lib_fees::{FeeParams, FeeInput, TxKind, SigScheme, compute_fee_v2};

use crate::config::MempoolConfig;
use crate::state::MempoolState;
use crate::errors::{AdmitError, AdmitErrorKind};

/// Result of admission check
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitResult {
    /// Transaction accepted into mempool
    Accepted,
    /// Transaction rejected with reason
    Rejected(AdmitErrorKind),
}

impl AdmitResult {
    pub fn is_accepted(&self) -> bool {
        matches!(self, AdmitResult::Accepted)
    }

    pub fn is_rejected(&self) -> bool {
        matches!(self, AdmitResult::Rejected(_))
    }
}

/// Transaction data needed for admission checks
///
/// This is a simplified view of a transaction for admission purposes.
/// The actual Transaction type lives in lib-blockchain.
#[derive(Debug, Clone)]
pub struct AdmitTx {
    /// Transaction fee
    pub fee: Amount,
    /// Total transaction size in bytes
    pub tx_bytes: u32,
    /// Witness size in bytes (signatures + proofs)
    pub witness_bytes: u32,
    /// Number of inputs
    pub input_count: u16,
    /// Number of outputs
    pub output_count: u16,
    /// Number of signatures
    pub sig_count: u8,
    /// Transaction kind
    pub tx_kind: TxKind,
    /// Signature scheme used
    pub sig_scheme: SigScheme,
    /// Sender address (for rate limiting)
    pub sender: Address,
    /// Compute units (estimated)
    pub compute_units: u32,
    /// State reads
    pub state_reads: u32,
    /// State writes
    pub state_writes: u32,
    /// State write bytes
    pub state_write_bytes: u32,
}

/// Perform mempool admission check
///
/// # Checks
///
/// 1. **Fee check**: `fee >= min_fee` from fee model
/// 2. **Witness caps**: Signature/proof sizes within TxKind limits
/// 3. **Signature limits**: Maximum signatures per transaction
/// 4. **Bounded totals**: Mempool size and per-address limits
///
/// # Arguments
///
/// * `tx` - Transaction to check
/// * `fee_params` - Fee model parameters
/// * `config` - Mempool configuration
/// * `state` - Current mempool state
/// * `current_block` - Current block height
///
/// # Returns
///
/// `AdmitResult::Accepted` or `AdmitResult::Rejected(reason)`
pub fn admit(
    tx: &AdmitTx,
    fee_params: &FeeParams,
    config: &MempoolConfig,
    state: &MempoolState,
    current_block: BlockHeight,
) -> AdmitResult {
    // =========================================================================
    // Check 1: Transaction size limits
    // =========================================================================
    if tx.tx_bytes > config.max_tx_bytes {
        return AdmitResult::Rejected(AdmitErrorKind::TxTooLarge {
            size: tx.tx_bytes,
            max: config.max_tx_bytes,
        });
    }

    // =========================================================================
    // Check 2: Witness caps (per TxKind)
    // =========================================================================
    if tx.witness_bytes > config.max_witness_bytes {
        return AdmitResult::Rejected(AdmitErrorKind::WitnessTooLarge {
            size: tx.witness_bytes,
            max: config.max_witness_bytes,
        });
    }

    // Also check against TxKind witness cap
    let kind_witness_cap = tx.tx_kind.witness_cap() as u32;
    if tx.witness_bytes > kind_witness_cap {
        return AdmitResult::Rejected(AdmitErrorKind::WitnessTooLarge {
            size: tx.witness_bytes,
            max: kind_witness_cap,
        });
    }

    // =========================================================================
    // Check 3: Signature limits
    // =========================================================================
    if tx.sig_count > config.max_signatures {
        return AdmitResult::Rejected(AdmitErrorKind::TooManySignatures {
            count: tx.sig_count,
            max: config.max_signatures,
        });
    }

    // =========================================================================
    // Check 4: Input/Output limits
    // =========================================================================
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

    // =========================================================================
    // Check 5: Fee >= minimum
    // =========================================================================
    let fee_input = FeeInput {
        kind: tx.tx_kind,
        sig_scheme: tx.sig_scheme,
        sig_count: tx.sig_count,
        envelope_bytes: 100, // Estimated header/metadata size
        payload_bytes: tx.tx_bytes.saturating_sub(tx.witness_bytes),
        witness_bytes: tx.witness_bytes,
        exec_units: tx.compute_units,
        state_reads: tx.state_reads,
        state_writes: tx.state_writes,
        state_write_bytes: tx.state_write_bytes,
    };

    let computed_fee = compute_fee_v2(&fee_input, fee_params);
    let required_fee = config.effective_min_fee(computed_fee as Amount);

    if tx.fee < required_fee {
        return AdmitResult::Rejected(AdmitErrorKind::InsufficientFee {
            required: required_fee,
            provided: tx.fee,
        });
    }

    // =========================================================================
    // Check 6: Mempool capacity (bounded totals)
    // =========================================================================
    if !state.has_tx_capacity(config.max_tx_count) {
        return AdmitResult::Rejected(AdmitErrorKind::MempoolFull);
    }

    if !state.has_byte_capacity(config.max_mempool_bytes) {
        return AdmitResult::Rejected(AdmitErrorKind::MempoolBytesFull {
            current: state.total_bytes,
            max: config.max_mempool_bytes,
        });
    }

    // =========================================================================
    // Check 7: Per-sender limits
    // =========================================================================
    let sender_pending = state.sender_pending_count(&tx.sender);
    if sender_pending >= config.max_per_sender {
        return AdmitResult::Rejected(AdmitErrorKind::SenderLimitReached {
            sender: tx.sender,
            count: sender_pending,
            max: config.max_per_sender,
        });
    }

    // =========================================================================
    // Check 8: Rate limiting
    // =========================================================================
    let period_count = state.sender_period_count(
        &tx.sender,
        current_block,
        config.rate_limit_period_blocks,
    );
    if period_count >= config.max_per_sender_per_period {
        return AdmitResult::Rejected(AdmitErrorKind::RateLimited {
            sender: tx.sender,
            period_count,
            max: config.max_per_sender_per_period,
        });
    }

    AdmitResult::Accepted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_tx() -> AdmitTx {
        AdmitTx {
            fee: 10_000,
            tx_bytes: 500,
            witness_bytes: 100,
            input_count: 1,
            output_count: 2,
            sig_count: 1,
            tx_kind: TxKind::NativeTransfer,
            sig_scheme: SigScheme::Ed25519,
            sender: Address::default(),
            compute_units: 100,
            state_reads: 1,
            state_writes: 2,
            state_write_bytes: 200,
        }
    }

    #[test]
    fn test_admit_valid_tx() {
        let tx = create_test_tx();
        let fee_params = FeeParams::for_testing();
        let config = MempoolConfig::for_testing();
        let state = MempoolState::new();

        let result = admit(&tx, &fee_params, &config, &state, 100);
        assert!(result.is_accepted());
    }

    #[test]
    fn test_admit_insufficient_fee() {
        let mut tx = create_test_tx();
        tx.fee = 0; // Zero fee

        let fee_params = FeeParams::default(); // Real fees
        let config = MempoolConfig::default();
        let state = MempoolState::new();

        let result = admit(&tx, &fee_params, &config, &state, 100);
        assert!(matches!(result, AdmitResult::Rejected(AdmitErrorKind::InsufficientFee { .. })));
    }

    #[test]
    fn test_admit_tx_too_large() {
        let mut tx = create_test_tx();
        tx.tx_bytes = 200_000; // Exceeds default 100KB limit

        let fee_params = FeeParams::for_testing();
        let config = MempoolConfig::default();
        let state = MempoolState::new();

        let result = admit(&tx, &fee_params, &config, &state, 100);
        assert!(matches!(result, AdmitResult::Rejected(AdmitErrorKind::TxTooLarge { .. })));
    }

    #[test]
    fn test_admit_witness_too_large() {
        let mut tx = create_test_tx();
        tx.witness_bytes = 100_000; // Exceeds default 50KB limit

        let fee_params = FeeParams::for_testing();
        let config = MempoolConfig::default();
        let state = MempoolState::new();

        let result = admit(&tx, &fee_params, &config, &state, 100);
        assert!(matches!(result, AdmitResult::Rejected(AdmitErrorKind::WitnessTooLarge { .. })));
    }

    #[test]
    fn test_admit_too_many_signatures() {
        let mut tx = create_test_tx();
        tx.sig_count = 20; // Exceeds default 16 limit

        let fee_params = FeeParams::for_testing();
        let config = MempoolConfig::default();
        let state = MempoolState::new();

        let result = admit(&tx, &fee_params, &config, &state, 100);
        assert!(matches!(result, AdmitResult::Rejected(AdmitErrorKind::TooManySignatures { .. })));
    }

    #[test]
    fn test_admit_mempool_full() {
        let tx = create_test_tx();
        let fee_params = FeeParams::for_testing();
        let mut config = MempoolConfig::for_testing();
        config.max_tx_count = 0; // No capacity
        let state = MempoolState::new();

        let result = admit(&tx, &fee_params, &config, &state, 100);
        assert!(matches!(result, AdmitResult::Rejected(AdmitErrorKind::MempoolFull)));
    }

    #[test]
    fn test_admit_sender_limit() {
        let tx = create_test_tx();
        let fee_params = FeeParams::for_testing();
        let mut config = MempoolConfig::for_testing();
        config.max_per_sender = 5;

        let mut state = MempoolState::new();
        // Add 5 txs from same sender
        for _ in 0..5 {
            state.add_tx(tx.sender, 100, 100, 10);
        }

        let result = admit(&tx, &fee_params, &config, &state, 100);
        assert!(matches!(result, AdmitResult::Rejected(AdmitErrorKind::SenderLimitReached { .. })));
    }

    #[test]
    fn test_admit_rate_limited() {
        let tx = create_test_tx();
        let fee_params = FeeParams::for_testing();
        let mut config = MempoolConfig::for_testing();
        config.max_per_sender_per_period = 3;
        config.rate_limit_period_blocks = 10;

        let mut state = MempoolState::new();
        // Add 3 txs from same sender in current period
        state.add_tx(tx.sender, 100, 100, 10);
        state.add_tx(tx.sender, 100, 102, 10);
        state.add_tx(tx.sender, 100, 105, 10);

        let result = admit(&tx, &fee_params, &config, &state, 108);
        assert!(matches!(result, AdmitResult::Rejected(AdmitErrorKind::RateLimited { .. })));

        // Should succeed in new period
        let result = admit(&tx, &fee_params, &config, &state, 115);
        assert!(result.is_accepted());
    }

    #[test]
    fn test_admit_witness_cap_per_tx_kind() {
        let mut tx = create_test_tx();
        // NativeTransfer has witness_cap of 2048
        tx.witness_bytes = 3000;

        let fee_params = FeeParams::for_testing();
        let mut config = MempoolConfig::for_testing();
        config.max_witness_bytes = 10_000; // Config allows it

        let state = MempoolState::new();

        // Should be rejected due to TxKind witness cap
        let result = admit(&tx, &fee_params, &config, &state, 100);
        assert!(matches!(result, AdmitResult::Rejected(AdmitErrorKind::WitnessTooLarge { .. })));
    }
}
