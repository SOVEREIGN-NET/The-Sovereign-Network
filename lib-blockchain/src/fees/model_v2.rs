//! Fee Model v2 Computation
//!
//! Pure, deterministic fee calculation for Phase 2.
//!
//! # Formula
//!
//! ```text
//! charged_witness_bytes = min(witness_bytes, witness_cap_bytes[tx_kind])
//! verify_units = sig_count * verify_units_per_sig[sig_scheme]
//! exec_units = exec_units[tx_kind]
//!
//! fee = base_tx_fee
//!     + exec_units * price_exec_unit
//!     + state_reads * price_state_read
//!     + state_writes * price_state_write
//!     + state_write_bytes * price_state_write_byte
//!     + payload_bytes * price_payload_byte
//!     + charged_witness_bytes * price_witness_byte (rational, round up)
//!     + verify_units * price_verify_unit
//! ```
//!
//! # Determinism
//!
//! This function is pure (no side effects) and deterministic (same input
//! always produces same output). All arithmetic uses u128 internally to
//! prevent overflow, with final result cast to u64.

use super::types::{FeeInput, FeeParamsV2};

/// Compute the minimum fee for a transaction under Fee Model v2.
///
/// # Arguments
///
/// * `input` - Transaction metrics (sizes, counts, types)
/// * `params` - Fee model parameters (prices, limits, per-kind values)
///
/// # Returns
///
/// The minimum fee in the smallest token unit (micro-tokens).
///
/// # Panics
///
/// This function does not panic. Overflow is prevented by using u128 arithmetic.
pub fn compute_fee_v2(input: &FeeInput, params: &FeeParamsV2) -> u64 {
    // Use u128 for all intermediate calculations to prevent overflow
    let mut fee: u128 = 0;

    // Base transaction fee
    fee += params.base_tx_fee as u128;

    // Execution cost
    let exec_units = params.get_exec_units(input.tx_kind) as u128;
    fee += exec_units * params.price_exec_unit as u128;

    // State read cost
    fee += input.state_reads as u128 * params.price_state_read as u128;

    // State write cost (per operation)
    fee += input.state_writes as u128 * params.price_state_write as u128;

    // State write cost (per byte)
    fee += input.state_write_bytes as u128 * params.price_state_write_byte as u128;

    // Payload byte cost
    fee += input.payload_bytes as u128 * params.price_payload_byte as u128;

    // Witness byte cost (with cap and rational pricing)
    let witness_cap = params.get_witness_cap_bytes(input.tx_kind);
    let charged_witness_bytes = std::cmp::min(input.witness_bytes, witness_cap) as u128;

    // Rational pricing: (bytes * numer + denom - 1) / denom for ceiling division
    if params.price_witness_byte_denom > 0 {
        let numer = charged_witness_bytes * params.price_witness_byte_numer as u128;
        let denom = params.price_witness_byte_denom as u128;
        // Ceiling division: (a + b - 1) / b
        let witness_cost = (numer + denom - 1) / denom;
        fee += witness_cost;
    }

    // Verification cost
    let verify_units = input.sig_count as u128
        * params.get_verify_units_per_sig(input.sig_scheme) as u128;
    fee += verify_units * params.price_verify_unit as u128;

    // Clamp to u64::MAX if overflow (should never happen with reasonable params)
    std::cmp::min(fee, u64::MAX as u128) as u64
}

/// Validate a transaction against block resource limits.
///
/// Returns Ok(()) if the transaction is within limits, or an error description.
pub fn validate_block_limits(input: &FeeInput, params: &FeeParamsV2) -> Result<(), String> {
    // Check witness bytes
    let max_witness = params.get_max_witness_bytes(input.tx_kind);
    if input.witness_bytes > max_witness {
        return Err(format!(
            "Witness bytes {} exceeds max {} for {:?}",
            input.witness_bytes, max_witness, input.tx_kind
        ));
    }

    // Check signature count
    let max_sigs = params.get_max_sigs(input.tx_kind);
    if input.sig_count as u16 > max_sigs {
        return Err(format!(
            "Signature count {} exceeds max {} for {:?}",
            input.sig_count, max_sigs, input.tx_kind
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fees::types::{SigScheme, TxKind};

    #[test]
    fn test_compute_fee_minimal() {
        let params = FeeParamsV2::default();
        let input = FeeInput::new(
            TxKind::NativeTransfer,
            SigScheme::Ed25519,
            0,   // no sigs (for minimal fee test)
            0,   // envelope
            0,   // payload
            0,   // witness
            0,   // reads
            0,   // writes
            0,   // write_bytes
        );

        let fee = compute_fee_v2(&input, &params);

        // Should be base_tx_fee + exec_units * price_exec_unit
        // = 100 + 5 * 10 = 150
        assert_eq!(fee, 150);
    }

    #[test]
    fn test_compute_fee_native_transfer() {
        let params = FeeParamsV2::default();
        let input = FeeInput::new(
            TxKind::NativeTransfer,
            SigScheme::Ed25519,
            1,     // 1 signature
            50,    // envelope
            200,   // payload
            64,    // witness (Ed25519 sig)
            2,     // 2 input UTXOs read
            4,     // 2 inputs deleted + 2 outputs created
            256,   // ~64 bytes per UTXO * 4
        );

        let fee = compute_fee_v2(&input, &params);

        // Let's compute expected:
        // base_tx_fee = 100
        // exec_units = 5 * 10 = 50
        // state_reads = 2 * 5 = 10
        // state_writes = 4 * 20 = 80
        // state_write_bytes = 256 * 1 = 256
        // payload_bytes = 200 * 1 = 200
        // witness_bytes = 64 (< cap 1536), rational 64 * 1 / 2 = 32 (ceiling)
        // verify_units = 1 * 1 * 50 = 50
        // Total = 100 + 50 + 10 + 80 + 256 + 200 + 32 + 50 = 778

        assert_eq!(fee, 778);
    }

    #[test]
    fn test_compute_fee_dilithium() {
        let params = FeeParamsV2::default();
        let input = FeeInput::new(
            TxKind::NativeTransfer,
            SigScheme::Dilithium5,
            1,      // 1 signature
            50,     // envelope
            200,    // payload
            4627,   // Dilithium5 signature size
            2,      // reads
            4,      // writes
            256,    // write_bytes
        );

        let fee = compute_fee_v2(&input, &params);

        // Witness is capped at 1536 for NativeTransfer
        // witness_cost = ceil(1536 * 1 / 2) = 768
        // verify_units = 1 * 4 * 50 = 200 (Dilithium5 = 4 units)
        // base + exec + reads + writes + write_bytes + payload + witness + verify
        // = 100 + 50 + 10 + 80 + 256 + 200 + 768 + 200 = 1664

        assert_eq!(fee, 1664);
    }

    #[test]
    fn test_compute_fee_token_transfer() {
        let params = FeeParamsV2::default();
        let input = FeeInput::new(
            TxKind::TokenTransfer,
            SigScheme::Ed25519,
            1,     // 1 signature
            30,    // smaller envelope
            80,    // payload (token_id, from, to, amount)
            64,    // witness
            2,     // read sender + receiver balance
            2,     // write sender + receiver balance
            64,    // ~32 bytes per balance entry
        );

        let fee = compute_fee_v2(&input, &params);

        // TokenTransfer has exec_units = 3
        // base + exec + reads + writes + write_bytes + payload + witness + verify
        // = 100 + (3 * 10) + (2 * 5) + (2 * 20) + (64 * 1) + (80 * 1) + ceil(64/2) + (1 * 1 * 50)
        // = 100 + 30 + 10 + 40 + 64 + 80 + 32 + 50 = 406

        assert_eq!(fee, 406);
    }

    #[test]
    fn test_witness_cap_applied() {
        let params = FeeParamsV2::default();

        // Witness bytes exceeding cap
        let input = FeeInput::new(
            TxKind::NativeTransfer,
            SigScheme::Ed25519,
            1,
            50,
            200,
            5000,  // Way over the 1536 cap
            2,
            4,
            256,
        );

        let fee_capped = compute_fee_v2(&input, &params);

        // Now with exactly the cap
        let input_at_cap = FeeInput::new(
            TxKind::NativeTransfer,
            SigScheme::Ed25519,
            1,
            50,
            200,
            1536,  // Exactly at cap
            2,
            4,
            256,
        );

        let fee_at_cap = compute_fee_v2(&input_at_cap, &params);

        // Fees should be the same (cap applied)
        assert_eq!(fee_capped, fee_at_cap);
    }

    #[test]
    fn test_rational_witness_pricing_rounds_up() {
        let params = FeeParamsV2::default();

        // 1 witness byte: ceil(1 * 1 / 2) = 1 (not 0)
        let input = FeeInput::new(
            TxKind::NativeTransfer,
            SigScheme::Ed25519,
            0,   // no sig for simplicity
            0,
            0,
            1,   // 1 witness byte
            0,
            0,
            0,
        );

        let fee1 = compute_fee_v2(&input, &params);

        // 2 witness bytes: ceil(2 * 1 / 2) = 1
        let input2 = FeeInput::new(
            TxKind::NativeTransfer,
            SigScheme::Ed25519,
            0,
            0,
            0,
            2,
            0,
            0,
            0,
        );

        let fee2 = compute_fee_v2(&input2, &params);

        // 3 witness bytes: ceil(3 * 1 / 2) = 2
        let input3 = FeeInput::new(
            TxKind::NativeTransfer,
            SigScheme::Ed25519,
            0,
            0,
            0,
            3,
            0,
            0,
            0,
        );

        let fee3 = compute_fee_v2(&input3, &params);

        // base + exec = 100 + 50 = 150
        // fee1 = 150 + 1 = 151
        // fee2 = 150 + 1 = 151
        // fee3 = 150 + 2 = 152
        assert_eq!(fee1, 151);
        assert_eq!(fee2, 151);
        assert_eq!(fee3, 152);
    }

    #[test]
    fn test_validate_block_limits() {
        let params = FeeParamsV2::default();

        // Valid input
        let valid = FeeInput::new(
            TxKind::NativeTransfer,
            SigScheme::Ed25519,
            1,
            50,
            200,
            1000, // Under 16KB limit
            2,
            4,
            256,
        );

        assert!(validate_block_limits(&valid, &params).is_ok());

        // Invalid: too many witness bytes
        let invalid_witness = FeeInput::new(
            TxKind::NativeTransfer,
            SigScheme::Ed25519,
            1,
            50,
            200,
            20000, // Over 16KB limit
            2,
            4,
            256,
        );

        assert!(validate_block_limits(&invalid_witness, &params).is_err());

        // Invalid: too many signatures
        let invalid_sigs = FeeInput::new(
            TxKind::NativeTransfer,
            SigScheme::Ed25519,
            5,  // Over max_sigs=2 for NativeTransfer
            50,
            200,
            1000,
            2,
            4,
            256,
        );

        assert!(validate_block_limits(&invalid_sigs, &params).is_err());
    }

    #[test]
    fn test_hybrid_signature_cost() {
        let params = FeeParamsV2::default();

        // Same transaction with different sig schemes
        let base_input = |scheme| FeeInput::new(
            TxKind::NativeTransfer,
            scheme,
            1,
            50,
            200,
            64,
            2,
            4,
            256,
        );

        let fee_ed25519 = compute_fee_v2(&base_input(SigScheme::Ed25519), &params);
        let fee_dilithium = compute_fee_v2(&base_input(SigScheme::Dilithium5), &params);
        let fee_hybrid = compute_fee_v2(&base_input(SigScheme::Hybrid), &params);

        // Ed25519: verify = 1 * 1 * 50 = 50
        // Dilithium5: verify = 1 * 4 * 50 = 200
        // Hybrid: verify = 1 * 5 * 50 = 250

        assert!(fee_ed25519 < fee_dilithium);
        assert!(fee_dilithium < fee_hybrid);
        assert_eq!(fee_dilithium - fee_ed25519, 150); // 200 - 50
        assert_eq!(fee_hybrid - fee_dilithium, 50);   // 250 - 200
    }

    // =========================================================================
    // Golden Vector Tests
    // =========================================================================
    //
    // These tests provide exact fee values for regression testing.
    // If the fee model changes, these tests MUST be updated intentionally.

    /// Golden vector 1: Minimal NativeTransfer with Dilithium5
    ///
    /// Parameters (default):
    /// - base_tx_fee = 100
    /// - price_exec_unit = 10, exec_units[NativeTransfer] = 5
    /// - price_state_read = 5
    /// - price_state_write = 20
    /// - price_state_write_byte = 1
    /// - price_payload_byte = 1
    /// - price_witness_byte = 1/2 (rational)
    /// - price_verify_unit = 50, verify_units[Dilithium5] = 4
    #[test]
    fn test_golden_vector_native_transfer_dilithium() {
        let params = FeeParamsV2::default();

        // Realistic NativeTransfer with Dilithium5 signature
        let input = FeeInput::new(
            TxKind::NativeTransfer,
            SigScheme::Dilithium5,
            1,       // 1 signature
            14,      // envelope: version(4) + chain_id(1) + type(1) + fee(8)
            164,     // payload: 1 input (68) + 1 output (96)
            4627,    // witness: Dilithium5 signature (capped at 1536)
            1,       // state_reads: 1 input UTXO
            2,       // state_writes: 1 input deleted + 1 output created
            256,     // state_write_bytes: ~128 per UTXO entry
        );

        let fee = compute_fee_v2(&input, &params);

        // Manual calculation:
        // base_tx_fee = 100
        // exec = 5 * 10 = 50
        // state_reads = 1 * 5 = 5
        // state_writes = 2 * 20 = 40
        // state_write_bytes = 256 * 1 = 256
        // payload = 164 * 1 = 164
        // witness = ceil(1536 * 1 / 2) = 768 (capped)
        // verify = 1 * 4 * 50 = 200
        // TOTAL = 100 + 50 + 5 + 40 + 256 + 164 + 768 + 200 = 1583

        assert_eq!(fee, 1583, "Golden vector: NativeTransfer with Dilithium5");
    }

    /// Golden vector 2: TokenTransfer (minimal)
    #[test]
    fn test_golden_vector_token_transfer() {
        let params = FeeParamsV2::default();

        let input = FeeInput::new(
            TxKind::TokenTransfer,
            SigScheme::Dilithium5,
            1,      // 1 signature
            14,     // envelope
            120,    // payload: TokenTransferData
            4627,   // witness: Dilithium5 (capped at 1536)
            2,      // state_reads: sender + receiver balance
            2,      // state_writes: sender + receiver balance
            128,    // state_write_bytes: 64 per balance entry
        );

        let fee = compute_fee_v2(&input, &params);

        // TokenTransfer exec_units = 3
        // base = 100
        // exec = 3 * 10 = 30
        // state_reads = 2 * 5 = 10
        // state_writes = 2 * 20 = 40
        // state_write_bytes = 128 * 1 = 128
        // payload = 120 * 1 = 120
        // witness = ceil(1536 * 1 / 2) = 768
        // verify = 1 * 4 * 50 = 200
        // TOTAL = 100 + 30 + 10 + 40 + 128 + 120 + 768 + 200 = 1396

        assert_eq!(fee, 1396, "Golden vector: TokenTransfer");
    }

    /// Golden vector 3: Rounding behavior test
    ///
    /// Verifies ceiling division for witness pricing.
    #[test]
    fn test_golden_vector_rounding() {
        let params = FeeParamsV2::default();

        // Test: 1 witness byte should cost 1 (ceil(1/2) = 1)
        let input1 = FeeInput::new(
            TxKind::NativeTransfer,
            SigScheme::Ed25519,
            0, 0, 0, 1, 0, 0, 0,  // Only 1 witness byte
        );

        // Test: 2 witness bytes should cost 1 (ceil(2/2) = 1)
        let input2 = FeeInput::new(
            TxKind::NativeTransfer,
            SigScheme::Ed25519,
            0, 0, 0, 2, 0, 0, 0,
        );

        // Test: 3 witness bytes should cost 2 (ceil(3/2) = 2)
        let input3 = FeeInput::new(
            TxKind::NativeTransfer,
            SigScheme::Ed25519,
            0, 0, 0, 3, 0, 0, 0,
        );

        let base_fee = compute_fee_v2(&FeeInput::new(
            TxKind::NativeTransfer,
            SigScheme::Ed25519,
            0, 0, 0, 0, 0, 0, 0,
        ), &params);

        let fee1 = compute_fee_v2(&input1, &params);
        let fee2 = compute_fee_v2(&input2, &params);
        let fee3 = compute_fee_v2(&input3, &params);

        // Witness costs should be: 1, 1, 2
        assert_eq!(fee1 - base_fee, 1, "1 byte should round up to 1");
        assert_eq!(fee2 - base_fee, 1, "2 bytes should equal 1");
        assert_eq!(fee3 - base_fee, 2, "3 bytes should round up to 2");
    }

    /// Golden vector 4: Multi-input NativeTransfer
    #[test]
    fn test_golden_vector_multi_input_transfer() {
        let params = FeeParamsV2::default();

        // 3 inputs, 2 outputs
        let input = FeeInput::new(
            TxKind::NativeTransfer,
            SigScheme::Hybrid,  // Ed25519 + Dilithium5
            1,        // 1 signature
            14,       // envelope
            396,      // payload: 3 inputs (68*3) + 2 outputs (96*2)
            1000,     // witness: less than cap
            3,        // state_reads: 3 input UTXOs
            5,        // state_writes: 3 deleted + 2 created
            640,      // state_write_bytes: 128 * 5
        );

        let fee = compute_fee_v2(&input, &params);

        // base = 100
        // exec = 5 * 10 = 50
        // state_reads = 3 * 5 = 15
        // state_writes = 5 * 20 = 100
        // state_write_bytes = 640 * 1 = 640
        // payload = 396 * 1 = 396
        // witness = ceil(1000 * 1 / 2) = 500
        // verify = 1 * 5 * 50 = 250 (Hybrid = 5 units)
        // TOTAL = 100 + 50 + 15 + 100 + 640 + 396 + 500 + 250 = 2051

        assert_eq!(fee, 2051, "Golden vector: Multi-input transfer with Hybrid sig");
    }
}
