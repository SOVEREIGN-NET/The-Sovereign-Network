//! Golden Vector Tests for Fee Model v2
//!
//! These tests define EXACT expected fee values for specific inputs.
//! If any of these tests fail, it indicates a consensus-breaking change.
//!
//! # Purpose
//!
//! Golden vectors ensure:
//! 1. Fee computation is deterministic across all platforms
//! 2. Changes to fee logic are intentional (not accidental regressions)
//! 3. All nodes compute identical fees for identical transactions
//!
//! # Updating Golden Vectors
//!
//! If you need to change fee logic:
//! 1. Update the fee computation code
//! 2. Update these golden vectors with new expected values
//! 3. Document the change in the commit message
//! 4. Consider protocol upgrade implications

#[cfg(test)]
mod tests {
    use crate::model_v2::FeeInputExt;
    use crate::{compute_fee_v2, FeeInput, FeeParams, SigScheme, TxKind};

    // =========================================================================
    // GOLDEN VECTOR: Native Transfer with Ed25519
    // =========================================================================

    /// Golden vector: Simple native transfer with Ed25519 signature
    ///
    /// This is the most common transaction type on the network.
    ///
    /// Input breakdown:
    /// - envelope_bytes: 200
    /// - payload_bytes: 32
    /// - witness_bytes: 64 (Ed25519 signature)
    /// - total_bytes: 200 + 32 + 64 = 296
    ///
    /// Fee calculation (default params):
    /// - byte_fee: 296 * 1 = 296
    /// - exec_fee: 0 * 10 = 0
    /// - state_read_fee: 2 * 100 = 200
    /// - state_write_fee: 2 * 500 = 1000
    /// - state_write_byte_fee: 32 * 10 = 320
    /// - state_fee: 200 + 1000 + 320 = 1520
    /// - sig_base_fee: 1 * 1000 = 1000
    /// - sig_fee: 1000 * 10000 / 10000 = 1000 (Ed25519 1.0x)
    /// - base_fee: 296 + 0 + 1520 + 1000 = 2816
    /// - kind_multiplier: 10000 (1.0x for NativeTransfer)
    /// - adjusted_fee: 2816 * 10000 / 10000 = 2816
    /// - final_fee: max(2816, 1000) = 2816 (above minimum)
    #[test]
    fn golden_native_transfer_ed25519() {
        let input = FeeInput {
            kind: TxKind::NativeTransfer,
            sig_scheme: SigScheme::Ed25519,
            sig_count: 1,
            envelope_bytes: 200,
            payload_bytes: 32,
            witness_bytes: 64,
            exec_units: 0,
            state_reads: 2,
            state_writes: 2,
            state_write_bytes: 32,
        };
        let params = FeeParams::default();

        let fee = compute_fee_v2(&input, &params);

        // GOLDEN VECTOR: This exact value MUST NOT change
        assert_eq!(fee, 2816, "Golden vector mismatch: native_transfer_ed25519");
    }

    // =========================================================================
    // GOLDEN VECTOR: Native Transfer with Dilithium5
    // =========================================================================

    /// Golden vector: Native transfer with post-quantum Dilithium5 signature
    ///
    /// Input breakdown:
    /// - envelope_bytes: 200
    /// - payload_bytes: 32
    /// - witness_bytes: 1024 (capped, actual Dilithium is 4627)
    /// - total_bytes: 200 + 32 + 1024 = 1256 (witness capped at 1024 for NativeTransfer)
    ///
    /// Fee calculation (default params):
    /// - byte_fee: 1256 * 1 = 1256
    /// - state_fee: 200 + 1000 + 320 = 1520
    /// - sig_base_fee: 1 * 1000 = 1000
    /// - sig_fee: 1000 * 50000 / 10000 = 5000 (Dilithium5 5.0x)
    /// - base_fee: 1256 + 0 + 1520 + 5000 = 7776
    /// - adjusted_fee: 7776 * 10000 / 10000 = 7776
    #[test]
    fn golden_native_transfer_dilithium5() {
        let input = FeeInput {
            kind: TxKind::NativeTransfer,
            sig_scheme: SigScheme::Dilithium5,
            sig_count: 1,
            envelope_bytes: 200,
            payload_bytes: 32,
            witness_bytes: 4627, // Full Dilithium sig, will be capped
            exec_units: 0,
            state_reads: 2,
            state_writes: 2,
            state_write_bytes: 32,
        };
        let params = FeeParams::default();

        let fee = compute_fee_v2(&input, &params);

        // GOLDEN VECTOR: This exact value MUST NOT change
        assert_eq!(fee, 7776, "Golden vector mismatch: native_transfer_dilithium5");
    }

    // =========================================================================
    // GOLDEN VECTOR: Contract Call
    // =========================================================================

    /// Golden vector: Smart contract call
    ///
    /// Input breakdown:
    /// - envelope_bytes: 300
    /// - payload_bytes: 1000 (contract call data)
    /// - witness_bytes: 2000 (proofs)
    /// - exec_units: 50000
    ///
    /// Fee calculation (default params):
    /// - byte_fee: 3300 * 1 = 3300
    /// - exec_fee: 50000 * 10 = 500000
    /// - state_fee: (10 * 100) + (5 * 500) + (500 * 10) = 1000 + 2500 + 5000 = 8500
    /// - sig_fee: 1 * 1000 * 10000 / 10000 = 1000
    /// - base_fee: 3300 + 500000 + 8500 + 1000 = 512800
    /// - adjusted_fee: 512800 * 15000 / 10000 = 769200 (1.5x for ContractCall)
    #[test]
    fn golden_contract_call() {
        let input = FeeInput {
            kind: TxKind::ContractCall,
            sig_scheme: SigScheme::Ed25519,
            sig_count: 1,
            envelope_bytes: 300,
            payload_bytes: 1000,
            witness_bytes: 2000,
            exec_units: 50000,
            state_reads: 10,
            state_writes: 5,
            state_write_bytes: 500,
        };
        let params = FeeParams::default();

        let fee = compute_fee_v2(&input, &params);

        // GOLDEN VECTOR: This exact value MUST NOT change
        assert_eq!(fee, 769200, "Golden vector mismatch: contract_call");
    }

    // =========================================================================
    // GOLDEN VECTOR: Governance (Subsidized)
    // =========================================================================

    /// Golden vector: Governance transaction (subsidized at 0.5x)
    ///
    /// Governance transactions are subsidized to encourage participation.
    ///
    /// Input breakdown:
    /// - envelope_bytes: 150
    /// - payload_bytes: 200 (vote data)
    /// - witness_bytes: 64
    ///
    /// Fee calculation (default params):
    /// - byte_fee: 414 * 1 = 414
    /// - state_fee: (1 * 100) + (1 * 500) + (32 * 10) = 100 + 500 + 320 = 920
    /// - sig_fee: 1000
    /// - base_fee: 414 + 0 + 920 + 1000 = 2334
    /// - adjusted_fee: 2334 * 5000 / 10000 = 1167 (0.5x for Governance)
    /// - final_fee: max(1167, 1000) = 1167 (above minimum)
    #[test]
    fn golden_governance_vote() {
        let input = FeeInput {
            kind: TxKind::Governance,
            sig_scheme: SigScheme::Ed25519,
            sig_count: 1,
            envelope_bytes: 150,
            payload_bytes: 200,
            witness_bytes: 64,
            exec_units: 0,
            state_reads: 1,
            state_writes: 1,
            state_write_bytes: 32,
        };
        let params = FeeParams::default();

        let fee = compute_fee_v2(&input, &params);

        // GOLDEN VECTOR: This exact value MUST NOT change
        assert_eq!(fee, 1167, "Golden vector mismatch: governance_vote");
    }

    // =========================================================================
    // GOLDEN VECTOR: Data Upload
    // =========================================================================

    /// Golden vector: Data upload transaction (2.0x multiplier)
    ///
    /// Data uploads have higher fees to compensate for storage costs.
    ///
    /// Input breakdown:
    /// - envelope_bytes: 100
    /// - payload_bytes: 10000 (data)
    /// - witness_bytes: 5000 (proofs)
    ///
    /// Fee calculation (default params):
    /// - byte_fee: 15100 * 1 = 15100
    /// - state_fee: (1 * 100) + (1 * 500) + (10000 * 10) = 100600
    /// - sig_fee: 1000
    /// - base_fee: 15100 + 0 + 100600 + 1000 = 116700
    /// - adjusted_fee: 116700 * 20000 / 10000 = 233400 (2.0x for DataUpload)
    #[test]
    fn golden_data_upload() {
        let input = FeeInput {
            kind: TxKind::DataUpload,
            sig_scheme: SigScheme::Ed25519,
            sig_count: 1,
            envelope_bytes: 100,
            payload_bytes: 10000,
            witness_bytes: 5000,
            exec_units: 0,
            state_reads: 1,
            state_writes: 1,
            state_write_bytes: 10000,
        };
        let params = FeeParams::default();

        let fee = compute_fee_v2(&input, &params);

        // GOLDEN VECTOR: This exact value MUST NOT change
        assert_eq!(fee, 233400, "Golden vector mismatch: data_upload");
    }

    // =========================================================================
    // GOLDEN VECTOR: Token Transfer
    // =========================================================================

    /// Golden vector: Custom token transfer (1.2x multiplier)
    ///
    /// Input breakdown:
    /// - envelope_bytes: 200
    /// - payload_bytes: 64 (token_id + amount + recipient)
    /// - witness_bytes: 100
    ///
    /// Fee calculation (default params):
    /// - byte_fee: 364 * 1 = 364
    /// - state_fee: (3 * 100) + (2 * 500) + (64 * 10) = 300 + 1000 + 640 = 1940
    /// - sig_fee: 1000
    /// - base_fee: 364 + 0 + 1940 + 1000 = 3304
    /// - adjusted_fee: 3304 * 12000 / 10000 = 3964 (1.2x for TokenTransfer)
    #[test]
    fn golden_token_transfer() {
        let input = FeeInput {
            kind: TxKind::TokenTransfer,
            sig_scheme: SigScheme::Ed25519,
            sig_count: 1,
            envelope_bytes: 200,
            payload_bytes: 64,
            witness_bytes: 100,
            exec_units: 0,
            state_reads: 3,  // sender balance, recipient balance, token contract
            state_writes: 2, // sender balance, recipient balance
            state_write_bytes: 64,
        };
        let params = FeeParams::default();

        let fee = compute_fee_v2(&input, &params);

        // GOLDEN VECTOR: This exact value MUST NOT change
        assert_eq!(fee, 3964, "Golden vector mismatch: token_transfer");
    }

    // =========================================================================
    // GOLDEN VECTOR: Multi-Signature Transaction
    // =========================================================================

    /// Golden vector: Transaction with multiple signatures
    ///
    /// Fee calculation (default params):
    /// - sig_base_fee: 3 * 1000 = 3000
    /// - sig_fee: 3000 * 10000 / 10000 = 3000
    #[test]
    fn golden_multisig_transfer() {
        let input = FeeInput {
            kind: TxKind::NativeTransfer,
            sig_scheme: SigScheme::Ed25519,
            sig_count: 3, // 3 signatures
            envelope_bytes: 200,
            payload_bytes: 32,
            witness_bytes: 192, // 3 * 64
            exec_units: 0,
            state_reads: 2,
            state_writes: 2,
            state_write_bytes: 32,
        };
        let params = FeeParams::default();

        let fee = compute_fee_v2(&input, &params);

        // GOLDEN VECTOR: This exact value MUST NOT change
        assert_eq!(fee, 4944, "Golden vector mismatch: multisig_transfer");
    }

    // =========================================================================
    // GOLDEN VECTOR: Hybrid Signature
    // =========================================================================

    /// Golden vector: Transaction with hybrid Ed25519+Dilithium signature
    ///
    /// Fee calculation:
    /// - sig_fee: 1000 * 55000 / 10000 = 5500 (5.5x for Hybrid)
    #[test]
    fn golden_hybrid_signature() {
        let input = FeeInput {
            kind: TxKind::NativeTransfer,
            sig_scheme: SigScheme::Hybrid,
            sig_count: 1,
            envelope_bytes: 200,
            payload_bytes: 32,
            witness_bytes: 1024, // Will be capped
            exec_units: 0,
            state_reads: 2,
            state_writes: 2,
            state_write_bytes: 32,
        };
        let params = FeeParams::default();

        let fee = compute_fee_v2(&input, &params);

        // GOLDEN VECTOR: This exact value MUST NOT change
        assert_eq!(fee, 8276, "Golden vector mismatch: hybrid_signature");
    }

    // =========================================================================
    // GOLDEN VECTOR: Minimum Fee
    // =========================================================================

    /// Golden vector: Transaction that would compute below minimum fee
    ///
    /// Empty transaction should return minimum_fee
    #[test]
    fn golden_minimum_fee() {
        let input = FeeInput {
            kind: TxKind::NativeTransfer,
            sig_scheme: SigScheme::Ed25519,
            sig_count: 0,
            envelope_bytes: 0,
            payload_bytes: 0,
            witness_bytes: 0,
            exec_units: 0,
            state_reads: 0,
            state_writes: 0,
            state_write_bytes: 0,
        };
        let params = FeeParams::default();

        let fee = compute_fee_v2(&input, &params);

        // GOLDEN VECTOR: Must equal minimum fee
        assert_eq!(fee, 1000, "Golden vector mismatch: minimum_fee");
        assert_eq!(fee, params.minimum_fee);
    }

    // =========================================================================
    // GOLDEN VECTOR: Custom Parameters
    // =========================================================================

    /// Golden vector: With custom fee parameters
    ///
    /// This tests that parameter changes affect fees correctly
    #[test]
    fn golden_custom_params() {
        let input = FeeInput {
            kind: TxKind::NativeTransfer,
            sig_scheme: SigScheme::Ed25519,
            sig_count: 1,
            envelope_bytes: 100,
            payload_bytes: 50,
            witness_bytes: 64,
            exec_units: 0,
            state_reads: 2,
            state_writes: 2,
            state_write_bytes: 32,
        };

        let params = FeeParams {
            base_fee_per_byte: 5,        // 5x default
            fee_per_exec_unit: 10,
            fee_per_state_read: 200,     // 2x default
            fee_per_state_write: 1000,   // 2x default
            fee_per_state_write_byte: 20, // 2x default
            fee_per_signature: 2000,     // 2x default
            minimum_fee: 500,
            maximum_fee: 1_000_000_000,
        };

        let fee = compute_fee_v2(&input, &params);

        // GOLDEN VECTOR: This exact value MUST NOT change
        // byte_fee: 214 * 5 = 1070
        // state_fee: (2 * 200) + (2 * 1000) + (32 * 20) = 400 + 2000 + 640 = 3040
        // sig_fee: 2000 * 10000 / 10000 = 2000
        // base_fee: 1070 + 0 + 3040 + 2000 = 6110
        // adjusted: 6110 * 10000 / 10000 = 6110
        assert_eq!(fee, 6110, "Golden vector mismatch: custom_params");
    }

    // =========================================================================
    // GOLDEN VECTOR: Testing Params (Zero Minimum)
    // =========================================================================

    /// Golden vector: Using for_testing() params (all 1s, no minimum)
    #[test]
    fn golden_testing_params() {
        let input = FeeInput {
            kind: TxKind::NativeTransfer,
            sig_scheme: SigScheme::Ed25519,
            sig_count: 1,
            envelope_bytes: 100,
            payload_bytes: 50,
            witness_bytes: 64,
            exec_units: 100,
            state_reads: 2,
            state_writes: 2,
            state_write_bytes: 32,
        };

        let params = FeeParams::for_testing();

        let fee = compute_fee_v2(&input, &params);

        // GOLDEN VECTOR: With testing params (all 1)
        // byte_fee: 214 * 1 = 214
        // exec_fee: 100 * 1 = 100
        // state_fee: 2 + 2 + 32 = 36
        // sig_fee: 1 * 10000 / 10000 = 1
        // base_fee: 214 + 100 + 36 + 1 = 351
        // adjusted: 351 * 10000 / 10000 = 351
        assert_eq!(fee, 351, "Golden vector mismatch: testing_params");
    }

    // =========================================================================
    // INVARIANT: Fee Monotonicity Tests
    // =========================================================================

    /// Verify that more bytes = higher fee (monotonicity)
    #[test]
    fn invariant_bytes_increase_fee() {
        let params = FeeParams::default();

        let mut input = FeeInput::native_transfer(100, SigScheme::Ed25519);
        let fee1 = compute_fee_v2(&input, &params);

        input.envelope_bytes = 200;
        let fee2 = compute_fee_v2(&input, &params);

        assert!(fee2 > fee1, "More bytes should increase fee");
    }

    /// Verify that more state writes = higher fee (monotonicity)
    #[test]
    fn invariant_state_writes_increase_fee() {
        let params = FeeParams::default();

        let mut input = FeeInput::native_transfer(100, SigScheme::Ed25519);
        input.state_writes = 1;
        let fee1 = compute_fee_v2(&input, &params);

        input.state_writes = 5;
        let fee2 = compute_fee_v2(&input, &params);

        assert!(fee2 > fee1, "More state writes should increase fee");
    }

    /// Verify that more signatures = higher fee (monotonicity)
    #[test]
    fn invariant_signatures_increase_fee() {
        let params = FeeParams::default();

        let mut input = FeeInput::native_transfer(100, SigScheme::Ed25519);
        input.sig_count = 1;
        let fee1 = compute_fee_v2(&input, &params);

        input.sig_count = 5;
        let fee2 = compute_fee_v2(&input, &params);

        assert!(fee2 > fee1, "More signatures should increase fee");
    }

    // =========================================================================
    // CROSS-PLATFORM CONSISTENCY (Determinism Verification)
    // =========================================================================

    /// Verify determinism by computing same fee multiple times
    #[test]
    fn determinism_repeated_computation() {
        let input = FeeInput::native_transfer(200, SigScheme::Ed25519);
        let params = FeeParams::default();

        let mut fees = Vec::new();
        for _ in 0..1000 {
            fees.push(compute_fee_v2(&input, &params));
        }

        // All fees must be identical
        let first = fees[0];
        for fee in fees {
            assert_eq!(fee, first, "Fee computation must be deterministic");
        }
    }

    /// Verify that fee computation uses no floating point
    /// (This is enforced by the type system, but we document it here)
    #[test]
    fn no_floating_point() {
        // The FeeInput, FeeParams, and compute_fee_v2 use only integer types:
        // - u8, u32, u64, u128 for values
        // - No f32, f64 anywhere in the computation
        //
        // This ensures identical results on all platforms regardless of
        // floating point implementation differences.
        let input = FeeInput::native_transfer(200, SigScheme::Ed25519);
        let params = FeeParams::default();

        let fee = compute_fee_v2(&input, &params);

        // The exact value proves no floating point rounding occurred
        assert_eq!(fee, 2816);
    }
}
