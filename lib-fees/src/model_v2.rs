//! Fee Model v2 (Pure Function)
//!
//! Deterministic fee computation for ZHTP transactions.
//!
//! # Rules (enforced in code)
//!
//! - `witness_bytes = min(witness_bytes, witness_cap[kind])`
//! - No floats - all arithmetic is integer
//! - u128 arithmetic internally to prevent overflow
//! - Deterministic across all platforms
//!
//! # Fee Multiplier Rationale (FEES-7, FEES-8, FEES-9)
//!
//! ## Witness Caps (basis points, 10000 = 1.0x)
//!
//! Witness data is capped to prevent DoS attacks where transactions include
//! excessive witness data. Caps are set based on typical use cases:
//!
//! | TxKind | Cap | Rationale |
//! |--------|-----|-----------|
//! | NativeTransfer | 1KB | Simple Ed25519 signatures (64 bytes) |
//! | TokenTransfer | 2KB | Token proofs + signatures |
//! | ContractCall | 64KB | Complex contract proofs with multiple signatures |
//! | DataUpload | 128KB | Large data proofs with attestations |
//! | Governance | 4KB | Governance proofs, typically multisig |
//! | Staking/Unstaking | 2KB | Delegation proofs |
//! | ValidatorRegistration | 4KB | Validator key material + proofs |
//! | ValidatorExit | 2KB | Exit proofs |
//!
//! ## Base Multipliers (basis points, 10000 = 1.0x)
//!
//! Multipliers adjust fees based on transaction complexity and resource usage:
//!
//! | TxKind | Multiplier | Rationale |
//! |--------|------------|-----------|
//! | NativeTransfer | 1.0x | Baseline, simplest operation |
//! | TokenTransfer | 1.2x | Token validation overhead |
//! | ContractCall | 1.5x | Computation cost + VM overhead |
//! | DataUpload | 2.0x | Storage commitment cost |
//! | Governance | 0.5x | Subsidized to encourage participation |
//! | Staking/Unstaking | 1.2x | Similar complexity to token transfers |
//! | ValidatorRegistration | 1.3x | Key validation + registry updates |
//! | ValidatorExit | 1.2x | Registry updates + cleanup |
//!
//! ## Signature Scheme Multipliers (FEES-8)
//!
//! Larger signatures cost more to verify and store:
//!
//! | Scheme | Multiplier | Size |
//! |--------|------------|------|
//! | Ed25519 | 1.0x | 64 bytes |
//! | Dilithium5 | 5.0x | 4,627 bytes (post-quantum) |
//! | Hybrid | 5.5x | 4,691 bytes (Ed25519 + Dilithium5) |
//!
//! # BlockExecutor Integration
//!
//! BlockExecutor MUST reject: `tx.fee < compute_fee_v2(...)`

use lib_types::fees::{FeeDeficit, FeeInput, FeeParams, SigScheme, TxKind};

// =============================================================================
// TXKIND EXTENSION TRAIT (behavior only, types in lib-types)
// =============================================================================

/// Extension trait for TxKind with fee calculation behavior
pub trait TxKindExt {
    /// Get the witness cap for this transaction kind (in bytes)
    fn witness_cap(self) -> u32;
    /// Get the base multiplier for this transaction kind (basis points)
    fn base_multiplier_bps(self) -> u32;
}

impl TxKindExt for TxKind {
    /// Get the witness cap for this transaction kind (in bytes)
    ///
    /// Witness data is capped to prevent denial-of-service attacks
    /// where transactions include excessive witness data.
    fn witness_cap(self) -> u32 {
        match self {
            TxKind::NativeTransfer => 1_024,        // 1KB - simple signatures
            TxKind::TokenTransfer => 2_048,         // 2KB - token proofs
            TxKind::ContractCall => 65_536,         // 64KB - contract proofs
            TxKind::DataUpload => 131_072,          // 128KB - data proofs
            TxKind::Governance => 4_096,            // 4KB - governance proofs
            TxKind::Staking => 2_048,               // 2KB - staking proofs
            TxKind::Unstaking => 2_048,             // 2KB - unstaking proofs
            TxKind::ValidatorRegistration => 4_096, // 4KB - validator key material
            TxKind::ValidatorExit => 2_048,         // 2KB - exit proofs
        }
    }

    /// Get the base multiplier for this transaction kind (basis points)
    ///
    /// 10000 = 1.0x, 15000 = 1.5x, etc.
    fn base_multiplier_bps(self) -> u32 {
        match self {
            TxKind::NativeTransfer => 10_000,        // 1.0x - standard
            TxKind::TokenTransfer => 12_000,         // 1.2x - slightly higher
            TxKind::ContractCall => 15_000,          // 1.5x - computation cost
            TxKind::DataUpload => 20_000,            // 2.0x - storage cost
            TxKind::Governance => 5_000,             // 0.5x - subsidized
            TxKind::Staking => 12_000,               // 1.2x - similar to token transfer
            TxKind::Unstaking => 12_000,             // 1.2x - similar to staking
            TxKind::ValidatorRegistration => 13_000, // 1.3x - key validation
            TxKind::ValidatorExit => 12_000,         // 1.2x - registry cleanup
        }
    }
}

// =============================================================================
// SIGSCHEME EXTENSION TRAIT (behavior only, types in lib-types)
// =============================================================================

/// Extension trait for SigScheme with fee calculation behavior
pub trait SigSchemeExt {
    /// Get the signature size multiplier (basis points)
    fn size_multiplier_bps(self) -> u32;
    /// Get approximate signature size in bytes
    fn signature_size(self) -> u32;
}

impl SigSchemeExt for SigScheme {
    /// Get the signature size multiplier (basis points)
    ///
    /// Larger signatures cost more to verify and store.
    fn size_multiplier_bps(self) -> u32 {
        match self {
            SigScheme::Ed25519 => 10_000,    // 1.0x baseline
            SigScheme::Dilithium5 => 50_000, // 5.0x (much larger)
            SigScheme::Hybrid => 55_000,     // 5.5x (both, with parallelization discount)
        }
    }

    /// Get approximate signature size in bytes
    fn signature_size(self) -> u32 {
        match self {
            SigScheme::Ed25519 => 64,
            SigScheme::Dilithium5 => 4_627,
            SigScheme::Hybrid => 4_691, // 64 + 4627
        }
    }
}

// =============================================================================
// FEEINPUT EXTENSION TRAIT (behavior only, types in lib-types)
// =============================================================================

/// Extension trait for FeeInput with helper methods
pub trait FeeInputExt {
    /// Create a simple native transfer input
    fn native_transfer(envelope_bytes: u32, sig_scheme: SigScheme) -> Self;
    /// Get the effective witness bytes (capped by kind)
    fn effective_witness_bytes(&self) -> u32;
    /// Get total transaction size in bytes
    fn total_bytes(&self) -> u32;
}

impl FeeInputExt for FeeInput {
    /// Create a simple native transfer input
    fn native_transfer(envelope_bytes: u32, sig_scheme: SigScheme) -> Self {
        Self {
            kind: TxKind::NativeTransfer,
            sig_scheme,
            sig_count: 1,
            envelope_bytes,
            payload_bytes: 32, // recipient + amount
            witness_bytes: sig_scheme.signature_size(),
            exec_units: 0,
            state_reads: 2,        // sender + recipient balance
            state_writes: 2,       // sender + recipient balance
            state_write_bytes: 32, // two u128 balances
            zk_verify_units: 0,
        }
    }

    /// Get the effective witness bytes (capped by kind)
    fn effective_witness_bytes(&self) -> u32 {
        self.witness_bytes.min(self.kind.witness_cap())
    }

    /// Get total transaction size in bytes
    fn total_bytes(&self) -> u32 {
        self.envelope_bytes
            .saturating_add(self.payload_bytes)
            .saturating_add(self.effective_witness_bytes())
    }
}

// =============================================================================
// FEE COMPUTATION (PURE FUNCTION)
// =============================================================================

/// Compute transaction fee using Fee Model v2
///
/// # Determinism
///
/// This function is **pure** and **deterministic**:
/// - No side effects
/// - No floating point arithmetic
/// - Uses u128 internally to prevent overflow
/// - Same inputs always produce same output on all platforms
///
/// # Algorithm
///
/// ```text
/// effective_witness = min(witness_bytes, witness_cap[kind])
/// total_bytes = envelope + payload + effective_witness
///
/// byte_fee = total_bytes * base_fee_per_byte
/// exec_fee = exec_units * fee_per_exec_unit
/// state_fee = (reads * fee_per_read) + (writes * fee_per_write) + (write_bytes * fee_per_write_byte)
/// sig_fee = sig_count * fee_per_signature * sig_scheme_multiplier
///
/// base_fee = byte_fee + exec_fee + state_fee + sig_fee
/// adjusted_fee = base_fee * kind_multiplier / 10000
///
/// final_fee = clamp(adjusted_fee, minimum_fee, maximum_fee)
/// ```
///
/// # BlockExecutor Integration
///
/// BlockExecutor MUST reject transactions where: `tx.fee < compute_fee_v2(...)`
pub fn compute_fee_v2(input: &FeeInput, params: &FeeParams) -> u64 {
    // Use u128 internally to prevent overflow
    // All multiplication happens in u128 space, then we clamp to u64

    // 1. Calculate effective witness bytes (capped by kind)
    let effective_witness: u128 = input.effective_witness_bytes() as u128;
    let total_bytes: u128 = (input.envelope_bytes as u128)
        .saturating_add(input.payload_bytes as u128)
        .saturating_add(effective_witness);

    // 2. Byte fee
    let byte_fee: u128 = total_bytes.saturating_mul(params.base_fee_per_byte as u128);

    // 3. Execution fee
    let exec_fee: u128 =
        (input.exec_units as u128).saturating_mul(params.fee_per_exec_unit as u128);

    // 4. State access fee
    let state_read_fee: u128 =
        (input.state_reads as u128).saturating_mul(params.fee_per_state_read as u128);
    let state_write_fee: u128 =
        (input.state_writes as u128).saturating_mul(params.fee_per_state_write as u128);
    let state_write_byte_fee: u128 =
        (input.state_write_bytes as u128).saturating_mul(params.fee_per_state_write_byte as u128);
    let state_fee: u128 = state_read_fee
        .saturating_add(state_write_fee)
        .saturating_add(state_write_byte_fee);

    // 5. Signature fee (includes scheme multiplier)
    let sig_base_fee: u128 =
        (input.sig_count as u128).saturating_mul(params.fee_per_signature as u128);
    let sig_multiplier: u128 = input.sig_scheme.size_multiplier_bps() as u128;
    // sig_fee = sig_base_fee * multiplier / 10000
    let sig_fee: u128 = sig_base_fee.saturating_mul(sig_multiplier) / 10_000;

    // 5a. ZK verification fee
    let zk_verify_fee: u128 =
        (input.zk_verify_units as u128).saturating_mul(params.fee_per_zk_verify_unit as u128);

    // 6. Base fee (sum of all components)
    let base_fee: u128 = byte_fee
        .saturating_add(exec_fee)
        .saturating_add(state_fee)
        .saturating_add(sig_fee)
        .saturating_add(zk_verify_fee);

    // 7. Apply kind multiplier
    let kind_multiplier: u128 = input.kind.base_multiplier_bps() as u128;
    // adjusted_fee = base_fee * multiplier / 10000
    let adjusted_fee: u128 = base_fee.saturating_mul(kind_multiplier) / 10_000;

    // 8. Clamp to [minimum_fee, maximum_fee] and convert to u64
    let min_fee = params.minimum_fee as u128;
    let max_fee = params.maximum_fee as u128;
    let clamped: u128 = adjusted_fee.max(min_fee).min(max_fee);

    // Safe conversion: clamped is guaranteed <= maximum_fee which is u64
    clamped as u64
}

/// Verify that a transaction has paid sufficient fee
///
/// Returns `Ok(())` if `paid_fee >= required_fee`, otherwise returns the deficit.
pub fn verify_fee(input: &FeeInput, params: &FeeParams, paid_fee: u64) -> Result<(), FeeDeficit> {
    let required = compute_fee_v2(input, params);
    if paid_fee >= required {
        Ok(())
    } else {
        Err(FeeDeficit {
            required,
            paid: paid_fee,
            deficit: required - paid_fee,
        })
    }
}

// =============================================================================
// FEE ESTIMATION HELPERS (FEES-12)
// =============================================================================

/// Estimate fee for a native transfer transaction
///
/// # Arguments
/// * `sig_scheme` - Signature scheme to use
/// * `params` - Fee parameters
pub fn estimate_native_transfer_fee(sig_scheme: SigScheme, params: &FeeParams) -> u64 {
    let input = FeeInput::native_transfer(200, sig_scheme);
    compute_fee_v2(&input, params)
}

/// Estimate fee for a token transfer transaction
///
/// # Arguments
/// * `sig_scheme` - Signature scheme to use
/// * `params` - Fee parameters
pub fn estimate_token_transfer_fee(sig_scheme: SigScheme, params: &FeeParams) -> u64 {
    let mut input = FeeInput::native_transfer(250, sig_scheme);
    input.kind = TxKind::TokenTransfer;
    input.payload_bytes = 64; // token_id + amount
    input.state_reads = 3; // sender + recipient + token contract
    input.state_writes = 3;
    compute_fee_v2(&input, params)
}

/// Estimate fee for a contract call transaction
///
/// # Arguments
/// * `sig_scheme` - Signature scheme to use
/// * `exec_units` - Estimated execution units
/// * `params` - Fee parameters
pub fn estimate_contract_call_fee(
    sig_scheme: SigScheme,
    exec_units: u32,
    params: &FeeParams,
) -> u64 {
    let input = FeeInput {
        kind: TxKind::ContractCall,
        sig_scheme,
        sig_count: 1,
        envelope_bytes: 300,
        payload_bytes: 256, // contract call data
        witness_bytes: sig_scheme.signature_size(),
        exec_units,
        state_reads: 5,
        state_writes: 3,
        state_write_bytes: 128,
        zk_verify_units: 0,
    };
    compute_fee_v2(&input, params)
}

/// Estimate fee range for a transaction kind
///
/// Returns (min_fee, max_fee) where:
/// - min_fee: Fee with minimal resources
/// - max_fee: Fee with typical resource usage
///
/// # Arguments
/// * `kind` - Transaction kind
/// * `sig_scheme` - Signature scheme to use
/// * `params` - Fee parameters
pub fn estimate_fee_range(kind: TxKind, sig_scheme: SigScheme, params: &FeeParams) -> (u64, u64) {
    let min_input = FeeInput {
        kind,
        sig_scheme,
        sig_count: 1,
        envelope_bytes: 100,
        payload_bytes: 32,
        witness_bytes: sig_scheme.signature_size(),
        exec_units: 0,
        state_reads: 2,
        state_writes: 2,
        state_write_bytes: 32,
        zk_verify_units: 0,
    };

    let max_input = FeeInput {
        kind,
        sig_scheme,
        sig_count: 1,
        envelope_bytes: 500,
        payload_bytes: 256,
        witness_bytes: kind.witness_cap().min(4096), // Cap at 4KB for estimation
        exec_units: match kind {
            TxKind::ContractCall => 1000,
            TxKind::DataUpload => 500,
            _ => 0,
        },
        state_reads: 10,
        state_writes: 5,
        state_write_bytes: 256,
        zk_verify_units: 0,
    };

    let min_fee = compute_fee_v2(&min_input, params);
    let max_fee = compute_fee_v2(&max_input, params);

    // Clamp to min/max fee limits
    let clamped_min = min_fee.max(params.minimum_fee).min(params.maximum_fee);
    let clamped_max = max_fee.max(params.minimum_fee).min(params.maximum_fee);

    (clamped_min, clamped_max)
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_transfer_fee() {
        let input = FeeInput::native_transfer(200, SigScheme::Ed25519);
        let params = FeeParams::default();
        let fee = compute_fee_v2(&input, &params);

        // Fee should be at least minimum
        assert!(fee >= params.minimum_fee);

        // Fee should be reasonable for a simple transfer
        assert!(fee < 100_000); // Less than 100k units
    }

    #[test]
    fn test_witness_cap_enforced() {
        let mut input = FeeInput::native_transfer(200, SigScheme::Ed25519);
        let params = FeeParams::default();

        // Set witness bytes way above cap
        input.witness_bytes = 1_000_000; // 1MB

        let fee1 = compute_fee_v2(&input, &params);

        // Set witness bytes to exactly cap
        input.witness_bytes = TxKind::NativeTransfer.witness_cap();
        let fee2 = compute_fee_v2(&input, &params);

        // Fees should be equal because both are capped
        assert_eq!(fee1, fee2);
    }

    #[test]
    fn test_effective_witness_bytes() {
        let mut input = FeeInput::native_transfer(100, SigScheme::Ed25519);

        // Below cap - should return actual
        input.witness_bytes = 500;
        assert_eq!(input.effective_witness_bytes(), 500);

        // At cap - should return cap
        input.witness_bytes = TxKind::NativeTransfer.witness_cap();
        assert_eq!(input.effective_witness_bytes(), 1_024);

        // Above cap - should return cap
        input.witness_bytes = 10_000;
        assert_eq!(input.effective_witness_bytes(), 1_024);
    }

    #[test]
    fn test_signature_scheme_affects_fee() {
        let params = FeeParams::default();

        let ed25519_input = FeeInput::native_transfer(200, SigScheme::Ed25519);
        let dilithium_input = FeeInput::native_transfer(200, SigScheme::Dilithium5);

        let ed25519_fee = compute_fee_v2(&ed25519_input, &params);
        let dilithium_fee = compute_fee_v2(&dilithium_input, &params);

        // Dilithium should be more expensive due to larger signatures
        assert!(dilithium_fee > ed25519_fee);
    }

    #[test]
    fn test_tx_kind_affects_fee() {
        let params = FeeParams::default();

        let transfer = FeeInput {
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
            zk_verify_units: 0,
        };

        let mut contract = transfer.clone();
        contract.kind = TxKind::ContractCall;

        let transfer_fee = compute_fee_v2(&transfer, &params);
        let contract_fee = compute_fee_v2(&contract, &params);

        // Contract call should be more expensive (1.5x multiplier)
        assert!(contract_fee > transfer_fee);
    }

    #[test]
    fn test_governance_subsidized() {
        let params = FeeParams::default();

        let mut transfer = FeeInput::native_transfer(200, SigScheme::Ed25519);
        let mut governance = transfer.clone();
        governance.kind = TxKind::Governance;

        let transfer_fee = compute_fee_v2(&transfer, &params);
        let governance_fee = compute_fee_v2(&governance, &params);

        // Governance should be cheaper (0.5x multiplier)
        assert!(governance_fee < transfer_fee);
    }

    #[test]
    fn test_staking_fee() {
        let params = FeeParams::default();

        let mut transfer = FeeInput::native_transfer(200, SigScheme::Ed25519);
        let mut staking = transfer.clone();
        staking.kind = TxKind::Staking;

        let transfer_fee = compute_fee_v2(&transfer, &params);
        let staking_fee = compute_fee_v2(&staking, &params);

        // Staking should be slightly higher than transfer (1.2x multiplier)
        assert!(staking_fee > transfer_fee);
        assert_eq!(TxKind::Staking.base_multiplier_bps(), 12_000);
        assert_eq!(TxKind::Staking.witness_cap(), 2_048);
    }

    #[test]
    fn test_unstaking_fee() {
        let params = FeeParams::default();

        let mut transfer = FeeInput::native_transfer(200, SigScheme::Ed25519);
        let mut unstaking = transfer.clone();
        unstaking.kind = TxKind::Unstaking;

        let transfer_fee = compute_fee_v2(&transfer, &params);
        let unstaking_fee = compute_fee_v2(&unstaking, &params);

        // Unstaking should be slightly higher than transfer (1.2x multiplier)
        assert!(unstaking_fee > transfer_fee);
        assert_eq!(TxKind::Unstaking.base_multiplier_bps(), 12_000);
        assert_eq!(TxKind::Unstaking.witness_cap(), 2_048);
    }

    #[test]
    fn test_minimum_fee_enforced() {
        let params = FeeParams::default();

        // Create minimal transaction
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
            zk_verify_units: 0,
        };

        let fee = compute_fee_v2(&input, &params);
        assert_eq!(fee, params.minimum_fee);
    }

    #[test]
    fn test_maximum_fee_enforced() {
        let mut params = FeeParams::default();
        params.maximum_fee = 1_000;

        // Create expensive transaction
        let input = FeeInput {
            kind: TxKind::DataUpload,
            sig_scheme: SigScheme::Hybrid,
            sig_count: 255,
            envelope_bytes: u32::MAX,
            payload_bytes: u32::MAX,
            witness_bytes: u32::MAX,
            exec_units: u32::MAX,
            state_reads: u32::MAX,
            state_writes: u32::MAX,
            state_write_bytes: u32::MAX,
            zk_verify_units: 0,
        };

        let fee = compute_fee_v2(&input, &params);
        assert_eq!(fee, params.maximum_fee);
    }

    #[test]
    fn test_verify_fee_success() {
        let input = FeeInput::native_transfer(200, SigScheme::Ed25519);
        let params = FeeParams::default();
        let required = compute_fee_v2(&input, &params);

        // Exact fee should pass
        assert!(verify_fee(&input, &params, required).is_ok());

        // Overpayment should pass
        assert!(verify_fee(&input, &params, required + 1000).is_ok());
    }

    #[test]
    fn test_verify_fee_failure() {
        let input = FeeInput::native_transfer(200, SigScheme::Ed25519);
        let params = FeeParams::default();
        let required = compute_fee_v2(&input, &params);

        // Underpayment should fail
        let result = verify_fee(&input, &params, required - 1);
        assert!(result.is_err());

        let deficit = result.unwrap_err();
        assert_eq!(deficit.required, required);
        assert_eq!(deficit.paid, required - 1);
        assert_eq!(deficit.deficit, 1);
    }

    #[test]
    fn test_no_overflow_extreme_values() {
        let params = FeeParams {
            base_fee_per_byte: u64::MAX,
            fee_per_exec_unit: u64::MAX,
            fee_per_state_read: u64::MAX,
            fee_per_state_write: u64::MAX,
            fee_per_state_write_byte: u64::MAX,
            fee_per_signature: u64::MAX,
            fee_per_zk_verify_unit: u64::MAX,
            minimum_fee: 0,
            maximum_fee: u64::MAX,
        };

        let input = FeeInput {
            kind: TxKind::DataUpload,
            sig_scheme: SigScheme::Hybrid,
            sig_count: 255,
            envelope_bytes: u32::MAX,
            payload_bytes: u32::MAX,
            witness_bytes: u32::MAX,
            exec_units: u32::MAX,
            state_reads: u32::MAX,
            state_writes: u32::MAX,
            state_write_bytes: u32::MAX,
            zk_verify_units: 0,
        };

        // Should not panic
        let fee = compute_fee_v2(&input, &params);

        // Result should be capped at maximum
        assert!(fee <= u64::MAX);
    }

    #[test]
    fn test_determinism() {
        let input = FeeInput::native_transfer(200, SigScheme::Ed25519);
        let params = FeeParams::default();

        // Compute multiple times
        let fee1 = compute_fee_v2(&input, &params);
        let fee2 = compute_fee_v2(&input, &params);
        let fee3 = compute_fee_v2(&input, &params);

        // All should be identical
        assert_eq!(fee1, fee2);
        assert_eq!(fee2, fee3);
    }

    #[test]
    fn test_total_bytes() {
        let mut input = FeeInput::native_transfer(100, SigScheme::Ed25519);
        input.envelope_bytes = 100;
        input.payload_bytes = 50;
        input.witness_bytes = 64;

        // Below cap: 100 + 50 + 64 = 214
        assert_eq!(input.total_bytes(), 214);

        // Above cap: 100 + 50 + 1024 (capped) = 1174
        input.witness_bytes = 10_000;
        assert_eq!(input.total_bytes(), 1174);
    }

    #[test]
    fn test_tx_kind_variants() {
        // Verify discriminant values are stable (from lib-types)
        assert_eq!(TxKind::NativeTransfer as u8, 0);
        assert_eq!(TxKind::TokenTransfer as u8, 1);
        assert_eq!(TxKind::ContractCall as u8, 2);
        assert_eq!(TxKind::DataUpload as u8, 3);
        assert_eq!(TxKind::Governance as u8, 4);
        assert_eq!(TxKind::Staking as u8, 5);
        assert_eq!(TxKind::Unstaking as u8, 6);
        assert_eq!(TxKind::ValidatorRegistration as u8, 7);
        assert_eq!(TxKind::ValidatorExit as u8, 8);
    }

    #[test]
    fn test_validator_registration_fee() {
        let params = FeeParams::default();

        let mut transfer = FeeInput::native_transfer(200, SigScheme::Ed25519);
        let mut validator_reg = transfer.clone();
        validator_reg.kind = TxKind::ValidatorRegistration;

        let transfer_fee = compute_fee_v2(&transfer, &params);
        let validator_reg_fee = compute_fee_v2(&validator_reg, &params);

        // Validator registration should be higher than transfer (1.3x multiplier)
        assert!(validator_reg_fee > transfer_fee);
        assert_eq!(TxKind::ValidatorRegistration.base_multiplier_bps(), 13_000);
        assert_eq!(TxKind::ValidatorRegistration.witness_cap(), 4_096);
    }

    #[test]
    fn test_validator_exit_fee() {
        let params = FeeParams::default();

        let mut transfer = FeeInput::native_transfer(200, SigScheme::Ed25519);
        let mut validator_exit = transfer.clone();
        validator_exit.kind = TxKind::ValidatorExit;

        let transfer_fee = compute_fee_v2(&transfer, &params);
        let validator_exit_fee = compute_fee_v2(&validator_exit, &params);

        // Validator exit should be slightly higher than transfer (1.2x multiplier)
        assert!(validator_exit_fee > transfer_fee);
        assert_eq!(TxKind::ValidatorExit.base_multiplier_bps(), 12_000);
        assert_eq!(TxKind::ValidatorExit.witness_cap(), 2_048);
    }

    #[test]
    fn test_sig_scheme_variants() {
        // Verify discriminant values are stable (from lib-types)
        assert_eq!(SigScheme::Ed25519 as u8, 0);
        assert_eq!(SigScheme::Dilithium5 as u8, 1);
        assert_eq!(SigScheme::Hybrid as u8, 2);
    }

    // =============================================================================
    // PROPERTY-BASED TESTS FOR FEE MONOTONICITY (FEES-14)
    // =============================================================================

    /// Fee should be monotonic with respect to envelope_bytes
    #[test]
    fn test_fee_monotonic_with_envelope_bytes() {
        let params = FeeParams::for_testing();
        let mut prev_fee = 0;

        for envelope_bytes in [100, 200, 500, 1000, 2000] {
            let input = FeeInput {
                kind: TxKind::NativeTransfer,
                sig_scheme: SigScheme::Ed25519,
                sig_count: 1,
                envelope_bytes,
                payload_bytes: 32,
                witness_bytes: 64,
                exec_units: 0,
                state_reads: 2,
                state_writes: 2,
                state_write_bytes: 32,
                zk_verify_units: 0,
            };
            let fee = compute_fee_v2(&input, &params);
            assert!(
                fee >= prev_fee,
                "Fee should increase with envelope_bytes: {} >= {}",
                fee,
                prev_fee
            );
            prev_fee = fee;
        }
    }

    /// Fee should be monotonic with respect to exec_units
    #[test]
    fn test_fee_monotonic_with_exec_units() {
        let params = FeeParams::for_testing();
        let mut prev_fee = 0;

        for exec_units in [0, 100, 500, 1000, 5000] {
            let input = FeeInput {
                kind: TxKind::ContractCall,
                sig_scheme: SigScheme::Ed25519,
                sig_count: 1,
                envelope_bytes: 200,
                payload_bytes: 256,
                witness_bytes: 64,
                exec_units,
                state_reads: 2,
                state_writes: 2,
                state_write_bytes: 32,
                zk_verify_units: 0,
            };
            let fee = compute_fee_v2(&input, &params);
            assert!(
                fee >= prev_fee,
                "Fee should increase with exec_units: {} >= {}",
                fee,
                prev_fee
            );
            prev_fee = fee;
        }
    }

    /// Fee should be monotonic with respect to state_reads
    #[test]
    fn test_fee_monotonic_with_state_reads() {
        let params = FeeParams::for_testing();
        let mut prev_fee = 0;

        for state_reads in [1, 2, 5, 10, 20] {
            let input = FeeInput {
                kind: TxKind::ContractCall,
                sig_scheme: SigScheme::Ed25519,
                sig_count: 1,
                envelope_bytes: 200,
                payload_bytes: 256,
                witness_bytes: 64,
                exec_units: 100,
                state_reads,
                state_writes: 2,
                state_write_bytes: 32,
                zk_verify_units: 0,
            };
            let fee = compute_fee_v2(&input, &params);
            assert!(
                fee >= prev_fee,
                "Fee should increase with state_reads: {} >= {}",
                fee,
                prev_fee
            );
            prev_fee = fee;
        }
    }

    /// Fee should be monotonic with respect to sig_count
    #[test]
    fn test_fee_monotonic_with_sig_count() {
        let params = FeeParams::for_testing();
        let mut prev_fee = 0;

        for sig_count in [1, 2, 5, 10] {
            let input = FeeInput {
                kind: TxKind::NativeTransfer,
                sig_scheme: SigScheme::Ed25519,
                sig_count,
                envelope_bytes: 200,
                payload_bytes: 32,
                witness_bytes: 64 * sig_count as u32,
                exec_units: 0,
                state_reads: 2,
                state_writes: 2,
                state_write_bytes: 32,
                zk_verify_units: 0,
            };
            let fee = compute_fee_v2(&input, &params);
            assert!(
                fee >= prev_fee,
                "Fee should increase with sig_count: {} >= {}",
                fee,
                prev_fee
            );
            prev_fee = fee;
        }
    }

    // =============================================================================
    // FEE ESTIMATION TESTS (FEES-12)
    // =============================================================================

    #[test]
    fn test_estimate_native_transfer_fee() {
        let params = FeeParams::for_testing();
        let fee = estimate_native_transfer_fee(SigScheme::Ed25519, &params);
        assert!(fee >= params.minimum_fee);
        assert!(fee <= params.maximum_fee);
    }

    #[test]
    fn test_estimate_token_transfer_fee() {
        let params = FeeParams::for_testing();
        let fee = estimate_token_transfer_fee(SigScheme::Ed25519, &params);
        assert!(fee >= params.minimum_fee);
        assert!(fee <= params.maximum_fee);
    }

    #[test]
    fn test_estimate_contract_call_fee() {
        let params = FeeParams::for_testing();
        let fee = estimate_contract_call_fee(SigScheme::Ed25519, 1000, &params);
        assert!(fee >= params.minimum_fee);
        assert!(fee <= params.maximum_fee);
    }

    #[test]
    fn test_estimate_fee_range() {
        let params = FeeParams::for_testing();
        let (min_fee, max_fee) =
            estimate_fee_range(TxKind::ContractCall, SigScheme::Ed25519, &params);
        assert!(min_fee <= max_fee);
        assert!(min_fee >= params.minimum_fee);
        assert!(max_fee <= params.maximum_fee);
    }

    #[test]
    fn test_fee_estimation_consistency() {
        let params = FeeParams::for_testing();

        // Native transfer estimation should match direct computation
        let estimated = estimate_native_transfer_fee(SigScheme::Ed25519, &params);
        let input = FeeInput::native_transfer(200, SigScheme::Ed25519);
        let computed = compute_fee_v2(&input, &params);
        assert_eq!(estimated, computed);
    }
}
