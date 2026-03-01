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
//! # BlockExecutor Integration
//!
//! BlockExecutor MUST reject: `tx.fee < compute_fee_v2(...)`

use serde::{Deserialize, Serialize};

// =============================================================================
// TRANSACTION KIND
// =============================================================================

/// Transaction type classification for fee calculation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TxKind {
    /// Native token transfer (SOV)
    NativeTransfer = 0,
    /// Custom token transfer
    TokenTransfer = 1,
    /// Smart contract call
    ContractCall = 2,
    /// Data upload (storage commitment)
    DataUpload = 3,
    /// Governance action (vote, proposal)
    Governance = 4,
}

impl TxKind {
    /// Get the witness cap for this transaction kind (in bytes)
    ///
    /// Witness data is capped to prevent denial-of-service attacks
    /// where transactions include excessive witness data.
    pub const fn witness_cap(self) -> u32 {
        match self {
            TxKind::NativeTransfer => 1_024,      // 1KB - simple signatures
            TxKind::TokenTransfer => 2_048,       // 2KB - token proofs
            TxKind::ContractCall => 65_536,       // 64KB - contract proofs
            TxKind::DataUpload => 131_072,        // 128KB - data proofs
            TxKind::Governance => 4_096,          // 4KB - governance proofs
        }
    }

    /// Get the base multiplier for this transaction kind (basis points)
    ///
    /// 10000 = 1.0x, 15000 = 1.5x, etc.
    ///
    /// # Multiplier Rationale
    ///
    /// Multipliers reflect the relative computational and storage costs
    /// of different transaction types, aligned with the ZHTP economic model.
    ///
    /// ## Economic Model
    ///
    /// | Kind | Multiplier | Rationale |
    /// |------|------------|-----------|
    /// | NativeTransfer | 1.0x | Baseline - minimal computation |
    /// | TokenTransfer | 1.2x | Token state lookups + balance checks |
    /// | ContractCall | 1.5x | VM execution + state transitions |
    /// | DataUpload | 2.0x | Permanent storage commitment |
    /// | Governance | 0.5x | Subsidized - encourages participation |
    ///
    /// ## Detailed Reasoning
    ///
    /// ### NativeTransfer (1.0x)
    /// Simplest transaction type. Only updates two balances (sender/recipient).
    /// Serves as the baseline for all other multipliers.
    ///
    /// ### TokenTransfer (1.2x)
    /// Slightly more expensive than native transfer due to:
    /// - Token contract state lookup
    /// - Additional balance validation logic
    /// - Potential allowance checks for delegated transfers
    ///
    /// ### ContractCall (1.5x)
    /// Higher cost reflects:
    /// - VM execution environment setup
    /// - Contract code loading and interpretation
    /// - Variable execution units (metered separately via exec_units)
    /// - More complex state transitions
    ///
    /// ### DataUpload (2.0x)
    /// Most expensive due to permanent storage commitment:
    /// - Data stored indefinitely on-chain
    /// - Storage is the scarcest resource in blockchain systems
    /// - Multiplier discourages unnecessary data bloat
    /// - Based on state rent economic model (see `docs/economy/STATE_RENT_MODEL.md`)
    ///
    /// ### Governance (0.5x)
    /// Subsidized to encourage network participation:
    /// - Voting is a civic duty in the ZHTP ecosystem
    /// - Lower barriers increase voter turnout
    /// - Cost still non-zero to prevent spam voting
    /// - Subsidy funded by network treasury
    ///
    /// # Examples
    ///
    /// ```
    /// use lib_fees::TxKind;
    ///
    /// // Governance is 50% cheaper than native transfer
    /// let gov_multiplier = TxKind::Governance.base_multiplier_bps();      // 5000
    /// let native_multiplier = TxKind::NativeTransfer.base_multiplier_bps(); // 10000
    /// assert_eq!(gov_multiplier * 2, native_multiplier);
    ///
    /// // Data upload is 2x more expensive
    /// let upload_multiplier = TxKind::DataUpload.base_multiplier_bps();   // 20000
    /// assert_eq!(upload_multiplier, native_multiplier * 2);
    /// ```
    pub const fn base_multiplier_bps(self) -> u32 {
        match self {
            TxKind::NativeTransfer => 10_000,   // 1.0x - standard
            TxKind::TokenTransfer => 12_000,    // 1.2x - slightly higher
            TxKind::ContractCall => 15_000,     // 1.5x - computation cost
            TxKind::DataUpload => 20_000,       // 2.0x - storage cost
            TxKind::Governance => 5_000,        // 0.5x - subsidized
        }
    }
}

// =============================================================================
// SIGNATURE SCHEME
// =============================================================================

/// Cryptographic signature scheme used
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum SigScheme {
    /// Ed25519 - compact, fast (64 byte signatures)
    Ed25519 = 0,
    /// Dilithium5 - post-quantum (4627 byte signatures)
    Dilithium5 = 1,
    /// Hybrid Ed25519 + Dilithium (combined)
    Hybrid = 2,
}

impl SigScheme {
    /// Get the signature size multiplier (basis points)
    ///
    /// Larger signatures cost more to verify and store.
    ///
    /// # Multiplier Rationale
    ///
    /// Multipliers account for the verification cost and storage overhead
    /// of different post-quantum cryptographic schemes.
    ///
    /// ## Cryptographic Specifications
    ///
    /// | Scheme | Sig Size | Multiplier | Verification Cost |
    /// |--------|----------|------------|-------------------|
    /// | Ed25519 | 64 bytes | 1.0x | ~50μs (fast) |
    /// | Dilithium5 | 4,627 bytes | 5.0x | ~200μs (4x slower) |
    /// | Hybrid | 4,691 bytes | 5.5x | Combined cost |
    ///
    /// ## Detailed Reasoning
    ///
    /// ### Ed25519 (1.0x)
    /// Standard elliptic curve signatures. Serves as the baseline.
    /// - 64 bytes (compact)
    /// - Fast verification (~50 microseconds)
    /// - Well-established security
    ///
    /// ### Dilithium5 (5.0x)
    /// NIST PQ Standard for digital signatures. Higher cost due to:
    /// - 4,627 bytes signature size (72x larger than Ed25519)
    /// - Increased bandwidth for network propagation
    /// - Higher storage cost in blocks
    /// - More complex verification algorithm (~4x slower)
    /// - NIST PQC Round 3 winner, security level equivalent to AES-256
    ///
    /// Reference: [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
    ///
    /// ### Hybrid (5.5x)
    /// Combines both Ed25519 and Dilithium5 for defense-in-depth:
    /// - Total size: 4,691 bytes (64 + 4,627)
    /// - Security: Protected against both classical and quantum attacks
    /// - Cost: 5.5x (slightly above Dilithium5 to account for Ed25519)
    /// - Rationale for 5.5x vs 6.0x:
    ///   - Ed25519 adds relatively small marginal verification cost on top of Dilithium5
    ///   - Additional storage and bandwidth overhead from the 64-byte Ed25519 signature is minor
    ///   - Hybrid is priced close to Dilithium5, rather than as a full additive 1.0x + 5.0x
    ///
    /// ## Tradeoff Analysis
    ///
    /// Signature size vs verification time tradeoff:
    /// - Larger signatures increase bandwidth and storage costs
    /// - Slower verification reduces transaction throughput
    /// - PQ security is essential for long-term protection
    /// - Multipliers balance these competing concerns
    ///
    /// # Examples
    ///
    /// ```
    /// use lib_fees::SigScheme;
    ///
    /// // Ed25519 is the baseline
    /// let ed_mult = SigScheme::Ed25519.size_multiplier_bps();      // 10000
    ///
    /// // Dilithium5 is 5x more expensive
    /// let dil_mult = SigScheme::Dilithium5.size_multiplier_bps();  // 50000
    /// assert_eq!(dil_mult, ed_mult * 5);
    ///
    /// // Hybrid combines both with slight efficiency discount
    /// let hyb_mult = SigScheme::Hybrid.size_multiplier_bps();      // 55000
    /// assert!(hyb_mult < ed_mult + dil_mult); // 55000 < 60000
    /// ```
    pub const fn size_multiplier_bps(self) -> u32 {
        match self {
            SigScheme::Ed25519 => 10_000,     // 1.0x baseline
            SigScheme::Dilithium5 => 50_000,  // 5.0x (much larger)
            SigScheme::Hybrid => 55_000,      // 5.5x (both, with parallelization discount)
        }
    }

    /// Get approximate signature size in bytes
    pub const fn signature_size(self) -> u32 {
        match self {
            SigScheme::Ed25519 => 64,
            SigScheme::Dilithium5 => 4_627,
            SigScheme::Hybrid => 4_691,  // 64 + 4627
        }
    }
}

// =============================================================================
// FEE INPUT
// =============================================================================

/// Input parameters for fee computation
///
/// All fields are transaction-derived and deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeInput {
    /// Transaction kind
    pub kind: TxKind,
    /// Signature scheme used
    pub sig_scheme: SigScheme,
    /// Number of signatures
    pub sig_count: u8,
    /// Size of transaction envelope (headers, metadata) in bytes
    pub envelope_bytes: u32,
    /// Size of transaction payload in bytes
    pub payload_bytes: u32,
    /// Size of witness data in bytes (will be capped)
    pub witness_bytes: u32,
    /// Execution units consumed (for contract calls)
    pub exec_units: u32,
    /// Number of state reads
    pub state_reads: u32,
    /// Number of state writes
    pub state_writes: u32,
    /// Total bytes written to state
    pub state_write_bytes: u32,
}

impl FeeInput {
    /// Create a simple native transfer input
    pub fn native_transfer(envelope_bytes: u32, sig_scheme: SigScheme) -> Self {
        Self {
            kind: TxKind::NativeTransfer,
            sig_scheme,
            sig_count: 1,
            envelope_bytes,
            payload_bytes: 32,  // recipient + amount
            witness_bytes: sig_scheme.signature_size(),
            exec_units: 0,
            state_reads: 2,     // sender + recipient balance
            state_writes: 2,    // sender + recipient balance
            state_write_bytes: 32,  // two u128 balances
        }
    }

    /// Get the effective witness bytes (capped by kind)
    pub fn effective_witness_bytes(&self) -> u32 {
        self.witness_bytes.min(self.kind.witness_cap())
    }

    /// Get total transaction size in bytes
    pub fn total_bytes(&self) -> u32 {
        self.envelope_bytes
            .saturating_add(self.payload_bytes)
            .saturating_add(self.effective_witness_bytes())
    }
}

// =============================================================================
// FEE PARAMETERS
// =============================================================================

/// Fee calculation parameters (set by governance)
///
/// All values are in smallest token units per unit of resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeParams {
    /// Base fee per byte of transaction data
    pub base_fee_per_byte: u64,
    /// Fee per execution unit (for contract calls)
    pub fee_per_exec_unit: u64,
    /// Fee per state read operation
    pub fee_per_state_read: u64,
    /// Fee per state write operation
    pub fee_per_state_write: u64,
    /// Fee per byte written to state
    pub fee_per_state_write_byte: u64,
    /// Fee per signature verification
    pub fee_per_signature: u64,
    /// Minimum fee for any transaction
    pub minimum_fee: u64,
    /// Maximum fee (sanity cap)
    pub maximum_fee: u64,
}

impl Default for FeeParams {
    fn default() -> Self {
        Self {
            base_fee_per_byte: 1,
            fee_per_exec_unit: 10,
            fee_per_state_read: 100,
            fee_per_state_write: 500,
            fee_per_state_write_byte: 10,
            fee_per_signature: 1_000,
            minimum_fee: 1_000,
            maximum_fee: 1_000_000_000,  // 1 billion units max
        }
    }
}

impl FeeParams {
    /// Create params for testing (lower fees)
    pub fn for_testing() -> Self {
        Self {
            base_fee_per_byte: 1,
            fee_per_exec_unit: 1,
            fee_per_state_read: 1,
            fee_per_state_write: 1,
            fee_per_state_write_byte: 1,
            fee_per_signature: 1,
            minimum_fee: 0,
            maximum_fee: u64::MAX,
        }
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
    let exec_fee: u128 = (input.exec_units as u128)
        .saturating_mul(params.fee_per_exec_unit as u128);

    // 4. State access fee
    let state_read_fee: u128 = (input.state_reads as u128)
        .saturating_mul(params.fee_per_state_read as u128);
    let state_write_fee: u128 = (input.state_writes as u128)
        .saturating_mul(params.fee_per_state_write as u128);
    let state_write_byte_fee: u128 = (input.state_write_bytes as u128)
        .saturating_mul(params.fee_per_state_write_byte as u128);
    let state_fee: u128 = state_read_fee
        .saturating_add(state_write_fee)
        .saturating_add(state_write_byte_fee);

    // 5. Signature fee (includes scheme multiplier)
    let sig_base_fee: u128 = (input.sig_count as u128)
        .saturating_mul(params.fee_per_signature as u128);
    let sig_multiplier: u128 = input.sig_scheme.size_multiplier_bps() as u128;
    // sig_fee = sig_base_fee * multiplier / 10000
    let sig_fee: u128 = sig_base_fee.saturating_mul(sig_multiplier) / 10_000;

    // 6. Base fee (sum of all components)
    let base_fee: u128 = byte_fee
        .saturating_add(exec_fee)
        .saturating_add(state_fee)
        .saturating_add(sig_fee);

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

/// Error returned when transaction fee is insufficient
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeDeficit {
    /// Required fee
    pub required: u64,
    /// Fee actually paid
    pub paid: u64,
    /// Shortfall amount
    pub deficit: u64,
}

impl std::fmt::Display for FeeDeficit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Insufficient fee: paid {} but required {} (deficit: {})",
            self.paid, self.required, self.deficit
        )
    }
}

impl std::error::Error for FeeDeficit {}

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
}
