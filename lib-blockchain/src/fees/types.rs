//! Fee Model v2 Types
//!
//! Defines the core types for deterministic fee calculation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Transaction kind for fee calculation
///
/// Each kind has different execution cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TxKind {
    /// Native UTXO transfer
    NativeTransfer,
    /// Token balance transfer
    TokenTransfer,
    /// Smart contract execution
    ContractCall,
    /// Data upload to chain
    DataUpload,
    /// Governance operation (proposals, votes)
    Governance,
    /// Staking operation (stake, unstake, delegate)
    Staking,
}

/// Signature scheme for fee calculation
///
/// Different schemes have different verification costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SigScheme {
    /// Ed25519 (classical, fast)
    Ed25519,
    /// Dilithium5 (post-quantum, larger signatures)
    Dilithium5,
    /// Hybrid (Ed25519 + Dilithium5)
    Hybrid,
}

/// Input to the fee calculation function
///
/// Contains all transaction metrics needed to compute minimum fee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeInput {
    /// Transaction kind
    pub tx_kind: TxKind,
    /// Signature scheme used
    pub sig_scheme: SigScheme,
    /// Number of signatures
    pub sig_count: u8,
    /// Fixed envelope bytes (header, type tags)
    pub envelope_bytes: u32,
    /// Payload bytes (inputs, outputs, amounts, data)
    pub payload_bytes: u32,
    /// Witness bytes (signatures, public keys, ZK proofs)
    pub witness_bytes: u32,
    /// Number of state read operations
    pub state_reads: u16,
    /// Number of state write operations
    pub state_writes: u16,
    /// Total bytes written to state
    pub state_write_bytes: u32,
}

impl FeeInput {
    /// Create a new FeeInput
    pub fn new(
        tx_kind: TxKind,
        sig_scheme: SigScheme,
        sig_count: u8,
        envelope_bytes: u32,
        payload_bytes: u32,
        witness_bytes: u32,
        state_reads: u16,
        state_writes: u16,
        state_write_bytes: u32,
    ) -> Self {
        Self {
            tx_kind,
            sig_scheme,
            sig_count,
            envelope_bytes,
            payload_bytes,
            witness_bytes,
            state_reads,
            state_writes,
            state_write_bytes,
        }
    }
}

/// Fee parameters for Fee Model v2
///
/// Contains all pricing and limit parameters for deterministic fee calculation.
/// All prices are in the smallest unit (micro-tokens).
#[derive(Debug, Clone)]
pub struct FeeParamsV2 {
    // =========================================================================
    // Base Costs
    // =========================================================================

    /// Base fee for any transaction (fixed overhead)
    pub base_tx_fee: u64,

    // =========================================================================
    // Unit Prices
    // =========================================================================

    /// Price per execution unit
    pub price_exec_unit: u64,
    /// Price per state read operation
    pub price_state_read: u64,
    /// Price per state write operation
    pub price_state_write: u64,
    /// Price per byte written to state
    pub price_state_write_byte: u64,
    /// Price per payload byte
    pub price_payload_byte: u64,
    /// Witness byte price numerator (rational pricing: numer/denom)
    pub price_witness_byte_numer: u64,
    /// Witness byte price denominator (rational pricing: numer/denom)
    pub price_witness_byte_denom: u64,
    /// Price per verification unit
    pub price_verify_unit: u64,

    // =========================================================================
    // Per-TxKind Parameters
    // =========================================================================

    /// Execution units per transaction kind
    pub exec_units: HashMap<TxKind, u32>,
    /// Witness cap (charged) bytes per transaction kind
    pub witness_cap_bytes: HashMap<TxKind, u32>,
    /// Maximum witness bytes per transaction kind
    pub max_witness_bytes: HashMap<TxKind, u32>,
    /// Maximum signatures per transaction kind
    pub max_sigs: HashMap<TxKind, u16>,

    // =========================================================================
    // Per-SigScheme Parameters
    // =========================================================================

    /// Verification units per signature for each scheme
    pub verify_units_per_sig: HashMap<SigScheme, u32>,

    // =========================================================================
    // Block Limits
    // =========================================================================

    /// Maximum payload bytes per block
    pub block_max_payload_bytes: u32,
    /// Maximum witness bytes per block
    pub block_max_witness_bytes: u32,
    /// Maximum verification units per block
    pub block_max_verify_units: u32,
    /// Maximum state write bytes per block
    pub block_max_state_write_bytes: u32,
    /// Maximum transactions per block
    pub block_max_txs: u32,
}

impl FeeParamsV2 {
    /// Get execution units for a transaction kind
    pub fn get_exec_units(&self, kind: TxKind) -> u32 {
        self.exec_units.get(&kind).copied().unwrap_or(10) // Default 10 if not specified
    }

    /// Get witness cap bytes for a transaction kind
    pub fn get_witness_cap_bytes(&self, kind: TxKind) -> u32 {
        self.witness_cap_bytes.get(&kind).copied().unwrap_or(1_536) // Default 1.5KB
    }

    /// Get maximum witness bytes for a transaction kind
    pub fn get_max_witness_bytes(&self, kind: TxKind) -> u32 {
        self.max_witness_bytes.get(&kind).copied().unwrap_or(16_384) // Default 16KB
    }

    /// Get maximum signatures for a transaction kind
    pub fn get_max_sigs(&self, kind: TxKind) -> u16 {
        self.max_sigs.get(&kind).copied().unwrap_or(2) // Default 2
    }

    /// Get verification units per signature for a scheme
    pub fn get_verify_units_per_sig(&self, scheme: SigScheme) -> u32 {
        self.verify_units_per_sig.get(&scheme).copied().unwrap_or(match scheme {
            SigScheme::Ed25519 => 1,
            SigScheme::Dilithium5 => 4,
            SigScheme::Hybrid => 5,
        })
    }
}

impl Default for FeeParamsV2 {
    /// Default parameters for Phase 2
    ///
    /// These are conservative defaults. Production values should be
    /// tuned based on actual resource costs.
    fn default() -> Self {
        let mut exec_units = HashMap::new();
        exec_units.insert(TxKind::NativeTransfer, 5);
        exec_units.insert(TxKind::TokenTransfer, 3);
        exec_units.insert(TxKind::ContractCall, 100);
        exec_units.insert(TxKind::DataUpload, 10);
        exec_units.insert(TxKind::Governance, 20);
        exec_units.insert(TxKind::Staking, 15);

        let mut witness_cap_bytes = HashMap::new();
        witness_cap_bytes.insert(TxKind::NativeTransfer, 1_536);
        witness_cap_bytes.insert(TxKind::TokenTransfer, 1_536);
        witness_cap_bytes.insert(TxKind::ContractCall, 4_096);
        witness_cap_bytes.insert(TxKind::DataUpload, 1_024);
        witness_cap_bytes.insert(TxKind::Governance, 2_048);
        witness_cap_bytes.insert(TxKind::Staking, 1_536);

        let mut max_witness_bytes = HashMap::new();
        max_witness_bytes.insert(TxKind::NativeTransfer, 16_384);
        max_witness_bytes.insert(TxKind::TokenTransfer, 16_384);
        max_witness_bytes.insert(TxKind::ContractCall, 65_536);
        max_witness_bytes.insert(TxKind::DataUpload, 8_192);
        max_witness_bytes.insert(TxKind::Governance, 32_768);
        max_witness_bytes.insert(TxKind::Staking, 16_384);

        let mut max_sigs = HashMap::new();
        max_sigs.insert(TxKind::NativeTransfer, 2);
        max_sigs.insert(TxKind::TokenTransfer, 1);
        max_sigs.insert(TxKind::ContractCall, 4);
        max_sigs.insert(TxKind::DataUpload, 1);
        max_sigs.insert(TxKind::Governance, 8);
        max_sigs.insert(TxKind::Staking, 2);

        let mut verify_units_per_sig = HashMap::new();
        verify_units_per_sig.insert(SigScheme::Ed25519, 1);
        verify_units_per_sig.insert(SigScheme::Dilithium5, 4);
        verify_units_per_sig.insert(SigScheme::Hybrid, 5);

        Self {
            // Base fee: 100 micro-tokens
            base_tx_fee: 100,

            // Unit prices (micro-tokens)
            price_exec_unit: 10,
            price_state_read: 5,
            price_state_write: 20,
            price_state_write_byte: 1,
            price_payload_byte: 1,
            // Rational witness pricing: 1/2 micro-token per byte (rounded up)
            price_witness_byte_numer: 1,
            price_witness_byte_denom: 2,
            price_verify_unit: 50,

            // Per-kind parameters
            exec_units,
            witness_cap_bytes,
            max_witness_bytes,
            max_sigs,

            // Per-scheme parameters
            verify_units_per_sig,

            // Block limits
            block_max_payload_bytes: 1_000_000,      // 1 MB
            block_max_witness_bytes: 2_000_000,      // 2 MB
            block_max_verify_units: 10_000,          // ~2000 Ed25519 or ~500 Dilithium5
            block_max_state_write_bytes: 500_000,    // 500 KB
            block_max_txs: 5_000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx_kind_values() {
        assert_ne!(TxKind::NativeTransfer, TxKind::TokenTransfer);
        assert_ne!(TxKind::ContractCall, TxKind::DataUpload);
    }

    #[test]
    fn test_sig_scheme_values() {
        assert_ne!(SigScheme::Ed25519, SigScheme::Dilithium5);
        assert_ne!(SigScheme::Dilithium5, SigScheme::Hybrid);
    }

    #[test]
    fn test_fee_params_default() {
        let params = FeeParamsV2::default();

        // Check base fee
        assert_eq!(params.base_tx_fee, 100);

        // Check exec units for NativeTransfer
        assert_eq!(params.get_exec_units(TxKind::NativeTransfer), 5);

        // Check verify units
        assert_eq!(params.get_verify_units_per_sig(SigScheme::Ed25519), 1);
        assert_eq!(params.get_verify_units_per_sig(SigScheme::Dilithium5), 4);

        // Check witness caps
        assert_eq!(params.get_witness_cap_bytes(TxKind::NativeTransfer), 1_536);
    }

    #[test]
    fn test_fee_input_creation() {
        let input = FeeInput::new(
            TxKind::NativeTransfer,
            SigScheme::Ed25519,
            1,    // sig_count
            50,   // envelope_bytes
            200,  // payload_bytes
            64,   // witness_bytes
            2,    // state_reads
            4,    // state_writes
            256,  // state_write_bytes
        );

        assert_eq!(input.tx_kind, TxKind::NativeTransfer);
        assert_eq!(input.sig_count, 1);
        assert_eq!(input.payload_bytes, 200);
    }
}
