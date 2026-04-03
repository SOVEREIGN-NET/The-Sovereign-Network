//! Mempool types for ZHTP
//!
//! Pure data types for mempool configuration, state tracking, and admission.
//! Behavior (admission logic, transaction ordering) lives in lib-mempool.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::fees::{SigScheme, TxKind};
use crate::{Address, Amount};

// =============================================================================
// CONFIGURATION
// =============================================================================

/// Configuration for mempool admission checks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolConfig {
    // =========================================================================
    // Size Limits
    // =========================================================================
    /// Maximum total mempool size in bytes
    pub max_mempool_bytes: u64,
    /// Maximum number of transactions in mempool
    pub max_tx_count: u32,
    /// Maximum transactions per sender address
    pub max_per_sender: u32,

    // =========================================================================
    // Transaction Limits
    // =========================================================================
    /// Maximum transaction size in bytes
    pub max_tx_bytes: u32,
    /// Maximum witness size per transaction in bytes
    pub max_witness_bytes: u32,
    /// Maximum number of signatures per transaction
    pub max_signatures: u8,
    /// Maximum number of inputs per transaction
    pub max_inputs: u16,
    /// Maximum number of outputs per transaction
    pub max_outputs: u16,

    // =========================================================================
    // Fee Thresholds
    // =========================================================================
    /// Minimum fee multiplier (1.0 = exact minimum, 1.1 = 10% above)
    /// Stored as basis points: 10000 = 1.0x, 11000 = 1.1x
    pub min_fee_multiplier_bps: u16,

    // =========================================================================
    // Rate Limiting
    // =========================================================================
    /// Maximum transactions per sender per block period
    pub max_per_sender_per_period: u32,
    /// Rate limit period in blocks
    pub rate_limit_period_blocks: u32,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            // Size limits (preserving original lib-mempool defaults)
            max_mempool_bytes: 50 * 1024 * 1024, // 50 MB
            max_tx_count: 50_000,
            max_per_sender: 100,

            // Transaction limits (preserving original lib-mempool defaults)
            max_tx_bytes: 100_000,     // 100 KB
            max_witness_bytes: 50_000, // 50 KB
            max_signatures: 16,
            max_inputs: 256,
            max_outputs: 256,

            // Fee threshold: 1.0x minimum
            min_fee_multiplier_bps: 10_000,

            // Rate limiting
            max_per_sender_per_period: 10,
            rate_limit_period_blocks: 10,
        }
    }
}

// =============================================================================
// STATE
// =============================================================================

/// Current state of the mempool for admission checks
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MempoolState {
    /// Current total bytes in mempool
    pub total_bytes: u64,
    /// Current transaction count
    pub tx_count: u32,
    /// Transactions per sender address
    pub per_sender: HashMap<Address, SenderState>,
}

impl MempoolState {
    /// Create empty mempool state
    pub fn new() -> Self {
        Self::default()
    }
}

/// Per-sender state tracking
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SenderState {
    /// Number of pending transactions from this sender
    pub pending_count: u32,
    /// Total bytes from this sender
    pub total_bytes: u64,
    /// Transactions in current rate limit period
    pub period_count: u32,
    /// Block height when period started
    pub period_start_block: u64,
}

// =============================================================================
// ADMISSION
// =============================================================================

/// Result of admission check
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmitResult {
    /// Transaction accepted into mempool
    Accepted,
    /// Transaction rejected with reason
    Rejected(AdmitErrorKind),
}

/// Specific reason for admission rejection
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmitErrorKind {
    // Fee errors
    InsufficientFee {
        required: Amount,
        provided: Amount,
    },

    // Size errors
    TxTooLarge {
        size: u32,
        max: u32,
    },
    WitnessTooLarge {
        size: u32,
        max: u32,
    },
    TooManyInputs {
        count: u16,
        max: u16,
    },
    TooManyOutputs {
        count: u16,
        max: u16,
    },
    TooManySignatures {
        count: u8,
        max: u8,
    },

    // Mempool capacity errors
    MempoolFull,
    MempoolBytesFull {
        prospective_total_bytes: u64,
        max: u64,
    },
    SenderLimitReached {
        sender: Address,
        count: u32,
        max: u32,
    },
    RateLimited {
        sender: Address,
        period_count: u32,
        max: u32,
    },

    // Validation errors
    InvalidTransaction(String),
    DuplicateTransaction,
}

/// Transaction data needed for admission checks
///
/// This is a simplified view of a transaction for admission purposes.
/// The actual Transaction type lives in lib-blockchain.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mempool_config_default() {
        let config = MempoolConfig::default();
        // Original lib-mempool defaults (preserved during type move)
        assert_eq!(config.max_mempool_bytes, 50 * 1024 * 1024); // 50 MB
        assert_eq!(config.max_tx_count, 50_000);
        assert_eq!(config.max_per_sender, 100);
        assert_eq!(config.max_witness_bytes, 50_000);
        assert_eq!(config.max_signatures, 16);
        assert_eq!(config.max_inputs, 256);
        assert_eq!(config.max_outputs, 256);
        assert_eq!(config.min_fee_multiplier_bps, 10_000);
    }

    #[test]
    fn test_mempool_config_serialization_roundtrip() {
        let config = MempoolConfig::default();
        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: MempoolConfig = serde_json::from_str(&serialized).unwrap();
        assert_eq!(config.max_mempool_bytes, deserialized.max_mempool_bytes);
        assert_eq!(config.max_tx_count, deserialized.max_tx_count);
        assert_eq!(
            config.min_fee_multiplier_bps,
            deserialized.min_fee_multiplier_bps
        );
    }

    #[test]
    fn test_mempool_state_default() {
        let state = MempoolState::default();
        assert_eq!(state.total_bytes, 0);
        assert_eq!(state.tx_count, 0);
        assert!(state.per_sender.is_empty());
    }

    #[test]
    fn test_mempool_state_serialization_roundtrip() {
        // Test with bincode since Address as HashMap key doesn't serialize to JSON
        let mut state = MempoolState::new();
        state.total_bytes = 1000;
        state.tx_count = 10;
        state.per_sender.insert(
            Address::default(),
            SenderState {
                pending_count: 1,
                total_bytes: 100,
                period_count: 0,
                period_start_block: 0,
            },
        );

        let serialized = bincode::serialize(&state).unwrap();
        let deserialized: MempoolState = bincode::deserialize(&serialized).unwrap();
        assert_eq!(state.total_bytes, deserialized.total_bytes);
        assert_eq!(state.tx_count, deserialized.tx_count);
        assert_eq!(state.per_sender.len(), deserialized.per_sender.len());
    }

    #[test]
    fn test_sender_state_default() {
        let state = SenderState::default();
        assert_eq!(state.pending_count, 0);
        assert_eq!(state.total_bytes, 0);
        assert_eq!(state.period_count, 0);
        assert_eq!(state.period_start_block, 0);
    }

    #[test]
    fn test_admit_result_variants() {
        assert_eq!(AdmitResult::Accepted, AdmitResult::Accepted);
        assert_ne!(
            AdmitResult::Accepted,
            AdmitResult::Rejected(AdmitErrorKind::MempoolFull)
        );

        let err = AdmitErrorKind::InsufficientFee {
            required: 100,
            provided: 50,
        };
        assert_eq!(
            AdmitResult::Rejected(err.clone()),
            AdmitResult::Rejected(err)
        );
    }

    #[test]
    fn test_admit_error_kind_variants() {
        let fee_err = AdmitErrorKind::InsufficientFee {
            required: 100,
            provided: 50,
        };
        assert!(matches!(fee_err, AdmitErrorKind::InsufficientFee { .. }));

        let size_err = AdmitErrorKind::TxTooLarge {
            size: 200_000,
            max: 100_000,
        };
        assert!(matches!(size_err, AdmitErrorKind::TxTooLarge { .. }));

        let rate_err = AdmitErrorKind::RateLimited {
            sender: Address::default(),
            period_count: 15,
            max: 10,
        };
        assert!(matches!(rate_err, AdmitErrorKind::RateLimited { .. }));
    }

    #[test]
    fn test_admit_error_kind_serialization_roundtrip() {
        let kinds = vec![
            AdmitErrorKind::MempoolFull,
            AdmitErrorKind::DuplicateTransaction,
            AdmitErrorKind::InvalidTransaction("test".to_string()),
            AdmitErrorKind::TxTooLarge { size: 100, max: 50 },
            AdmitErrorKind::InsufficientFee {
                required: 100,
                provided: 50,
            },
            AdmitErrorKind::SenderLimitReached {
                sender: Address::default(),
                count: 10,
                max: 5,
            },
        ];

        for kind in kinds {
            let serialized = serde_json::to_string(&kind).unwrap();
            let deserialized: AdmitErrorKind = serde_json::from_str(&serialized).unwrap();
            assert_eq!(kind, deserialized);
        }
    }

    #[test]
    fn test_admit_tx_creation() {
        let tx = AdmitTx {
            fee: 1000,
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
        };

        assert_eq!(tx.fee, 1000);
        assert_eq!(tx.input_count, 2);
        assert_eq!(tx.output_count, 2);
    }

    #[test]
    fn test_admit_tx_serialization_roundtrip() {
        let tx = AdmitTx {
            fee: 1000,
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
        };

        let serialized = serde_json::to_string(&tx).unwrap();
        let deserialized: AdmitTx = serde_json::from_str(&serialized).unwrap();
        assert_eq!(tx.fee, deserialized.fee);
        assert_eq!(tx.tx_bytes, deserialized.tx_bytes);
        assert_eq!(tx.tx_kind, deserialized.tx_kind);
        assert_eq!(tx.sig_scheme, deserialized.sig_scheme);
    }
}
