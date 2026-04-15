//! Fee primitives for the Sovereign Network.
//!
//! Pure data types for fee calculation. Behavior (computation logic) lives in lib-fees.
//!
//! Rule: These types must remain behavior-free and serialization-stable.

use serde::{Deserialize, Serialize};

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
    /// Staking (delegation)
    Staking = 5,
    /// Unstaking (withdrawal)
    Unstaking = 6,
    /// Validator registration
    ValidatorRegistration = 7,
    /// Validator exit
    ValidatorExit = 8,
}

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
    /// ZK proof verification units (derived from benchmarked verifier latency)
    #[serde(default)]
    pub zk_verify_units: u32,
}

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
    /// Fee per ZK proof verification unit
    pub fee_per_zk_verify_unit: u64,
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
            fee_per_zk_verify_unit: 0,
            minimum_fee: 1_000,
            maximum_fee: 1_000_000_000, // 1 billion units max
        }
    }
}

/// Validation errors for FeeParams
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeeParamsError {
    /// Minimum fee exceeds maximum fee
    MinExceedsMax { min: u64, max: u64 },
    /// Base fee per byte is zero
    ZeroBaseFeePerByte,
    /// Fee per state read is zero
    ZeroFeePerStateRead,
    /// Fee per state write is zero
    ZeroFeePerStateWrite,
    /// Fee per signature is zero
    ZeroFeePerSignature,
    /// Fee per execution unit is zero
    ZeroFeePerExecUnit,
}

impl std::fmt::Display for FeeParamsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeeParamsError::MinExceedsMax { min, max } => {
                write!(f, "minimum_fee ({}) exceeds maximum_fee ({})", min, max)
            }
            FeeParamsError::ZeroBaseFeePerByte => write!(f, "base_fee_per_byte must be > 0"),
            FeeParamsError::ZeroFeePerStateRead => write!(f, "fee_per_state_read must be > 0"),
            FeeParamsError::ZeroFeePerStateWrite => write!(f, "fee_per_state_write must be > 0"),
            FeeParamsError::ZeroFeePerSignature => write!(f, "fee_per_signature must be > 0"),
            FeeParamsError::ZeroFeePerExecUnit => write!(f, "fee_per_exec_unit must be > 0"),
        }
    }
}

impl std::error::Error for FeeParamsError {}

impl FeeParams {
    /// Create params for testing with realistic values
    ///
    /// These values are lower than production but still maintain
    /// realistic ratios between different fee components.
    pub fn for_testing() -> Self {
        Self {
            base_fee_per_byte: 1,
            fee_per_exec_unit: 10,
            fee_per_state_read: 100,
            fee_per_state_write: 500,
            fee_per_state_write_byte: 10,
            fee_per_signature: 1_000,
            fee_per_zk_verify_unit: 0,
            minimum_fee: 1_000,
            maximum_fee: 100_000_000,
        }
    }

    /// Validate fee parameters for consistency
    ///
    /// # Checks performed
    /// - minimum_fee < maximum_fee
    /// - All fee rates are non-zero (prevents free operations)
    pub fn validate(&self) -> Result<(), FeeParamsError> {
        if self.minimum_fee > self.maximum_fee {
            return Err(FeeParamsError::MinExceedsMax {
                min: self.minimum_fee,
                max: self.maximum_fee,
            });
        }
        if self.base_fee_per_byte == 0 {
            return Err(FeeParamsError::ZeroBaseFeePerByte);
        }
        if self.fee_per_state_read == 0 {
            return Err(FeeParamsError::ZeroFeePerStateRead);
        }
        if self.fee_per_state_write == 0 {
            return Err(FeeParamsError::ZeroFeePerStateWrite);
        }
        if self.fee_per_signature == 0 {
            return Err(FeeParamsError::ZeroFeePerSignature);
        }
        if self.fee_per_exec_unit == 0 {
            return Err(FeeParamsError::ZeroFeePerExecUnit);
        }
        // fee_per_zk_verify_unit is u64 so cannot be negative; no explicit check needed
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx_kind_variants() {
        // Verify discriminant values are stable
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
    fn test_sig_scheme_variants() {
        // Verify discriminant values are stable
        assert_eq!(SigScheme::Ed25519 as u8, 0);
        assert_eq!(SigScheme::Dilithium5 as u8, 1);
        assert_eq!(SigScheme::Hybrid as u8, 2);
    }

    #[test]
    fn test_fee_params_default() {
        let params = FeeParams::default();
        assert_eq!(params.base_fee_per_byte, 1);
        assert_eq!(params.fee_per_exec_unit, 10);
        assert_eq!(params.minimum_fee, 1_000);
        assert_eq!(params.maximum_fee, 1_000_000_000);
    }

    #[test]
    fn test_fee_params_for_testing() {
        let params = FeeParams::for_testing();
        // Updated for realistic testing values (FEES-11)
        assert_eq!(params.minimum_fee, 1_000);
        assert_eq!(params.maximum_fee, 100_000_000);
        assert_eq!(params.base_fee_per_byte, 1);
        assert_eq!(params.fee_per_exec_unit, 10);
        assert_eq!(params.fee_per_state_read, 100);
        assert_eq!(params.fee_per_state_write, 500);
        assert_eq!(params.fee_per_signature, 1_000);
        assert_eq!(params.fee_per_zk_verify_unit, 0);
    }

    #[test]
    fn test_fee_deficit_display() {
        let deficit = FeeDeficit {
            required: 1000,
            paid: 500,
            deficit: 500,
        };
        let msg = format!("{}", deficit);
        assert!(msg.contains("1000"));
        assert!(msg.contains("500"));
    }

    #[test]
    fn test_fee_params_validation_success() {
        let params = FeeParams::default();
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_fee_params_validation_min_exceeds_max() {
        let params = FeeParams {
            minimum_fee: 1000,
            maximum_fee: 500,
            ..FeeParams::default()
        };
        let err = params.validate().unwrap_err();
        assert!(matches!(
            err,
            FeeParamsError::MinExceedsMax {
                min: 1000,
                max: 500
            }
        ));
    }

    #[test]
    fn test_fee_params_validation_zero_base_fee() {
        let params = FeeParams {
            base_fee_per_byte: 0,
            ..FeeParams::default()
        };
        let err = params.validate().unwrap_err();
        assert!(matches!(err, FeeParamsError::ZeroBaseFeePerByte));
    }

    #[test]
    fn test_fee_params_validation_zero_state_read() {
        let params = FeeParams {
            fee_per_state_read: 0,
            ..FeeParams::default()
        };
        let err = params.validate().unwrap_err();
        assert!(matches!(err, FeeParamsError::ZeroFeePerStateRead));
    }

    #[test]
    fn test_fee_params_validation_zero_state_write() {
        let params = FeeParams {
            fee_per_state_write: 0,
            ..FeeParams::default()
        };
        let err = params.validate().unwrap_err();
        assert!(matches!(err, FeeParamsError::ZeroFeePerStateWrite));
    }

    #[test]
    fn test_fee_params_validation_zero_signature() {
        let params = FeeParams {
            fee_per_signature: 0,
            ..FeeParams::default()
        };
        let err = params.validate().unwrap_err();
        assert!(matches!(err, FeeParamsError::ZeroFeePerSignature));
    }

    #[test]
    fn test_fee_params_validation_zero_exec_unit() {
        let params = FeeParams {
            fee_per_exec_unit: 0,
            ..FeeParams::default()
        };
        let err = params.validate().unwrap_err();
        assert!(matches!(err, FeeParamsError::ZeroFeePerExecUnit));
    }

    #[test]
    fn test_fee_input_serialization_roundtrip() {
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
            zk_verify_units: 0,
        };

        let json = serde_json::to_string(&input).unwrap();
        let deserialized: FeeInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, deserialized);
    }

    #[test]
    fn test_fee_params_serialization_roundtrip() {
        let params = FeeParams::default();
        let json = serde_json::to_string(&params).unwrap();
        let deserialized: FeeParams = serde_json::from_str(&json).unwrap();
        assert_eq!(params, deserialized);
    }
}
