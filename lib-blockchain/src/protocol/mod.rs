//! Protocol Parameters Module (Phase 3B/3C)
//!
//! Defines consensus-critical protocol parameters that govern blockchain behavior.
//! These parameters are set at genesis and can be updated through governance.
//!
//! # Fee Model Versioning (Phase 3B)
//!
//! The fee model version determines which fee calculation rules apply to a block:
//!
//! - **Version 1**: Legacy fee model (simple per-byte fees)
//! - **Version 2**: Fee Model v2 (detailed computation with exec units, witness caps, etc.)
//!
//! Activation is controlled by `fee_model_active_from_height_v2`:
//! - At heights < activation: version 1 required, version 2 forbidden
//! - At heights >= activation: version 2 required, version 1 forbidden
//!
//! # Fee Distribution (Phase 3C)
//!
//! All network fees are accumulated per block into a deterministic sink address.
//! The coinbase transaction includes:
//! - Block reward output (if any)
//! - Fees collected output to `fee_sink_address`
//!
//! Invariant: sum(inputs) - sum(outputs excluding coinbase) == fees_collected
//!
//! # Design Principles
//!
//! 1. **Deterministic**: All nodes compute the same active version for any height
//! 2. **No mixing**: A block cannot use a version that is not active at its height
//! 3. **Forward-only**: Activation heights cannot decrease once set
//! 4. **Genesis-defined**: Initial parameters are set in genesis state

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::storage::Address;

/// Fee model version constants
pub mod fee_model {
    /// Legacy fee model (Phase 1/pre-Phase 2)
    pub const VERSION_1: u16 = 1;
    /// Fee Model v2 (Phase 2+)
    pub const VERSION_2: u16 = 2;
}

/// Errors related to protocol parameters
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ProtocolError {
    /// Fee model version is not valid for the block height
    #[error("Invalid fee model version {version} at height {height}: expected {expected}")]
    InvalidFeeModelVersion {
        height: u64,
        version: u16,
        expected: u16,
    },

    /// Protocol parameters not initialized
    #[error("Protocol parameters not initialized")]
    NotInitialized,
}

pub type ProtocolResult<T> = Result<T, ProtocolError>;

/// Protocol parameters stored in consensus state
///
/// These parameters are set at genesis and can be updated through governance.
/// They are deterministic - all nodes will compute the same values for any height.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolParams {
    /// Height at which Fee Model v2 becomes active.
    ///
    /// - For heights < this value: version 1 required
    /// - For heights >= this value: version 2 required
    ///
    /// Set to 0 for chains that start with v2 (Phase 2+).
    pub fee_model_active_from_height_v2: u64,

    /// Deterministic sink address for all network fees (Phase 3C).
    ///
    /// All transaction fees collected in a block are sent to this address
    /// as part of the coinbase transaction. This ensures deterministic
    /// fee routing that all nodes can verify.
    #[serde(default = "default_fee_sink_address")]
    pub fee_sink_address: Address,
}

/// Default fee sink address (all zeros - must be set in genesis for production)
fn default_fee_sink_address() -> Address {
    Address::new([0u8; 32])
}

impl Default for ProtocolParams {
    fn default() -> Self {
        Self {
            // Default: Fee Model v2 active from genesis (Phase 2+)
            fee_model_active_from_height_v2: 0,
            fee_sink_address: default_fee_sink_address(),
        }
    }
}

impl ProtocolParams {
    /// Create new protocol params with v2 active from genesis
    pub fn new_v2_from_genesis() -> Self {
        Self {
            fee_model_active_from_height_v2: 0,
            fee_sink_address: default_fee_sink_address(),
        }
    }

    /// Create new protocol params with v2 activation at a specific height
    pub fn new_with_v2_activation(activation_height: u64) -> Self {
        Self {
            fee_model_active_from_height_v2: activation_height,
            fee_sink_address: default_fee_sink_address(),
        }
    }

    /// Create new protocol params with custom fee sink address
    pub fn with_fee_sink(mut self, fee_sink_address: Address) -> Self {
        self.fee_sink_address = fee_sink_address;
        self
    }

    /// Get the fee sink address
    pub fn fee_sink_address(&self) -> &Address {
        &self.fee_sink_address
    }

    /// Get the required fee model version for a given block height.
    ///
    /// This is the canonical source for fee model version selection.
    /// All nodes MUST use this function to determine which version applies.
    ///
    /// # Returns
    /// - `VERSION_1` if height < fee_model_active_from_height_v2
    /// - `VERSION_2` if height >= fee_model_active_from_height_v2
    pub fn active_fee_model_version(&self, height: u64) -> u16 {
        if height < self.fee_model_active_from_height_v2 {
            fee_model::VERSION_1
        } else {
            fee_model::VERSION_2
        }
    }

    /// Validate that a block's fee model version is correct for its height.
    ///
    /// # Arguments
    /// * `height` - The block height
    /// * `version` - The fee_model_version from the block header
    ///
    /// # Returns
    /// * `Ok(())` if the version is valid for the height
    /// * `Err(InvalidFeeModelVersion)` if the version is wrong
    pub fn validate_fee_model_version(&self, height: u64, version: u16) -> ProtocolResult<()> {
        let expected = self.active_fee_model_version(height);
        if version != expected {
            return Err(ProtocolError::InvalidFeeModelVersion {
                height,
                version,
                expected,
            });
        }
        Ok(())
    }

    /// Check if Fee Model v2 is active at a given height
    pub fn is_v2_active(&self, height: u64) -> bool {
        height >= self.fee_model_active_from_height_v2
    }
}

// =============================================================================
// Storage Key
// =============================================================================

/// Storage key for protocol parameters
pub const PROTOCOL_PARAMS_KEY: &[u8] = b"protocol:params";

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_v2_from_genesis() {
        let params = ProtocolParams::default();

        // v2 active from height 0
        assert_eq!(params.active_fee_model_version(0), fee_model::VERSION_2);
        assert_eq!(params.active_fee_model_version(100), fee_model::VERSION_2);
        assert_eq!(params.active_fee_model_version(u64::MAX), fee_model::VERSION_2);
    }

    #[test]
    fn test_v2_activation_at_height() {
        let params = ProtocolParams::new_with_v2_activation(100);

        // Before activation: v1 required
        assert_eq!(params.active_fee_model_version(0), fee_model::VERSION_1);
        assert_eq!(params.active_fee_model_version(99), fee_model::VERSION_1);

        // At and after activation: v2 required
        assert_eq!(params.active_fee_model_version(100), fee_model::VERSION_2);
        assert_eq!(params.active_fee_model_version(101), fee_model::VERSION_2);
        assert_eq!(params.active_fee_model_version(1000), fee_model::VERSION_2);
    }

    #[test]
    fn test_validate_version_before_activation() {
        let params = ProtocolParams::new_with_v2_activation(100);

        // Height 99: v1 accepted, v2 rejected
        assert!(params.validate_fee_model_version(99, fee_model::VERSION_1).is_ok());
        assert!(matches!(
            params.validate_fee_model_version(99, fee_model::VERSION_2),
            Err(ProtocolError::InvalidFeeModelVersion { height: 99, version: 2, expected: 1 })
        ));
    }

    #[test]
    fn test_validate_version_at_activation() {
        let params = ProtocolParams::new_with_v2_activation(100);

        // Height 100: v2 accepted, v1 rejected
        assert!(params.validate_fee_model_version(100, fee_model::VERSION_2).is_ok());
        assert!(matches!(
            params.validate_fee_model_version(100, fee_model::VERSION_1),
            Err(ProtocolError::InvalidFeeModelVersion { height: 100, version: 1, expected: 2 })
        ));
    }

    #[test]
    fn test_validate_version_after_activation() {
        let params = ProtocolParams::new_with_v2_activation(100);

        // Height 101: v2 accepted, v1 rejected
        assert!(params.validate_fee_model_version(101, fee_model::VERSION_2).is_ok());
        assert!(matches!(
            params.validate_fee_model_version(101, fee_model::VERSION_1),
            Err(ProtocolError::InvalidFeeModelVersion { height: 101, version: 1, expected: 2 })
        ));
    }

    #[test]
    fn test_is_v2_active() {
        let params = ProtocolParams::new_with_v2_activation(100);

        assert!(!params.is_v2_active(0));
        assert!(!params.is_v2_active(99));
        assert!(params.is_v2_active(100));
        assert!(params.is_v2_active(101));
    }

    #[test]
    fn test_boundary_height_zero() {
        // Activation at height 0 means v2 always active
        let params = ProtocolParams::new_with_v2_activation(0);

        assert_eq!(params.active_fee_model_version(0), fee_model::VERSION_2);
        assert!(params.validate_fee_model_version(0, fee_model::VERSION_2).is_ok());
        assert!(params.validate_fee_model_version(0, fee_model::VERSION_1).is_err());
    }

    #[test]
    fn test_boundary_max_height() {
        // Activation at u64::MAX means v1 always active (except at max)
        let params = ProtocolParams::new_with_v2_activation(u64::MAX);

        assert_eq!(params.active_fee_model_version(0), fee_model::VERSION_1);
        assert_eq!(params.active_fee_model_version(u64::MAX - 1), fee_model::VERSION_1);
        assert_eq!(params.active_fee_model_version(u64::MAX), fee_model::VERSION_2);
    }
}
