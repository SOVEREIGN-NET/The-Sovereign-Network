//! Governance Transaction Types
//!
//! Defines the canonical governance transaction for configuration updates.

use serde::{Deserialize, Serialize};
use lib_types::{BlockHeight, TokenId};

use crate::fields::ConfigField;
use crate::errors::{GovernanceError, GovernanceResult};

/// Governance configuration transaction
///
/// Proposes a change to a configurable field that activates at a future block height.
///
/// # Rules
///
/// 1. **No immediate activation**: `activates_at` MUST be greater than current block height
/// 2. **Height-based only**: No time-based activation
/// 3. **Applied in executor**: Processed like any transaction
/// 4. **Stored in chain state**: Becomes a pending change until activation
///
/// # Fields
///
/// - `target`: The token or contract being configured
/// - `field`: Which configuration field to change
/// - `new_value_hash`: Hash of the new value (actual value stored separately)
/// - `activates_at`: Block height when the change takes effect
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceConfigTx {
    /// Target token or contract ID
    pub target: TokenId,
    /// Configuration field to modify
    pub field: ConfigField,
    /// Hash of the new value (blake3)
    pub new_value_hash: [u8; 32],
    /// Block height when change activates
    pub activates_at: BlockHeight,
}

impl GovernanceConfigTx {
    /// Create a new governance config transaction
    pub fn new(
        target: TokenId,
        field: ConfigField,
        new_value_hash: [u8; 32],
        activates_at: BlockHeight,
    ) -> Self {
        Self {
            target,
            field,
            new_value_hash,
            activates_at,
        }
    }

    /// Validate the transaction against current state
    ///
    /// # Rules enforced
    ///
    /// - `activates_at > current_height` (no immediate activation)
    /// - `activates_at <= current_height + max_delay` (bounded future)
    pub fn validate(&self, current_height: BlockHeight, max_delay: BlockHeight) -> GovernanceResult<()> {
        // Rule 1: No immediate activation
        if self.activates_at <= current_height {
            return Err(GovernanceError::ImmediateActivation {
                activates_at: self.activates_at,
                current_height,
            });
        }

        // Rule 2: Bounded future (prevent unbounded pending changes)
        let max_activation = current_height.saturating_add(max_delay);
        if self.activates_at > max_activation {
            return Err(GovernanceError::ActivationTooFar {
                activates_at: self.activates_at,
                max_allowed: max_activation,
            });
        }

        // Rule 3: Field must be governable
        if !self.field.is_governable() {
            return Err(GovernanceError::FieldNotGovernable(self.field));
        }

        Ok(())
    }

    /// Get the unique identifier for this pending change
    ///
    /// Used to detect duplicate or conflicting changes.
    pub fn change_id(&self) -> [u8; 32] {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.target.as_bytes().hash(&mut hasher);
        self.field.hash(&mut hasher);

        let hash = hasher.finish();
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&hash.to_le_bytes());
        id
    }
}

/// Default maximum delay for governance changes (about 30 days at 6s blocks)
pub const DEFAULT_MAX_DELAY: BlockHeight = 432_000;

/// Minimum delay for governance changes (about 1 day at 6s blocks)
pub const MIN_DELAY: BlockHeight = 14_400;

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_tx(activates_at: BlockHeight) -> GovernanceConfigTx {
        GovernanceConfigTx {
            target: TokenId::default(),
            field: ConfigField::TransferFeeBps,
            new_value_hash: [0u8; 32],
            activates_at,
        }
    }

    #[test]
    fn test_validate_immediate_activation_rejected() {
        let tx = create_test_tx(100);
        let result = tx.validate(100, DEFAULT_MAX_DELAY);
        assert!(matches!(result, Err(GovernanceError::ImmediateActivation { .. })));

        let result = tx.validate(150, DEFAULT_MAX_DELAY);
        assert!(matches!(result, Err(GovernanceError::ImmediateActivation { .. })));
    }

    #[test]
    fn test_validate_future_activation_accepted() {
        let tx = create_test_tx(200);
        let result = tx.validate(100, DEFAULT_MAX_DELAY);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_activation_too_far() {
        let tx = create_test_tx(1_000_000);
        let result = tx.validate(100, 1000);
        assert!(matches!(result, Err(GovernanceError::ActivationTooFar { .. })));
    }

    #[test]
    fn test_change_id_deterministic() {
        let tx1 = create_test_tx(100);
        let tx2 = create_test_tx(200); // Different activation, same target+field

        // Same target+field should produce same change_id
        assert_eq!(tx1.change_id(), tx2.change_id());
    }

    #[test]
    fn test_change_id_different_fields() {
        let tx1 = GovernanceConfigTx {
            target: TokenId::default(),
            field: ConfigField::TransferFeeBps,
            new_value_hash: [0u8; 32],
            activates_at: 100,
        };

        let tx2 = GovernanceConfigTx {
            target: TokenId::default(),
            field: ConfigField::BurnFeeBps,
            new_value_hash: [0u8; 32],
            activates_at: 100,
        };

        // Different fields should produce different change_id
        assert_ne!(tx1.change_id(), tx2.change_id());
    }
}
