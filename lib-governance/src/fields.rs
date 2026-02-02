//! Configurable Fields
//!
//! Defines which configuration fields can be modified through governance.

use serde::{Deserialize, Serialize};

/// Configuration fields that can be modified through governance
///
/// Each field has specific rules about:
/// - Who can propose changes (authority requirements)
/// - Validation constraints
/// - Whether it's governable at all
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConfigField {
    // =========================================================================
    // Token Fee Configuration
    // =========================================================================
    /// Transfer fee in basis points (0-10000)
    TransferFeeBps,
    /// Burn fee in basis points (0-10000)
    BurnFeeBps,
    /// Maximum fee cap
    FeeCap,
    /// Minimum fee amount
    MinFee,

    // =========================================================================
    // Token Policy Configuration
    // =========================================================================
    /// Transfer policy (Free, AllowlistOnly, NonTransferable)
    TransferPolicy,
    /// Fee recipient address
    FeeRecipient,
    /// Treasury address
    TreasuryAddress,

    // =========================================================================
    // Supply Configuration
    // =========================================================================
    /// Maximum supply (only for CappedMint)
    MaxSupply,

    // =========================================================================
    // Authority Configuration
    // =========================================================================
    /// Add address to a role
    AuthorityAdd,
    /// Remove address from a role
    AuthorityRemove,

    // =========================================================================
    // Protocol Parameters
    // =========================================================================
    /// Block size limit
    BlockSizeLimit,
    /// Transaction count limit per block
    TxCountLimit,
    /// Base fee per byte
    BaseFeePerByte,

    // =========================================================================
    // Immutable (for completeness - always rejected)
    // =========================================================================
    /// Token name (immutable)
    Name,
    /// Token symbol (immutable)
    Symbol,
    /// Token decimals (immutable)
    Decimals,
    /// Token ID (immutable)
    TokenId,
}

impl ConfigField {
    /// Check if this field can be modified through governance
    pub fn is_governable(&self) -> bool {
        match self {
            // Governable fee fields
            ConfigField::TransferFeeBps => true,
            ConfigField::BurnFeeBps => true,
            ConfigField::FeeCap => true,
            ConfigField::MinFee => true,

            // Governable policy fields
            ConfigField::TransferPolicy => true,
            ConfigField::FeeRecipient => true,
            ConfigField::TreasuryAddress => true,

            // Governable supply fields
            ConfigField::MaxSupply => true,

            // Governable authority fields
            ConfigField::AuthorityAdd => true,
            ConfigField::AuthorityRemove => true,

            // Governable protocol params
            ConfigField::BlockSizeLimit => true,
            ConfigField::TxCountLimit => true,
            ConfigField::BaseFeePerByte => true,

            // Immutable fields - NOT governable
            ConfigField::Name => false,
            ConfigField::Symbol => false,
            ConfigField::Decimals => false,
            ConfigField::TokenId => false,
        }
    }

    /// Get the category of this field
    pub fn category(&self) -> FieldCategory {
        match self {
            ConfigField::TransferFeeBps
            | ConfigField::BurnFeeBps
            | ConfigField::FeeCap
            | ConfigField::MinFee => FieldCategory::Fee,

            ConfigField::TransferPolicy
            | ConfigField::FeeRecipient
            | ConfigField::TreasuryAddress => FieldCategory::Policy,

            ConfigField::MaxSupply => FieldCategory::Supply,

            ConfigField::AuthorityAdd
            | ConfigField::AuthorityRemove => FieldCategory::Authority,

            ConfigField::BlockSizeLimit
            | ConfigField::TxCountLimit
            | ConfigField::BaseFeePerByte => FieldCategory::Protocol,

            ConfigField::Name
            | ConfigField::Symbol
            | ConfigField::Decimals
            | ConfigField::TokenId => FieldCategory::Immutable,
        }
    }

    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            ConfigField::TransferFeeBps => "Transfer fee (basis points)",
            ConfigField::BurnFeeBps => "Burn fee (basis points)",
            ConfigField::FeeCap => "Maximum fee cap",
            ConfigField::MinFee => "Minimum fee amount",
            ConfigField::TransferPolicy => "Transfer policy",
            ConfigField::FeeRecipient => "Fee recipient address",
            ConfigField::TreasuryAddress => "Treasury address",
            ConfigField::MaxSupply => "Maximum supply",
            ConfigField::AuthorityAdd => "Add authority",
            ConfigField::AuthorityRemove => "Remove authority",
            ConfigField::BlockSizeLimit => "Block size limit",
            ConfigField::TxCountLimit => "Transaction count limit",
            ConfigField::BaseFeePerByte => "Base fee per byte",
            ConfigField::Name => "Token name (immutable)",
            ConfigField::Symbol => "Token symbol (immutable)",
            ConfigField::Decimals => "Token decimals (immutable)",
            ConfigField::TokenId => "Token ID (immutable)",
        }
    }
}

/// Category of configuration fields
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldCategory {
    /// Fee-related configuration
    Fee,
    /// Policy-related configuration
    Policy,
    /// Supply-related configuration
    Supply,
    /// Authority-related configuration
    Authority,
    /// Protocol-level parameters
    Protocol,
    /// Immutable fields (cannot be changed)
    Immutable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_fields_governable() {
        assert!(ConfigField::TransferFeeBps.is_governable());
        assert!(ConfigField::BurnFeeBps.is_governable());
        assert!(ConfigField::FeeCap.is_governable());
        assert!(ConfigField::MinFee.is_governable());
    }

    #[test]
    fn test_immutable_fields_not_governable() {
        assert!(!ConfigField::Name.is_governable());
        assert!(!ConfigField::Symbol.is_governable());
        assert!(!ConfigField::Decimals.is_governable());
        assert!(!ConfigField::TokenId.is_governable());
    }

    #[test]
    fn test_field_categories() {
        assert_eq!(ConfigField::TransferFeeBps.category(), FieldCategory::Fee);
        assert_eq!(ConfigField::TransferPolicy.category(), FieldCategory::Policy);
        assert_eq!(ConfigField::MaxSupply.category(), FieldCategory::Supply);
        assert_eq!(ConfigField::AuthorityAdd.category(), FieldCategory::Authority);
        assert_eq!(ConfigField::BlockSizeLimit.category(), FieldCategory::Protocol);
        assert_eq!(ConfigField::Name.category(), FieldCategory::Immutable);
    }
}
