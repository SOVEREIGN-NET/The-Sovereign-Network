use serde::{Deserialize, Serialize};

/// Contract types supported by the ZHTP smart contract platform
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractType {
    /// Token contract - supports ZHTP native and custom tokens
    Token,
    /// Whisper messaging contract - encrypted messaging with token gates
    WhisperMessaging,
    /// Contact registry contract - decentralized address book
    ContactRegistry,
    /// Group chat contract - multi-party encrypted communication
    GroupChat,
    /// File sharing contract - encrypted file storage and sharing
    FileSharing,
    /// Governance contract - on-chain governance and voting
    Governance,
    /// Web4 website contract - decentralized website hosting
    Web4Website,
}

impl ContractType {
    /// Get the gas cost multiplier for this contract type
    pub fn gas_cost(&self) -> u64 {
        match self {
            ContractType::Token => crate::contracts::GAS_TOKEN,
            ContractType::WhisperMessaging => crate::contracts::GAS_MESSAGING,
            ContractType::ContactRegistry => crate::contracts::GAS_CONTACT,
            ContractType::GroupChat => crate::contracts::GAS_GROUP,
            ContractType::FileSharing => crate::contracts::GAS_MESSAGING, // Same as messaging due to complexity
            ContractType::Governance => crate::contracts::GAS_GROUP, // Same as group due to voting complexity
            ContractType::Web4Website => crate::contracts::GAS_MESSAGING, // Similar to file sharing complexity
        }
    }

    /// Check if this contract type supports minting operations
    pub fn supports_minting(&self) -> bool {
        matches!(self, ContractType::Token)
    }

    /// Check if this contract type supports burning operations
    pub fn supports_burning(&self) -> bool {
        matches!(
            self,
            ContractType::Token | ContractType::WhisperMessaging
        )
    }

    /// Get human-readable name for the contract type
    pub fn name(&self) -> &'static str {
        match self {
            ContractType::Token => "Token Contract",
            ContractType::WhisperMessaging => "Whisper Messaging Contract",
            ContractType::ContactRegistry => "Contact Registry Contract",
            ContractType::GroupChat => "Group Chat Contract",
            ContractType::FileSharing => "File Sharing Contract",
            ContractType::Governance => "Governance Contract",
            ContractType::Web4Website => "Web4 Website Contract",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contract_type_gas_costs() {
        assert_eq!(ContractType::Token.gas_cost(), 2000);
        assert_eq!(ContractType::WhisperMessaging.gas_cost(), 3000);
        assert_eq!(ContractType::ContactRegistry.gas_cost(), 1500);
        assert_eq!(ContractType::GroupChat.gas_cost(), 2500);
        assert_eq!(ContractType::FileSharing.gas_cost(), 3000);
        assert_eq!(ContractType::Governance.gas_cost(), 2500);
        assert_eq!(ContractType::Web4Website.gas_cost(), 3000);
    }

    #[test]
    fn test_contract_type_capabilities() {
        assert!(ContractType::Token.supports_minting());
        assert!(!ContractType::WhisperMessaging.supports_minting());

        assert!(ContractType::Token.supports_burning());
        assert!(ContractType::WhisperMessaging.supports_burning());
        assert!(!ContractType::ContactRegistry.supports_burning());
    }

    #[test]
    fn test_contract_type_names() {
        assert_eq!(ContractType::Token.name(), "Token Contract");
        assert_eq!(
            ContractType::WhisperMessaging.name(),
            "Whisper Messaging Contract"
        );
        assert_eq!(
            ContractType::ContactRegistry.name(),
            "Contact Registry Contract"
        );
    }

    #[test]
    fn test_contract_type_serialization() {
        let contract_type = ContractType::Token;
        let serialized = bincode::serialize(&contract_type).unwrap();
        let deserialized: ContractType = bincode::deserialize(&serialized).unwrap();
        assert_eq!(contract_type, deserialized);
    }
}
