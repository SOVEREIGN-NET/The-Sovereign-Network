use serde::{Deserialize, Serialize};
use crate::integration::crypto_integration::PublicKey;
use crate::types::{ContractType, ContractPermissions};

/// Core smart contract structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmartContract {
    /// Unique identifier for the contract
    pub contract_id: [u8; 32],
    /// Contract bytecode (serialized contract data)
    pub bytecode: Vec<u8>,
    /// Public key of the contract creator
    pub creator: PublicKey,
    /// Block height when the contract was created
    pub creation_height: u64,
    /// Type of contract (Token, Messaging, etc.)
    pub contract_type: ContractType,
    /// Contract permissions and administrative controls
    pub permissions: ContractPermissions,
}

impl SmartContract {
    /// Create a new smart contract
    pub fn new(
        contract_id: [u8; 32],
        bytecode: Vec<u8>,
        creator: PublicKey,
        creation_height: u64,
        contract_type: ContractType,
        permissions: ContractPermissions,
    ) -> Self {
        Self {
            contract_id,
            bytecode,
            creator,
            creation_height,
            contract_type,
            permissions,
        }
    }

    /// Create a token contract
    pub fn new_token_contract(
        contract_id: [u8; 32],
        bytecode: Vec<u8>,
        creator: PublicKey,
        creation_height: u64,
        can_mint: bool,
        can_burn: bool,
    ) -> Self {
        let permissions = ContractPermissions::for_token(creator.clone(), can_mint, can_burn);
        Self::new(
            contract_id,
            bytecode,
            creator,
            creation_height,
            ContractType::Token,
            permissions,
        )
    }

    /// Create a SOV native token contract
    pub fn new_lib_token_contract(
        contract_id: [u8; 32],
        bytecode: Vec<u8>,
        creator: PublicKey,
        creation_height: u64,
    ) -> Self {
        let permissions = ContractPermissions::for_lib_token();
        Self::new(
            contract_id,
            bytecode,
            creator,
            creation_height,
            ContractType::Token,
            permissions,
        )
    }

    /// Create a messaging contract
    pub fn new_messaging_contract(
        contract_id: [u8; 32],
        bytecode: Vec<u8>,
        creator: PublicKey,
        creation_height: u64,
    ) -> Self {
        let permissions = ContractPermissions::for_messaging();
        Self::new(
            contract_id,
            bytecode,
            creator,
            creation_height,
            ContractType::WhisperMessaging,
            permissions,
        )
    }

    /// Create a contact registry contract
    pub fn new_contact_registry_contract(
        contract_id: [u8; 32],
        bytecode: Vec<u8>,
        creator: PublicKey,
        creation_height: u64,
    ) -> Self {
        let permissions = ContractPermissions::for_social(creator.clone());
        Self::new(
            contract_id,
            bytecode,
            creator,
            creation_height,
            ContractType::ContactRegistry,
            permissions,
        )
    }

    /// Create a group chat contract
    pub fn new_group_chat_contract(
        contract_id: [u8; 32],
        bytecode: Vec<u8>,
        creator: PublicKey,
        creation_height: u64,
    ) -> Self {
        let permissions = ContractPermissions::for_social(creator.clone());
        Self::new(
            contract_id,
            bytecode,
            creator,
            creation_height,
            ContractType::GroupChat,
            permissions,
        )
    }

    /// Create a file sharing contract
    pub fn new_file_sharing_contract(
        contract_id: [u8; 32],
        bytecode: Vec<u8>,
        creator: PublicKey,
        creation_height: u64,
    ) -> Self {
        let permissions = ContractPermissions::for_social(creator.clone());
        Self::new(
            contract_id,
            bytecode,
            creator,
            creation_height,
            ContractType::FileSharing,
            permissions,
        )
    }

    /// Get the contract's gas cost for operations
    pub fn gas_cost(&self) -> u64 {
        self.contract_type.gas_cost()
    }

    /// Check if the caller is authorized to perform an operation
    pub fn is_authorized(&self, caller: &PublicKey, operation: &str) -> bool {
        // Creator always has permissions
        if &self.creator == caller {
            return true;
        }

        // Check specific permissions
        self.permissions.can_perform_operation(operation, caller)
    }

    /// Check if the contract is owned by a specific public key
    pub fn is_owned_by(&self, public_key: &PublicKey) -> bool {
        self.creator == *public_key
    }

    /// Get the size of the contract in bytes
    pub fn size(&self) -> usize {
        32 + // contract_id
        4 + self.bytecode.len() + // bytecode with length prefix
        self.creator.size() + // creator public key
        8 + // creation_height
        bincode::serialized_size(&self.contract_type).unwrap_or(0) as usize + // contract_type
        bincode::serialized_size(&self.permissions).unwrap_or(0) as usize // permissions
    }

    /// Validate the contract structure
    pub fn validate(&self) -> Result<(), String> {
        if self.bytecode.is_empty() {
            return Err("Contract bytecode cannot be empty".to_string());
        }

        if self.creation_height == 0 {
            return Err("Creation height must be greater than 0".to_string());
        }

        // Validate contract type and permissions compatibility
        match self.contract_type {
            ContractType::Token => {
                // Token contracts should have appropriate minting/burning permissions
                if !self.permissions.can_mint && !self.permissions.can_burn {
                    return Err("Token contracts should have at least minting or burning permissions".to_string());
                }
            }
            ContractType::WhisperMessaging => {
                // Messaging contracts should allow burning (for message deletion)
                if !self.permissions.can_burn {
                    return Err("Messaging contracts should allow burning for message deletion".to_string());
                }
            }
            _ => {} // Other contract types have no specific requirements
        }

        Ok(())
    }

    /// Update contract permissions (only by admins)
    pub fn update_permissions(&mut self, new_permissions: ContractPermissions, caller: &PublicKey) -> Result<(), String> {
        if !self.is_authorized(caller, "admin") {
            return Err("Only admins can update contract permissions".to_string());
        }

        self.permissions = new_permissions;
        Ok(())
    }

    /// Get a summary of the contract
    pub fn summary(&self) -> String {
        format!(
            "SmartContract {{ id: {}, type: {}, creator: {}, height: {}, size: {} bytes }}",
            hex::encode(self.contract_id),
            self.contract_type.name(),
            hex::encode(&self.creator.key_id),
            self.creation_height,
            self.size()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_public_key(id: u8) -> PublicKey {
        PublicKey::new(vec![id; 32])
    }

    #[test]
    fn test_smart_contract_creation() {
        let public_key = create_test_public_key(1);
        let contract_id = [1u8; 32];
        let bytecode = vec![1, 2, 3, 4, 5];
        let creation_height = 100;
        let permissions = ContractPermissions::new();

        let contract = SmartContract::new(
            contract_id,
            bytecode.clone(),
            public_key.clone(),
            creation_height,
            ContractType::Token,
            permissions.clone(),
        );

        assert_eq!(contract.contract_id, contract_id);
        assert_eq!(contract.bytecode, bytecode);
        assert_eq!(contract.creator, public_key);
        assert_eq!(contract.creation_height, creation_height);
        assert_eq!(contract.contract_type, ContractType::Token);
        assert_eq!(contract.permissions, permissions);
    }

    #[test]
    fn test_token_contract_creation() {
        let public_key = create_test_public_key(2);
        let contract_id = [2u8; 32];
        let bytecode = vec![1, 2, 3];
        let creation_height = 200;

        let contract = SmartContract::new_token_contract(
            contract_id,
            bytecode,
            public_key.clone(),
            creation_height,
            true,
            true,
        );

        assert_eq!(contract.contract_type, ContractType::Token);
        assert!(contract.permissions.can_mint);
        assert!(contract.permissions.can_burn);
        assert!(contract.permissions.is_admin(&public_key));
    }

    #[test]
    fn test_lib_token_contract_creation() {
        let public_key = create_test_public_key(3);
        let contract_id = [3u8; 32];
        let bytecode = vec![1, 2, 3, 4];
        let creation_height = 300;

        let contract = SmartContract::new_lib_token_contract(
            contract_id,
            bytecode,
            public_key.clone(),
            creation_height,
        );

        assert_eq!(contract.contract_type, ContractType::Token);
        assert!(contract.permissions.can_mint);
        assert!(!contract.permissions.can_burn);
        assert!(contract.permissions.admins.is_empty()); // No single admin for SOV
    }

    #[test]
    fn test_messaging_contract_creation() {
        let public_key = create_test_public_key(4);
        let contract_id = [4u8; 32];
        let bytecode = vec![5, 6, 7];
        let creation_height = 400;

        let contract = SmartContract::new_messaging_contract(
            contract_id,
            bytecode,
            public_key.clone(),
            creation_height,
        );

        assert_eq!(contract.contract_type, ContractType::WhisperMessaging);
        assert!(!contract.permissions.can_mint);
        assert!(contract.permissions.can_burn); // For message deletion
    }

    #[test]
    fn test_authorization() {
        let public_key1 = create_test_public_key(1);
        let public_key2 = create_test_public_key(2);
        
        let contract = SmartContract::new_token_contract(
            [5u8; 32],
            vec![1, 2, 3],
            public_key1.clone(),
            500,
            true,
            false,
        );

        // Creator should be authorized
        assert!(contract.is_authorized(&public_key1, "mint"));
        assert!(contract.is_authorized(&public_key1, "admin"));

        // Non-creator should not be authorized for admin operations
        assert!(!contract.is_authorized(&public_key2, "mint"));
        assert!(!contract.is_authorized(&public_key2, "admin"));

        // But burning should work for anyone if enabled
        let burn_contract = SmartContract::new_token_contract(
            [6u8; 32],
            vec![1, 2, 3],
            public_key1.clone(),
            600,
            false,
            true,
        );
        assert!(burn_contract.is_authorized(&public_key2, "burn"));
    }

    #[test]
    fn test_contract_validation() {
        let public_key = create_test_public_key(7);

        // Valid contract
        let valid_contract = SmartContract::new_token_contract(
            [7u8; 32],
            vec![1, 2, 3],
            public_key.clone(),
            700,
            true,
            false,
        );
        assert!(valid_contract.validate().is_ok());

        // Empty bytecode
        let invalid_contract = SmartContract::new(
            [8u8; 32],
            vec![], // Empty bytecode
            public_key.clone(),
            800,
            ContractType::Token,
            ContractPermissions::new(),
        );
        assert!(invalid_contract.validate().is_err());

        // Zero creation height
        let invalid_contract = SmartContract::new(
            [9u8; 32],
            vec![1, 2, 3],
            public_key.clone(),
            0, // Zero height
            ContractType::Token,
            ContractPermissions::new(),
        );
        assert!(invalid_contract.validate().is_err());
    }

    #[test]
    fn test_contract_utilities() {
        let public_key = create_test_public_key(10);
        let contract = SmartContract::new_token_contract(
            [10u8; 32],
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            public_key.clone(),
            1000,
            true,
            true,
        );

        assert_eq!(contract.gas_cost(), ContractType::Token.gas_cost());
        assert!(contract.is_owned_by(&public_key));
        assert!(contract.size() > 0);

        let summary = contract.summary();
        assert!(summary.contains("SmartContract"));
        assert!(summary.contains("Token Contract"));
        assert!(summary.contains("height: 1000"));
    }
}
