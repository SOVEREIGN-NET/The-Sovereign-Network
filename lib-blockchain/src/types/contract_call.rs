use serde::{Deserialize, Serialize};
use super::ContractType;

/// Contract function call request
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractCall {
    /// Type of contract being called
    pub contract_type: ContractType,
    /// Function/method name to execute
    pub method: String,
    /// Function parameters (serialized as bytes)
    pub params: Vec<u8>,
    /// Permissions required for this call
    pub permissions: CallPermissions,
}

impl ContractCall {
    /// Create a new contract call
    pub fn new(
        contract_type: ContractType,
        method: String,
        params: Vec<u8>,
        permissions: CallPermissions,
    ) -> Self {
        Self {
            contract_type,
            method,
            params,
            permissions,
        }
    }

    /// Create a public contract call (no special permissions required)
    pub fn public_call(
        contract_type: ContractType,
        method: String,
        params: Vec<u8>,
    ) -> Self {
        Self::new(contract_type, method, params, CallPermissions::Public)
    }

    /// Create a token contract call
    pub fn token_call(method: String, params: Vec<u8>) -> Self {
        Self::public_call(ContractType::Token, method, params)
    }

    /// Create a messaging contract call
    pub fn messaging_call(method: String, params: Vec<u8>) -> Self {
        Self::public_call(ContractType::WhisperMessaging, method, params)
    }

    /// Create a contact contract call
    pub fn contact_call(method: String, params: Vec<u8>) -> Self {
        Self::public_call(ContractType::ContactRegistry, method, params)
    }

    /// Create a group contract call
    pub fn group_call(method: String, params: Vec<u8>) -> Self {
        Self::public_call(ContractType::GroupChat, method, params)
    }

    /// Create a file contract call
    pub fn file_call(method: String, params: Vec<u8>) -> Self {
        Self::public_call(ContractType::FileSharing, method, params)
    }

    /// Validate the contract call structure
    pub fn validate(&self) -> Result<(), String> {
        if self.method.is_empty() {
            return Err("Method name cannot be empty".to_string());
        }

        if self.method.len() > 64 {
            return Err("Method name too long (max 64 characters)".to_string());
        }

        // Validate method name contains only alphanumeric characters and underscores
        if !self
            .method
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_')
        {
            return Err("Method name contains invalid characters".to_string());
        }

        // Validate parameter size
        if self.params.len() > 1024 * 1024 {
            return Err("Parameters too large (max 1MB)".to_string());
        }

        Ok(())
    }

    /// Get the caller's public key from permissions (if available)
    pub fn get_caller(&self) -> Result<crate::integration::crypto_integration::PublicKey, String> {
        match &self.permissions {
            CallPermissions::Public => {
                Err("Public call does not specify caller".to_string())
            }
            CallPermissions::Restricted { caller, .. } => {
                Ok(caller.clone())
            }
            CallPermissions::AdminOnly { admin } => {
                Ok(admin.clone())
            }
        }
    }

    /// Serialize a parameter for inclusion in params
    pub fn serialize_params<T: Serialize>(params: &T) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(params)
    }

    /// Deserialize parameters from the call
    pub fn deserialize_params<T: for<'de> Deserialize<'de>>(&self) -> Result<T, String> {
        bincode::deserialize(&self.params)
            .map_err(|e| format!("Failed to deserialize parameters: {}", e))
    }

    /// Check if the call has parameters
    pub fn has_params(&self) -> bool {
        !self.params.is_empty()
    }

    /// Get parameter size
    pub fn param_size(&self) -> usize {
        self.params.len()
    }

    /// Get contract type gas cost
    pub fn base_gas_cost(&self) -> u64 {
        self.contract_type.gas_cost()
    }
}

/// Extended permissions for contract calls
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallPermissions {
    /// Public call, no special permissions required
    Public,
    /// Restricted call requiring specific caller
    Restricted {
        caller: crate::integration::crypto_integration::PublicKey,
        permissions: Vec<String>,
    },
    /// Admin-only call
    AdminOnly {
        admin: crate::integration::crypto_integration::PublicKey,
    },
}

impl CallPermissions {
    /// Create restricted permissions
    pub fn restricted(caller: crate::integration::crypto_integration::PublicKey, permissions: Vec<String>) -> Self {
        Self::Restricted { caller, permissions }
    }

    /// Create admin-only permissions
    pub fn admin_only(admin: crate::integration::crypto_integration::PublicKey) -> Self {
        Self::AdminOnly { admin }
    }

    /// Check if permissions allow a specific operation
    pub fn allows_operation(&self, operation: &str, caller: &crate::integration::crypto_integration::PublicKey) -> bool {
        match self {
            CallPermissions::Public => true,
            CallPermissions::Restricted { caller: allowed_caller, permissions } => {
                allowed_caller == caller && (permissions.is_empty() || permissions.contains(&operation.to_string()))
            }
            CallPermissions::AdminOnly { admin } => admin == caller,
        }
    }

    /// Check if permissions require a specific caller
    pub fn requires_caller(&self) -> bool {
        !matches!(self, CallPermissions::Public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    

    #[test]
    fn test_contract_call_creation() {
        let call = ContractCall::new(
            ContractType::Token,
            "transfer".to_string(),
            vec![1, 2, 3],
            CallPermissions::Public,
        );

        assert_eq!(call.contract_type, ContractType::Token);
        assert_eq!(call.method, "transfer");
        assert_eq!(call.params, vec![1, 2, 3]);
        assert!(matches!(call.permissions, CallPermissions::Public));
    }

    #[test]
    fn test_contract_call_shortcuts() {
        let token_call = ContractCall::token_call("mint".to_string(), vec![1, 2, 3]);
        assert_eq!(token_call.contract_type, ContractType::Token);

        let messaging_call = ContractCall::messaging_call("send_message".to_string(), vec![4, 5, 6]);
        assert_eq!(messaging_call.contract_type, ContractType::WhisperMessaging);

        let contact_call = ContractCall::contact_call("add_contact".to_string(), vec![7, 8, 9]);
        assert_eq!(contact_call.contract_type, ContractType::ContactRegistry);

        let group_call = ContractCall::group_call("create_group".to_string(), vec![10, 11, 12]);
        assert_eq!(group_call.contract_type, ContractType::GroupChat);

        let file_call = ContractCall::file_call("share_file".to_string(), vec![13, 14, 15]);
        assert_eq!(file_call.contract_type, ContractType::FileSharing);
    }

    #[test]
    fn test_contract_call_validation() {
        // Valid call
        let valid_call = ContractCall::token_call("transfer".to_string(), vec![1, 2, 3]);
        assert!(valid_call.validate().is_ok());

        // Empty method name
        let invalid_call = ContractCall::token_call("".to_string(), vec![]);
        assert!(invalid_call.validate().is_err());

        // Method name too long
        let invalid_call = ContractCall::token_call("x".repeat(65), vec![]);
        assert!(invalid_call.validate().is_err());

        // Invalid method name
        let invalid_call = ContractCall::token_call("transfer-tokens".to_string(), vec![]);
        assert!(invalid_call.validate().is_err());
    }

    #[test]
    fn test_parameter_handling() {
        let amount: u64 = 1000;
        let params = ContractCall::serialize_params(&amount).unwrap();

        let call = ContractCall::token_call("transfer".to_string(), params);

        assert!(call.has_params());
        assert!(call.param_size() > 0);

        let parsed_amount: u64 = call.deserialize_params().unwrap();
        assert_eq!(parsed_amount, amount);
    }

    #[test]
    fn test_gas_cost() {
        let token_call = ContractCall::token_call("transfer".to_string(), vec![]);
        assert_eq!(token_call.base_gas_cost(), ContractType::Token.gas_cost());

        let messaging_call = ContractCall::messaging_call("send_message".to_string(), vec![]);
        assert_eq!(messaging_call.base_gas_cost(), ContractType::WhisperMessaging.gas_cost());
    }
}
