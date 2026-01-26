//! Cross-contract call representation
//!
//! Encapsulates all information needed to execute a cross-contract call,
//! including caller/callee identities, method name, serialized arguments, and depth.

use super::errors::ContractId;

/// Represents a single cross-contract method call
///
/// This struct captures all necessary information for:
/// - Intent recording (for ADR-0017 consensus)
/// - Call validation (parameter type checking)
/// - Execution (by Treasury Kernel)
/// - Recursion tracking (depth field)
///
/// # Design
/// - Arguments are pre-serialized (agnostic to format)
/// - Depth is attached for intent recording
/// - Immutable after construction (builder pattern for flexibility)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossContractCall {
    /// Contract making the call (caller)
    pub caller: ContractId,
    /// Contract being called (callee)
    pub callee: ContractId,
    /// Method name in the callee
    pub method: String,
    /// Serialized arguments (format negotiated via ABI)
    pub args: Vec<u8>,
    /// Current recursion depth at time of call
    pub depth: u16,
}

impl CrossContractCall {
    /// Create a new cross-contract call
    ///
    /// # Arguments
    /// - `caller`: Contract making the call
    /// - `callee`: Contract being called
    /// - `method`: Method name to invoke
    /// - `args`: Serialized arguments (bincode or serde format negotiated via ABI)
    ///
    /// # Returns
    /// A new call with depth initialized to 0
    pub fn new(caller: ContractId, callee: ContractId, method: String, args: Vec<u8>) -> Self {
        Self {
            caller,
            callee,
            method,
            args,
            depth: 0,
        }
    }

    /// Set the call depth (for intent recording)
    ///
    /// Returns self for chaining.
    pub fn with_depth(mut self, depth: u16) -> Self {
        self.depth = depth;
        self
    }

    /// Get the size of the serialized arguments
    pub fn args_len(&self) -> usize {
        self.args.len()
    }

    /// Check if arguments are empty
    pub fn has_args(&self) -> bool {
        !self.args.is_empty()
    }

    /// Create a copy of this call with a different depth
    /// (useful for replay/simulation)
    pub fn with_new_depth(&self, depth: u16) -> Self {
        Self {
            caller: self.caller,
            callee: self.callee,
            method: self.method.clone(),
            args: self.args.clone(),
            depth,
        }
    }

    /// Verify that this call has valid structure
    ///
    /// Performs basic sanity checks:
    /// - Caller and callee are different
    /// - Method name is not empty
    /// - Caller and callee are not null addresses
    pub fn validate_structure(&self) -> Result<(), String> {
        // Check for null addresses
        let null_address = [0u8; 32];
        if self.caller == null_address {
            return Err("Caller cannot be null address".to_string());
        }
        if self.callee == null_address {
            return Err("Callee cannot be null address".to_string());
        }

        // Check for self-calls (not allowed - would create logical errors and cycles)
        if self.caller == self.callee {
            return Err("Caller and callee must be different contracts".to_string());
        }

        // Check method name
        if self.method.is_empty() {
            return Err("Method name cannot be empty".to_string());
        }

        if self.method.len() > 255 {
            return Err("Method name must be 255 characters or less".to_string());
        }

        // Check for valid identifier characters (alphanumeric + underscore)
        if !self
            .method
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_')
        {
            return Err(
                "Method name must contain only alphanumeric characters and underscores"
                    .to_string(),
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_call() {
        let caller = [1u8; 32];
        let callee = [2u8; 32];
        let method = "transfer".to_string();
        let args = vec![1, 2, 3, 4];

        let call = CrossContractCall::new(caller, callee, method.clone(), args.clone());

        assert_eq!(call.caller, caller);
        assert_eq!(call.callee, callee);
        assert_eq!(call.method, method);
        assert_eq!(call.args, args);
        assert_eq!(call.depth, 0);
    }

    #[test]
    fn test_with_depth() {
        let caller = [1u8; 32];
        let callee = [2u8; 32];

        let call = CrossContractCall::new(caller, callee, "method".to_string(), vec![])
            .with_depth(5);

        assert_eq!(call.depth, 5);
    }

    #[test]
    fn test_with_depth_chaining() {
        let caller = [1u8; 32];
        let callee = [2u8; 32];

        let call = CrossContractCall::new(caller, callee, "method".to_string(), vec![])
            .with_depth(1)
            .with_depth(3); // Override

        assert_eq!(call.depth, 3);
    }

    #[test]
    fn test_args_len() {
        let caller = [1u8; 32];
        let callee = [2u8; 32];

        let args = vec![1, 2, 3, 4, 5];
        let call = CrossContractCall::new(caller, callee, "method".to_string(), args);

        assert_eq!(call.args_len(), 5);
    }

    #[test]
    fn test_has_args() {
        let caller = [1u8; 32];
        let callee = [2u8; 32];

        let call_with_args =
            CrossContractCall::new(caller, callee, "method".to_string(), vec![1, 2, 3]);
        assert!(call_with_args.has_args());

        let call_no_args =
            CrossContractCall::new(caller, callee, "method".to_string(), vec![]);
        assert!(!call_no_args.has_args());
    }

    #[test]
    fn test_with_new_depth() {
        let caller = [1u8; 32];
        let callee = [2u8; 32];
        let args = vec![1, 2];

        let original =
            CrossContractCall::new(caller, callee, "test".to_string(), args.clone()).with_depth(5);

        let modified = original.with_new_depth(10);

        // Original unchanged
        assert_eq!(original.depth, 5);
        // New copy has new depth
        assert_eq!(modified.depth, 10);
        // Rest of data identical
        assert_eq!(modified.caller, original.caller);
        assert_eq!(modified.callee, original.callee);
        assert_eq!(modified.method, original.method);
        assert_eq!(modified.args, original.args);
    }

    #[test]
    fn test_validate_structure_valid() {
        let caller = [1u8; 32];
        let callee = [2u8; 32];

        let call = CrossContractCall::new(caller, callee, "transfer".to_string(), vec![]);

        assert!(call.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_null_caller() {
        let null = [0u8; 32];
        let callee = [2u8; 32];

        let call = CrossContractCall::new(null, callee, "transfer".to_string(), vec![]);

        let result = call.validate_structure();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_lowercase()
            .contains("caller cannot be null"));
    }

    #[test]
    fn test_validate_structure_null_callee() {
        let caller = [1u8; 32];
        let null = [0u8; 32];

        let call = CrossContractCall::new(caller, null, "transfer".to_string(), vec![]);

        let result = call.validate_structure();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_lowercase()
            .contains("callee cannot be null"));
    }

    #[test]
    fn test_validate_structure_self_call() {
        let contract = [1u8; 32];

        let call = CrossContractCall::new(contract, contract, "method".to_string(), vec![]);

        let result = call.validate_structure();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_lowercase().contains("different"));
    }

    #[test]
    fn test_validate_structure_empty_method() {
        let caller = [1u8; 32];
        let callee = [2u8; 32];

        let call = CrossContractCall::new(caller, callee, "".to_string(), vec![]);

        let result = call.validate_structure();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_lowercase().contains("empty"));
    }

    #[test]
    fn test_validate_structure_method_too_long() {
        let caller = [1u8; 32];
        let callee = [2u8; 32];
        let long_method = "a".repeat(256);

        let call = CrossContractCall::new(caller, callee, long_method, vec![]);

        let result = call.validate_structure();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_lowercase().contains("255"));
    }

    #[test]
    fn test_validate_structure_invalid_characters() {
        let caller = [1u8; 32];
        let callee = [2u8; 32];

        let invalid_methods = vec![
            "method-name",
            "method.name",
            "method@name",
            "method name",
            "method!",
        ];

        for method in invalid_methods {
            let call = CrossContractCall::new(caller, callee, method.to_string(), vec![]);
            let result = call.validate_structure();
            assert!(
                result.is_err(),
                "Method '{}' should fail validation",
                method
            );
        }
    }

    #[test]
    fn test_validate_structure_valid_identifiers() {
        let caller = [1u8; 32];
        let callee = [2u8; 32];

        let valid_methods = vec![
            "transfer",
            "approve",
            "transfer_from",
            "claim_rewards",
            "mint_nft",
            "vote_proposal",
            "method123",
            "method_123_test",
            "_private_method",
            "m",
        ];

        for method in valid_methods {
            let call = CrossContractCall::new(caller, callee, method.to_string(), vec![]);
            assert!(
                call.validate_structure().is_ok(),
                "Method '{}' should pass validation",
                method
            );
        }
    }

    #[test]
    fn test_clone_preserves_data() {
        let caller = [1u8; 32];
        let callee = [2u8; 32];
        let args = vec![1, 2, 3];

        let call = CrossContractCall::new(caller, callee, "method".to_string(), args)
            .with_depth(3);

        let cloned = call.clone();

        assert_eq!(call, cloned);
    }

    #[test]
    fn test_equality() {
        let caller = [1u8; 32];
        let callee = [2u8; 32];

        let call1 = CrossContractCall::new(caller, callee, "method".to_string(), vec![1, 2])
            .with_depth(5);

        let call2 = CrossContractCall::new(caller, callee, "method".to_string(), vec![1, 2])
            .with_depth(5);

        assert_eq!(call1, call2);
    }

    #[test]
    fn test_inequality_different_method() {
        let caller = [1u8; 32];
        let callee = [2u8; 32];

        let call1 = CrossContractCall::new(caller, callee, "method1".to_string(), vec![]);
        let call2 = CrossContractCall::new(caller, callee, "method2".to_string(), vec![]);

        assert_ne!(call1, call2);
    }

    #[test]
    fn test_inequality_different_args() {
        let caller = [1u8; 32];
        let callee = [2u8; 32];

        let call1 = CrossContractCall::new(caller, callee, "method".to_string(), vec![1, 2]);
        let call2 = CrossContractCall::new(caller, callee, "method".to_string(), vec![3, 4]);

        assert_ne!(call1, call2);
    }

    #[test]
    fn test_inequality_different_depth() {
        let caller = [1u8; 32];
        let callee = [2u8; 32];

        let call1 = CrossContractCall::new(caller, callee, "method".to_string(), vec![])
            .with_depth(1);
        let call2 = CrossContractCall::new(caller, callee, "method".to_string(), vec![])
            .with_depth(2);

        assert_ne!(call1, call2);
    }

    #[test]
    fn test_large_args() {
        let caller = [1u8; 32];
        let callee = [2u8; 32];
        let large_args = vec![0u8; 10_000];

        let call = CrossContractCall::new(caller, callee, "method".to_string(), large_args.clone());

        assert_eq!(call.args_len(), 10_000);
        assert_eq!(call.args, large_args);
    }

    #[test]
    fn test_different_contracts() {
        let caller = [1u8; 32];
        let callee = [255u8; 32];

        let call = CrossContractCall::new(caller, callee, "method".to_string(), vec![]);

        assert_eq!(call.caller, caller);
        assert_eq!(call.callee, callee);
        assert_ne!(call.caller, call.callee);
    }
}
