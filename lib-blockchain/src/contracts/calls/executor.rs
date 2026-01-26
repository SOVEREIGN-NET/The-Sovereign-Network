//! Cross-contract call execution
//!
//! Orchestrates the safe execution of cross-contract calls by:
//! - Validating calls against ABI specifications
//! - Tracking call stack to prevent infinite recursion
//! - Recording intents for ADR-0017 compliance
//! - Handling errors in a wrapped, deterministic format

use super::call::CrossContractCall;
use super::errors::{CalleeErrorCode, ContractId, CrossContractError};
use super::stack::{CallStack, MAX_RECURSION_DEPTH};
use super::validator::{CallValidator, MethodSignature};
use anyhow::{anyhow, Result};
use std::cell::RefCell;

/// Result of executing a cross-contract call
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossContractCallResult {
    /// Call succeeded and returned a value
    Success { return_value: Vec<u8> },
    /// Call failed with wrapped error
    Error { error: CrossContractError },
}

impl CrossContractCallResult {
    /// Check if the call succeeded
    pub fn is_success(&self) -> bool {
        matches!(self, CrossContractCallResult::Success { .. })
    }

    /// Check if the call failed
    pub fn is_error(&self) -> bool {
        matches!(self, CrossContractCallResult::Error { .. })
    }

    /// Extract the return value, or error if call failed
    pub fn into_result(self) -> Result<Vec<u8>, CrossContractError> {
        match self {
            CrossContractCallResult::Success { return_value } => Ok(return_value),
            CrossContractCallResult::Error { error } => Err(error),
        }
    }
}

/// Represents intent to call another contract
///
/// Per ADR-0017, calls record INTENT (recorded as events) for consensus validation.
/// The Treasury Kernel later executes the actual state changes.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CrossContractCallIntent {
    /// Contract making the call
    pub caller: ContractId,
    /// Contract being called
    pub callee: ContractId,
    /// Method name
    pub method: String,
    /// Hash of serialized arguments (blake3)
    pub args_hash: [u8; 32],
    /// Hash of callee's ABI (for version tracking)
    pub abi_hash: [u8; 32],
    /// Call depth (0 = top-level)
    pub depth: u16,
    /// Block height where intent was recorded
    pub timestamp_block: u64,
}

impl CrossContractCallIntent {
    /// Create a new call intent
    pub fn new(
        caller: ContractId,
        callee: ContractId,
        method: String,
        args_hash: [u8; 32],
        abi_hash: [u8; 32],
        depth: u16,
        timestamp_block: u64,
    ) -> Self {
        Self {
            caller,
            callee,
            method,
            args_hash,
            abi_hash,
            depth,
            timestamp_block,
        }
    }

    /// Compute hash of this intent (for deduplication, signing)
    pub fn hash(&self) -> [u8; 32] {
        // Hash all fields in canonical order for determinism
        let mut hasher = blake3::Hasher::new();

        hasher.update(&self.caller);
        hasher.update(&self.callee);
        hasher.update(self.method.as_bytes());
        hasher.update(&self.args_hash);
        hasher.update(&self.abi_hash);
        hasher.update(&self.depth.to_le_bytes());
        hasher.update(&self.timestamp_block.to_le_bytes());

        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_bytes());
        result
    }
}

/// Executes cross-contract calls safely
///
/// # Design
/// - Maintains call stack for recursion tracking
/// - Validates against ABI specifications
/// - Records intents (not actual execution)
/// - Wraps all errors to prevent ABI information leakage
pub struct CallExecutor {
    /// Maps contract IDs to their ABI methods
    /// In real implementation, this would be backed by AbiRegistry
    abi_registry: std::collections::HashMap<ContractId, Vec<MethodSignature>>,
    /// Tracks the current call stack
    call_stack: RefCell<CallStack>,
    /// Current block height (for intent timestamps)
    current_block_height: u64,
}

impl CallExecutor {
    /// Create a new call executor
    pub fn new(current_block_height: u64) -> Self {
        Self {
            abi_registry: std::collections::HashMap::new(),
            call_stack: RefCell::new(CallStack::new()),
            current_block_height,
        }
    }

    /// Register an ABI for a contract
    ///
    /// In production, this would be managed by AbiRegistry.
    /// For testing, allows manual registration.
    pub fn register_abi(
        &mut self,
        contract_id: ContractId,
        methods: Vec<MethodSignature>,
    ) {
        self.abi_registry.insert(contract_id, methods);
    }

    /// Get the current call depth
    pub fn current_depth(&self) -> u16 {
        self.call_stack.borrow().current_depth()
    }

    /// Get the current call chain
    pub fn call_chain(&self) -> Vec<(ContractId, String)> {
        self.call_stack
            .borrow()
            .chain()
            .to_vec()
    }

    /// Execute a cross-contract call
    ///
    /// # Steps
    /// 1. Validate call structure
    /// 2. Check depth limit
    /// 3. Load callee's ABI
    /// 4. Validate parameters
    /// 5. Push onto call stack
    /// 6. Record intent
    /// 7. Return success or wrapped error
    pub fn execute_call(
        &self,
        call: CrossContractCall,
        param_count: usize,
        expected_return_type: &str,
        caller_abi_version: &str,
    ) -> Result<CrossContractCallResult> {
        // Step 1: Validate call structure
        call.validate_structure()
            .map_err(|e| anyhow!(e))?;

        // Step 2: Check depth limit BEFORE attempting to push
        if self.current_depth() >= MAX_RECURSION_DEPTH {
            let error = CrossContractError::call_depth_exceeded(
                call.callee,
                call.method.clone(),
                self.current_depth(),
            );
            return Ok(CrossContractCallResult::Error { error });
        }

        // Step 3: Load callee's ABI
        let methods = self.abi_registry.get(&call.callee).ok_or_else(|| {
            anyhow!("Contract {} not registered in ABI registry", hex::encode(call.callee))
        })?;

        // Step 4: Validate against ABI
        match CallValidator::validate_call(
            &call,
            methods,
            param_count,
            expected_return_type,
            caller_abi_version,
        ) {
            Ok(_) => {
                // Validation passed, proceed
            }
            Err(e) => {
                // Return wrapped validation error
                let error = CrossContractError::validation_failed(
                    call.callee,
                    call.method.clone(),
                    &e.to_string(),
                );
                return Ok(CrossContractCallResult::Error { error });
            }
        }

        // Step 5: Get current depth (depth of this call), then push, record, and pop
        let depth_of_this_call = self.current_depth();

        let mut stack = self.call_stack.borrow_mut();
        match stack.push(call.callee, call.method.clone()) {
            Ok(_) => {
                drop(stack); // Release borrow for record_intent

                let intent = self.record_intent(&call, depth_of_this_call)?;

                // Pop from stack (which also decrements depth)
                self.call_stack.borrow_mut().pop();

                // Return success with minimal data (actual execution deferred to Treasury Kernel)
                Ok(CrossContractCallResult::Success {
                    return_value: intent.hash().to_vec(),
                })
            }
            Err(_) => {
                // Depth exceeded
                drop(stack);
                let error = self.call_stack.borrow()
                    .depth_exceeded_error(call.callee, call.method.clone());
                Ok(CrossContractCallResult::Error { error })
            }
        }
    }

    /// Record intent for a cross-contract call
    ///
    /// Per ADR-0017, intents are recorded as events for consensus validation.
    fn record_intent(
        &self,
        call: &CrossContractCall,
        depth: u16,
    ) -> Result<CrossContractCallIntent> {
        // Hash arguments
        let args_hash = {
            let hash = blake3::hash(&call.args);
            let mut result = [0u8; 32];
            result.copy_from_slice(hash.as_bytes());
            result
        };

        // Hash ABI (placeholder: would come from registry)
        let abi_hash = {
            let hash = blake3::hash(call.method.as_bytes());
            let mut result = [0u8; 32];
            result.copy_from_slice(hash.as_bytes());
            result
        };

        let intent = CrossContractCallIntent::new(
            call.caller,
            call.callee,
            call.method.clone(),
            args_hash,
            abi_hash,
            depth,
            self.current_block_height,
        );

        Ok(intent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_executor() -> CallExecutor {
        CallExecutor::new(100)
    }

    fn create_test_call() -> CrossContractCall {
        let caller = [1u8; 32];
        let callee = [2u8; 32];
        CrossContractCall::new(caller, callee, "transfer".to_string(), vec![1, 2, 3])
    }

    fn create_test_method() -> MethodSignature {
        MethodSignature {
            name: "transfer".to_string(),
            parameter_count: 2,
            return_type: "bool".to_string(),
            abi_version: "1.0.0".to_string(),
        }
    }

    #[test]
    fn test_create_executor() {
        let executor = create_test_executor();
        assert_eq!(executor.current_depth(), 0);
        assert_eq!(executor.call_chain().len(), 0);
    }

    #[test]
    fn test_register_abi() {
        let mut executor = create_test_executor();
        let contract_id = [2u8; 32];
        let methods = vec![create_test_method()];

        executor.register_abi(contract_id, methods);

        // ABI should be registered
        assert!(executor.abi_registry.contains_key(&contract_id));
    }

    #[test]
    fn test_execute_call_success() {
        let mut executor = create_test_executor();
        let call = create_test_call();
        let contract_id = call.callee;
        let methods = vec![create_test_method()];

        executor.register_abi(contract_id, methods);

        let result = executor.execute_call(
            call,
            2,       // param count
            "bool",  // return type
            "1.0.0", // caller abi version
        );

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_success());
    }

    #[test]
    fn test_execute_call_invalid_structure() {
        let executor = create_test_executor();
        let mut call = create_test_call();
        call.method = "".to_string(); // Invalid: empty method

        let result = executor.execute_call(
            call,
            2,
            "bool",
            "1.0.0",
        );

        assert!(result.is_err()); // Invalid structure should error
    }

    #[test]
    fn test_execute_call_missing_abi() {
        let executor = create_test_executor();
        let call = create_test_call();

        // Don't register the ABI - should fail
        let result = executor.execute_call(
            call,
            2,
            "bool",
            "1.0.0",
        );

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .to_lowercase()
            .contains("not registered"));
    }

    #[test]
    fn test_execute_call_method_not_found() {
        let mut executor = create_test_executor();
        let mut call = create_test_call();
        call.method = "unknown_method".to_string();

        let contract_id = call.callee;
        let methods = vec![create_test_method()];
        executor.register_abi(contract_id, methods);

        let result = executor.execute_call(
            call,
            2,
            "bool",
            "1.0.0",
        );

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_error());
        match result {
            CrossContractCallResult::Error { error } => {
                assert_eq!(error.code, CalleeErrorCode::ValidationFailed);
            }
            _ => panic!("Expected error"),
        }
    }

    #[test]
    fn test_execute_call_parameter_count_mismatch() {
        let mut executor = create_test_executor();
        let call = create_test_call();

        let contract_id = call.callee;
        let methods = vec![create_test_method()];
        executor.register_abi(contract_id, methods);

        let result = executor.execute_call(
            call,
            3, // Wrong count
            "bool",
            "1.0.0",
        );

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_error());
    }

    #[test]
    fn test_execute_call_return_type_mismatch() {
        let mut executor = create_test_executor();
        let call = create_test_call();

        let contract_id = call.callee;
        let methods = vec![create_test_method()];
        executor.register_abi(contract_id, methods);

        let result = executor.execute_call(
            call,
            2,
            "u64", // Wrong return type
            "1.0.0",
        );

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_error());
    }

    #[test]
    fn test_max_depth_enforcement() {
        let executor = create_test_executor();
        let call = create_test_call();

        let contract_id = call.callee;

        // Can't register ABI because we need mutable executor
        // Instead, test depth tracking directly
        let mut stack = executor.call_stack.borrow_mut();

        // Fill stack to max
        for i in 0..MAX_RECURSION_DEPTH {
            stack.push(contract_id, format!("method_{}", i)).ok();
        }

        // Stack should be full
        assert_eq!(stack.current_depth(), MAX_RECURSION_DEPTH);

        // Attempting another push should fail
        let result = stack.push(contract_id, "overflow".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_call_stack_tracking() {
        let executor = create_test_executor();
        let mut stack = executor.call_stack.borrow_mut();

        let contract1 = [1u8; 32];
        let contract2 = [2u8; 32];

        stack.push(contract1, "method1".to_string()).ok();
        stack.push(contract2, "method2".to_string()).ok();

        let chain = stack.chain();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].0, contract1);
        assert_eq!(chain[1].0, contract2);
    }

    #[test]
    fn test_cross_contract_call_intent_creation() {
        let caller = [1u8; 32];
        let callee = [2u8; 32];
        let intent = CrossContractCallIntent::new(
            caller,
            callee,
            "transfer".to_string(),
            [5u8; 32],
            [10u8; 32],
            1,
            100,
        );

        assert_eq!(intent.caller, caller);
        assert_eq!(intent.callee, callee);
        assert_eq!(intent.method, "transfer");
        assert_eq!(intent.depth, 1);
        assert_eq!(intent.timestamp_block, 100);
    }

    #[test]
    fn test_intent_hash_deterministic() {
        let intent1 = CrossContractCallIntent::new(
            [1u8; 32],
            [2u8; 32],
            "transfer".to_string(),
            [5u8; 32],
            [10u8; 32],
            1,
            100,
        );

        let intent2 = CrossContractCallIntent::new(
            [1u8; 32],
            [2u8; 32],
            "transfer".to_string(),
            [5u8; 32],
            [10u8; 32],
            1,
            100,
        );

        assert_eq!(intent1.hash(), intent2.hash());
    }

    #[test]
    fn test_intent_hash_differs_for_different_data() {
        let intent1 = CrossContractCallIntent::new(
            [1u8; 32],
            [2u8; 32],
            "transfer".to_string(),
            [5u8; 32],
            [10u8; 32],
            1,
            100,
        );

        let intent2 = CrossContractCallIntent::new(
            [1u8; 32],
            [2u8; 32],
            "approve".to_string(), // Different method
            [5u8; 32],
            [10u8; 32],
            1,
            100,
        );

        assert_ne!(intent1.hash(), intent2.hash());
    }

    #[test]
    fn test_call_result_success() {
        let result = CrossContractCallResult::Success {
            return_value: vec![1, 2, 3],
        };

        assert!(result.is_success());
        assert!(!result.is_error());
    }

    #[test]
    fn test_call_result_error() {
        let error = CrossContractError::validation_failed(
            [1u8; 32],
            "method".to_string(),
            "test",
        );
        let result = CrossContractCallResult::Error { error };

        assert!(!result.is_success());
        assert!(result.is_error());
    }

    #[test]
    fn test_call_result_into_result_success() {
        let data = vec![1, 2, 3];
        let result = CrossContractCallResult::Success {
            return_value: data.clone(),
        };

        match result.into_result() {
            Ok(value) => assert_eq!(value, data),
            Err(_) => panic!("Expected success"),
        }
    }

    #[test]
    fn test_call_result_into_result_error() {
        let error = CrossContractError::validation_failed(
            [1u8; 32],
            "method".to_string(),
            "test",
        );
        let result = CrossContractCallResult::Error {
            error: error.clone(),
        };

        match result.into_result() {
            Ok(_) => panic!("Expected error"),
            Err(e) => assert_eq!(e, error),
        }
    }

    #[test]
    fn test_multiple_sequential_calls() {
        let mut executor = create_test_executor();
        let call = create_test_call();
        let contract_id = call.callee;
        let methods = vec![create_test_method()];

        executor.register_abi(contract_id, methods);

        // Execute first call
        let result1 = executor.execute_call(
            call.clone(),
            2,
            "bool",
            "1.0.0",
        );
        assert!(result1.is_ok());

        // Depth should be back to 0 after first call completes
        assert_eq!(executor.current_depth(), 0);

        // Execute second call
        let result2 = executor.execute_call(
            call,
            2,
            "bool",
            "1.0.0",
        );
        assert!(result2.is_ok());

        // Depth should still be 0
        assert_eq!(executor.current_depth(), 0);
    }

    #[test]
    fn test_nested_call_depth_tracking() {
        let executor = create_test_executor();
        let mut stack = executor.call_stack.borrow_mut();

        let contract = [1u8; 32];

        // Simulate nested calls
        stack.push(contract, "method1".to_string()).ok();
        assert_eq!(stack.current_depth(), 1);

        stack.push(contract, "method2".to_string()).ok();
        assert_eq!(stack.current_depth(), 2);

        stack.push(contract, "method3".to_string()).ok();
        assert_eq!(stack.current_depth(), 3);

        // Unwind
        stack.pop();
        stack.pop();
        stack.pop();

        assert_eq!(stack.current_depth(), 0);
        assert!(stack.chain().is_empty());
    }
}
