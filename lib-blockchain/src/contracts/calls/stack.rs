//! Call stack tracking for cross-contract recursion prevention
//!
//! Tracks the call chain to enforce maximum recursion depth and prevent infinite loops.
//! The call depth is a critical parameter in recorded intents for deterministic replay validation.

use super::errors::{CalleeErrorCode, CrossContractError, ContractId};
use anyhow::{anyhow, Result};

/// Maximum allowed recursion depth for cross-contract calls (hard limit)
pub const MAX_RECURSION_DEPTH: u16 = 16;

/// Tracks the call stack to prevent infinite recursion
///
/// # Design
/// - Maintains both depth counter and full call chain
/// - Depth counter increments per cross-contract hop
/// - Exceeding limit triggers deterministic `CallDepthExceeded` error
/// - Full chain available for audit trail and debugging
#[derive(Debug, Clone)]
pub struct CallStack {
    /// Current depth in call chain (0 = top-level)
    depth: u16,
    /// Full call chain: (contract_id, method_name) pairs
    chain: Vec<(ContractId, String)>,
}

impl CallStack {
    /// Create a new empty call stack (top-level context)
    pub fn new() -> Self {
        Self {
            depth: 0,
            chain: Vec::new(),
        }
    }

    /// Push a call onto the stack
    ///
    /// Returns the new depth if successful, or error if depth exceeds limit
    pub fn push(&mut self, contract: ContractId, method: String) -> Result<u16> {
        // Check depth limit BEFORE incrementing
        if self.depth >= MAX_RECURSION_DEPTH {
            return Err(anyhow!(
                "Call depth {} exceeds maximum allowed recursion depth of {}",
                self.depth,
                MAX_RECURSION_DEPTH
            ));
        }

        // Record this call in the chain before incrementing
        self.chain.push((contract, method));

        // Increment depth for next call
        self.depth += 1;

        Ok(self.depth)
    }

    /// Pop a call from the stack (for unwinding after execution)
    ///
    /// # Panics
    /// Panics if stack is empty (indicates protocol violation)
    pub fn pop(&mut self) {
        if self.chain.is_empty() {
            panic!("CallStack::pop() called on empty stack - protocol violation");
        }

        self.chain.pop();
        // Decrement depth after pop
        if self.depth > 0 {
            self.depth -= 1;
        }
    }

    /// Get current call depth
    ///
    /// This is the depth that will be recorded in the next call's intent.
    pub fn current_depth(&self) -> u16 {
        self.depth
    }

    /// Get the full call chain (ordered from first to most recent)
    pub fn chain(&self) -> &[(ContractId, String)] {
        &self.chain
    }

    /// Get the most recent call (top of stack)
    pub fn peek(&self) -> Option<&(ContractId, String)> {
        self.chain.last()
    }

    /// Clear the call stack (used for context switches)
    pub fn clear(&mut self) {
        self.depth = 0;
        self.chain.clear();
    }

    /// Create a cross-contract error for depth exceeded
    pub fn depth_exceeded_error(
        &self,
        callee: ContractId,
        method: String,
    ) -> CrossContractError {
        CrossContractError::call_depth_exceeded(callee, method, self.depth)
    }
}

impl Default for CallStack {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_call_stack_empty() {
        let stack = CallStack::new();
        assert_eq!(stack.current_depth(), 0);
        assert!(stack.chain().is_empty());
        assert!(stack.peek().is_none());
    }

    #[test]
    fn test_push_single_call() {
        let mut stack = CallStack::new();
        let contract_id = [1u8; 32];
        let method = "transfer".to_string();

        let depth = stack.push(contract_id, method.clone()).unwrap();

        assert_eq!(depth, 1);
        assert_eq!(stack.current_depth(), 1);
        assert_eq!(stack.chain().len(), 1);
        assert_eq!(stack.chain()[0].0, contract_id);
        assert_eq!(stack.chain()[0].1, method);
    }

    #[test]
    fn test_push_multiple_calls() {
        let mut stack = CallStack::new();

        let contract1 = [1u8; 32];
        let contract2 = [2u8; 32];
        let contract3 = [3u8; 32];

        let d1 = stack.push(contract1, "vote".to_string()).unwrap();
        let d2 = stack.push(contract2, "transfer".to_string()).unwrap();
        let d3 = stack.push(contract3, "claim".to_string()).unwrap();

        assert_eq!(d1, 1);
        assert_eq!(d2, 2);
        assert_eq!(d3, 3);
        assert_eq!(stack.current_depth(), 3);
        assert_eq!(stack.chain().len(), 3);

        // Verify chain order
        assert_eq!(stack.chain()[0].0, contract1);
        assert_eq!(stack.chain()[1].0, contract2);
        assert_eq!(stack.chain()[2].0, contract3);
    }

    #[test]
    fn test_pop_removes_from_chain() {
        let mut stack = CallStack::new();
        let contract1 = [1u8; 32];
        let contract2 = [2u8; 32];

        stack.push(contract1, "method1".to_string()).unwrap();
        stack.push(contract2, "method2".to_string()).unwrap();

        assert_eq!(stack.chain().len(), 2);

        stack.pop();

        assert_eq!(stack.chain().len(), 1);
        assert_eq!(stack.chain()[0].0, contract1);
    }

    #[test]
    fn test_pop_all_calls() {
        let mut stack = CallStack::new();
        let contract = [1u8; 32];

        stack.push(contract, "method1".to_string()).unwrap();
        stack.push(contract, "method2".to_string()).unwrap();
        stack.push(contract, "method3".to_string()).unwrap();

        assert_eq!(stack.chain().len(), 3);

        stack.pop();
        stack.pop();
        stack.pop();

        assert_eq!(stack.chain().len(), 0);
        assert!(stack.peek().is_none());
    }

    #[test]
    #[should_panic(expected = "protocol violation")]
    fn test_pop_empty_stack_panics() {
        let mut stack = CallStack::new();
        stack.pop(); // Should panic
    }

    #[test]
    fn test_max_depth_enforcement() {
        let mut stack = CallStack::new();
        let contract = [1u8; 32];

        // Push up to the limit
        for i in 0..MAX_RECURSION_DEPTH {
            let result = stack.push(contract, format!("method_{}", i));
            assert!(result.is_ok(), "Push #{} should succeed", i);
        }

        assert_eq!(stack.current_depth(), MAX_RECURSION_DEPTH);

        // Next push should fail
        let result = stack.push(contract, "method_overflow".to_string());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("exceeds maximum"));
    }

    #[test]
    fn test_max_depth_is_16() {
        let mut stack = CallStack::new();
        let contract = [1u8; 32];

        // Fill to MAX_RECURSION_DEPTH
        for i in 0..MAX_RECURSION_DEPTH {
            stack.push(contract, format!("m{}", i)).ok();
        }

        assert_eq!(stack.current_depth(), 16);

        // Verify it rejects the 17th call
        let overflow = stack.push(contract, "m16".to_string());
        assert!(overflow.is_err());
    }

    #[test]
    fn test_peek_shows_most_recent() {
        let mut stack = CallStack::new();
        let contract1 = [1u8; 32];
        let contract2 = [2u8; 32];

        let method1 = "method1".to_string();
        let method2 = "method2".to_string();

        stack.push(contract1, method1.clone()).unwrap();
        assert_eq!(stack.peek().unwrap().0, contract1);
        assert_eq!(stack.peek().unwrap().1, method1);

        stack.push(contract2, method2.clone()).unwrap();
        assert_eq!(stack.peek().unwrap().0, contract2);
        assert_eq!(stack.peek().unwrap().1, method2);
    }

    #[test]
    fn test_clear_resets_stack() {
        let mut stack = CallStack::new();
        let contract = [1u8; 32];

        stack.push(contract, "m1".to_string()).unwrap();
        stack.push(contract, "m2".to_string()).unwrap();
        stack.push(contract, "m3".to_string()).unwrap();

        assert_eq!(stack.current_depth(), 3);
        assert_eq!(stack.chain().len(), 3);

        stack.clear();

        assert_eq!(stack.current_depth(), 0);
        assert_eq!(stack.chain().len(), 0);
        assert!(stack.peek().is_none());
    }

    #[test]
    fn test_depth_exceeded_error_contains_correct_info() {
        let stack = CallStack::new();
        let callee = [5u8; 32];
        let method = "testMethod".to_string();

        let error = stack.depth_exceeded_error(callee, method.clone());

        assert_eq!(error.callee, callee);
        assert_eq!(error.method, method);
        assert_eq!(error.code, CalleeErrorCode::CallDepthExceeded);
    }

    #[test]
    fn test_call_stack_preserves_method_names() {
        let mut stack = CallStack::new();
        let contract = [1u8; 32];

        let methods = vec![
            "transfer",
            "approve",
            "mint",
            "burn",
            "claim_rewards",
        ];

        for method in &methods {
            stack.push(contract, method.to_string()).ok();
        }

        for (i, method) in methods.iter().enumerate() {
            assert_eq!(stack.chain()[i].1, *method);
        }
    }

    #[test]
    fn test_call_stack_with_different_contracts() {
        let mut stack = CallStack::new();

        let contracts = vec![
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
        ];

        for contract in &contracts {
            stack.push(*contract, "method".to_string()).ok();
        }

        for (i, contract) in contracts.iter().enumerate() {
            assert_eq!(stack.chain()[i].0, *contract);
        }
    }

    #[test]
    fn test_default_creates_empty_stack() {
        let stack = CallStack::default();
        assert_eq!(stack.current_depth(), 0);
        assert!(stack.chain().is_empty());
    }
}
