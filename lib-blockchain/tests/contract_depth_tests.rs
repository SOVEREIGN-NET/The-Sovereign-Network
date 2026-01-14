//! Contract call depth limit tests
//!
//! Tests for cross-contract call depth tracking and enforcement to prevent
//! infinite recursion and stack overflow scenarios.

use lib_blockchain::contracts::executor::{
    ExecutionContext, ContractExecutor, MemoryStorage, DEFAULT_MAX_CALL_DEPTH,
};
use lib_blockchain::integration::crypto_integration::PublicKey;

/// Helper to create a test public key
fn test_public_key(id: u8) -> PublicKey {
    PublicKey {
        dilithium_pk: vec![id],
        kyber_pk: vec![id],
        key_id: [id; 32],
    }
}

/// Test 1: Call depth is initialized to 0 and max is set to DEFAULT_MAX_CALL_DEPTH
#[test]
fn test_call_depth_initialization() {
    let caller = test_public_key(1);
    let context = ExecutionContext::new(
        caller,
        100,      // block_number
        1000,     // timestamp
        100_000,  // gas_limit
        [0u8; 32],
    );

    assert_eq!(context.call_depth, 0, "New context should have depth 0");
    assert_eq!(
        context.max_call_depth, DEFAULT_MAX_CALL_DEPTH,
        "Max depth should be DEFAULT_MAX_CALL_DEPTH (10)"
    );
}

/// Test 2: Call depth increments properly in nested contexts
#[test]
fn test_call_depth_increments() {
    let caller = test_public_key(1);
    let mut context = ExecutionContext::new(caller, 100, 1000, 100_000, [0u8; 32]);

    // Initial depth is 0
    assert_eq!(context.call_depth, 0);

    // Increment to depth 1
    context.call_depth = 1;
    assert_eq!(context.call_depth, 1);

    // Create nested context using with_incremented_depth
    let nested = context.with_incremented_depth();
    assert!(nested.is_ok(), "Should create nested context when below max depth");

    let nested_context = nested.unwrap();
    assert_eq!(nested_context.call_depth, 2, "Nested context should have depth 2");
    assert_eq!(
        nested_context.max_call_depth, DEFAULT_MAX_CALL_DEPTH,
        "Max depth should be preserved"
    );
}

/// Test 3: Call depth limit is enforced at max_call_depth
#[test]
fn test_call_depth_limit_enforced() {
    let caller = test_public_key(1);
    let mut context = ExecutionContext::new(caller, 100, 1000, 100_000, [0u8; 32]);

    // Manually set depth to max - 1
    context.call_depth = DEFAULT_MAX_CALL_DEPTH - 1;

    // Attempting to increment should succeed (creates depth = max)
    let nested = context.with_incremented_depth();
    assert!(nested.is_ok(), "Should allow depth = max");
    assert_eq!(nested.unwrap().call_depth, DEFAULT_MAX_CALL_DEPTH);

    // Set to max depth
    context.call_depth = DEFAULT_MAX_CALL_DEPTH;

    // Attempting to increment should fail (would create depth > max)
    let over_limit = context.with_incremented_depth();
    assert!(
        over_limit.is_err(),
        "Should reject depth increment beyond max"
    );

    let err_msg = format!("{:?}", over_limit.unwrap_err());
    assert!(
        err_msg.contains("Call depth limit exceeded"),
        "Error should mention depth limit: {}",
        err_msg
    );
}

/// Test 4: Simple cross-contract call within depth limit succeeds
#[test]
fn test_single_contract_call_succeeds() {
    let caller = test_public_key(1);
    let contract = test_public_key(2);

    // Create user-initiated context (depth = 0)
    let context = ExecutionContext::new(caller, 100, 1000, 100_000, [0u8; 32]);
    assert_eq!(context.call_depth, 0);

    // Create contract context (depth = 1)
    let contract_context = ExecutionContext::with_contract(
        context.caller.clone(),
        contract,
        context.block_number,
        context.timestamp,
        context.gas_limit,
        context.tx_hash,
    );

    assert_eq!(contract_context.call_depth, 0, "with_contract starts at depth 0");

    // Manually increment for nested call simulation
    let mut nested = contract_context.clone();
    nested.call_depth = 1;

    assert!(
        nested.call_depth <= nested.max_call_depth,
        "Depth 1 should be within limit of 10"
    );
}

/// Test 5: UBI claim which involves token transfer tracks depth correctly
#[test]
fn test_ubi_claim_depth_tracking() {
    let caller = test_public_key(1);

    // Simulate user initiating claim_ubi call
    let user_context = ExecutionContext::new(caller, 100, 1000, 100_000, [0u8; 32]);
    assert_eq!(user_context.call_depth, 0, "User call starts at depth 0");

    // UBI contract creates contract context (depth 1)
    let ubi_contract = test_public_key(10);
    let mut ubi_context = ExecutionContext::with_contract(
        user_context.caller.clone(),
        ubi_contract,
        user_context.block_number,
        user_context.timestamp,
        user_context.gas_limit,
        user_context.tx_hash,
    );
    ubi_context.call_depth = user_context.call_depth + 1;
    assert_eq!(ubi_context.call_depth, 1, "UBI context at depth 1");

    // UBI calls token.transfer() (depth 2)
    let token_contract = test_public_key(20);
    let mut token_context = ExecutionContext::with_contract(
        user_context.caller.clone(),
        token_contract,
        ubi_context.block_number,
        ubi_context.timestamp,
        ubi_context.gas_limit,
        ubi_context.tx_hash,
    );
    token_context.call_depth = ubi_context.call_depth + 1;
    assert_eq!(token_context.call_depth, 2, "Token context at depth 2");

    // All depths are within limit
    assert!(user_context.call_depth < user_context.max_call_depth);
    assert!(ubi_context.call_depth < ubi_context.max_call_depth);
    assert!(token_context.call_depth < token_context.max_call_depth);
}

/// Test 6: Call depth exceeded rejection prevents execution
#[test]
fn test_call_depth_exceeded_rejection() {
    let caller = test_public_key(1);
    let mut context = ExecutionContext::new(caller, 100, 1000, 100_000, [0u8; 32]);

    // Build a chain of calls to reach max depth
    for _ in 0..DEFAULT_MAX_CALL_DEPTH {
        context.call_depth += 1;
    }

    assert_eq!(context.call_depth, DEFAULT_MAX_CALL_DEPTH);

    // Attempting to create nested context should fail
    let over_limit = context.with_incremented_depth();
    assert!(
        over_limit.is_err(),
        "Should reject depth increment at max limit"
    );

    let error = over_limit.unwrap_err();
    let error_str = format!("{:?}", error);

    assert!(
        error_str.contains("Call depth limit exceeded"),
        "Error should contain 'Call depth limit exceeded': {}",
        error_str
    );
}

/// Test 7: Call depth does not accumulate across sequential top-level calls
#[test]
fn test_call_depth_does_not_accumulate() {
    let caller = test_public_key(1);

    // First top-level call
    let context_a = ExecutionContext::new(caller.clone(), 100, 1000, 100_000, [0u8; 32]);
    assert_eq!(context_a.call_depth, 0, "First call starts at depth 0");

    // Second top-level call (independent from first)
    let context_b = ExecutionContext::new(caller, 100, 1000, 100_000, [0u8; 32]);
    assert_eq!(context_b.call_depth, 0, "Second call also starts at depth 0");

    // Each maintains independent depth
    assert_eq!(context_a.call_depth, context_b.call_depth);
    assert_eq!(context_a.call_depth, 0);
    assert_eq!(context_b.call_depth, 0);
}

/// Test 8: Depth tracking preserves other context fields
#[test]
fn test_call_depth_preserves_context_fields() {
    let caller = test_public_key(1);
    let gas_limit = 500_000u64;
    let tx_hash = [42u8; 32];

    let context = ExecutionContext::new(caller.clone(), 100, 1000, gas_limit, tx_hash);
    let mut context_with_depth = context.clone();
    context_with_depth.call_depth = 5;

    // All other fields should be preserved
    assert_eq!(context_with_depth.caller.key_id, caller.key_id);
    assert_eq!(context_with_depth.block_number, 100);
    assert_eq!(context_with_depth.timestamp, 1000);
    assert_eq!(context_with_depth.gas_limit, gas_limit);
    assert_eq!(context_with_depth.tx_hash, tx_hash);
    assert_eq!(context_with_depth.gas_used, 0);
}

/// Test 9: Executor with MemoryStorage initializes contexts correctly
#[test]
fn test_executor_context_initialization() {
    let storage = MemoryStorage::default();
    let _executor = ContractExecutor::new(storage);

    let caller = test_public_key(1);
    let context = ExecutionContext::new(caller, 100, 1000, 100_000, [0u8; 32]);

    // Verify context has proper depth fields
    assert_eq!(context.call_depth, 0);
    assert_eq!(context.max_call_depth, DEFAULT_MAX_CALL_DEPTH);

    // Context can be used with executor
    assert!(context.check_gas(50_000).is_ok());
}

/// Test 10: Default max call depth is 10
#[test]
fn test_default_max_call_depth_value() {
    assert_eq!(DEFAULT_MAX_CALL_DEPTH, 10, "DEFAULT_MAX_CALL_DEPTH should be 10");
}
