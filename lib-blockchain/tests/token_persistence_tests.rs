//! Token Persistence Tests
//!
//! Test suite for atomic persistence mechanism for token state.

use lib_blockchain::contracts::executor::{
    ContractExecutor, MemoryStorage, SystemConfig,
};
use lib_blockchain::integration::crypto_integration::PublicKey;
use anyhow::Result;

/// Helper to create a test public key
fn test_public_key(id: u8) -> PublicKey {
    PublicKey {
        dilithium_pk: vec![id],
        kyber_pk: vec![id],
        key_id: [id; 32],
    }
}

/// Helper to create a test system config (by reference)
fn test_system_config(governance_id: u8) -> SystemConfig {
    SystemConfig {
        governance_authority: test_public_key(governance_id),
        blocks_per_month: 2592000, // 30 days at 1 block per second
    }
}

/// Test 1: System initialization succeeds
#[test]
fn test_system_initialization() -> Result<()> {
    let storage = MemoryStorage::default();
    let mut executor = ContractExecutor::new(storage);

    // Initialize system
    let result = executor.init_system(test_system_config(1));
    assert!(result.is_ok(), "System initialization should succeed");

    Ok(())
}

/// Test 2: Get system config after initialization
#[test]
fn test_get_system_config() -> Result<()> {
    let storage = MemoryStorage::default();
    let mut executor = ContractExecutor::new(storage);

    // Initialize system
    executor.init_system(test_system_config(1))?;

    // Get system config
    let config = executor.get_system_config()?;
    assert_eq!(config.governance_authority.key_id, test_public_key(1).key_id);

    Ok(())
}

/// Test 3: SOV can be loaded after initialization
#[test]
fn test_sov_loads_after_init() -> Result<()> {
    let storage = MemoryStorage::default();
    let mut executor = ContractExecutor::new(storage);

    // Initialize system
    executor.init_system(test_system_config(1))?;

    // Get SOV
    let sov = executor.get_or_load_sov()?;
    assert_eq!(sov.name, "Sovereign");
    assert_eq!(sov.symbol, "SOV");

    Ok(())
}

/// Test 4: SOV loads consistently across calls
#[test]
fn test_sov_loads_consistently() -> Result<()> {
    let storage = MemoryStorage::default();
    let mut executor = ContractExecutor::new(storage);

    executor.init_system(test_system_config(1))?;

    // Load SOV twice
    let id1 = executor.get_or_load_sov()?.token_id;
    let id2 = executor.get_or_load_sov()?.token_id;

    assert_eq!(id1, id2, "SOV token IDs should be consistent");

    Ok(())
}

/// Test 5: Begin block creates staging area
#[test]
fn test_begin_block_creates_staging() -> Result<()> {
    let storage = MemoryStorage::default();
    let mut executor = ContractExecutor::new(storage);

    executor.init_system(test_system_config(1))?;

    // Begin block
    executor.begin_block(1);

    // Should be able to finalize immediately
    let result = executor.finalize_block_state(1);
    assert!(result.is_ok());

    Ok(())
}

/// Test 6: Finalize with wrong block height fails
#[test]
fn test_finalize_wrong_block_height_fails() -> Result<()> {
    let storage = MemoryStorage::default();
    let mut executor = ContractExecutor::new(storage);

    executor.init_system(test_system_config(1))?;
    executor.begin_block(1);

    // Try to finalize wrong height
    let result = executor.finalize_block_state(2);
    assert!(result.is_err(), "Finalizing wrong block height should fail");

    Ok(())
}

/// Test 7: Rollback clears staging
#[test]
fn test_rollback_clears_staging() -> Result<()> {
    let storage = MemoryStorage::default();
    let mut executor = ContractExecutor::new(storage);

    executor.init_system(test_system_config(1))?;

    // Begin and rollback
    executor.begin_block(1);
    executor.rollback_pending_state();

    // Should be able to start new block
    executor.begin_block(2);
    let result = executor.finalize_block_state(2);
    assert!(result.is_ok());

    Ok(())
}

/// Test 8: Multiple sequential blocks
#[test]
fn test_multiple_sequential_blocks() -> Result<()> {
    let storage = MemoryStorage::default();
    let mut executor = ContractExecutor::new(storage);

    executor.init_system(test_system_config(1))?;

    // Process blocks 1-3
    for block_height in 1..=3 {
        executor.begin_block(block_height);
        executor.finalize_block_state(block_height)?;
    }

    Ok(())
}

/// Test 9: Finalize without begin returns ok
#[test]
fn test_finalize_without_begin_returns_ok() -> Result<()> {
    let storage = MemoryStorage::default();
    let mut executor = ContractExecutor::new(storage);

    executor.init_system(test_system_config(1))?;

    // Try to finalize without begin (should be ok, no pending changes)
    let result = executor.finalize_block_state(1);
    assert!(result.is_ok(), "Finalizing with no pending changes should be ok");

    Ok(())
}

/// Test 10: Executor can be created multiple times
#[test]
fn test_multiple_executor_instances() -> Result<()> {
    let storage1 = MemoryStorage::default();
    let storage2 = MemoryStorage::default();

    let mut executor1 = ContractExecutor::new(storage1);
    let mut executor2 = ContractExecutor::new(storage2);

    // Both should initialize independently
    executor1.init_system(test_system_config(1))?;
    executor2.init_system(test_system_config(1))?;

    // Both should have SOV
    let sov1 = executor1.get_or_load_sov()?;
    let sov2 = executor2.get_or_load_sov()?;

    assert_eq!(sov1.name, sov2.name);

    Ok(())
}

/// Test 11: Token transfer with staging
#[test]
fn test_token_transfer_with_staging() -> Result<()> {
    use lib_blockchain::types::contract_call::ContractCall;
    use lib_blockchain::contracts::executor::{ExecutionContext, CallOrigin};

    let storage = MemoryStorage::default();
    let mut executor = ContractExecutor::new(storage);
    executor.init_system(test_system_config(1))?;

    // Create custom token
    let creator = test_public_key(1);
    let mut context = ExecutionContext {
        caller: creator.clone(),
        contract: test_public_key(0),
        call_origin: CallOrigin::User,
        block_number: 1,
        timestamp: 1000000,
        gas_limit: 1000000,
        gas_used: 0,
        tx_hash: [1u8; 32],
        call_depth: 0,
        max_call_depth: 10,
    };

    let call = ContractCall::token_call(
        "create_custom_token".to_string(),
        bincode::serialize(&("TestToken".to_string(), "TEST".to_string(), 1000000u64))?
    );

    let result = executor.execute_call(call, &mut context)?;
    let token_id: [u8; 32] = bincode::deserialize(&result.return_data)?;

    // Begin block for staging
    executor.begin_block(1);

    // Transfer tokens
    let recipient = test_public_key(2);
    let transfer_call = ContractCall::token_call(
        "transfer".to_string(),
        bincode::serialize(&(token_id, recipient.clone(), 1000u64))?
    );

    let transfer_result = executor.execute_call(transfer_call, &mut context)?;
    assert!(transfer_result.success, "Transfer should succeed");

    // Finalize block
    executor.finalize_block_state(1)?;

    // Verify balance persisted
    let balance_call = ContractCall::token_call(
        "balance_of".to_string(),
        bincode::serialize(&(token_id, recipient))?
    );

    let balance_result = executor.execute_call(balance_call, &mut context)?;
    let balance: u64 = bincode::deserialize(&balance_result.return_data)?;
    assert_eq!(balance, 1000, "Recipient should have 1000 tokens after finalization");

    Ok(())
}

/// Test 12: Token mint with staging
#[test]
fn test_token_mint_with_staging() -> Result<()> {
    use lib_blockchain::types::contract_call::ContractCall;
    use lib_blockchain::contracts::executor::{ExecutionContext, CallOrigin};

    let storage = MemoryStorage::default();
    let mut executor = ContractExecutor::new(storage);
    executor.init_system(test_system_config(1))?;

    // Create custom token
    let creator = test_public_key(1);
    let mut context = ExecutionContext {
        caller: creator.clone(),
        contract: test_public_key(0),
        call_origin: CallOrigin::User,
        block_number: 1,
        timestamp: 1000000,
        gas_limit: 1000000,
        gas_used: 0,
        tx_hash: [1u8; 32],
        call_depth: 0,
        max_call_depth: 10,
    };

    let call = ContractCall::token_call("create_custom_token".to_string(), bincode::serialize(&("TestToken".to_string(), "TEST".to_string(), 1000000u64))?
    );

    let result = executor.execute_call(call, &mut context)?;
    let token_id: [u8; 32] = bincode::deserialize(&result.return_data)?;

    // Begin block for staging
    executor.begin_block(1);

    // Mint tokens
    let recipient = test_public_key(2);
    let mint_call = ContractCall::token_call("mint".to_string(), bincode::serialize(&(token_id, recipient.clone(), 5000u64))?,
    );

    let mint_result = executor.execute_call(mint_call, &mut context)?;
    assert!(mint_result.success, "Mint should succeed");

    // Finalize block
    executor.finalize_block_state(1)?;

    // Verify balance persisted
    let balance_call = ContractCall::token_call("balance_of".to_string(), bincode::serialize(&(token_id, recipient))?,
    );

    let balance_result = executor.execute_call(balance_call, &mut context)?;
    let balance: u64 = bincode::deserialize(&balance_result.return_data)?;
    assert_eq!(balance, 5000, "Recipient should have 5000 minted tokens after finalization");

    Ok(())
}

/// Test 13: WAL recovery mechanism exists
#[test]
fn test_wal_key_generation() -> Result<()> {
    // This test verifies the Write-Ahead Log mechanism exists
    // The WAL key is generated for each block height
    // It's used to ensure atomic persistence of block state changes
    use lib_blockchain::contracts::utils::generate_storage_key;
    
    let block_height = 100u64;
    let wal_key = generate_storage_key("block_state_wal", &block_height.to_be_bytes());
    
    // Verify the key is generated correctly
    assert!(!wal_key.is_empty(), "WAL key should not be empty");
    
    // Different block heights should produce different keys
    let wal_key2 = generate_storage_key("block_state_wal", &101u64.to_be_bytes());
    assert_ne!(wal_key, wal_key2, "Different block heights should have different WAL keys");
    
    Ok(())
}

/// Test 14: Multiple token operations in single block
#[test]
fn test_multiple_token_operations_in_block() -> Result<()> {
    use lib_blockchain::types::contract_call::ContractCall;
    use lib_blockchain::contracts::executor::{ExecutionContext, CallOrigin};

    let storage = MemoryStorage::default();
    let mut executor = ContractExecutor::new(storage);
    executor.init_system(test_system_config(1))?;

    // Create custom token
    let creator = test_public_key(1);
    let mut context = ExecutionContext {
        caller: creator.clone(),
        contract: test_public_key(0),
        call_origin: CallOrigin::User,
        block_number: 1,
        timestamp: 1000000,
        gas_limit: 1000000,
        gas_used: 0,
        tx_hash: [1u8; 32],
        call_depth: 0,
        max_call_depth: 10,
    };

    let call = ContractCall::token_call("create_custom_token".to_string(), bincode::serialize(&("TestToken".to_string(), "TEST".to_string(), 1000000u64))?
    );

    let result = executor.execute_call(call, &mut context)?;
    let token_id: [u8; 32] = bincode::deserialize(&result.return_data)?;

    // Begin block for staging
    executor.begin_block(1);

    // Perform multiple operations
    let recipient1 = test_public_key(2);
    let recipient2 = test_public_key(3);

    // Transfer to recipient1
    let transfer1 = ContractCall::token_call("transfer".to_string(), bincode::serialize(&(token_id, recipient1.clone(), 1000u64))?,
    );
    executor.execute_call(transfer1, &mut context)?;

    // Transfer to recipient2
    let transfer2 = ContractCall::token_call("transfer".to_string(), bincode::serialize(&(token_id, recipient2.clone(), 2000u64))?,
    );
    executor.execute_call(transfer2, &mut context)?;

    // Finalize all changes atomically
    executor.finalize_block_state(1)?;

    // Verify both balances persisted
    let balance1_call = ContractCall::token_call("balance_of".to_string(), bincode::serialize(&(token_id, recipient1))?,
    );
    let balance1_result = executor.execute_call(balance1_call, &mut context)?;
    let balance1: u64 = bincode::deserialize(&balance1_result.return_data)?;

    let balance2_call = ContractCall::token_call("balance_of".to_string(), bincode::serialize(&(token_id, recipient2))?,
    );
    let balance2_result = executor.execute_call(balance2_call, &mut context)?;
    let balance2: u64 = bincode::deserialize(&balance2_result.return_data)?;

    assert_eq!(balance1, 1000, "Recipient1 should have 1000 tokens");
    assert_eq!(balance2, 2000, "Recipient2 should have 2000 tokens");

    Ok(())
}
