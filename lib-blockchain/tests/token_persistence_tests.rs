//! Token Persistence Tests
//!
//! Test suite for atomic persistence mechanism for token state.

use lib_blockchain::contracts::executor::{
    ContractExecutor, ExecutionContext, MemoryStorage, SystemConfig,
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

/// Test 3: ZHTP can be loaded after initialization
#[test]
fn test_zhtp_loads_after_init() -> Result<()> {
    let storage = MemoryStorage::default();
    let mut executor = ContractExecutor::new(storage);

    // Initialize system
    executor.init_system(test_system_config(1))?;

    // Get ZHTP
    let zhtp = executor.get_or_load_zhtp()?;
    assert_eq!(zhtp.name, "ZHTP");
    assert_eq!(zhtp.symbol, "ZHTP");

    Ok(())
}

/// Test 4: ZHTP loads consistently across calls
#[test]
fn test_zhtp_loads_consistently() -> Result<()> {
    let storage = MemoryStorage::default();
    let mut executor = ContractExecutor::new(storage);

    executor.init_system(test_system_config(1))?;

    // Load ZHTP twice
    let id1 = executor.get_or_load_zhtp()?.token_id;
    let id2 = executor.get_or_load_zhtp()?.token_id;

    assert_eq!(id1, id2, "ZHTP token IDs should be consistent");

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

    // Both should have ZHTP
    let zhtp1 = executor1.get_or_load_zhtp()?;
    let zhtp2 = executor2.get_or_load_zhtp()?;

    assert_eq!(zhtp1.name, zhtp2.name);

    Ok(())
}
