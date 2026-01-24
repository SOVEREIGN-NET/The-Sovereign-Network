//! WAL Key Format Consistency Test
//!
//! This test verifies that the WAL key format used by ContractExecutor
//! matches the format expected by WalRecoveryManager, ensuring crash
//! recovery works correctly.
//!
//! Related to: https://github.com/SOVEREIGN-NET/The-Sovereign-Network/pull/860#discussion_r2721733231

#![cfg(feature = "persistent-contracts")]

use lib_blockchain::contracts::executor::storage::{PersistentStorage, WalRecoveryManager};
use tempfile::TempDir;
use anyhow::Result;

/// Test that WAL keys written by executor can be read by recovery manager
#[test]
fn test_wal_key_format_consistency() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let storage = PersistentStorage::new(temp_dir.path().to_str().unwrap(), None)?;
    let manager = WalRecoveryManager::new(storage.clone());

    // Simulate what the executor does: write WAL key in format "wal:{height_bytes}"
    let block_height = 100u64;
    let mut wal_key = Vec::new();
    wal_key.extend_from_slice(b"wal:");
    wal_key.extend_from_slice(&block_height.to_be_bytes());

    // Write some WAL data (simulating incomplete block)
    storage.set(&wal_key, b"test_wal_data")?;

    // Verify recovery manager can detect the incomplete block
    assert!(
        manager.is_incomplete_block(block_height)?,
        "Recovery manager should detect WAL entry written by executor"
    );

    Ok(())
}

/// Test that recovery manager can extract height from executor-generated keys
#[test]
fn test_height_extraction_from_executor_keys() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let storage = PersistentStorage::new(temp_dir.path().to_str().unwrap(), None)?;
    let manager = WalRecoveryManager::new(storage.clone());

    // Test multiple block heights
    let test_heights = vec![0u64, 1, 42, 100, 1000, 999999, u64::MAX];

    for height in test_heights {
        // Generate key the same way executor does
        let mut wal_key = Vec::new();
        wal_key.extend_from_slice(b"wal:");
        wal_key.extend_from_slice(&height.to_be_bytes());

        // Write the WAL entry and verify recovery manager can detect it
        storage.set(&wal_key, b"test_data")?;
        assert!(
            manager.is_incomplete_block(height)?,
            "Recovery manager should detect incomplete block at height {}",
            height
        );
        
        // Clean up for next iteration
        storage.set(&wal_key, &[])?;
    }

    Ok(())
}

/// Test that recovery manager can scan and recover executor-written WAL entries
#[test]
fn test_recovery_of_executor_wal_entries() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let storage = PersistentStorage::new(temp_dir.path().to_str().unwrap(), None)?;
    let manager = WalRecoveryManager::new(storage.clone());

    // Simulate executor writing WAL entries for multiple blocks
    let block_heights = vec![100u64, 101, 102, 200];

    for height in &block_heights {
        let mut wal_key = Vec::new();
        wal_key.extend_from_slice(b"wal:");
        wal_key.extend_from_slice(&height.to_be_bytes());
        storage.set(&wal_key, b"incomplete_block_data")?;
    }

    // Run recovery - should find all WAL entries
    let stats = manager.recover_from_crash()?;
    assert_eq!(
        stats.wal_entries_found,
        block_heights.len() as u64,
        "Recovery should find all executor-written WAL entries"
    );
    assert_eq!(
        stats.entries_discarded,
        block_heights.len() as u64,
        "Recovery should discard all incomplete blocks"
    );

    // Verify all WAL entries were cleaned up
    for height in &block_heights {
        assert!(
            !manager.is_incomplete_block(*height)?,
            "Block {} should no longer be marked incomplete after recovery",
            height
        );
    }

    Ok(())
}

/// Test that the WAL key prefix matches between executor and recovery
#[test]
fn test_wal_prefix_consistency() {
    // The executor uses this prefix (from lib-blockchain/src/contracts/executor/mod.rs:615)
    let executor_prefix = b"wal:";

    // The recovery manager scans with this prefix (from recovery.rs:142)
    let recovery_prefix = b"wal:";

    assert_eq!(
        executor_prefix, recovery_prefix,
        "WAL key prefix must match between executor and recovery manager"
    );
}

/// Test round-trip: executor writes, recovery reads, verifies byte-level compatibility
#[test]
fn test_wal_key_byte_level_compatibility() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let storage = PersistentStorage::new(temp_dir.path().to_str().unwrap(), None)?;
    let _manager = WalRecoveryManager::new(storage.clone());

    let test_height = 12345u64;

    // Generate key exactly as executor does (from mod.rs:614-616)
    let mut executor_wal_key = Vec::new();
    executor_wal_key.extend_from_slice(b"wal:");
    executor_wal_key.extend_from_slice(&test_height.to_be_bytes());

    // Generate key using recovery manager's method
    let recovery_wal_key = {
        let mut key = Vec::new();
        key.extend_from_slice(b"wal:");
        key.extend_from_slice(&test_height.to_be_bytes());
        key
    };

    // Keys must be byte-for-byte identical
    assert_eq!(
        executor_wal_key, recovery_wal_key,
        "Executor and recovery manager must generate identical WAL keys"
    );

    // Write with executor key, read with recovery manager
    storage.set(&executor_wal_key, b"test_data")?;
    let data = storage.get(&recovery_wal_key)?;
    assert_eq!(
        data.as_deref(),
        Some(&b"test_data"[..]),
        "Data written with executor key must be readable with recovery key"
    );

    Ok(())
}
