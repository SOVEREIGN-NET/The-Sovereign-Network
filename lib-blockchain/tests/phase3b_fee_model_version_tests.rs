//! Phase 3B Fee Model Version Tests
//!
//! Tests for fee model version validation at activation boundaries.
//! Requirements:
//! - Block at height H-1 with v1 accepted, v2 rejected
//! - Block at height H with v2 accepted, v1 rejected
//! - Chain import validates the same

use std::sync::Arc;
use tempfile::TempDir;

use lib_blockchain::block::{Block, BlockHeader};
use lib_blockchain::execution::{BlockExecutor, ExecutorConfig, BlockApplyError};
use lib_blockchain::protocol::{ProtocolParams, fee_model};
use lib_blockchain::storage::{BlockchainStore, SledStore};
use lib_blockchain::sync::ChainSync;
use lib_blockchain::types::{Difficulty, Hash};

// =============================================================================
// Test Helpers
// =============================================================================

fn create_test_store() -> (TempDir, Arc<dyn BlockchainStore>) {
    let dir = TempDir::new().unwrap();
    let store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(dir.path()).unwrap());
    (dir, store)
}

fn create_executor_with_activation(store: Arc<dyn BlockchainStore>, activation_height: u64) -> BlockExecutor {
    let protocol_params = ProtocolParams::new_with_v2_activation(activation_height);
    let mut config = ExecutorConfig::default();
    config.protocol_params = protocol_params;
    BlockExecutor::from_config(store, config)
}

fn create_genesis_block(fee_model_version: u16) -> Block {
    let mut hash_bytes = [0u8; 32];
    hash_bytes[0] = 0x01;
    let block_hash = Hash::new(hash_bytes);

    let header = BlockHeader {
        version: 1,
        previous_block_hash: Hash::default(),
        merkle_root: Hash::default(),
        state_root: Hash::default(),
        timestamp: 1000,
        difficulty: Difficulty::minimum(),
        nonce: 0,
        cumulative_difficulty: Difficulty::minimum(),
        height: 0,
        block_hash,
        transaction_count: 0,
        block_size: 0,
        fee_model_version,
    };
    Block::new(header, vec![])
}

fn create_block_at_height(height: u64, prev_hash: Hash, fee_model_version: u16) -> Block {
    let mut hash_bytes = [0u8; 32];
    hash_bytes[0..8].copy_from_slice(&height.to_be_bytes());
    hash_bytes[8] = fee_model_version as u8;
    let block_hash = Hash::new(hash_bytes);

    let header = BlockHeader {
        version: 1,
        previous_block_hash: prev_hash,
        merkle_root: Hash::default(),
        state_root: Hash::default(),
        timestamp: 1000 + height * 600,
        difficulty: Difficulty::minimum(),
        nonce: 0,
        cumulative_difficulty: Difficulty::minimum(),
        height,
        block_hash,
        transaction_count: 0,
        block_size: 0,
        fee_model_version,
    };
    Block::new(header, vec![])
}

// =============================================================================
// Phase 3B Tests: Fee Model Version Validation
// =============================================================================

/// Test: Block at height H-1 with v1 accepted (before activation)
#[test]
fn test_v1_accepted_before_activation() {
    let (_dir, store) = create_test_store();
    let activation_height = 5;
    let executor = create_executor_with_activation(store.clone(), activation_height);

    // Genesis with v1
    let genesis = create_genesis_block(fee_model::VERSION_1);
    executor.apply_block(&genesis).expect("Genesis should be accepted");

    // Build chain up to H-1 (height 4) with v1
    let mut prev_hash = genesis.hash();
    for h in 1..activation_height {
        let block = create_block_at_height(h, prev_hash, fee_model::VERSION_1);
        executor.apply_block(&block).expect(&format!("Block at height {} with v1 should be accepted", h));
        prev_hash = block.hash();
    }

    // Verify chain height
    assert_eq!(store.latest_height().unwrap(), activation_height - 1);
}

/// Test: Block at height H-1 with v2 rejected (before activation)
#[test]
fn test_v2_rejected_before_activation() {
    let (_dir, store) = create_test_store();
    let activation_height = 5;
    let executor = create_executor_with_activation(store.clone(), activation_height);

    // Genesis with v1 (correct for height 0 before activation)
    let genesis = create_genesis_block(fee_model::VERSION_1);
    executor.apply_block(&genesis).expect("Genesis should be accepted");

    // Build chain up to H-2 with v1
    let mut prev_hash = genesis.hash();
    for h in 1..(activation_height - 1) {
        let block = create_block_at_height(h, prev_hash, fee_model::VERSION_1);
        executor.apply_block(&block).expect(&format!("Block at height {} with v1 should be accepted", h));
        prev_hash = block.hash();
    }

    // Try to apply block at H-1 with v2 (should be rejected)
    let h_minus_1 = activation_height - 1;
    let invalid_block = create_block_at_height(h_minus_1, prev_hash, fee_model::VERSION_2);
    let result = executor.apply_block(&invalid_block);

    assert!(result.is_err(), "Block at H-1 with v2 should be rejected");
    match result {
        Err(BlockApplyError::InvalidFeeModelVersion { height, actual, expected }) => {
            assert_eq!(height, h_minus_1);
            assert_eq!(actual, fee_model::VERSION_2);
            assert_eq!(expected, fee_model::VERSION_1);
        }
        _ => panic!("Expected InvalidFeeModelVersion error"),
    }
}

/// Test: Block at height H with v2 accepted (at activation)
#[test]
fn test_v2_accepted_at_activation() {
    let (_dir, store) = create_test_store();
    let activation_height = 5;
    let executor = create_executor_with_activation(store.clone(), activation_height);

    // Genesis with v1
    let genesis = create_genesis_block(fee_model::VERSION_1);
    executor.apply_block(&genesis).expect("Genesis should be accepted");

    // Build chain up to H-1 with v1
    let mut prev_hash = genesis.hash();
    for h in 1..activation_height {
        let block = create_block_at_height(h, prev_hash, fee_model::VERSION_1);
        executor.apply_block(&block).expect(&format!("Block at height {} with v1 should be accepted", h));
        prev_hash = block.hash();
    }

    // Apply block at H with v2 (should be accepted)
    let block_at_h = create_block_at_height(activation_height, prev_hash, fee_model::VERSION_2);
    executor.apply_block(&block_at_h).expect("Block at H with v2 should be accepted");

    // Verify chain height
    assert_eq!(store.latest_height().unwrap(), activation_height);
}

/// Test: Block at height H with v1 rejected (at activation)
#[test]
fn test_v1_rejected_at_activation() {
    let (_dir, store) = create_test_store();
    let activation_height = 5;
    let executor = create_executor_with_activation(store.clone(), activation_height);

    // Genesis with v1
    let genesis = create_genesis_block(fee_model::VERSION_1);
    executor.apply_block(&genesis).expect("Genesis should be accepted");

    // Build chain up to H-1 with v1
    let mut prev_hash = genesis.hash();
    for h in 1..activation_height {
        let block = create_block_at_height(h, prev_hash, fee_model::VERSION_1);
        executor.apply_block(&block).expect(&format!("Block at height {} with v1 should be accepted", h));
        prev_hash = block.hash();
    }

    // Try to apply block at H with v1 (should be rejected)
    let invalid_block = create_block_at_height(activation_height, prev_hash, fee_model::VERSION_1);
    let result = executor.apply_block(&invalid_block);

    assert!(result.is_err(), "Block at H with v1 should be rejected");
    match result {
        Err(BlockApplyError::InvalidFeeModelVersion { height, actual, expected }) => {
            assert_eq!(height, activation_height);
            assert_eq!(actual, fee_model::VERSION_1);
            assert_eq!(expected, fee_model::VERSION_2);
        }
        _ => panic!("Expected InvalidFeeModelVersion error"),
    }
}

/// Test: Block after activation with v2 accepted
#[test]
fn test_v2_accepted_after_activation() {
    let (_dir, store) = create_test_store();
    let activation_height = 5;
    let executor = create_executor_with_activation(store.clone(), activation_height);

    // Genesis with v1
    let genesis = create_genesis_block(fee_model::VERSION_1);
    executor.apply_block(&genesis).expect("Genesis should be accepted");

    // Build chain through activation
    let mut prev_hash = genesis.hash();
    for h in 1..activation_height {
        let block = create_block_at_height(h, prev_hash, fee_model::VERSION_1);
        executor.apply_block(&block).unwrap();
        prev_hash = block.hash();
    }

    // Apply blocks after activation with v2
    for h in activation_height..activation_height + 3 {
        let block = create_block_at_height(h, prev_hash, fee_model::VERSION_2);
        executor.apply_block(&block).expect(&format!("Block at height {} with v2 should be accepted", h));
        prev_hash = block.hash();
    }

    assert_eq!(store.latest_height().unwrap(), activation_height + 2);
}

/// Test: Block after activation with v1 rejected
#[test]
fn test_v1_rejected_after_activation() {
    let (_dir, store) = create_test_store();
    let activation_height = 5;
    let executor = create_executor_with_activation(store.clone(), activation_height);

    // Genesis with v1
    let genesis = create_genesis_block(fee_model::VERSION_1);
    executor.apply_block(&genesis).expect("Genesis should be accepted");

    // Build chain through activation
    let mut prev_hash = genesis.hash();
    for h in 1..activation_height {
        let block = create_block_at_height(h, prev_hash, fee_model::VERSION_1);
        executor.apply_block(&block).unwrap();
        prev_hash = block.hash();
    }

    // Apply block at activation with v2
    let block_at_h = create_block_at_height(activation_height, prev_hash, fee_model::VERSION_2);
    executor.apply_block(&block_at_h).unwrap();
    prev_hash = block_at_h.hash();

    // Try to apply block after activation with v1 (should be rejected)
    let after_h = activation_height + 1;
    let invalid_block = create_block_at_height(after_h, prev_hash, fee_model::VERSION_1);
    let result = executor.apply_block(&invalid_block);

    assert!(result.is_err(), "Block after H with v1 should be rejected");
    match result {
        Err(BlockApplyError::InvalidFeeModelVersion { height, actual, expected }) => {
            assert_eq!(height, after_h);
            assert_eq!(actual, fee_model::VERSION_1);
            assert_eq!(expected, fee_model::VERSION_2);
        }
        _ => panic!("Expected InvalidFeeModelVersion error"),
    }
}

// =============================================================================
// Chain Import Tests: Validates fee model version through import
// =============================================================================

/// Helper to build a chain of blocks with specified fee model versions
fn build_chain_with_versions(heights_and_versions: &[(u64, u16)]) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut prev_hash = Hash::default();

    for &(h, version) in heights_and_versions {
        let block = if h == 0 {
            create_genesis_block(version)
        } else {
            create_block_at_height(h, prev_hash, version)
        };
        prev_hash = block.hash();
        blocks.push(block);
    }

    blocks
}

/// Test: Chain import validates fee model version (v1 before activation accepted)
#[test]
fn test_chain_import_validates_v1_before_activation() {
    let activation_height = 5u64;

    // Build blocks with correct v1 before activation
    let heights_and_versions: Vec<(u64, u16)> = (0..activation_height)
        .map(|h| (h, fee_model::VERSION_1))
        .collect();
    let blocks = build_chain_with_versions(&heights_and_versions);
    assert_eq!(blocks.len(), activation_height as usize);

    // Import to new chain with same activation
    let (_dest_dir, dest_store) = create_test_store();
    let protocol_params = ProtocolParams::new_with_v2_activation(activation_height);
    let dest_sync = ChainSync::with_protocol_params(dest_store.clone(), protocol_params);

    dest_sync.import_blocks(blocks).expect("Import should succeed with correct versions");
    assert_eq!(dest_store.latest_height().unwrap(), activation_height - 1);
}

/// Test: Chain import rejects v2 at H-1 (before activation)
#[test]
fn test_chain_import_rejects_v2_before_activation() {
    let activation_height = 5u64;

    // Build blocks with v1, but WRONG v2 at H-1
    let mut heights_and_versions: Vec<(u64, u16)> = (0..(activation_height - 1))
        .map(|h| (h, fee_model::VERSION_1))
        .collect();
    // Last block before activation with wrong v2
    heights_and_versions.push((activation_height - 1, fee_model::VERSION_2));

    let blocks = build_chain_with_versions(&heights_and_versions);

    // Import to new chain should fail
    let (_dest_dir, dest_store) = create_test_store();
    let protocol_params = ProtocolParams::new_with_v2_activation(activation_height);
    let dest_sync = ChainSync::with_protocol_params(dest_store.clone(), protocol_params);

    let result = dest_sync.import_blocks(blocks);
    assert!(result.is_err(), "Import should fail with wrong version at H-1");
}

/// Test: Chain import validates v2 at H accepted
#[test]
fn test_chain_import_validates_v2_at_activation() {
    let activation_height = 5u64;

    // Build blocks with v1 before activation, v2 at activation
    let mut heights_and_versions: Vec<(u64, u16)> = (0..activation_height)
        .map(|h| (h, fee_model::VERSION_1))
        .collect();
    heights_and_versions.push((activation_height, fee_model::VERSION_2));

    let blocks = build_chain_with_versions(&heights_and_versions);
    assert_eq!(blocks.len(), (activation_height + 1) as usize);

    // Import to new chain
    let (_dest_dir, dest_store) = create_test_store();
    let protocol_params = ProtocolParams::new_with_v2_activation(activation_height);
    let dest_sync = ChainSync::with_protocol_params(dest_store.clone(), protocol_params);

    dest_sync.import_blocks(blocks).expect("Import should succeed");
    assert_eq!(dest_store.latest_height().unwrap(), activation_height);
}

/// Test: Chain import rejects v1 at H (at activation)
#[test]
fn test_chain_import_rejects_v1_at_activation() {
    let activation_height = 5u64;

    // Build blocks with v1 before and AT activation (wrong at activation)
    let heights_and_versions: Vec<(u64, u16)> = (0..=activation_height)
        .map(|h| (h, fee_model::VERSION_1))
        .collect();

    let blocks = build_chain_with_versions(&heights_and_versions);

    // Import to new chain should fail at height H
    let (_dest_dir, dest_store) = create_test_store();
    let protocol_params = ProtocolParams::new_with_v2_activation(activation_height);
    let dest_sync = ChainSync::with_protocol_params(dest_store.clone(), protocol_params);

    let result = dest_sync.import_blocks(blocks);
    assert!(result.is_err(), "Import should fail with wrong version at H");
}

// =============================================================================
// Edge Cases
// =============================================================================

/// Test: Activation at height 0 (v2 from genesis)
#[test]
fn test_v2_from_genesis() {
    let (_dir, store) = create_test_store();
    let executor = create_executor_with_activation(store.clone(), 0);

    // Genesis must be v2
    let genesis_v2 = create_genesis_block(fee_model::VERSION_2);
    executor.apply_block(&genesis_v2).expect("Genesis with v2 should be accepted");

    // Genesis with v1 should be rejected
    let (_dir2, store2) = create_test_store();
    let executor2 = create_executor_with_activation(store2.clone(), 0);

    let genesis_v1 = create_genesis_block(fee_model::VERSION_1);
    let result = executor2.apply_block(&genesis_v1);
    assert!(result.is_err(), "Genesis with v1 should be rejected when activation is at height 0");
}

/// Test: ProtocolParams deterministically computes version
#[test]
fn test_protocol_params_deterministic() {
    let params1 = ProtocolParams::new_with_v2_activation(100);
    let params2 = ProtocolParams::new_with_v2_activation(100);

    // Same activation height should give same versions
    for h in 0..200 {
        assert_eq!(
            params1.active_fee_model_version(h),
            params2.active_fee_model_version(h),
            "Version should be deterministic at height {}", h
        );
    }

    // Check boundary
    assert_eq!(params1.active_fee_model_version(99), fee_model::VERSION_1);
    assert_eq!(params1.active_fee_model_version(100), fee_model::VERSION_2);
    assert_eq!(params1.active_fee_model_version(101), fee_model::VERSION_2);
}

/// Test: Different activation heights give different behavior
#[test]
fn test_different_activation_heights() {
    let params_early = ProtocolParams::new_with_v2_activation(50);
    let params_late = ProtocolParams::new_with_v2_activation(100);

    // At height 75: early has v2, late has v1
    assert_eq!(params_early.active_fee_model_version(75), fee_model::VERSION_2);
    assert_eq!(params_late.active_fee_model_version(75), fee_model::VERSION_1);
}
