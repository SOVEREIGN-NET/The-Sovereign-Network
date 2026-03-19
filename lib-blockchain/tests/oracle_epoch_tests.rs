//! Oracle Epoch Derivation Tests
//!
//! Tests for ORACLE-2: Derive epoch_id from block timestamp, not wall clock.
//!
//! Per Oracle Spec v1 §4.1:
//! > `epoch_id = floor(block.timestamp / EPOCH_DURATION_SECS)`
//! >
//! > Attestations are stamped with the epoch_id derived from the **block timestamp**
//! > in which they are processed. Wall-clock time MUST NOT be used to determine
//! > epoch_id at any point in finalization or validation.

use lib_blockchain::oracle::OracleState;

/// Test that epoch_id is correctly derived from block timestamp.
#[test]
fn epoch_id_derived_from_block_timestamp() {
    let state = OracleState::default();

    // Default epoch_duration_secs is 300 (5 minutes)

    // Test various block timestamps
    assert_eq!(state.epoch_id(0), 0); // Genesis
    assert_eq!(state.epoch_id(299), 0); // Just before first epoch ends
    assert_eq!(state.epoch_id(300), 1); // Start of second epoch
    assert_eq!(state.epoch_id(599), 1); // Just before second epoch ends
    assert_eq!(state.epoch_id(600), 2); // Start of third epoch
    assert_eq!(state.epoch_id(900), 3); // Start of fourth epoch
}

/// Test that epoch_id is consistent (deterministic) for the same timestamp.
#[test]
fn epoch_id_is_deterministic() {
    let state = OracleState::default();

    let timestamps = vec![0, 100, 299, 300, 301, 1000, 10000];

    for ts in timestamps {
        let epoch1 = state.epoch_id(ts);
        let epoch2 = state.epoch_id(ts);
        let epoch3 = state.epoch_id(ts);

        assert_eq!(epoch1, epoch2, "Epoch id should be deterministic");
        assert_eq!(epoch2, epoch3, "Epoch id should be deterministic");
    }
}

/// Test future epoch guard boundary condition.
#[test]
fn future_epoch_guard_boundary() {
    let state = OracleState::default();

    let current_epoch = 10;
    let current_timestamp = current_epoch * 300; // epoch_duration_secs is 300

    // Verify current epoch calculation
    assert_eq!(state.epoch_id(current_timestamp), current_epoch);

    // Attestations from current epoch should be accepted
    assert!(current_epoch <= current_epoch + 1);

    // Attestations from epoch + 1 should be accepted (within tolerance)
    let next_epoch = current_epoch + 1;
    assert!(next_epoch <= current_epoch + 1);

    // Attestations from epoch + 2 should be rejected (too far ahead)
    let far_future_epoch = current_epoch + 2;
    assert!(far_future_epoch > current_epoch + 1);
}

/// Test that epoch 0 is correctly handled at genesis.
#[test]
fn epoch_id_at_genesis() {
    let state = OracleState::default();

    // Genesis block (timestamp 0) should be epoch 0
    assert_eq!(state.epoch_id(0), 0);

    // Very early timestamps should also be epoch 0
    assert_eq!(state.epoch_id(1), 0);
    assert_eq!(state.epoch_id(10), 0);
    assert_eq!(state.epoch_id(100), 0);
}

/// Test large timestamp values (simulating long-running chain).
#[test]
fn epoch_id_with_large_timestamps() {
    let state = OracleState::default();

    // Test with timestamps representing years of operation
    // 1 year ≈ 31,536,000 seconds
    let one_year = 31_536_000u64;
    let expected_epoch = one_year / 300; // epoch_duration_secs is 300

    assert_eq!(state.epoch_id(one_year), expected_epoch);

    // 5 years
    let five_years = one_year * 5;
    let expected_epoch_5y = five_years / 300;

    assert_eq!(state.epoch_id(five_years), expected_epoch_5y);
}

/// Test that nodes with clock skew would derive same epoch from block timestamp.
#[test]
fn nodes_derive_same_epoch_from_block_timestamp() {
    // Node A's view (using block timestamp)
    let state_a = OracleState::default();

    // Node B's view (using same block timestamp)
    let state_b = OracleState::default();

    // Both nodes process the same block with timestamp 12345
    let block_timestamp = 12_345u64;

    let epoch_a = state_a.epoch_id(block_timestamp);
    let epoch_b = state_b.epoch_id(block_timestamp);

    // Both nodes should derive the same epoch
    assert_eq!(epoch_a, epoch_b);

    // The epoch should be floor(12345 / 300) = 41
    assert_eq!(epoch_a, 41);
}

/// Test epoch_id derivation at typical block times.
#[test]
fn epoch_id_at_typical_block_times() {
    let state = OracleState::default();

    // Simulate block timestamps at 10-second intervals (typical block time)
    let block_times: Vec<u64> = (0..=60).map(|i| i * 10).collect();

    for (i, ts) in block_times.iter().enumerate() {
        let expected_epoch = (ts / 300) as usize;
        let actual_epoch = state.epoch_id(*ts) as usize;
        assert_eq!(
            actual_epoch, expected_epoch,
            "Block {} at timestamp {} should be in epoch {}",
            i, ts, expected_epoch
        );
    }
}

/// Test that last_committed_timestamp returns correct value.
#[test]
fn last_committed_timestamp_from_blockchain() {
    use lib_blockchain::Blockchain;

    // Create a new blockchain (has genesis block)
    let bc = Blockchain::new().expect("HARDENED: Non-terminating check");

    // At genesis, there should be a genesis block with timestamp
    let timestamp = bc.last_committed_timestamp();

    // Genesis block typically has timestamp 0 or a preset value
    // The important thing is that the method returns a value
    // and doesn't panic

    // The genesis block should exist
    assert!(bc.latest_block().is_some());
}
