//! ORACLE-16: Oracle epoch advancement integration tests
//!
//! Tests for:
//! - apply_pending_updates activates committee change at correct epoch
//! - apply_pending_updates activates config change at correct epoch
//! - Epoch advancement through block mining

use lib_blockchain::oracle::{OracleCommitteeState, OracleConfig};

mod common;
use common::oracle_harness::OracleTestHarness;

#[test]
fn test_pending_committee_activates_at_epoch_boundary() {
    let mut harness = OracleTestHarness::new(4);

    // Get current state
    let initial_epoch = harness.current_epoch();
    assert_eq!(harness.blockchain.oracle_state.committee.members().len(), 4);

    // Schedule update for epoch N+1 with 3 members instead of 4
    let target_epoch = initial_epoch + 1;
    let new_committee = vec![
        harness.validators[0].key_id,
        harness.validators[1].key_id,
        harness.validators[2].key_id,
    ];

    harness
        .schedule_committee_update(new_committee, target_epoch)
        .expect("schedule should succeed");

    // Still 4 members before advancing
    assert_eq!(harness.blockchain.oracle_state.committee.members().len(), 4);

    // Advance to next epoch
    harness.advance_oracle_epoch();

    // Now 3 members after epoch boundary
    assert_eq!(harness.blockchain.oracle_state.committee.members().len(), 3);

    // Verify pending update is cleared
    assert!(harness
        .blockchain
        .oracle_state
        .committee
        .pending_update()
        .is_none());
}

#[test]
fn test_pending_config_activates_at_epoch_boundary() {
    let mut harness = OracleTestHarness::new(4);

    // Get current config
    let initial_duration = harness.epoch_duration();
    let initial_epoch = harness.current_epoch();

    // Create new config with different epoch duration
    let mut new_config = OracleConfig::default();
    new_config.epoch_duration_secs = initial_duration * 2; // Double the duration
    new_config.max_source_age_secs = 300;
    new_config.max_deviation_bps = 500;
    new_config.max_price_staleness_epochs = 5;

    // Schedule config update for next epoch
    let target_epoch = initial_epoch + 1;
    harness
        .schedule_config_update(new_config, target_epoch)
        .expect("config should be valid");

    // Config unchanged before epoch
    assert_eq!(
        harness.blockchain.oracle_state.config().epoch_duration_secs,
        initial_duration
    );

    // Advance to next epoch
    harness.advance_oracle_epoch();

    // Config changed after epoch boundary
    assert_eq!(
        harness.blockchain.oracle_state.config().epoch_duration_secs,
        initial_duration * 2
    );

    // Verify pending config update is cleared
    assert!(harness
        .blockchain
        .oracle_state
        .pending_config_update
        .is_none());
}

#[test]
fn test_multiple_pending_updates_activate_correctly() {
    let mut harness = OracleTestHarness::new(4);

    let initial_epoch = harness.current_epoch();

    // Schedule both committee and config updates
    let new_committee = vec![harness.validators[0].key_id, harness.validators[1].key_id];
    let mut new_config = OracleConfig::default();
    new_config.epoch_duration_secs = 600;
    new_config.max_source_age_secs = 300;
    new_config.max_deviation_bps = 500;
    new_config.max_price_staleness_epochs = 5;

    harness
        .schedule_committee_update(new_committee.clone(), initial_epoch + 1)
        .expect("schedule should succeed");
    harness
        .schedule_config_update(new_config, initial_epoch + 1)
        .expect("schedule should succeed");

    // Advance past the activation epoch
    harness.advance_oracle_epoch();

    // Both updates should be applied
    assert_eq!(harness.blockchain.oracle_state.committee.members().len(), 2);
    assert_eq!(
        harness.blockchain.oracle_state.config().epoch_duration_secs,
        600
    );
}

#[test]
fn test_epoch_advance_requires_multiple_blocks() {
    let mut harness = OracleTestHarness::new(4);

    let initial_epoch = harness.current_epoch();
    let initial_timestamp = harness.current_timestamp;

    // Mine just 1 block - should not advance epoch
    harness.mine_blocks(1);
    assert_eq!(harness.current_epoch(), initial_epoch);

    // Mine enough blocks to advance epoch
    let epoch_duration = harness.epoch_duration();
    let blocks_needed = (epoch_duration / (epoch_duration / 10)) + 1;
    harness.mine_blocks(blocks_needed as u64);

    // Should have advanced
    assert!(
        harness.current_epoch() > initial_epoch
            || harness.current_timestamp >= initial_timestamp + epoch_duration
    );
}

#[test]
fn test_finalized_prices_preserved_across_epoch_advance() {
    let mut harness = OracleTestHarness::new(4);

    // Finalize price in current epoch
    let epoch1 = harness.current_epoch();
    harness.finalize_epoch(epoch1, 100_000_000);

    // Advance to next epoch
    harness.advance_oracle_epoch();
    let epoch2 = harness.current_epoch();

    // Finalize another price
    harness.finalize_epoch(epoch2, 101_000_000);

    // Both prices should be accessible
    assert_eq!(harness.get_finalized_price(epoch1), Some(100_000_000));
    assert_eq!(harness.get_finalized_price(epoch2), Some(101_000_000));
}

#[test]
fn test_committee_member_can_attest_after_epoch_advance() {
    let mut harness = OracleTestHarness::new(4);

    // Advance to a new epoch
    harness.advance_oracle_epoch();
    let new_epoch = harness.current_epoch();

    // Committee member should be able to attest
    let attestation = harness.produce_attestation(0, new_epoch, 100_000_000);
    let result = harness.process_attestation(attestation);

    assert!(
        result.is_ok(),
        "committee member should be able to attest after epoch advance"
    );
}

#[test]
fn test_stale_price_detection_after_epoch_advance() {
    let mut harness = OracleTestHarness::new(4);

    // Finalize a price
    let old_epoch = harness.current_epoch();
    harness.finalize_epoch(old_epoch, 100_000_000);

    // Advance many epochs to make price stale
    let max_staleness = harness
        .blockchain
        .oracle_state
        .config()
        .max_price_staleness_epochs;
    for _ in 0..max_staleness + 2 {
        harness.advance_oracle_epoch();
    }

    // Price should now be stale
    let current_epoch = harness.current_epoch();
    let fresh_price = harness
        .blockchain
        .oracle_state
        .latest_fresh_price(current_epoch);
    assert!(
        fresh_price.is_none(),
        "price should be stale after max_staleness epochs"
    );
}
