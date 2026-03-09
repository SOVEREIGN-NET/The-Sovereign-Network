//! ORACLE-16: Oracle persistence integration tests
//!
//! Tests that oracle state survives:
//! - Blockchain restart (save → load round-trip)
//! - BlockchainImport round-trip (export → import) - requires ORACLE-10 completion

use lib_blockchain::{
    oracle::{FinalizedOraclePrice, OracleConfig},
    Blockchain,
};
use tempfile::tempdir;

mod common;
use common::oracle_harness::OracleTestHarness;

#[test]
fn test_oracle_state_survives_blockchain_restart() {
    // Create harness and finalize a price
    let mut harness = OracleTestHarness::new(4);
    let epoch = harness.current_epoch();
    harness.finalize_epoch(epoch, 100_000_000);

    // Verify state before save
    assert_eq!(harness.blockchain.oracle_state.finalized_prices_len(), 1);
    let committee_before = harness.blockchain.oracle_state.committee.members().to_vec();

    // Set last_oracle_epoch_processed to prevent apply_pending_updates during load
    harness.blockchain.last_oracle_epoch_processed = harness.blockchain.last_committed_timestamp();

    // Save to temp file
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.dat");
    #[allow(deprecated)]
    harness.blockchain.save_to_file(&path).unwrap();

    // Reload blockchain
    #[allow(deprecated)]
    let reloaded = Blockchain::load_from_file(&path).unwrap();

    // Verify oracle state survived
    assert_eq!(
        reloaded.oracle_state.finalized_prices_len(),
        harness.blockchain.oracle_state.finalized_prices_len(),
        "finalized prices count should match after reload"
    );

    assert_eq!(
        reloaded.oracle_state.committee.members(),
        committee_before,
        "committee members should match after reload"
    );

    // Verify the finalized price is accessible
    let price = reloaded.oracle_state.finalized_price(epoch);
    assert!(
        price.is_some(),
        "finalized price should be accessible after reload"
    );
    assert_eq!(price.unwrap().sov_usd_price, 100_000_000);
}

#[test]
fn test_oracle_state_in_blockchain_import() {
    // ORACLE-10: Verify oracle_state is included in BlockchainImport/export
    let mut harness = OracleTestHarness::new(4);

    // Finalize prices for current epoch and next epoch
    let epoch1 = harness.current_epoch();
    harness.finalize_epoch(epoch1, 100_000_000);

    harness.advance_oracle_epoch();
    let epoch2 = harness.current_epoch();
    harness.finalize_epoch(epoch2, 101_000_000);

    // Verify prices are finalized
    assert_eq!(
        harness.blockchain.oracle_state.finalized_prices_len(),
        2,
        "should have 2 finalized prices before export"
    );

    // Export blockchain state
    let exported = harness
        .blockchain
        .export_chain()
        .expect("export should succeed");

    // Deserialize and verify oracle state is present
    let import: lib_blockchain::BlockchainImport =
        bincode::deserialize(&exported).expect("deserialize should succeed");

    assert!(
        import.oracle_state.is_some(),
        "oracle_state should be in export"
    );
    let oracle_state = import.oracle_state.unwrap();
    assert_eq!(
        oracle_state.finalized_prices_len(),
        2,
        "should have 2 finalized prices in import"
    );

    // Verify specific prices are present
    let price1 = oracle_state.finalized_price(epoch1);
    assert!(price1.is_some(), "price for epoch {} should exist", epoch1);
    assert_eq!(price1.unwrap().sov_usd_price, 100_000_000);

    let price2 = oracle_state.finalized_price(epoch2);
    assert!(price2.is_some(), "price for epoch {} should exist", epoch2);
    assert_eq!(price2.unwrap().sov_usd_price, 101_000_000);
}

#[test]
fn test_oracle_config_persists_across_restart() {
    let mut harness = OracleTestHarness::new(4);

    // Create custom config by modifying default
    let mut custom_config = OracleConfig::default();
    custom_config.epoch_duration_secs = 600; // 10 minutes
    custom_config.max_source_age_secs = 300;
    custom_config.max_deviation_bps = 500;
    custom_config.max_price_staleness_epochs = 5;

    // Schedule config update for future activation
    let current_epoch = harness.current_epoch();
    harness
        .schedule_config_update(custom_config.clone(), current_epoch + 1)
        .expect("config update should be valid");

    // Apply the update at the target epoch
    harness
        .blockchain
        .oracle_state
        .apply_pending_updates(current_epoch + 1);

    // Verify config changed
    assert_eq!(
        harness.blockchain.oracle_state.config().epoch_duration_secs,
        600
    );

    // Save and reload
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.dat");
    #[allow(deprecated)]
    harness.blockchain.save_to_file(&path).unwrap();

    #[allow(deprecated)]
    let reloaded = Blockchain::load_from_file(&path).unwrap();

    // Verify config persisted
    assert_eq!(reloaded.oracle_state.config().epoch_duration_secs, 600);
    assert_eq!(reloaded.oracle_state.config().max_source_age_secs, 300);
    assert_eq!(reloaded.oracle_state.config().max_deviation_bps, 500);
}

#[test]
fn test_pending_updates_persist_across_restart() {
    let mut harness = OracleTestHarness::new(4);

    // Schedule a committee update for a future epoch
    let current_epoch = harness.current_epoch();
    let target_epoch = current_epoch + 5;

    // Create a smaller committee
    let new_committee = vec![
        harness.validators[0].key_id,
        harness.validators[1].key_id,
        harness.validators[2].key_id,
    ];

    harness
        .schedule_committee_update(new_committee.clone(), target_epoch)
        .expect("schedule should succeed");

    // Verify pending update exists
    assert!(harness
        .blockchain
        .oracle_state
        .committee
        .pending_update()
        .is_some());

    // Set last_oracle_epoch_processed to prevent apply_pending_updates during load
    // (the genesis timestamp creates a large epoch, which would auto-activate pending updates)
    harness.blockchain.last_oracle_epoch_processed = harness.blockchain.last_committed_timestamp();

    // Save and reload
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.dat");
    #[allow(deprecated)]
    harness.blockchain.save_to_file(&path).unwrap();

    #[allow(deprecated)]
    let mut reloaded = Blockchain::load_from_file(&path).unwrap();

    // Verify pending update survived
    assert!(reloaded.oracle_state.committee.pending_update().is_some());

    // Apply the update at target epoch
    reloaded.oracle_state.apply_pending_updates(target_epoch);

    // Verify committee changed
    assert_eq!(reloaded.oracle_state.committee.members().len(), 3);
}
