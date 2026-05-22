//! Oracle Slashing Tests (ORACLE-4)
//!
//! Tests for double-sign and wrong-epoch slashing penalties.

use lib_blockchain::{
    oracle::{OracleCommitteeState, OracleSlashReason, OracleSlashingConfig, OracleState},
    storage::SledStore,
    types::hash::blake3_hash,
    Blockchain, ValidatorInfo,
};

/// BST-203: oracle slash events live behind the BlockchainStore. Tests that
/// previously read `blockchain.oracle_slash_events` directly must (a) attach
/// an in-memory store so the `slash_oracle_validator` write has somewhere to
/// land, and (b) read them back via the store.
fn blockchain_with_store() -> Blockchain {
    let mut blockchain = Blockchain::default();
    let store: std::sync::Arc<dyn lib_blockchain::storage::BlockchainStore> =
        std::sync::Arc::new(SledStore::open_temporary().expect("open_temporary"));
    blockchain.set_store_handle(Some(store));
    blockchain
}

fn store_slash_events(bc: &Blockchain) -> Vec<lib_blockchain::oracle::OracleSlashEvent> {
    bc.store()
        .expect("store attached")
        .iter_oracle_slash_events()
        .expect("iter_oracle_slash_events")
}

/// Create a mock validator info with given consensus_key and stake
fn create_validator_info(consensus_key: [u8; 2592], stake: u64) -> (ValidatorInfo, [u8; 32]) {
    let key_id = blake3_hash(&consensus_key).as_array();
    let info = ValidatorInfo {
        identity_id: hex::encode(key_id),
        stake,
        storage_provided: 0,
        consensus_key,
        networking_key: vec![],
        rewards_key: vec![],
        network_address: "127.0.0.1".to_string(),
        commission_rate: 0,
        status: "active".to_string(),
        registered_at: 0,
        last_activity: 0,
        blocks_validated: 0,
        slash_count: 0,
        admission_source: "test".to_string(),
        governance_proposal_id: None,
        oracle_key_id: Some(key_id),
    };
    (info, key_id)
}

/// Test that slashing reduces stake correctly with default 1% config.
#[test]
fn slashing_reduces_stake_by_one_percent() {
    let mut blockchain = blockchain_with_store();

    let consensus_key = [1u8; 2592];
    let (validator, key_id) = create_validator_info(consensus_key, 1_000_000);

    blockchain
        .insert_validator_unchecked(hex::encode(key_id), validator);

    // Default config is 1%
    assert_eq!(blockchain.oracle_slashing_config().slash_fraction_bps, 100);

    // Slash the validator
    let slashed =
        blockchain.slash_oracle_validator(key_id, OracleSlashReason::ConflictingAttestation, 100);

    // 1% of 1M = 10K
    assert_eq!(slashed, 10_000);

    // Verify stake reduced
    let v = blockchain
        .validator_registry()
        .get(&hex::encode(key_id))
        .unwrap();
    assert_eq!(v.stake, 990_000); // 1M - 10K
}

/// Test slashing with custom slash fraction.
#[test]
fn custom_slash_fraction() {
    let mut blockchain = blockchain_with_store();

    let consensus_key = [2u8; 2592];
    let (validator, key_id) = create_validator_info(consensus_key, 1_000_000);

    blockchain
        .insert_validator_unchecked(hex::encode(key_id), validator);

    // Use 5% slash fraction
    blockchain.set_oracle_slashing_config_unchecked(OracleSlashingConfig::with_slash_fraction(500));

    let slashed = blockchain.slash_oracle_validator(key_id, OracleSlashReason::WrongEpoch, 50);

    // 5% of 1M = 50K
    assert_eq!(slashed, 50_000);

    let v = blockchain
        .validator_registry()
        .get(&hex::encode(key_id))
        .unwrap();
    assert_eq!(v.stake, 950_000);
}

/// Test that slashing records the slash event.
#[test]
fn slashing_records_event() {
    let mut blockchain = blockchain_with_store();

    let consensus_key = [3u8; 2592];
    let (validator, key_id) = create_validator_info(consensus_key, 500_000);

    blockchain
        .insert_validator_unchecked(hex::encode(key_id), validator);

    blockchain.slash_oracle_validator(key_id, OracleSlashReason::ConflictingAttestation, 42);

    // Verify event recorded (via the store — BST-203)
    let events = store_slash_events(&blockchain);
    assert_eq!(events.len(), 1);

    let event = &events[0];
    assert_eq!(event.validator_key_id, key_id);
    assert_eq!(event.reason, OracleSlashReason::ConflictingAttestation);
    assert_eq!(event.epoch_id, 42);
    assert_eq!(event.slash_amount, 5_000); // 1% of 500K
    assert_eq!(event.slashed_at_height, 0); // Default height
}

/// Test that slashing bans the validator.
#[test]
fn slashing_bans_validator() {
    let mut blockchain = blockchain_with_store();

    let consensus_key = [4u8; 2592];
    let (validator, key_id) = create_validator_info(consensus_key, 100_000);

    blockchain
        .insert_validator_unchecked(hex::encode(key_id), validator);

    // Initially not banned
    assert!(!blockchain.oracle_banned_validators().contains(&key_id));

    blockchain.slash_oracle_validator(key_id, OracleSlashReason::WrongEpoch, 100);

    // Now banned
    assert!(blockchain.oracle_banned_validators().contains(&key_id));
}

/// Test that slashing removes validator from committee.
#[test]
fn slashing_removes_from_committee() {
    let mut blockchain = blockchain_with_store();

    let consensus_key = [5u8; 2592];
    let (validator, key_id) = create_validator_info(consensus_key, 100_000);

    blockchain
        .insert_validator_unchecked(hex::encode(key_id), validator);

    // Setup committee with validator
    blockchain.replace_oracle_state_unchecked(OracleState::default());
    blockchain.oracle_state_mut().committee = OracleCommitteeState::new(vec![key_id], None);

    assert!(blockchain
        .oracle_state()
        .committee
        .members()
        .contains(&key_id));

    // Slash removes from committee
    blockchain.slash_oracle_validator(key_id, OracleSlashReason::ConflictingAttestation, 100);

    // No longer in committee
    assert!(!blockchain
        .oracle_state()
        .committee
        .members()
        .contains(&key_id));
    assert!(blockchain.oracle_state().committee.members().is_empty());
}

/// Test that slashing events survive a store handle restart.
///
/// BST-203: slash events live in the BlockchainStore, not in the bincode
/// snapshot. The previous version of this test exercised
/// `bincode(Blockchain)` round-tripping; that path no longer carries slash
/// events. Equivalent guarantee for the new model: events written via
/// `slash_oracle_validator` survive a fresh `Blockchain` constructed against
/// the same store. Banned validators are still bincode-serialised (in-struct
/// HashSet) — keep that assertion.
#[test]
fn slashing_events_survive_restart() {
    let store: std::sync::Arc<dyn lib_blockchain::storage::BlockchainStore> =
        std::sync::Arc::new(SledStore::open_temporary().expect("open_temporary"));

    let mut blockchain = Blockchain::default();
    blockchain.set_store_handle(Some(std::sync::Arc::clone(&store)));

    let consensus_key = [6u8; 2592];
    let (validator, key_id) = create_validator_info(consensus_key, 100_000);

    blockchain
        .insert_validator_unchecked(hex::encode(key_id), validator);

    blockchain.slash_oracle_validator(key_id, OracleSlashReason::ConflictingAttestation, 100);

    // Banned-validator state is still in-struct → survives a bincode round-trip.
    let serialized = bincode::serialize(&blockchain).unwrap();
    let restored: Blockchain = bincode::deserialize(&serialized).unwrap();
    assert_eq!(restored.oracle_banned_validators().len(), 1);
    assert!(restored.oracle_banned_validators().contains(&key_id));

    // Slash events: read directly from the shared store handle (the "restart"
    // analogue — a new Blockchain over the same store can see the events).
    let mut restarted = Blockchain::default();
    restarted.set_store_handle(Some(std::sync::Arc::clone(&store)));
    let events = store_slash_events(&restarted);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].validator_key_id, key_id);
    assert_eq!(events[0].reason, OracleSlashReason::ConflictingAttestation);
}

/// Test slashing reason display format.
#[test]
fn slashing_reason_display() {
    assert_eq!(
        OracleSlashReason::ConflictingAttestation.to_string(),
        "conflicting_attestation"
    );
    assert_eq!(OracleSlashReason::WrongEpoch.to_string(), "wrong_epoch");
}

/// Test slashing config default.
#[test]
fn slashing_config_default_one_percent() {
    let config = OracleSlashingConfig::default();
    assert_eq!(config.slash_fraction_bps, 100); // 1%

    // Test calculation
    assert_eq!(config.calculate_slash(1_000_000), 10_000); // 1% of 1M
    assert_eq!(config.calculate_slash(100_000), 1_000); // 1% of 100K
}

/// Test slashing with zero stake (edge case).
#[test]
fn slashing_zero_stake() {
    let mut blockchain = blockchain_with_store();

    let consensus_key = [7u8; 2592];
    let (validator, key_id) = create_validator_info(consensus_key, 0);

    blockchain
        .insert_validator_unchecked(hex::encode(key_id), validator);

    let slashed = blockchain.slash_oracle_validator(key_id, OracleSlashReason::WrongEpoch, 100);

    // Nothing to slash
    assert_eq!(slashed, 0);

    // But still banned and recorded (event via store — BST-203)
    assert!(blockchain.oracle_banned_validators().contains(&key_id));
    let events = store_slash_events(&blockchain);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].slash_amount, 0);
}

/// Test multiple slash events accumulate.
#[test]
fn multiple_slashes_recorded() {
    let mut blockchain = blockchain_with_store();

    let consensus_key1 = [8u8; 2592];
    let consensus_key2 = [9u8; 2592];

    let (validator1, key_id1) = create_validator_info(consensus_key1, 100_000);
    let (validator2, key_id2) = create_validator_info(consensus_key2, 200_000);

    blockchain
        .insert_validator_unchecked(hex::encode(key_id1), validator1);
    blockchain
        .insert_validator_unchecked(hex::encode(key_id2), validator2);

    // Slash both
    blockchain.slash_oracle_validator(key_id1, OracleSlashReason::ConflictingAttestation, 100);
    blockchain.slash_oracle_validator(key_id2, OracleSlashReason::WrongEpoch, 101);

    // Both events recorded (via the store — BST-203). The store iterates
    // by (height-BE, key_id, epoch-BE); both slashes happen at height 0, so
    // ordering is by key_id then epoch, NOT insertion order. Match by content.
    let events = store_slash_events(&blockchain);
    assert_eq!(events.len(), 2);
    let event1 = events
        .iter()
        .find(|e| e.validator_key_id == key_id1)
        .expect("event for key_id1");
    assert_eq!(event1.reason, OracleSlashReason::ConflictingAttestation);
    let event2 = events
        .iter()
        .find(|e| e.validator_key_id == key_id2)
        .expect("event for key_id2");
    assert_eq!(event2.reason, OracleSlashReason::WrongEpoch);

    // Both banned
    assert!(blockchain.oracle_banned_validators().contains(&key_id1));
    assert!(blockchain.oracle_banned_validators().contains(&key_id2));
}
