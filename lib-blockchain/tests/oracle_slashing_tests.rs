//! Oracle Slashing Tests (ORACLE-4)
//!
//! Tests for double-sign and wrong-epoch slashing penalties.

use lib_blockchain::{
    oracle::{
        OracleCommitteeState, OracleSlashingConfig, OracleSlashReason,
        OracleState,
    },
    types::hash::blake3_hash,
    Blockchain, ValidatorInfo,
};

/// Create a mock validator info with given consensus_key and stake
fn create_validator_info(consensus_key: Vec<u8>, stake: u64) -> (ValidatorInfo, [u8; 32]) {
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
    let mut blockchain = Blockchain::default();
    
    let consensus_key = vec![1u8; 32];
    let (validator, key_id) = create_validator_info(consensus_key, 1_000_000);
    
    blockchain.validator_registry.insert(
        hex::encode(key_id),
        validator,
    );
    
    // Default config is 1%
    assert_eq!(blockchain.oracle_slashing_config.slash_fraction_bps, 100);
    
    // Slash the validator
    let slashed = blockchain.slash_oracle_validator(
        key_id,
        OracleSlashReason::ConflictingAttestation,
        100,
    );
    
    // 1% of 1M = 10K
    assert_eq!(slashed, 10_000);
    
    // Verify stake reduced
    let v = blockchain.validator_registry.get(&hex::encode(key_id)).unwrap();
    assert_eq!(v.stake, 990_000); // 1M - 10K
}

/// Test slashing with custom slash fraction.
#[test]
fn custom_slash_fraction() {
    let mut blockchain = Blockchain::default();
    
    let consensus_key = vec![2u8; 32];
    let (validator, key_id) = create_validator_info(consensus_key, 1_000_000);
    
    blockchain.validator_registry.insert(
        hex::encode(key_id),
        validator,
    );
    
    // Use 5% slash fraction
    blockchain.oracle_slashing_config = OracleSlashingConfig::with_slash_fraction(500);
    
    let slashed = blockchain.slash_oracle_validator(
        key_id,
        OracleSlashReason::WrongEpoch,
        50,
    );
    
    // 5% of 1M = 50K
    assert_eq!(slashed, 50_000);
    
    let v = blockchain.validator_registry.get(&hex::encode(key_id)).unwrap();
    assert_eq!(v.stake, 950_000);
}

/// Test that slashing records the slash event.
#[test]
fn slashing_records_event() {
    let mut blockchain = Blockchain::default();
    
    let consensus_key = vec![3u8; 32];
    let (validator, key_id) = create_validator_info(consensus_key, 500_000);
    
    blockchain.validator_registry.insert(
        hex::encode(key_id),
        validator,
    );
    
    blockchain.slash_oracle_validator(
        key_id,
        OracleSlashReason::ConflictingAttestation,
        42,
    );
    
    // Verify event recorded
    assert_eq!(blockchain.oracle_slash_events.len(), 1);
    
    let event = &blockchain.oracle_slash_events[0];
    assert_eq!(event.validator_key_id, key_id);
    assert_eq!(event.reason, OracleSlashReason::ConflictingAttestation);
    assert_eq!(event.epoch_id, 42);
    assert_eq!(event.slash_amount, 5_000); // 1% of 500K
    assert_eq!(event.slashed_at_height, 0); // Default height
}

/// Test that slashing bans the validator.
#[test]
fn slashing_bans_validator() {
    let mut blockchain = Blockchain::default();
    
    let consensus_key = vec![4u8; 32];
    let (validator, key_id) = create_validator_info(consensus_key, 100_000);
    
    blockchain.validator_registry.insert(
        hex::encode(key_id),
        validator,
    );
    
    // Initially not banned
    assert!(!blockchain.oracle_banned_validators.contains(&key_id));
    
    blockchain.slash_oracle_validator(
        key_id,
        OracleSlashReason::WrongEpoch,
        100,
    );
    
    // Now banned
    assert!(blockchain.oracle_banned_validators.contains(&key_id));
}

/// Test that slashing removes validator from committee.
#[test]
fn slashing_removes_from_committee() {
    let mut blockchain = Blockchain::default();
    
    let consensus_key = vec![5u8; 32];
    let (validator, key_id) = create_validator_info(consensus_key, 100_000);
    
    blockchain.validator_registry.insert(
        hex::encode(key_id),
        validator,
    );
    
    // Setup committee with validator
    blockchain.oracle_state = OracleState::default();
    blockchain.oracle_state.committee = OracleCommitteeState::new(vec![key_id], None);
    
    assert!(blockchain.oracle_state.committee.members().contains(&key_id));
    
    // Slash removes from committee
    blockchain.slash_oracle_validator(
        key_id,
        OracleSlashReason::ConflictingAttestation,
        100,
    );
    
    // No longer in committee
    assert!(!blockchain.oracle_state.committee.members().contains(&key_id));
    assert!(blockchain.oracle_state.committee.members().is_empty());
}

/// Test that slashing events survive blockchain serialization.
#[test]
fn slashing_events_survive_restart() {
    let mut blockchain = Blockchain::default();
    
    let consensus_key = vec![6u8; 32];
    let (validator, key_id) = create_validator_info(consensus_key, 100_000);
    
    blockchain.validator_registry.insert(
        hex::encode(key_id),
        validator,
    );
    
    blockchain.slash_oracle_validator(
        key_id,
        OracleSlashReason::ConflictingAttestation,
        100,
    );
    
    // Serialize/deserialize
    let serialized = bincode::serialize(&blockchain).unwrap();
    let restored: Blockchain = bincode::deserialize(&serialized).unwrap();
    
    // Verify slashing events preserved
    assert_eq!(restored.oracle_slash_events.len(), 1);
    assert_eq!(restored.oracle_banned_validators.len(), 1);
    assert!(restored.oracle_banned_validators.contains(&key_id));
    
    // Verify event details preserved
    let event = &restored.oracle_slash_events[0];
    assert_eq!(event.validator_key_id, key_id);
    assert_eq!(event.reason, OracleSlashReason::ConflictingAttestation);
}

/// Test slashing reason display format.
#[test]
fn slashing_reason_display() {
    assert_eq!(
        OracleSlashReason::ConflictingAttestation.to_string(),
        "conflicting_attestation"
    );
    assert_eq!(
        OracleSlashReason::WrongEpoch.to_string(),
        "wrong_epoch"
    );
}

/// Test slashing config default.
#[test]
fn slashing_config_default_one_percent() {
    let config = OracleSlashingConfig::default();
    assert_eq!(config.slash_fraction_bps, 100); // 1%
    
    // Test calculation
    assert_eq!(config.calculate_slash(1_000_000), 10_000); // 1% of 1M
    assert_eq!(config.calculate_slash(100_000), 1_000);    // 1% of 100K
}

/// Test slashing with zero stake (edge case).
#[test]
fn slashing_zero_stake() {
    let mut blockchain = Blockchain::default();
    
    let consensus_key = vec![7u8; 32];
    let (validator, key_id) = create_validator_info(consensus_key, 0);
    
    blockchain.validator_registry.insert(
        hex::encode(key_id),
        validator,
    );
    
    let slashed = blockchain.slash_oracle_validator(
        key_id,
        OracleSlashReason::WrongEpoch,
        100,
    );
    
    // Nothing to slash
    assert_eq!(slashed, 0);
    
    // But still banned and recorded
    assert!(blockchain.oracle_banned_validators.contains(&key_id));
    assert_eq!(blockchain.oracle_slash_events.len(), 1);
    assert_eq!(blockchain.oracle_slash_events[0].slash_amount, 0);
}

/// Test multiple slash events accumulate.
#[test]
fn multiple_slashes_recorded() {
    let mut blockchain = Blockchain::default();
    
    let consensus_key1 = vec![8u8; 32];
    let consensus_key2 = vec![9u8; 32];
    
    let (validator1, key_id1) = create_validator_info(consensus_key1, 100_000);
    let (validator2, key_id2) = create_validator_info(consensus_key2, 200_000);
    
    blockchain.validator_registry.insert(
        hex::encode(key_id1),
        validator1,
    );
    blockchain.validator_registry.insert(
        hex::encode(key_id2),
        validator2,
    );
    
    // Slash both
    blockchain.slash_oracle_validator(key_id1, OracleSlashReason::ConflictingAttestation, 100);
    blockchain.slash_oracle_validator(key_id2, OracleSlashReason::WrongEpoch, 101);
    
    // Both events recorded
    assert_eq!(blockchain.oracle_slash_events.len(), 2);
    
    // First event
    assert_eq!(blockchain.oracle_slash_events[0].validator_key_id, key_id1);
    assert_eq!(blockchain.oracle_slash_events[0].reason, OracleSlashReason::ConflictingAttestation);
    
    // Second event
    assert_eq!(blockchain.oracle_slash_events[1].validator_key_id, key_id2);
    assert_eq!(blockchain.oracle_slash_events[1].reason, OracleSlashReason::WrongEpoch);
    
    // Both banned
    assert!(blockchain.oracle_banned_validators.contains(&key_id1));
    assert!(blockchain.oracle_banned_validators.contains(&key_id2));
}
