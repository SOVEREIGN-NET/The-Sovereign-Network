//! Oracle Governance Transaction Tests (ORACLE-6)
//!
//! Tests for UpdateOracleCommittee and UpdateOracleConfig governance transactions.

#![cfg(feature = "testing")]

use lib_blockchain::{
    oracle::{OracleCommitteeState, OracleConfig, OracleState},
    transaction::{OracleCommitteeUpdateData, OracleConfigUpdateData},
    types::transaction_type::TransactionType,
};

/// Test that UpdateOracleCommittee transaction type exists and has correct value.
#[test]
fn update_oracle_committee_transaction_type() {
    let tx_type = TransactionType::UpdateOracleCommittee;
    assert_eq!(tx_type as u8, 34);
    assert_eq!(tx_type.description(), "Update oracle committee membership (via DAO governance)");
    assert_eq!(tx_type.as_str(), "update_oracle_committee");
    assert!(tx_type.is_oracle_governance_transaction());
    assert!(tx_type.is_dao_transaction());
}

/// Test that UpdateOracleConfig transaction type exists and has correct value.
#[test]
fn update_oracle_config_transaction_type() {
    let tx_type = TransactionType::UpdateOracleConfig;
    assert_eq!(tx_type as u8, 35);
    assert_eq!(tx_type.description(), "Update oracle configuration parameters (via DAO governance)");
    assert_eq!(tx_type.as_str(), "update_oracle_config");
    assert!(tx_type.is_oracle_governance_transaction());
    assert!(tx_type.is_dao_transaction());
}

/// Test serialization roundtrip for OracleCommitteeUpdateData.
#[test]
fn committee_update_data_serialization() {
    let data = OracleCommitteeUpdateData {
        new_members: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
        activate_at_epoch: 100,
        reason: "Adding new validators".to_string(),
    };
    
    let serialized = bincode::serialize(&data).unwrap();
    let deserialized: OracleCommitteeUpdateData = bincode::deserialize(&serialized).unwrap();
    
    assert_eq!(data.new_members, deserialized.new_members);
    assert_eq!(data.activate_at_epoch, deserialized.activate_at_epoch);
    assert_eq!(data.reason, deserialized.reason);
}

/// Test serialization roundtrip for OracleConfigUpdateData.
#[test]
fn config_update_data_serialization() {
    let data = OracleConfigUpdateData {
        epoch_duration_secs: 600,
        max_source_age_secs: 120,
        max_deviation_bps: 1000,
        max_price_staleness_epochs: 12,
        activate_at_epoch: 50,
        reason: "Increasing epoch duration".to_string(),
    };
    
    let serialized = bincode::serialize(&data).unwrap();
    let deserialized: OracleConfigUpdateData = bincode::deserialize(&serialized).unwrap();
    
    assert_eq!(data.epoch_duration_secs, deserialized.epoch_duration_secs);
    assert_eq!(data.max_source_age_secs, deserialized.max_source_age_secs);
    assert_eq!(data.max_deviation_bps, deserialized.max_deviation_bps);
    assert_eq!(data.max_price_staleness_epochs, deserialized.max_price_staleness_epochs);
    assert_eq!(data.activate_at_epoch, deserialized.activate_at_epoch);
    assert_eq!(data.reason, deserialized.reason);
}

/// Test committee update validation with current epoch.
#[test]
fn committee_update_validation_with_epoch() {
    let valid = OracleCommitteeUpdateData {
        new_members: vec![[1u8; 32]],
        activate_at_epoch: 10,
        reason: "Test".to_string(),
    };
    assert!(valid.validate(5).is_ok());
    
    // Same epoch should fail
    assert!(valid.validate(10).is_err());
    
    // Past epoch should fail
    assert!(valid.validate(15).is_err());
}

/// Test config update validation with current epoch.
#[test]
fn config_update_validation_with_epoch() {
    let valid = OracleConfigUpdateData {
        epoch_duration_secs: 300,
        max_source_age_secs: 60,
        max_deviation_bps: 500,
        max_price_staleness_epochs: 10,
        activate_at_epoch: 100,
        reason: "Test".to_string(),
    };
    assert!(valid.validate(50).is_ok());
    
    // Same epoch should fail
    assert!(valid.validate(100).is_err());
}

/// Test that committee can be scheduled via governance path.
#[test]
fn schedule_committee_update_for_test_via_governance() {
    let mut state = OracleState::default();
    let current_epoch = 10;
    
    // Initial committee
    state.committee = OracleCommitteeState::new(vec![[1u8; 32], [2u8; 32]], None);
    assert_eq!(state.committee.members().len(), 2);
    
    // Schedule update (activates at current_epoch + 1)
    let result = state.schedule_committee_update_for_test(
        vec![[3u8; 32], [4u8; 32], [5u8; 32]],
        current_epoch + 1,
        current_epoch,
        None,
    );
    assert!(result.is_ok());
    
    // Committee unchanged until activation
    assert_eq!(state.committee.members().len(), 2);
    
    // Apply at activation epoch (11)
    state.apply_pending_updates(current_epoch + 1);
    
    // Committee now updated
    assert_eq!(state.committee.members().len(), 3);
    assert!(state.committee.members().contains(&[3u8; 32]));
    assert!(state.committee.members().contains(&[4u8; 32]));
    assert!(state.committee.members().contains(&[5u8; 32]));
}

/// Test that config can be scheduled via governance path.
#[test]
fn schedule_config_update_for_test_via_governance() {
    let mut state = OracleState::default();
    let current_epoch = 10;
    
    // Initial config
    let initial_duration = state.config.epoch_duration_secs;
    
    // Schedule config update (activates at current_epoch + 1)
    let mut new_config = OracleConfig::default();
    new_config.epoch_duration_secs = 600;
    new_config.max_source_age_secs = 120;
    new_config.max_deviation_bps = 1000;
    
    let result = state.schedule_config_update_for_test(
        new_config,
        current_epoch + 1,
        current_epoch,
        None,
    );
    assert!(result.is_ok());
    
    // Config unchanged until activation
    assert_eq!(state.config.epoch_duration_secs, initial_duration);
    
    // Apply at activation epoch (11)
    state.apply_pending_updates(current_epoch + 1);
    
    // Config now updated
    assert_eq!(state.config.epoch_duration_secs, 600);
    assert_eq!(state.config.max_source_age_secs, 120);
    assert_eq!(state.config.max_deviation_bps, 1000);
}

/// Test that scheduled update replaces previous pending update.
#[test]
fn scheduled_update_replaces_previous() {
    let mut state = OracleState::default();
    
    // Schedule first update
    state.schedule_committee_update_for_test(
        vec![[1u8; 32]],
        11,
        0,
        None,
    ).unwrap();
    
    assert_eq!(state.committee.pending_update().unwrap().members.len(), 1);
    
    // Schedule second update (should replace first)
    state.schedule_committee_update_for_test(
        vec![[2u8; 32], [3u8; 32]],
        11,
        0,
        None,
    ).unwrap();
    
    assert_eq!(state.committee.pending_update().unwrap().members.len(), 2);
}

/// Test transaction type parsing from string.
#[test]
fn transaction_type_parsing() {
    assert_eq!(
        TransactionType::from_str("update_oracle_committee"),
        Some(TransactionType::UpdateOracleCommittee)
    );
    assert_eq!(
        TransactionType::from_str("update_oracle_config"),
        Some(TransactionType::UpdateOracleConfig)
    );
    assert_eq!(
        TransactionType::from_str("invalid_type"),
        None
    );
}

/// Test validation failure for empty committee.
#[test]
fn committee_update_rejects_empty() {
    let data = OracleCommitteeUpdateData {
        new_members: vec![],
        activate_at_epoch: 100,
        reason: "Empty committee".to_string(),
    };
    assert!(data.validate(50).is_err());
}

/// Test validation failure for duplicate committee members.
#[test]
fn committee_update_rejects_duplicates() {
    let data = OracleCommitteeUpdateData {
        new_members: vec![[1u8; 32], [1u8; 32], [2u8; 32]],
        activate_at_epoch: 100,
        reason: "Has duplicate".to_string(),
    };
    assert!(data.validate(50).is_err());
}

/// Test config validation failure for zero epoch duration.
#[test]
fn config_update_rejects_zero_epoch_duration() {
    let data = OracleConfigUpdateData {
        epoch_duration_secs: 0,
        max_source_age_secs: 60,
        max_deviation_bps: 500,
        max_price_staleness_epochs: 10,
        activate_at_epoch: 100,
        reason: "Zero duration".to_string(),
    };
    assert!(data.validate(50).is_err());
}

/// Test config validation failure for zero max source age.
#[test]
fn config_update_rejects_zero_max_source_age() {
    let data = OracleConfigUpdateData {
        epoch_duration_secs: 300,
        max_source_age_secs: 0,
        max_deviation_bps: 500,
        max_price_staleness_epochs: 10,
        activate_at_epoch: 100,
        reason: "Zero source age".to_string(),
    };
    assert!(data.validate(50).is_err());
}

/// Test config validation failure for zero max price staleness.
#[test]
fn config_update_rejects_zero_max_price_staleness() {
    let data = OracleConfigUpdateData {
        epoch_duration_secs: 300,
        max_source_age_secs: 60,
        max_deviation_bps: 500,
        max_price_staleness_epochs: 0,
        activate_at_epoch: 100,
        reason: "Zero staleness".to_string(),
    };
    assert!(data.validate(50).is_err());
}

/// Test that committee data can be created for governance proposal.
#[test]
fn committee_update_data_for_governance() {
    // Simulate what governance would create
    let committee_data = OracleCommitteeUpdateData {
        new_members: vec![
            [0x01; 32], [0x02; 32], [0x03; 32],
            [0x04; 32], [0x05; 32],
        ],
        activate_at_epoch: 100,
        reason: "Expand committee for increased security".to_string(),
    };
    
    // Validate before proposal submission
    assert!(committee_data.validate(50).is_ok());
    assert_eq!(committee_data.new_members.len(), 5);
}

/// Test that config data can be created for governance proposal.
#[test]
fn config_update_data_for_governance() {
    // Simulate what governance would create
    let config_data = OracleConfigUpdateData {
        epoch_duration_secs: 600,    // 10 minute epochs
        max_source_age_secs: 180,     // 3 minute max age
        max_deviation_bps: 1000,      // 10% max deviation
        max_price_staleness_epochs: 12, // 2 epochs at 10 min each
        activate_at_epoch: 50,
        reason: "Increase epoch duration to reduce network overhead".to_string(),
    };
    
    // Validate before proposal submission
    assert!(config_data.validate(25).is_ok());
    assert_eq!(config_data.epoch_duration_secs, 600);
    assert_eq!(config_data.max_price_staleness_epochs, 12);
}
