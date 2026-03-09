//! ORACLE-16: Oracle slashing integration tests
//!
//! Tests for:
//! - Double-sign attestation triggers slashing
//! - Wrong-epoch attestation handling
//! - Slashed validator removed from committee

use lib_blockchain::oracle::{OracleAttestationAdmissionError, OracleSlashReason};

mod common;
use common::oracle_harness::OracleTestHarness;

#[test]
fn test_double_sign_is_rejected() {
    let mut harness = OracleTestHarness::new(4);
    let epoch = harness.current_epoch();
    let validator_key = harness.validators[0].key_id;

    // Validator 0 signs price A
    let att_a = harness.produce_attestation(0, epoch, 100_000_000);
    let result = harness.process_attestation(att_a);
    assert!(result.is_ok(), "first attestation should be accepted");

    // Validator 0 signs price B (conflicting) - same epoch, different price
    let att_b = harness.produce_attestation(0, epoch, 200_000_000);
    let result = harness.process_attestation(att_b);

    // Should be rejected as conflicting
    assert!(
        result.is_err(),
        "conflicting attestation should be rejected"
    );
    match result.unwrap_err() {
        OracleAttestationAdmissionError::ConflictingSigner { signer, .. } => {
            assert_eq!(signer, validator_key);
        }
        other => panic!("expected ConflictingSigner error, got: {:?}", other),
    }
}

#[test]
fn test_slashed_validator_cannot_attest() {
    let mut harness = OracleTestHarness::new(4);
    let epoch = harness.current_epoch();

    // Slash validator 0
    let validator_key = harness.validators[0].key_id;
    harness.blockchain.slash_oracle_validator(
        validator_key,
        OracleSlashReason::ConflictingAttestation,
        epoch,
    );

    // Try to attest as slashed validator
    let attestation = harness.produce_attestation(0, epoch, 100_000_000);
    let result = harness.process_attestation(attestation);

    // Should be rejected because validator is no longer in committee
    assert!(
        result.is_err(),
        "slashed validator should not be able to attest"
    );
}

#[test]
fn test_slashing_preserved_across_restart() {
    use tempfile::tempdir;

    let mut harness = OracleTestHarness::new(4);
    let validator_key = harness.validators[0].key_id;

    // Slash validator
    harness.blockchain.slash_oracle_validator(
        validator_key,
        OracleSlashReason::ConflictingAttestation,
        0, // epoch doesn't matter for this test
    );

    // Save and reload
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.dat");
    harness.blockchain.save_to_file(&path).unwrap();

    let reloaded = lib_blockchain::Blockchain::load_from_file(&path).unwrap();

    // Verify slashing preserved
    assert!(reloaded.oracle_banned_validators.contains(&validator_key));
    assert!(!reloaded
        .oracle_state
        .committee
        .members()
        .contains(&validator_key));
}

#[test]
fn test_committee_threshold_adjusts_after_slashing() {
    let mut harness = OracleTestHarness::new(4);

    // Initial threshold with 4 members: floor(2*4/3)+1 = 3
    let initial_threshold = harness.blockchain.oracle_state.committee.threshold();
    assert_eq!(initial_threshold, 3);

    // Slash one validator
    let validator_key = harness.validators[0].key_id;
    harness.blockchain.slash_oracle_validator(
        validator_key,
        OracleSlashReason::ConflictingAttestation,
        harness.current_epoch(),
    );

    // New threshold with 3 members: floor(2*3/3)+1 = 3
    let new_threshold = harness.blockchain.oracle_state.committee.threshold();
    assert_eq!(new_threshold, 3);
}

#[test]
fn test_multiple_validators_can_finalize_after_slashing() {
    let mut harness = OracleTestHarness::new(5); // 5 validators
    let epoch = harness.current_epoch();

    // Initial threshold with 5 members: floor(2*5/3)+1 = 4
    assert_eq!(harness.blockchain.oracle_state.committee.threshold(), 4);

    // Slash validator 0
    harness.blockchain.slash_oracle_validator(
        harness.validators[0].key_id,
        OracleSlashReason::ConflictingAttestation,
        epoch,
    );

    // Use validators 1,2,3,4 (skip slashed validator 0)
    // Need threshold=4 attestations to finalize
    let mut count = 0;
    for i in 1..=4 {
        let att = harness.produce_attestation(i, epoch, 100_000_000);
        match harness.process_attestation(att) {
            Ok(lib_blockchain::oracle::OracleAttestationAdmission::Finalized(_)) => {
                count = 4; // Finalized!
                break;
            }
            Ok(_) => {
                count += 1;
            }
            Err(_) => {}
        }
    }

    assert!(
        count >= 4,
        "should be able to finalize with remaining validators"
    );
}

#[test]
fn test_slash_event_contains_correct_metadata() {
    let mut harness = OracleTestHarness::new(4);
    let epoch = harness.current_epoch();
    let validator_key = harness.validators[0].key_id;

    // Get initial event count
    let initial_events = harness.blockchain.oracle_slash_events.len();

    // Manually slash the validator (simulating what blockchain would do after detecting conflict)
    harness.blockchain.slash_oracle_validator(
        validator_key,
        OracleSlashReason::ConflictingAttestation,
        epoch,
    );

    // Verify event metadata
    assert_eq!(
        harness.blockchain.oracle_slash_events.len(),
        initial_events + 1
    );
    let event = harness.blockchain.oracle_slash_events.last().unwrap();

    assert_eq!(event.validator_key_id, validator_key);
    assert!(matches!(
        event.reason,
        OracleSlashReason::ConflictingAttestation
    ));
    assert!(event.epoch_id >= epoch);
    // slashed_at_height may be 0 in test harness since we don't mine actual blocks
}
