//! Oracle Committee Governance Tests
//!
//! Tests for ORACLE-1: Enforce governance-only oracle committee membership.
//!
//! Per Oracle Spec v1 §3.1, committee membership MUST only be modified through
//! governance. The committee set is immutable within an epoch and is updated
//! atomically at epoch boundaries using the pending update mechanism.

#![cfg(feature = "testing")]

use lib_blockchain::oracle::{OracleCommitteeState, OracleState, PendingCommitteeUpdate};

/// Test that committee updates go through the governance path and activate at epoch boundaries.
#[test]
fn committee_update_through_governance_path_activates_at_epoch_boundary() {
    let mut state = OracleState::default();

    // Simulate genesis bootstrap: set initial committee via constructor
    state.committee = OracleCommitteeState::new(
        vec![[1u8; 32], [2u8; 32], [3u8; 32]],
        None,
    );
    assert_eq!(state.committee.members().len(), 3);
    assert_eq!(state.committee.threshold(), 3); // floor(2*3/3) + 1 = 3

    // Schedule a committee update via governance path (the ONLY allowed way post-genesis)
    state
        .schedule_committee_update_for_test(vec![[9u8; 32], [8u8; 32]], 11)
        .expect("schedule must succeed");

    // Pending update should exist but not be active yet
    assert!(state.committee.pending_update().is_some());
    assert_eq!(state.committee.members().len(), 3); // Still 3 members

    // Apply pending updates at epoch 10 (should NOT apply yet - activates at 11)
    state.apply_pending_updates(10);
    assert_eq!(state.committee.members().len(), 3); // Still 3 members
    assert!(state.committee.pending_update().is_some()); // Still pending

    // Apply pending updates at epoch 11 (update activates)
    state.apply_pending_updates(11);
    assert_eq!(state.committee.members().len(), 2); // Now 2 members
    assert_eq!(state.committee.members(), &[[8u8; 32], [9u8; 32]]);
    assert!(state.committee.pending_update().is_none()); // Pending cleared
    assert_eq!(state.committee.threshold(), 2); // floor(2*2/3) + 1 = 2
}

/// Test that schedule_committee_update validates input.
#[test]
fn schedule_committee_update_for_test_validates_input() {
    let mut state = OracleState::default();

    // Empty committee should be rejected
    let result = state.schedule_committee_update_for_test(vec![], 11);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("must not be empty"));

    // Duplicate members should be rejected
    let result = state.schedule_committee_update_for_test(vec![[1u8; 32], [1u8; 32]], 11);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("duplicate"));

    // Valid committee should be accepted
    let result = state.schedule_committee_update_for_test(vec![[1u8; 32], [2u8; 32]], 11);
    assert!(result.is_ok());
}

/// Test that committee members are always normalized (sorted, deduplicated).
#[test]
fn committee_members_are_normalized() {
    // Add members in unsorted order with duplicates
    let committee = OracleCommitteeState::new(
        vec![[3u8; 32], [1u8; 32], [2u8; 32], [1u8; 32]],
        None,
    );

    // Should be normalized to sorted, deduplicated
    assert_eq!(
        committee.members(),
        &[[1u8; 32], [2u8; 32], [3u8; 32]]
    );
    assert_eq!(committee.members().len(), 3);
}

/// Test threshold calculation for various committee sizes.
#[test]
fn committee_threshold_calculation() {
    let test_cases = [
        (1, 1),  // floor(2*1/3) + 1 = 1
        (2, 2),  // floor(2*2/3) + 1 = 2
        (3, 3),  // floor(2*3/3) + 1 = 3
        (4, 3),  // floor(2*4/3) + 1 = 3
        (5, 4),  // floor(2*5/3) + 1 = 4
        (6, 5),  // floor(2*6/3) + 1 = 5
        (7, 5),  // floor(2*7/3) + 1 = 5
        (10, 7), // floor(2*10/3) + 1 = 7
    ];

    for (num_members, expected_threshold) in test_cases.iter() {
        let members: Vec<[u8; 32]> = (0..*num_members)
            .map(|i| [i as u8; 32])
            .collect();
        
        let committee = OracleCommitteeState::new(members, None);
        assert_eq!(
            committee.threshold(),
            *expected_threshold,
            "Threshold for {} members should be {}",
            num_members,
            expected_threshold
        );
    }
}

/// Test that pending committee updates are properly normalized.
#[test]
fn pending_committee_update_members_are_normalized() {
    let pending = PendingCommitteeUpdate {
        activate_at_epoch: 10,
        members: vec![[3u8; 32], [1u8; 32], [3u8; 32], [2u8; 32]],
    };

    let committee = OracleCommitteeState::new(vec![], Some(pending));
    let pending_ref = committee.pending_update().expect("pending must exist");
    
    // Should be normalized
    assert_eq!(pending_ref.members, vec![[1u8; 32], [2u8; 32], [3u8; 32]]);
}

/// Test that multiple pending updates replace each other.
#[test]
fn subsequent_schedule_replaces_pending_update() {
    let mut state = OracleState::default();

    // Schedule first update
    state
        .schedule_committee_update_for_test(vec![[1u8; 32], [2u8; 32]], 11)
        .expect("schedule must succeed");
    
    assert_eq!(
        state.committee.pending_update().unwrap().members,
        vec![[1u8; 32], [2u8; 32]]
    );

    // Schedule second update (should replace first)
    state
        .schedule_committee_update_for_test(vec![[3u8; 32], [4u8; 32], [5u8; 32]], 11)
        .expect("schedule must succeed");
    
    assert_eq!(
        state.committee.pending_update().unwrap().members,
        vec![[3u8; 32], [4u8; 32], [5u8; 32]]
    );
}

/// Test genesis bootstrap scenario.
#[test]
fn genesis_bootstrap_creates_initial_committee() {
    // Simulate genesis block initialization
    let mut state = OracleState::default();

    // Genesis validators are active at block 0
    let genesis_validators = vec![
        [0x01; 32], // validator 1
        [0x02; 32], // validator 2
        [0x03; 32], // validator 3
        [0x04; 32], // validator 4
    ];

    // Set initial committee via genesis constructor
    state.committee = OracleCommitteeState::new(genesis_validators, None);

    // Verify initial committee
    assert_eq!(state.committee.members().len(), 4);
    assert_eq!(state.committee.threshold(), 3); // floor(2*4/3) + 1 = 3

    // After genesis, all updates must go through governance
    // Schedule an update for a future epoch
    state
        .schedule_committee_update_for_test(
            vec![[0x01; 32], [0x02; 32], [0x05; 32]], // Add validator 5, remove 3 and 4
            1, // Activate at epoch 1
        )
        .expect("schedule must succeed");

    // Apply at epoch 1 (update activates at epoch 1 since scheduled at 0)
    state.apply_pending_updates(1);

    // Verify updated committee
    assert_eq!(state.committee.members().len(), 3);
    assert!(state.committee.pending_update().is_none());
}

/// Test that empty committee state has threshold of 1 (defensive).
#[test]
fn empty_committee_threshold_is_one() {
    let committee = OracleCommitteeState::default();
    assert_eq!(committee.threshold(), 1);
    assert!(committee.members().is_empty());
}

/// Test that committee changes after genesis use the governance path.
///
/// This verifies runtime behavior: post-genesis, committee updates must go through
/// `schedule_committee_update_for_test()` → `apply_pending_updates()`. 
///
/// For compile-time verification that `set_members_genesis_only` is unreachable from
/// external crates, see the `compile_fail` doctest on `OracleCommitteeState::set_members_genesis_only`.
#[test]
fn committee_changes_require_governance_path() {
    let mut state = OracleState::default();

    // Pre-genesis/bootstrap: committee can be set via constructor
    state.committee = OracleCommitteeState::new(vec![[1u8; 32], [2u8; 32]], None);
    assert_eq!(state.committee.members().len(), 2);

    // Post-genesis: committee changes must go through schedule_committee_update
    // (The pub(crate) visibility enforces this at compile time for production code)
    
    // Verify the governance path works
    state
        .schedule_committee_update_for_test(vec![[3u8; 32]], 6)
        .expect("governance schedule must succeed");
    
    state.apply_pending_updates(6);
    assert_eq!(state.committee.members().len(), 1);
    assert_eq!(state.committee.members(), &[[3u8; 32]]);
}
