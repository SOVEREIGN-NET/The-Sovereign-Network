//! Integration tests for consensus safety invariants (Issue #1015).
//!
//! This test suite validates the refactored invariant checking system,
//! ensuring it provides fail-fast enforcement and clear diagnostic messages
//! for consensus safety violations.

use lib_consensus::invariants::{
    ConsensusInvariant, ConsensusState, check_invariant, enforce_consensus_invariants,
};

/// Helper to create a valid baseline state for testing.
fn valid_state() -> ConsensusState {
    ConsensusState {
        current_height: 2,
        previous_height: Some(1),
        votes_received: 3,
        total_validators: 4,
        fork_detected: false,
        reorg_detected: false,
    }
}

#[test]
fn test_all_invariants_pass_on_valid_state() {
    let state = valid_state();
    
    // All individual checks should pass
    assert!(state.check_no_fork());
    assert!(state.check_monotonic_height());
    assert!(state.check_quorum_satisfied());
    assert!(state.check_finality_irreversible());
    
    // check_all_invariants should return empty vector
    let violations = state.check_all_invariants();
    assert!(violations.is_empty(), "expected no violations, found: {:?}", violations);
    
    // enforce_consensus_invariants should not panic
    enforce_consensus_invariants(&state);
}

#[test]
fn test_check_invariant_fork_detection() {
    let mut state = valid_state();
    state.fork_detected = true;
    
    let result = check_invariant(&ConsensusInvariant::NoFork, &state);
    assert!(result.is_err());
    
    let msg = result.unwrap_err();
    assert!(msg.contains("NoFork"), "message should mention NoFork: {msg}");
    assert!(msg.contains("no two commits may exist at the same height"), 
            "message should include description: {msg}");
}

#[test]
fn test_check_invariant_monotonic_height_regression() {
    let state = ConsensusState {
        current_height: 2,
        previous_height: Some(5), // height regression
        votes_received: 3,
        total_validators: 4,
        fork_detected: false,
        reorg_detected: false,
    };
    
    assert!(!state.check_monotonic_height());
    
    let result = check_invariant(&ConsensusInvariant::MonotonicHeight, &state);
    assert!(result.is_err());
    
    let msg = result.unwrap_err();
    assert!(msg.contains("MonotonicHeight"), "message should mention MonotonicHeight: {msg}");
}

#[test]
fn test_check_invariant_quorum_insufficient() {
    let state = ConsensusState {
        current_height: 1,
        previous_height: None,
        votes_received: 2, // Only 2 votes, need 3 for 4 validators
        total_validators: 4,
        fork_detected: false,
        reorg_detected: false,
    };
    
    assert!(!state.check_quorum_satisfied());
    
    let result = check_invariant(&ConsensusInvariant::QuorumRequired, &state);
    assert!(result.is_err());
    
    let msg = result.unwrap_err();
    assert!(msg.contains("QuorumRequired"), "message should mention QuorumRequired: {msg}");
}

#[test]
fn test_check_invariant_finality_violation() {
    let mut state = valid_state();
    state.reorg_detected = true;
    
    assert!(!state.check_finality_irreversible());
    
    let result = check_invariant(&ConsensusInvariant::FinalityIrreversible, &state);
    assert!(result.is_err());
    
    let msg = result.unwrap_err();
    assert!(msg.contains("FinalityIrreversible"), 
            "message should mention FinalityIrreversible: {msg}");
}

#[test]
#[should_panic(expected = "CONSENSUS SAFETY BUG")]
fn test_enforce_panics_on_fork() {
    let mut state = valid_state();
    state.fork_detected = true;
    enforce_consensus_invariants(&state);
}

#[test]
#[should_panic(expected = "CONSENSUS SAFETY BUG")]
fn test_enforce_panics_on_height_regression() {
    let state = ConsensusState {
        current_height: 2,
        previous_height: Some(5),
        votes_received: 3,
        total_validators: 4,
        fork_detected: false,
        reorg_detected: false,
    };
    enforce_consensus_invariants(&state);
}

#[test]
#[should_panic(expected = "CONSENSUS SAFETY BUG")]
fn test_enforce_panics_on_quorum_failure() {
    let state = ConsensusState {
        current_height: 1,
        previous_height: None,
        votes_received: 2,
        total_validators: 4,
        fork_detected: false,
        reorg_detected: false,
    };
    enforce_consensus_invariants(&state);
}

#[test]
#[should_panic(expected = "CONSENSUS SAFETY BUG")]
fn test_enforce_panics_on_finality_violation() {
    let mut state = valid_state();
    state.reorg_detected = true;
    enforce_consensus_invariants(&state);
}

#[test]
fn test_panic_message_includes_invariant_details() {
    let result = std::panic::catch_unwind(|| {
        let mut state = valid_state();
        state.fork_detected = true;
        enforce_consensus_invariants(&state);
    });
    
    assert!(result.is_err(), "expected panic on fork violation");
    
    let panic_msg = match result {
        Err(payload) => {
            if let Some(s) = payload.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                String::from("non-string panic payload")
            }
        }
        Ok(_) => unreachable!(),
    };
    
    assert!(
        panic_msg.contains("CONSENSUS SAFETY BUG"),
        "panic message should contain safety prefix, got: {panic_msg}"
    );
    assert!(
        panic_msg.contains("NoFork"),
        "panic message should identify NoFork invariant, got: {panic_msg}"
    );
    assert!(
        panic_msg.contains("no two commits may exist at the same height"),
        "panic message should describe NoFork invariant, got: {panic_msg}"
    );
}

#[test]
fn test_genesis_block_height_validation() {
    // Genesis block (no previous height) should be valid
    let state = ConsensusState {
        current_height: 0,
        previous_height: None,
        votes_received: 3,
        total_validators: 4,
        fork_detected: false,
        reorg_detected: false,
    };
    
    assert!(state.check_monotonic_height());
    enforce_consensus_invariants(&state);
}

#[test]
fn test_quorum_calculation_various_validator_counts() {
    // Test quorum calculation with different validator counts
    // Formula: 2*((n-1)/3) + 1
    
    // 4 validators: quorum = 2*1 + 1 = 3
    let state = ConsensusState {
        current_height: 1,
        previous_height: None,
        votes_received: 3,
        total_validators: 4,
        fork_detected: false,
        reorg_detected: false,
    };
    assert!(state.check_quorum_satisfied());
    
    // 7 validators: quorum = 2*2 + 1 = 5
    let state = ConsensusState {
        current_height: 1,
        previous_height: None,
        votes_received: 5,
        total_validators: 7,
        fork_detected: false,
        reorg_detected: false,
    };
    assert!(state.check_quorum_satisfied());
    
    let state = ConsensusState {
        current_height: 1,
        previous_height: None,
        votes_received: 4, // Not enough
        total_validators: 7,
        fork_detected: false,
        reorg_detected: false,
    };
    assert!(!state.check_quorum_satisfied());
    
    // 10 validators: quorum = 2*3 + 1 = 7
    let state = ConsensusState {
        current_height: 1,
        previous_height: None,
        votes_received: 7,
        total_validators: 10,
        fork_detected: false,
        reorg_detected: false,
    };
    assert!(state.check_quorum_satisfied());
}

#[test]
fn test_multiple_violations_reported() {
    let result = std::panic::catch_unwind(|| {
        let state = ConsensusState {
            current_height: 2,
            previous_height: Some(5), // Height regression
            votes_received: 1,         // Insufficient quorum
            total_validators: 4,
            fork_detected: true,       // Fork
            reorg_detected: true,      // Reorg
        };
        enforce_consensus_invariants(&state);
    });
    
    assert!(result.is_err(), "expected panic with multiple violations");
    
    let panic_msg = match result {
        Err(payload) => {
            if let Some(s) = payload.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                String::from("non-string panic payload")
            }
        }
        Ok(_) => unreachable!(),
    };
    
    // Should mention all violated invariants
    assert!(panic_msg.contains("NoFork"), "should mention NoFork: {panic_msg}");
    assert!(panic_msg.contains("MonotonicHeight"), "should mention MonotonicHeight: {panic_msg}");
    assert!(panic_msg.contains("QuorumRequired"), "should mention QuorumRequired: {panic_msg}");
    assert!(panic_msg.contains("FinalityIrreversible"), "should mention FinalityIrreversible: {panic_msg}");
}
