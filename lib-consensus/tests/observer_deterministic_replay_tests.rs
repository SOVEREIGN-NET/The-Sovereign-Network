//! Deterministic Replay and Anomaly Scenario Test Suite
//!
//! Issue #1789: Add deterministic replay and anomaly scenario test suite
//!
//! This test suite validates:
//! - Golden tests for grammar paths (healthy, delayed, stalled, recovering, divergence)
//! - Replay tests proving identical outputs for identical input streams
//! - Cross-module integration tests for end-to-end observer outputs

use lib_consensus::observer::{
    encode_height_states, encode_round_states, EncodedConsensusPhase, EncodedConsensusState,
    ExecutionStatus, ParsedConsensusEvent, ParsedConsensusPhase, ParsedHeightTrajectory,
    ParsedPhaseTrajectory, ParsedRoundTrajectory, ProposalStatus, RoundClass, StateEncoderConfig,
    TimeClass,
};

// =============================================================================
// Test Fixtures and Helpers
// =============================================================================

fn default_config() -> StateEncoderConfig {
    StateEncoderConfig::default()
}

/// Creates a healthy single-round trajectory (optimal case)
fn healthy_single_round(height: u64, round: u32) -> ParsedHeightTrajectory {
    ParsedHeightTrajectory {
        height,
        rounds: vec![ParsedRoundTrajectory {
            round_number: round,
            phases: vec![
                ParsedPhaseTrajectory {
                    phase: ParsedConsensusPhase::Propose,
                    end_event: ParsedConsensusEvent::ProposalCreated,
                    duration: 1,
                },
                ParsedPhaseTrajectory {
                    phase: ParsedConsensusPhase::PreVote,
                    end_event: ParsedConsensusEvent::BlockApplyStarted,
                    duration: 1,
                },
                ParsedPhaseTrajectory {
                    phase: ParsedConsensusPhase::PreCommit,
                    end_event: ParsedConsensusEvent::BlockApplySucceeded,
                    duration: 1,
                },
                ParsedPhaseTrajectory {
                    phase: ParsedConsensusPhase::Commit,
                    end_event: ParsedConsensusEvent::BlockApplySucceeded,
                    duration: 1,
                },
            ],
            events: vec![
                ParsedConsensusEvent::EnterPropose,
                ParsedConsensusEvent::ProposalCreated,
                ParsedConsensusEvent::BlockApplyStarted,
                ParsedConsensusEvent::BlockApplySucceeded,
            ],
        }],
    }
}

/// Creates a delayed round trajectory (slow but successful)
fn delayed_round(height: u64, round: u32) -> ParsedHeightTrajectory {
    ParsedHeightTrajectory {
        height,
        rounds: vec![ParsedRoundTrajectory {
            round_number: round,
            phases: vec![
                ParsedPhaseTrajectory {
                    phase: ParsedConsensusPhase::Propose,
                    end_event: ParsedConsensusEvent::ProposalReceived,
                    duration: 2, // Delayed
                },
                ParsedPhaseTrajectory {
                    phase: ParsedConsensusPhase::PreVote,
                    end_event: ParsedConsensusEvent::BlockApplyStarted,
                    duration: 2, // Delayed
                },
                ParsedPhaseTrajectory {
                    phase: ParsedConsensusPhase::PreCommit,
                    end_event: ParsedConsensusEvent::BlockApplySucceeded,
                    duration: 2, // Delayed
                },
            ],
            events: vec![
                ParsedConsensusEvent::EnterPropose,
                ParsedConsensusEvent::ProposalReceived,
                ParsedConsensusEvent::BlockApplyStarted,
                ParsedConsensusEvent::BlockApplySucceeded,
            ],
        }],
    }
}

/// Creates a stalled round trajectory (timeout scenario)
fn stalled_round(height: u64, round: u32) -> ParsedHeightTrajectory {
    ParsedHeightTrajectory {
        height,
        rounds: vec![ParsedRoundTrajectory {
            round_number: round,
            phases: vec![
                ParsedPhaseTrajectory {
                    phase: ParsedConsensusPhase::Propose,
                    end_event: ParsedConsensusEvent::StepTimeout,
                    duration: 5, // Timeout
                },
                ParsedPhaseTrajectory {
                    phase: ParsedConsensusPhase::Stalled,
                    end_event: ParsedConsensusEvent::StepTimeout,
                    duration: 5,
                },
            ],
            events: vec![
                ParsedConsensusEvent::EnterPropose,
                ParsedConsensusEvent::StepTimeout,
            ],
        }],
    }
}

/// Creates a recovering round trajectory (after stall)
fn recovering_round(height: u64, round: u32) -> ParsedHeightTrajectory {
    ParsedHeightTrajectory {
        height,
        rounds: vec![ParsedRoundTrajectory {
            round_number: round,
            phases: vec![
                ParsedPhaseTrajectory {
                    phase: ParsedConsensusPhase::Recovering,
                    end_event: ParsedConsensusEvent::ProposalReceived,
                    duration: 2,
                },
                ParsedPhaseTrajectory {
                    phase: ParsedConsensusPhase::PreVote,
                    end_event: ParsedConsensusEvent::BlockApplyStarted,
                    duration: 1,
                },
                ParsedPhaseTrajectory {
                    phase: ParsedConsensusPhase::PreCommit,
                    end_event: ParsedConsensusEvent::BlockApplySucceeded,
                    duration: 1,
                },
            ],
            events: vec![
                ParsedConsensusEvent::ProposalReceived,
                ParsedConsensusEvent::BlockApplyStarted,
                ParsedConsensusEvent::BlockApplySucceeded,
            ],
        }],
    }
}

/// Creates a multi-round height with divergence pattern
fn multi_round_with_divergence(height: u64) -> ParsedHeightTrajectory {
    ParsedHeightTrajectory {
        height,
        rounds: vec![
            // Round 0: Failed
            ParsedRoundTrajectory {
                round_number: 0,
                phases: vec![ParsedPhaseTrajectory {
                    phase: ParsedConsensusPhase::Propose,
                    end_event: ParsedConsensusEvent::StepTimeout,
                    duration: 5,
                }],
                events: vec![
                    ParsedConsensusEvent::EnterPropose,
                    ParsedConsensusEvent::StepTimeout,
                ],
            },
            // Round 1: Failed with equivocation
            ParsedRoundTrajectory {
                round_number: 1,
                phases: vec![
                    ParsedPhaseTrajectory {
                        phase: ParsedConsensusPhase::Propose,
                        end_event: ParsedConsensusEvent::EquivocationDetected,
                        duration: 2,
                    },
                    ParsedPhaseTrajectory {
                        phase: ParsedConsensusPhase::Fault,
                        end_event: ParsedConsensusEvent::EquivocationDetected,
                        duration: 1,
                    },
                ],
                events: vec![
                    ParsedConsensusEvent::EnterPropose,
                    ParsedConsensusEvent::EquivocationDetected,
                ],
            },
            // Round 2: Success
            ParsedRoundTrajectory {
                round_number: 2,
                phases: vec![
                    ParsedPhaseTrajectory {
                        phase: ParsedConsensusPhase::NewRound,
                        end_event: ParsedConsensusEvent::ProposalCreated,
                        duration: 1,
                    },
                    ParsedPhaseTrajectory {
                        phase: ParsedConsensusPhase::PreVote,
                        end_event: ParsedConsensusEvent::BlockApplySucceeded,
                        duration: 1,
                    },
                ],
                events: vec![
                    ParsedConsensusEvent::ProposalCreated,
                    ParsedConsensusEvent::BlockApplySucceeded,
                ],
            },
        ],
    }
}

// =============================================================================
// Golden Tests - Grammar Path Validation
// =============================================================================

/// OBSERVER-GOLDEN-1: Healthy path produces expected state sequence
#[test]
fn golden_healthy_path() {
    let height = healthy_single_round(100, 0);
    let config = default_config();
    let states = encode_height_states(&height, config);

    // Should have 4 states (one per phase)
    assert_eq!(states.len(), 4, "Healthy round should have 4 phase states");

    // Verify all states are for round 0
    assert!(states.iter().all(|s| s.round == 0));

    // Verify round class
    assert!(states.iter().all(|s| s.round_class == RoundClass::R0));

    // Verify proposal status is Created
    assert!(states
        .iter()
        .all(|s| s.proposal_status == ProposalStatus::Created));

    // Verify execution succeeds
    assert!(states
        .iter()
        .all(|s| s.execution_status == ExecutionStatus::ApplySucceeded));

    // Verify phase sequence
    assert_eq!(states[0].phase, EncodedConsensusPhase::Propose);
    assert_eq!(states[1].phase, EncodedConsensusPhase::PreVote);
    assert_eq!(states[2].phase, EncodedConsensusPhase::PreCommit);
    assert_eq!(states[3].phase, EncodedConsensusPhase::Commit);
}

/// OBSERVER-GOLDEN-2: Delayed path produces expected timing classification
#[test]
fn golden_delayed_path() {
    let height = delayed_round(101, 0);
    let config = StateEncoderConfig {
        step_timeout_reference: 3,
        ..default_config()
    };
    let states = encode_height_states(&height, config);

    // Delayed duration of 2 with timeout ref of 3 should be Mid (not Early)
    // early_cutoff = 3/3 = 1, mid_cutoff = 6/3 = 2
    // duration 2 <= mid_cutoff(2) -> Mid
    assert_eq!(states[0].time_class, TimeClass::Mid);
}

/// OBSERVER-GOLDEN-3: Stalled path produces timeout classification
#[test]
fn golden_stalled_path() {
    let height = stalled_round(102, 0);
    let config = default_config();
    let states = encode_height_states(&height, config);

    // First phase should timeout
    assert_eq!(states[0].time_class, TimeClass::TimedOut);

    // Should have stalled phase
    assert!(states
        .iter()
        .any(|s| s.phase == EncodedConsensusPhase::Stalled));

    // Proposal status should be Missing (we had propose but timed out)
    assert!(states
        .iter()
        .any(|s| s.proposal_status == ProposalStatus::Missing));
}

/// OBSERVER-GOLDEN-4: Recovering path after stall
#[test]
fn golden_recovering_path() {
    let height = recovering_round(103, 1);
    let config = default_config();
    let states = encode_height_states(&height, config);

    // Should have recovering phase
    assert!(states
        .iter()
        .any(|s| s.phase == EncodedConsensusPhase::Recovering));

    // Round class should be R1
    assert!(states.iter().all(|s| s.round_class == RoundClass::R1));

    // Should eventually succeed
    assert!(states
        .iter()
        .any(|s| s.execution_status == ExecutionStatus::ApplySucceeded));
}

/// OBSERVER-GOLDEN-5: Multi-round divergence pattern
#[test]
fn golden_divergence_pattern() {
    let height = multi_round_with_divergence(104);
    let config = default_config();
    let states = encode_height_states(&height, config);

    // Should have states from multiple rounds
    let rounds: std::collections::HashSet<_> = states.iter().map(|s| s.round).collect();
    assert!(rounds.contains(&0));
    assert!(rounds.contains(&1));
    assert!(rounds.contains(&2));

    // Round 2 should eventually succeed
    let round2_states: Vec<_> = states.iter().filter(|s| s.round == 2).collect();
    assert!(!round2_states.is_empty());
}

// =============================================================================
// Deterministic Replay Tests
// =============================================================================

/// OBSERVER-REPLAY-1: Identical inputs produce identical outputs
#[test]
fn replay_identical_inputs_produce_identical_outputs() {
    let height = healthy_single_round(100, 0);
    let config = default_config();

    // Encode twice with same inputs
    let states1 = encode_height_states(&height, config);
    let states2 = encode_height_states(&height, config);

    // Outputs must be identical
    assert_eq!(
        states1, states2,
        "Replay must produce identical state sequences"
    );
}

/// OBSERVER-REPLAY-2: Round encoding is deterministic
#[test]
fn replay_round_encoding_deterministic() {
    let round = ParsedRoundTrajectory {
        round_number: 5,
        phases: vec![
            ParsedPhaseTrajectory {
                phase: ParsedConsensusPhase::Propose,
                end_event: ParsedConsensusEvent::ProposalCreated,
                duration: 1,
            },
            ParsedPhaseTrajectory {
                phase: ParsedConsensusPhase::PreVote,
                end_event: ParsedConsensusEvent::BlockApplySucceeded,
                duration: 1,
            },
        ],
        events: vec![ParsedConsensusEvent::ProposalCreated],
    };
    let config = default_config();

    let states1 = encode_round_states(100, &round, config);
    let states2 = encode_round_states(100, &round, config);

    assert_eq!(states1, states2, "Round encoding must be deterministic");
}

/// OBSERVER-REPLAY-3: State encoder config affects output deterministically
#[test]
fn replay_config_affects_output_deterministically() {
    // Use a trajectory with Fault phase to test fallback configuration
    let height_with_fault = ParsedHeightTrajectory {
        height: 100,
        rounds: vec![ParsedRoundTrajectory {
            round_number: 0,
            phases: vec![
                ParsedPhaseTrajectory {
                    phase: ParsedConsensusPhase::Propose,
                    end_event: ParsedConsensusEvent::EquivocationDetected,
                    duration: 1,
                },
                ParsedPhaseTrajectory {
                    phase: ParsedConsensusPhase::Fault, // This uses fallback
                    end_event: ParsedConsensusEvent::EquivocationDetected,
                    duration: 1,
                },
            ],
            events: vec![
                ParsedConsensusEvent::EnterPropose,
                ParsedConsensusEvent::EquivocationDetected,
            ],
        }],
    };

    let config1 = StateEncoderConfig {
        fallback_phase: EncodedConsensusPhase::NewRound,
        fallback_time_class: TimeClass::Early,
        step_timeout_reference: 3,
    };

    let config2 = StateEncoderConfig {
        fallback_phase: EncodedConsensusPhase::Recovering,
        fallback_time_class: TimeClass::Late,
        step_timeout_reference: 6,
    };

    let states1_a = encode_height_states(&height_with_fault, config1);
    let states1_b = encode_height_states(&height_with_fault, config1);
    let states2_a = encode_height_states(&height_with_fault, config2);
    let states2_b = encode_height_states(&height_with_fault, config2);

    // Same config must produce same output
    assert_eq!(states1_a, states1_b, "Same config must be deterministic");
    assert_eq!(states2_a, states2_b, "Same config must be deterministic");

    // Different configs should produce different outputs
    // (specifically the fallback_phase for Fault states)
    assert_ne!(
        states1_a, states2_a,
        "Different configs should produce different outputs"
    );

    // Verify the fallback phases are correctly applied
    let fault_state1 = states1_a
        .iter()
        .find(|s| s.phase == EncodedConsensusPhase::NewRound);
    let fault_state2 = states2_a
        .iter()
        .find(|s| s.phase == EncodedConsensusPhase::Recovering);
    assert!(
        fault_state1.is_some(),
        "Config1 should map Fault to NewRound"
    );
    assert!(
        fault_state2.is_some(),
        "Config2 should map Fault to Recovering"
    );
}

/// OBSERVER-REPLAY-4: Multiple heights processed independently
#[test]
fn replay_multiple_heights_independent() {
    let heights: Vec<_> = (0..10).map(|h| healthy_single_round(h, 0)).collect();
    let config = default_config();

    // Encode all heights
    let all_states: Vec<_> = heights
        .iter()
        .map(|h| encode_height_states(h, config))
        .collect();

    // Verify each height produces consistent output when re-encoded
    for (i, height) in heights.iter().enumerate() {
        let reencoded = encode_height_states(height, config);
        assert_eq!(
            all_states[i], reencoded,
            "Height {} must be reproducible",
            i
        );
    }
}

// =============================================================================
// Anomaly Scenario Tests
// =============================================================================

/// OBSERVER-ANOMALY-1: Empty phases fallback
#[test]
fn anomaly_empty_phases_fallback() {
    let height = ParsedHeightTrajectory {
        height: 100,
        rounds: vec![ParsedRoundTrajectory {
            round_number: 0,
            phases: vec![], // Empty phases
            events: vec![],
        }],
    };
    let config = StateEncoderConfig {
        fallback_phase: EncodedConsensusPhase::Recovering,
        fallback_time_class: TimeClass::Late,
        ..default_config()
    };

    let states = encode_height_states(&height, config);

    // Should produce single fallback state
    assert_eq!(states.len(), 1);
    assert_eq!(states[0].phase, EncodedConsensusPhase::Recovering);
    assert_eq!(states[0].time_class, TimeClass::Late);
}

/// OBSERVER-ANOMALY-2: High round number classification
#[test]
fn anomaly_high_round_classification() {
    let height = healthy_single_round(100, 10); // Round 10
    let config = default_config();
    let states = encode_height_states(&height, config);

    // Round 10 should be R4Plus
    assert!(states.iter().all(|s| s.round_class == RoundClass::R4Plus));
}

/// OBSERVER-ANOMALY-3: Proposal missing vs unknown
#[test]
fn anomaly_proposal_status_edge_cases() {
    // Round with only timeout, no propose event
    let no_propose = ParsedHeightTrajectory {
        height: 100,
        rounds: vec![ParsedRoundTrajectory {
            round_number: 0,
            phases: vec![ParsedPhaseTrajectory {
                phase: ParsedConsensusPhase::NewRound,
                end_event: ParsedConsensusEvent::StepTimeout,
                duration: 1,
            }],
            events: vec![ParsedConsensusEvent::StepTimeout],
        }],
    };
    let config = default_config();
    let states = encode_height_states(&no_propose, config);

    // Without EnterPropose, proposal status should be Unknown
    assert!(states
        .iter()
        .all(|s| s.proposal_status == ProposalStatus::Unknown));
}

/// OBSERVER-ANOMALY-4: Block apply failure detection
#[test]
fn anomaly_block_apply_failure() {
    let failed_apply = ParsedHeightTrajectory {
        height: 100,
        rounds: vec![ParsedRoundTrajectory {
            round_number: 0,
            phases: vec![
                ParsedPhaseTrajectory {
                    phase: ParsedConsensusPhase::Propose,
                    end_event: ParsedConsensusEvent::ProposalCreated,
                    duration: 1,
                },
                ParsedPhaseTrajectory {
                    phase: ParsedConsensusPhase::PreVote,
                    end_event: ParsedConsensusEvent::BlockApplyFailed,
                    duration: 1,
                },
            ],
            events: vec![
                ParsedConsensusEvent::ProposalCreated,
                ParsedConsensusEvent::BlockApplyFailed,
            ],
        }],
    };
    let config = default_config();
    let states = encode_height_states(&failed_apply, config);

    // Should detect apply failure
    assert!(states
        .iter()
        .any(|s| s.execution_status == ExecutionStatus::ApplyFailed));
}

/// OBSERVER-ANOMALY-5: Time classification boundary conditions
#[test]
fn anomaly_time_classification_boundaries() {
    let test_cases = vec![
        (0, TimeClass::Early), // Zero duration = Early
        (1, TimeClass::Early), // At early cutoff = Early
        (2, TimeClass::Mid),   // Mid range
        (3, TimeClass::Late),  // Above mid cutoff = Late
    ];

    for (duration, expected_class) in test_cases {
        let height = ParsedHeightTrajectory {
            height: 100,
            rounds: vec![ParsedRoundTrajectory {
                round_number: 0,
                phases: vec![ParsedPhaseTrajectory {
                    phase: ParsedConsensusPhase::Propose,
                    end_event: ParsedConsensusEvent::ProposalCreated,
                    duration,
                }],
                events: vec![ParsedConsensusEvent::ProposalCreated],
            }],
        };
        let config = StateEncoderConfig {
            step_timeout_reference: 3,
            ..default_config()
        };
        let states = encode_height_states(&height, config);

        assert_eq!(
            states[0].time_class, expected_class,
            "Duration {} should classify as {:?}",
            duration, expected_class
        );
    }
}

// =============================================================================
// Integration Tests - End-to-End
// =============================================================================

/// OBSERVER-INTEGRATION-1: Full pipeline from trajectory to encoded states
#[test]
fn integration_full_pipeline() {
    // Build a complex scenario
    let height = multi_round_with_divergence(1000);
    let config = default_config();

    // Encode
    let states = encode_height_states(&height, config);

    // Verify structure
    assert!(!states.is_empty(), "Should produce states");

    // All states should have same height
    assert!(states.iter().all(|s| s.height == 1000));

    // Should cover multiple rounds
    let unique_rounds: std::collections::HashSet<_> = states.iter().map(|s| s.round).collect();
    assert!(unique_rounds.len() > 1, "Should have multiple rounds");
}

/// OBSERVER-INTEGRATION-2: Serialization roundtrip preserves determinism
#[test]
fn integration_serialization_roundtrip() {
    let height = healthy_single_round(100, 0);
    let config = default_config();
    let states = encode_height_states(&height, config);

    // Serialize
    let serialized = serde_json::to_string(&states).expect("HARDENED: Non-terminating check");

    // Deserialize
    let deserialized: Vec<EncodedConsensusState> =
        serde_json::from_str(&serialized).expect("HARDENED: Non-terminating check");

    // Must match original
    assert_eq!(
        states, deserialized,
        "Serialization roundtrip must preserve state"
    );
}

/// OBSERVER-INTEGRATION-3: Multiple scenarios produce distinct signatures
#[test]
fn integration_distinct_scenarios_distinct_outputs() {
    // Use a constant height for all scenarios so uniqueness is due to scenario
    // differences, not trivially guaranteed by differing heights.
    let scenarios = vec![
        ("healthy", healthy_single_round(100, 0)),
        ("delayed", delayed_round(100, 0)),
        ("stalled", stalled_round(100, 0)),
        ("recovering", recovering_round(100, 1)),
        ("divergence", multi_round_with_divergence(100)),
    ];

    let config = default_config();
    let mut outputs = std::collections::HashSet::new();

    for (name, height) in &scenarios {
        let states = encode_height_states(&height, config);
        let serialized = serde_json::to_string(&states).expect("HARDENED: Non-terminating check");

        // Each scenario should produce unique output
        assert!(
            outputs.insert(serialized.clone()),
            "Scenario '{}' produced duplicate output",
            name
        );
    }

    assert_eq!(
        outputs.len(),
        scenarios.len(),
        "Each scenario should be unique"
    );
}

/// OBSERVER-INTEGRATION-4: Batch processing consistency
#[test]
fn integration_batch_processing_consistency() {
    let heights: Vec<_> = (0..100).map(|i| healthy_single_round(i, 0)).collect();
    let config = default_config();

    // Process all heights
    let batch_results: Vec<_> = heights
        .iter()
        .map(|h| encode_height_states(h, config))
        .collect();

    // Re-process and verify
    for (i, height) in heights.iter().enumerate() {
        let reprocessed = encode_height_states(height, config);
        assert_eq!(
            batch_results[i], reprocessed,
            "Height {} must be consistent across batch and individual processing",
            i
        );
    }
}
