use serde::{Deserialize, Serialize};

use crate::observer::{
    build_height_trajectories, ConsensusBehaviorEventType, ConsensusNormalizedEvent,
    ConsensusPhaseType, HeightTrajectory, RoundTrajectory,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GrammarViolation {
    MissingRoundsAtHeight {
        height: u64,
    },
    EmptyRound {
        round: u32,
    },
    MissingCommitQuorum {
        round: u32,
    },
    MissingBlockCommit {
        round: u32,
    },
    InvalidPhaseOrder {
        round: u32,
        expected_before: ConsensusPhaseType,
        found: ConsensusPhaseType,
    },
    MissingProposeEntry {
        round: u32,
    },
    MissingProposalOutcome {
        round: u32,
    },
    MissingPreVoteEntry {
        round: u32,
    },
    MissingPreVoteCast {
        round: u32,
    },
    MissingPreCommitEntry {
        round: u32,
    },
    MissingPreCommitCast {
        round: u32,
    },
    MissingCommitEntry {
        round: u32,
    },
    MissingRoundAdvanceAfterTimeout {
        round: u32,
    },
    MissingApplyStartAfterCommit {
        round: u32,
    },
    MissingApplyOutcomeAfterStart {
        round: u32,
    },
    MissingCommitBlockAtHeight {
        height: u64,
    },
    MissingRecoveryCatchupStart {
        height: u64,
    },
    MissingRecoveryCatchupOutcome {
        height: u64,
    },
    MissingConsensusRecoveredAfterCatchupSuccess {
        height: u64,
    },
    MissingDivergenceParentHashMismatch {
        height: u64,
    },
    MissingDivergenceCatchupStart {
        height: u64,
    },
    DuplicateCommitBlocksAtHeight {
        height: u64,
        count: usize,
    },
    CommitBlockNotInFinalRound {
        height: u64,
        round: u32,
    },
    InvalidEventOrder {
        round: u32,
        expected_before: ConsensusBehaviorEventType,
        found: ConsensusBehaviorEventType,
    },
    InvalidRecoveryOrder {
        height: u64,
        expected_before: ConsensusBehaviorEventType,
        found: ConsensusBehaviorEventType,
    },
    InvalidDivergenceOrder {
        height: u64,
        expected_before: ConsensusBehaviorEventType,
        found: ConsensusBehaviorEventType,
    },
}

pub fn parse_consensus_trajectories(events: &[ConsensusNormalizedEvent]) -> Vec<HeightTrajectory> {
    build_height_trajectories(events)
}

pub fn validate_height_grammar(height: &HeightTrajectory) -> Vec<GrammarViolation> {
    let mut violations = Vec::new();
    if height.rounds.is_empty() {
        violations.push(GrammarViolation::MissingRoundsAtHeight {
            height: height.height,
        });
        return violations;
    }

    for round in &height.rounds {
        violations.extend(validate_round_grammar(round));
    }

    let commit_block_count = height
        .events
        .iter()
        .filter(|e| e.event_type == ConsensusBehaviorEventType::BlockCommitted)
        .count();
    if commit_block_count == 0 {
        violations.push(GrammarViolation::MissingCommitBlockAtHeight {
            height: height.height,
        });
    } else if commit_block_count > 1 {
        violations.push(GrammarViolation::DuplicateCommitBlocksAtHeight {
            height: height.height,
            count: commit_block_count,
        });
    }

    let final_round_number = height.rounds.last().map(|r| r.round_number);
    for round in &height.rounds {
        let has_commit_in_round = round
            .events
            .iter()
            .any(|e| e.event_type == ConsensusBehaviorEventType::BlockCommitted);
        if has_commit_in_round && Some(round.round_number) != final_round_number {
            violations.push(GrammarViolation::CommitBlockNotInFinalRound {
                height: height.height,
                round: round.round_number,
            });
        }
    }

    let has_stalled = height
        .events
        .iter()
        .any(|e| e.event_type == ConsensusBehaviorEventType::ConsensusStalled);
    if has_stalled {
        let has_catchup_start = height
            .events
            .iter()
            .any(|e| e.event_type == ConsensusBehaviorEventType::CatchupSyncStarted);
        if !has_catchup_start {
            violations.push(GrammarViolation::MissingRecoveryCatchupStart {
                height: height.height,
            });
        }

        let has_catchup_success = height
            .events
            .iter()
            .any(|e| e.event_type == ConsensusBehaviorEventType::CatchupSyncSucceeded);
        let has_catchup_failed = height
            .events
            .iter()
            .any(|e| e.event_type == ConsensusBehaviorEventType::CatchupSyncFailed);
        if !has_catchup_success && !has_catchup_failed {
            violations.push(GrammarViolation::MissingRecoveryCatchupOutcome {
                height: height.height,
            });
        }
        if has_catchup_success
            && !height
                .events
                .iter()
                .any(|e| e.event_type == ConsensusBehaviorEventType::ConsensusRecovered)
        {
            violations.push(
                GrammarViolation::MissingConsensusRecoveredAfterCatchupSuccess {
                    height: height.height,
                },
            );
        }

        if let (Some(start_idx), Some(success_idx)) = (
            first_event_index(
                &height.events,
                ConsensusBehaviorEventType::CatchupSyncStarted,
            ),
            first_event_index(
                &height.events,
                ConsensusBehaviorEventType::CatchupSyncSucceeded,
            ),
        ) {
            if start_idx > success_idx {
                violations.push(GrammarViolation::InvalidRecoveryOrder {
                    height: height.height,
                    expected_before: ConsensusBehaviorEventType::CatchupSyncStarted,
                    found: ConsensusBehaviorEventType::CatchupSyncSucceeded,
                });
            }
        }

        if let (Some(success_idx), Some(recovered_idx)) = (
            first_event_index(
                &height.events,
                ConsensusBehaviorEventType::CatchupSyncSucceeded,
            ),
            first_event_index(
                &height.events,
                ConsensusBehaviorEventType::ConsensusRecovered,
            ),
        ) {
            if success_idx > recovered_idx {
                violations.push(GrammarViolation::InvalidRecoveryOrder {
                    height: height.height,
                    expected_before: ConsensusBehaviorEventType::CatchupSyncSucceeded,
                    found: ConsensusBehaviorEventType::ConsensusRecovered,
                });
            }
        }
    }

    let has_apply_failed = height
        .events
        .iter()
        .any(|e| e.event_type == ConsensusBehaviorEventType::BlockApplyFailed);
    if has_apply_failed {
        if !height
            .events
            .iter()
            .any(|e| e.event_type == ConsensusBehaviorEventType::ParentHashMismatch)
        {
            violations.push(GrammarViolation::MissingDivergenceParentHashMismatch {
                height: height.height,
            });
        }
        if !height
            .events
            .iter()
            .any(|e| e.event_type == ConsensusBehaviorEventType::CatchupSyncStarted)
        {
            violations.push(GrammarViolation::MissingDivergenceCatchupStart {
                height: height.height,
            });
        }

        if let (Some(failed_idx), Some(parent_mismatch_idx)) = (
            first_event_index(&height.events, ConsensusBehaviorEventType::BlockApplyFailed),
            first_event_index(
                &height.events,
                ConsensusBehaviorEventType::ParentHashMismatch,
            ),
        ) {
            if failed_idx > parent_mismatch_idx {
                violations.push(GrammarViolation::InvalidDivergenceOrder {
                    height: height.height,
                    expected_before: ConsensusBehaviorEventType::BlockApplyFailed,
                    found: ConsensusBehaviorEventType::ParentHashMismatch,
                });
            }
        }

        if let (Some(parent_mismatch_idx), Some(catchup_start_idx)) = (
            first_event_index(
                &height.events,
                ConsensusBehaviorEventType::ParentHashMismatch,
            ),
            first_event_index(
                &height.events,
                ConsensusBehaviorEventType::CatchupSyncStarted,
            ),
        ) {
            if parent_mismatch_idx > catchup_start_idx {
                violations.push(GrammarViolation::InvalidDivergenceOrder {
                    height: height.height,
                    expected_before: ConsensusBehaviorEventType::ParentHashMismatch,
                    found: ConsensusBehaviorEventType::CatchupSyncStarted,
                });
            }
        }
    }

    violations
}

pub fn validate_round_grammar(round: &RoundTrajectory) -> Vec<GrammarViolation> {
    let mut violations = Vec::new();
    if round.events.is_empty() {
        violations.push(GrammarViolation::EmptyRound {
            round: round.round_number,
        });
        return violations;
    }

    let has_propose = round
        .phases
        .iter()
        .any(|p| p.phase_type == ConsensusPhaseType::Propose);
    let has_prevote = round
        .phases
        .iter()
        .any(|p| p.phase_type == ConsensusPhaseType::PreVote);
    let has_precommit = round
        .phases
        .iter()
        .any(|p| p.phase_type == ConsensusPhaseType::PreCommit);
    let has_commit = round
        .phases
        .iter()
        .any(|p| p.phase_type == ConsensusPhaseType::Commit);

    if has_prevote && !has_propose {
        violations.push(GrammarViolation::InvalidPhaseOrder {
            round: round.round_number,
            expected_before: ConsensusPhaseType::Propose,
            found: ConsensusPhaseType::PreVote,
        });
    }
    if has_precommit && !has_prevote {
        violations.push(GrammarViolation::InvalidPhaseOrder {
            round: round.round_number,
            expected_before: ConsensusPhaseType::PreVote,
            found: ConsensusPhaseType::PreCommit,
        });
    }
    if has_commit && !has_precommit {
        violations.push(GrammarViolation::InvalidPhaseOrder {
            round: round.round_number,
            expected_before: ConsensusPhaseType::PreCommit,
            found: ConsensusPhaseType::Commit,
        });
    }

    let has_timeout = round
        .events
        .iter()
        .any(|e| e.event_type == ConsensusBehaviorEventType::StepTimeout);
    let has_round_advance = round.events.iter().any(|e| {
        matches!(
            e.event_type,
            ConsensusBehaviorEventType::RoundAdvanced
                | ConsensusBehaviorEventType::HigherRoundObserved
                | ConsensusBehaviorEventType::EnterNewRound
        )
    });

    let has_commit_quorum = round
        .events
        .iter()
        .any(|e| e.event_type == ConsensusBehaviorEventType::CommitQuorumReached);
    let has_block_commit = round
        .events
        .iter()
        .any(|e| e.event_type == ConsensusBehaviorEventType::BlockCommitted);

    if has_block_commit && !has_commit_quorum {
        violations.push(GrammarViolation::MissingCommitQuorum {
            round: round.round_number,
        });
    }
    if has_commit_quorum && !has_block_commit {
        violations.push(GrammarViolation::MissingBlockCommit {
            round: round.round_number,
        });
    }

    if !has_propose {
        violations.push(GrammarViolation::MissingProposeEntry {
            round: round.round_number,
        });
    }

    if has_propose
        && !round.events.iter().any(|e| {
            matches!(
                e.event_type,
                ConsensusBehaviorEventType::ProposalCreated
                    | ConsensusBehaviorEventType::ProposalReceived
                    | ConsensusBehaviorEventType::StepTimeout
            )
        })
    {
        violations.push(GrammarViolation::MissingProposalOutcome {
            round: round.round_number,
        });
    }
    if let (Some(enter_propose_idx), Some(outcome_idx), Some(outcome)) = (
        first_event_index(&round.events, ConsensusBehaviorEventType::EnterPropose),
        first_event_index_any(
            &round.events,
            &[
                ConsensusBehaviorEventType::ProposalCreated,
                ConsensusBehaviorEventType::ProposalReceived,
                ConsensusBehaviorEventType::StepTimeout,
            ],
        ),
        first_event_type_any(
            &round.events,
            &[
                ConsensusBehaviorEventType::ProposalCreated,
                ConsensusBehaviorEventType::ProposalReceived,
                ConsensusBehaviorEventType::StepTimeout,
            ],
        ),
    ) {
        if enter_propose_idx > outcome_idx {
            violations.push(GrammarViolation::InvalidEventOrder {
                round: round.round_number,
                expected_before: ConsensusBehaviorEventType::EnterPropose,
                found: outcome,
            });
        }
    }

    if has_timeout && !has_round_advance {
        violations.push(GrammarViolation::MissingRoundAdvanceAfterTimeout {
            round: round.round_number,
        });
    }
    if let (Some(timeout_idx), Some(round_advance_idx), Some(round_advance_event)) = (
        first_event_index(&round.events, ConsensusBehaviorEventType::StepTimeout),
        first_event_index_any(
            &round.events,
            &[
                ConsensusBehaviorEventType::RoundAdvanced,
                ConsensusBehaviorEventType::HigherRoundObserved,
                ConsensusBehaviorEventType::EnterNewRound,
            ],
        ),
        first_event_type_any(
            &round.events,
            &[
                ConsensusBehaviorEventType::RoundAdvanced,
                ConsensusBehaviorEventType::HigherRoundObserved,
                ConsensusBehaviorEventType::EnterNewRound,
            ],
        ),
    ) {
        if timeout_idx > round_advance_idx {
            violations.push(GrammarViolation::InvalidEventOrder {
                round: round.round_number,
                expected_before: ConsensusBehaviorEventType::StepTimeout,
                found: round_advance_event,
            });
        }
    }

    let needs_vote_commit_path = has_block_commit || has_commit_quorum || has_commit;
    if needs_vote_commit_path {
        if !round
            .events
            .iter()
            .any(|e| e.event_type == ConsensusBehaviorEventType::EnterPreVote)
        {
            violations.push(GrammarViolation::MissingPreVoteEntry {
                round: round.round_number,
            });
        }
        if !round
            .events
            .iter()
            .any(|e| e.event_type == ConsensusBehaviorEventType::PreVoteCast)
        {
            violations.push(GrammarViolation::MissingPreVoteCast {
                round: round.round_number,
            });
        }
        if !round
            .events
            .iter()
            .any(|e| e.event_type == ConsensusBehaviorEventType::EnterPreCommit)
        {
            violations.push(GrammarViolation::MissingPreCommitEntry {
                round: round.round_number,
            });
        }
        if !round
            .events
            .iter()
            .any(|e| e.event_type == ConsensusBehaviorEventType::PreCommitCast)
        {
            violations.push(GrammarViolation::MissingPreCommitCast {
                round: round.round_number,
            });
        }
        if !round
            .events
            .iter()
            .any(|e| e.event_type == ConsensusBehaviorEventType::EnterCommit)
        {
            violations.push(GrammarViolation::MissingCommitEntry {
                round: round.round_number,
            });
        }

        validate_ordering(
            &mut violations,
            round.round_number,
            &round.events,
            ConsensusBehaviorEventType::EnterPreVote,
            ConsensusBehaviorEventType::PreVoteCast,
        );
        validate_ordering(
            &mut violations,
            round.round_number,
            &round.events,
            ConsensusBehaviorEventType::PreVoteCast,
            ConsensusBehaviorEventType::EnterPreCommit,
        );
        validate_ordering(
            &mut violations,
            round.round_number,
            &round.events,
            ConsensusBehaviorEventType::EnterPreCommit,
            ConsensusBehaviorEventType::PreCommitCast,
        );
        validate_ordering(
            &mut violations,
            round.round_number,
            &round.events,
            ConsensusBehaviorEventType::PreCommitCast,
            ConsensusBehaviorEventType::EnterCommit,
        );
        validate_ordering(
            &mut violations,
            round.round_number,
            &round.events,
            ConsensusBehaviorEventType::EnterCommit,
            ConsensusBehaviorEventType::CommitQuorumReached,
        );
        validate_ordering(
            &mut violations,
            round.round_number,
            &round.events,
            ConsensusBehaviorEventType::CommitQuorumReached,
            ConsensusBehaviorEventType::BlockCommitted,
        );
    }

    let has_apply_start = round
        .events
        .iter()
        .any(|e| e.event_type == ConsensusBehaviorEventType::BlockApplyStarted);
    let has_apply_outcome = round.events.iter().any(|e| {
        matches!(
            e.event_type,
            ConsensusBehaviorEventType::BlockApplySucceeded
                | ConsensusBehaviorEventType::BlockApplyFailed
        )
    });
    if has_block_commit && !has_apply_start {
        violations.push(GrammarViolation::MissingApplyStartAfterCommit {
            round: round.round_number,
        });
    }
    if has_apply_start && !has_apply_outcome {
        violations.push(GrammarViolation::MissingApplyOutcomeAfterStart {
            round: round.round_number,
        });
    }
    validate_ordering(
        &mut violations,
        round.round_number,
        &round.events,
        ConsensusBehaviorEventType::BlockCommitted,
        ConsensusBehaviorEventType::BlockApplyStarted,
    );
    if let Some(outcome) = first_event_type_any(
        &round.events,
        &[
            ConsensusBehaviorEventType::BlockApplySucceeded,
            ConsensusBehaviorEventType::BlockApplyFailed,
        ],
    ) {
        validate_ordering(
            &mut violations,
            round.round_number,
            &round.events,
            ConsensusBehaviorEventType::BlockApplyStarted,
            outcome,
        );
    }

    violations
}

fn validate_ordering(
    violations: &mut Vec<GrammarViolation>,
    round_number: u32,
    events: &[ConsensusNormalizedEvent],
    expected_before: ConsensusBehaviorEventType,
    found: ConsensusBehaviorEventType,
) {
    let Some(before_idx) = first_event_index(events, expected_before) else {
        return;
    };
    let Some(found_idx) = first_event_index(events, found) else {
        return;
    };
    if before_idx > found_idx {
        violations.push(GrammarViolation::InvalidEventOrder {
            round: round_number,
            expected_before,
            found,
        });
    }
}

fn first_event_index(
    events: &[ConsensusNormalizedEvent],
    event_type: ConsensusBehaviorEventType,
) -> Option<usize> {
    events.iter().position(|e| e.event_type == event_type)
}

fn first_event_index_any(
    events: &[ConsensusNormalizedEvent],
    event_types: &[ConsensusBehaviorEventType],
) -> Option<usize> {
    events
        .iter()
        .position(|event| event_types.contains(&event.event_type))
}

fn first_event_type_any(
    events: &[ConsensusNormalizedEvent],
    event_types: &[ConsensusBehaviorEventType],
) -> Option<ConsensusBehaviorEventType> {
    events
        .iter()
        .map(|event| event.event_type)
        .find(|event_type| event_types.contains(event_type))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn ev(
        round: u32,
        event_type: ConsensusBehaviorEventType,
        logical_time: u64,
    ) -> ConsensusNormalizedEvent {
        ConsensusNormalizedEvent {
            height: 11,
            round,
            step: None,
            event_type,
            validator_id: None,
            logical_time: Some(logical_time),
            wallclock_time: None,
            peer_id: None,
            proposal_id: None,
            metadata: BTreeMap::new(),
            inferred: false,
        }
    }

    #[test]
    fn valid_round_has_no_violations() {
        let trajectories = parse_consensus_trajectories(&[
            ev(0, ConsensusBehaviorEventType::EnterPropose, 1),
            ev(0, ConsensusBehaviorEventType::ProposalCreated, 2),
            ev(0, ConsensusBehaviorEventType::EnterPreVote, 2),
            ev(0, ConsensusBehaviorEventType::PreVoteCast, 3),
            ev(0, ConsensusBehaviorEventType::EnterPreCommit, 4),
            ev(0, ConsensusBehaviorEventType::PreCommitCast, 5),
            ev(0, ConsensusBehaviorEventType::EnterCommit, 6),
            ev(0, ConsensusBehaviorEventType::CommitQuorumReached, 7),
            ev(0, ConsensusBehaviorEventType::BlockCommitted, 8),
            ev(0, ConsensusBehaviorEventType::BlockApplyStarted, 9),
            ev(0, ConsensusBehaviorEventType::BlockApplySucceeded, 10),
        ]);
        let violations = validate_height_grammar(&trajectories[0]);
        assert!(violations.is_empty());
    }

    #[test]
    fn detects_missing_commit_quorum() {
        let trajectories = parse_consensus_trajectories(&[
            ev(0, ConsensusBehaviorEventType::EnterCommit, 1),
            ev(0, ConsensusBehaviorEventType::BlockCommitted, 2),
        ]);
        let violations = validate_height_grammar(&trajectories[0]);
        assert!(violations
            .iter()
            .any(|v| matches!(v, GrammarViolation::MissingCommitQuorum { .. })));
    }

    #[test]
    fn detects_invalid_phase_order() {
        let trajectories = parse_consensus_trajectories(&[
            ev(0, ConsensusBehaviorEventType::EnterPreCommit, 1),
            ev(0, ConsensusBehaviorEventType::PreCommitCast, 2),
        ]);
        let violations = validate_height_grammar(&trajectories[0]);
        assert!(violations.iter().any(|v| matches!(
            v,
            GrammarViolation::InvalidPhaseOrder {
                expected_before: ConsensusPhaseType::PreVote,
                found: ConsensusPhaseType::PreCommit,
                ..
            }
        )));
    }

    #[test]
    fn delayed_round_path_is_valid() {
        let trajectories = parse_consensus_trajectories(&[
            ev(0, ConsensusBehaviorEventType::EnterPropose, 1),
            ev(0, ConsensusBehaviorEventType::StepTimeout, 2),
            ev(0, ConsensusBehaviorEventType::RoundAdvanced, 3),
            ev(1, ConsensusBehaviorEventType::EnterNewRound, 4),
            ev(1, ConsensusBehaviorEventType::EnterPropose, 5),
            ev(1, ConsensusBehaviorEventType::ProposalReceived, 6),
            ev(1, ConsensusBehaviorEventType::EnterPreVote, 7),
            ev(1, ConsensusBehaviorEventType::PreVoteCast, 8),
            ev(1, ConsensusBehaviorEventType::EnterPreCommit, 9),
            ev(1, ConsensusBehaviorEventType::PreCommitCast, 10),
            ev(1, ConsensusBehaviorEventType::EnterCommit, 11),
            ev(1, ConsensusBehaviorEventType::CommitQuorumReached, 12),
            ev(1, ConsensusBehaviorEventType::BlockCommitted, 13),
            ev(1, ConsensusBehaviorEventType::BlockApplyStarted, 14),
            ev(1, ConsensusBehaviorEventType::BlockApplySucceeded, 15),
        ]);
        let violations = validate_height_grammar(&trajectories[0]);
        assert!(!violations
            .iter()
            .any(|v| matches!(v, GrammarViolation::MissingRoundAdvanceAfterTimeout { .. })));
    }

    #[test]
    fn detects_missing_recovery_sequence() {
        let trajectories = parse_consensus_trajectories(&[
            ev(0, ConsensusBehaviorEventType::EnterPropose, 1),
            ev(0, ConsensusBehaviorEventType::ProposalCreated, 2),
            ev(0, ConsensusBehaviorEventType::ConsensusStalled, 3),
            ev(0, ConsensusBehaviorEventType::BlockCommitted, 4),
            ev(0, ConsensusBehaviorEventType::BlockApplyStarted, 5),
            ev(0, ConsensusBehaviorEventType::BlockApplySucceeded, 6),
        ]);
        let violations = validate_height_grammar(&trajectories[0]);
        assert!(violations
            .iter()
            .any(|v| matches!(v, GrammarViolation::MissingRecoveryCatchupStart { .. })));
        assert!(violations
            .iter()
            .any(|v| matches!(v, GrammarViolation::MissingRecoveryCatchupOutcome { .. })));
    }

    #[test]
    fn detects_execution_divergence_requirements() {
        let trajectories = parse_consensus_trajectories(&[
            ev(0, ConsensusBehaviorEventType::EnterPropose, 1),
            ev(0, ConsensusBehaviorEventType::ProposalCreated, 2),
            ev(0, ConsensusBehaviorEventType::EnterPreVote, 3),
            ev(0, ConsensusBehaviorEventType::PreVoteCast, 4),
            ev(0, ConsensusBehaviorEventType::EnterPreCommit, 5),
            ev(0, ConsensusBehaviorEventType::PreCommitCast, 6),
            ev(0, ConsensusBehaviorEventType::EnterCommit, 7),
            ev(0, ConsensusBehaviorEventType::CommitQuorumReached, 8),
            ev(0, ConsensusBehaviorEventType::BlockCommitted, 9),
            ev(0, ConsensusBehaviorEventType::BlockApplyStarted, 10),
            ev(0, ConsensusBehaviorEventType::BlockApplyFailed, 11),
        ]);
        let violations = validate_height_grammar(&trajectories[0]);
        assert!(violations.iter().any(|v| matches!(
            v,
            GrammarViolation::MissingDivergenceParentHashMismatch { .. }
        )));
        assert!(violations
            .iter()
            .any(|v| matches!(v, GrammarViolation::MissingDivergenceCatchupStart { .. })));
    }

    #[test]
    fn detects_invalid_commit_event_order() {
        let trajectories = parse_consensus_trajectories(&[
            ev(0, ConsensusBehaviorEventType::EnterPropose, 1),
            ev(0, ConsensusBehaviorEventType::ProposalCreated, 2),
            ev(0, ConsensusBehaviorEventType::EnterPreVote, 3),
            ev(0, ConsensusBehaviorEventType::PreVoteCast, 4),
            ev(0, ConsensusBehaviorEventType::EnterPreCommit, 5),
            ev(0, ConsensusBehaviorEventType::PreCommitCast, 6),
            ev(0, ConsensusBehaviorEventType::CommitQuorumReached, 7),
            ev(0, ConsensusBehaviorEventType::EnterCommit, 8),
            ev(0, ConsensusBehaviorEventType::BlockCommitted, 9),
            ev(0, ConsensusBehaviorEventType::BlockApplyStarted, 10),
            ev(0, ConsensusBehaviorEventType::BlockApplySucceeded, 11),
        ]);
        let violations = validate_height_grammar(&trajectories[0]);
        assert!(violations.iter().any(|v| matches!(
            v,
            GrammarViolation::InvalidEventOrder {
                expected_before: ConsensusBehaviorEventType::EnterCommit,
                found: ConsensusBehaviorEventType::CommitQuorumReached,
                ..
            }
        )));
    }

    #[test]
    fn detects_commit_block_not_in_last_round() {
        let trajectories = parse_consensus_trajectories(&[
            ev(0, ConsensusBehaviorEventType::EnterPropose, 1),
            ev(0, ConsensusBehaviorEventType::ProposalCreated, 2),
            ev(0, ConsensusBehaviorEventType::EnterPreVote, 3),
            ev(0, ConsensusBehaviorEventType::PreVoteCast, 4),
            ev(0, ConsensusBehaviorEventType::EnterPreCommit, 5),
            ev(0, ConsensusBehaviorEventType::PreCommitCast, 6),
            ev(0, ConsensusBehaviorEventType::EnterCommit, 7),
            ev(0, ConsensusBehaviorEventType::CommitQuorumReached, 8),
            ev(0, ConsensusBehaviorEventType::BlockCommitted, 9),
            ev(0, ConsensusBehaviorEventType::BlockApplyStarted, 10),
            ev(0, ConsensusBehaviorEventType::BlockApplySucceeded, 11),
            ev(1, ConsensusBehaviorEventType::EnterNewRound, 12),
            ev(1, ConsensusBehaviorEventType::EnterPropose, 13),
            ev(1, ConsensusBehaviorEventType::StepTimeout, 14),
            ev(1, ConsensusBehaviorEventType::RoundAdvanced, 15),
        ]);
        let violations = validate_height_grammar(&trajectories[0]);
        assert!(violations
            .iter()
            .any(|v| matches!(v, GrammarViolation::CommitBlockNotInFinalRound { .. })));
    }

    #[test]
    fn detects_invalid_recovery_event_order() {
        let trajectories = parse_consensus_trajectories(&[
            ev(0, ConsensusBehaviorEventType::EnterPropose, 1),
            ev(0, ConsensusBehaviorEventType::ProposalCreated, 2),
            ev(0, ConsensusBehaviorEventType::ConsensusStalled, 3),
            ev(0, ConsensusBehaviorEventType::CatchupSyncSucceeded, 4),
            ev(0, ConsensusBehaviorEventType::CatchupSyncStarted, 5),
            ev(0, ConsensusBehaviorEventType::ConsensusRecovered, 6),
            ev(0, ConsensusBehaviorEventType::BlockCommitted, 7),
            ev(0, ConsensusBehaviorEventType::BlockApplyStarted, 8),
            ev(0, ConsensusBehaviorEventType::BlockApplySucceeded, 9),
        ]);
        let violations = validate_height_grammar(&trajectories[0]);
        assert!(violations.iter().any(|v| matches!(
            v,
            GrammarViolation::InvalidRecoveryOrder {
                expected_before: ConsensusBehaviorEventType::CatchupSyncStarted,
                found: ConsensusBehaviorEventType::CatchupSyncSucceeded,
                ..
            }
        )));
    }

    #[test]
    fn detects_invalid_divergence_event_order() {
        let trajectories = parse_consensus_trajectories(&[
            ev(0, ConsensusBehaviorEventType::EnterPropose, 1),
            ev(0, ConsensusBehaviorEventType::ProposalCreated, 2),
            ev(0, ConsensusBehaviorEventType::EnterPreVote, 3),
            ev(0, ConsensusBehaviorEventType::PreVoteCast, 4),
            ev(0, ConsensusBehaviorEventType::EnterPreCommit, 5),
            ev(0, ConsensusBehaviorEventType::PreCommitCast, 6),
            ev(0, ConsensusBehaviorEventType::EnterCommit, 7),
            ev(0, ConsensusBehaviorEventType::CommitQuorumReached, 8),
            ev(0, ConsensusBehaviorEventType::BlockCommitted, 9),
            ev(0, ConsensusBehaviorEventType::BlockApplyStarted, 10),
            ev(0, ConsensusBehaviorEventType::ParentHashMismatch, 11),
            ev(0, ConsensusBehaviorEventType::BlockApplyFailed, 12),
            ev(0, ConsensusBehaviorEventType::CatchupSyncStarted, 13),
        ]);
        let violations = validate_height_grammar(&trajectories[0]);
        assert!(violations.iter().any(|v| matches!(
            v,
            GrammarViolation::InvalidDivergenceOrder {
                expected_before: ConsensusBehaviorEventType::BlockApplyFailed,
                found: ConsensusBehaviorEventType::ParentHashMismatch,
                ..
            }
        )));
    }
}
