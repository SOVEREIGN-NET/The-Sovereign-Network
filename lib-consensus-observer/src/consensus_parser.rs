use serde::{Deserialize, Serialize};

use crate::{
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

    check_height_commit_block_count(height, &mut violations);
    check_commit_block_in_final_round(height, &mut violations);
    check_height_recovery_after_stall(height, &mut violations);
    check_height_divergence_after_apply_failed(height, &mut violations);

    violations
}

/// Each height must have exactly one BlockCommitted event.
fn check_height_commit_block_count(
    height: &HeightTrajectory,
    violations: &mut Vec<GrammarViolation>,
) {
    let count = height
        .events
        .iter()
        .filter(|e| e.event_type == ConsensusBehaviorEventType::BlockCommitted)
        .count();
    match count {
        0 => violations.push(GrammarViolation::MissingCommitBlockAtHeight {
            height: height.height,
        }),
        1 => {}
        n => violations.push(GrammarViolation::DuplicateCommitBlocksAtHeight {
            height: height.height,
            count: n,
        }),
    }
}

/// A round that contains a BlockCommitted event must be the final round at the height.
fn check_commit_block_in_final_round(
    height: &HeightTrajectory,
    violations: &mut Vec<GrammarViolation>,
) {
    let final_round_number = height.rounds.last().map(|r| r.round_number);
    for round in &height.rounds {
        let has_commit = round
            .events
            .iter()
            .any(|e| e.event_type == ConsensusBehaviorEventType::BlockCommitted);
        if has_commit && Some(round.round_number) != final_round_number {
            violations.push(GrammarViolation::CommitBlockNotInFinalRound {
                height: height.height,
                round: round.round_number,
            });
        }
    }
}

/// If consensus stalled at this height, recovery events must follow:
/// catchup_started → (catchup_succeeded | catchup_failed) → consensus_recovered.
fn check_height_recovery_after_stall(
    height: &HeightTrajectory,
    violations: &mut Vec<GrammarViolation>,
) {
    let events = &height.events;
    let has_event = |t| events.iter().any(|e| e.event_type == t);

    if !has_event(ConsensusBehaviorEventType::ConsensusStalled) {
        return;
    }

    if !has_event(ConsensusBehaviorEventType::CatchupSyncStarted) {
        violations.push(GrammarViolation::MissingRecoveryCatchupStart {
            height: height.height,
        });
    }

    let has_catchup_success = has_event(ConsensusBehaviorEventType::CatchupSyncSucceeded);
    let has_catchup_failed = has_event(ConsensusBehaviorEventType::CatchupSyncFailed);
    if !has_catchup_success && !has_catchup_failed {
        violations.push(GrammarViolation::MissingRecoveryCatchupOutcome {
            height: height.height,
        });
    }

    if has_catchup_success && !has_event(ConsensusBehaviorEventType::ConsensusRecovered) {
        violations.push(
            GrammarViolation::MissingConsensusRecoveredAfterCatchupSuccess {
                height: height.height,
            },
        );
    }

    check_height_pair_order(
        height,
        violations,
        ConsensusBehaviorEventType::CatchupSyncStarted,
        ConsensusBehaviorEventType::CatchupSyncSucceeded,
        |before, found| GrammarViolation::InvalidRecoveryOrder {
            height: height.height,
            expected_before: before,
            found,
        },
    );

    check_height_pair_order(
        height,
        violations,
        ConsensusBehaviorEventType::CatchupSyncSucceeded,
        ConsensusBehaviorEventType::ConsensusRecovered,
        |before, found| GrammarViolation::InvalidRecoveryOrder {
            height: height.height,
            expected_before: before,
            found,
        },
    );
}

/// If a block-apply failed, the divergence-handling sequence must be present in order:
/// block_apply_failed → parent_hash_mismatch → catchup_started.
fn check_height_divergence_after_apply_failed(
    height: &HeightTrajectory,
    violations: &mut Vec<GrammarViolation>,
) {
    let events = &height.events;
    let has_event = |t| events.iter().any(|e| e.event_type == t);

    if !has_event(ConsensusBehaviorEventType::BlockApplyFailed) {
        return;
    }

    if !has_event(ConsensusBehaviorEventType::ParentHashMismatch) {
        violations.push(GrammarViolation::MissingDivergenceParentHashMismatch {
            height: height.height,
        });
    }

    if !has_event(ConsensusBehaviorEventType::CatchupSyncStarted) {
        violations.push(GrammarViolation::MissingDivergenceCatchupStart {
            height: height.height,
        });
    }

    check_height_pair_order(
        height,
        violations,
        ConsensusBehaviorEventType::BlockApplyFailed,
        ConsensusBehaviorEventType::ParentHashMismatch,
        |before, found| GrammarViolation::InvalidDivergenceOrder {
            height: height.height,
            expected_before: before,
            found,
        },
    );

    check_height_pair_order(
        height,
        violations,
        ConsensusBehaviorEventType::ParentHashMismatch,
        ConsensusBehaviorEventType::CatchupSyncStarted,
        |before, found| GrammarViolation::InvalidDivergenceOrder {
            height: height.height,
            expected_before: before,
            found,
        },
    );
}

/// Generic helper: when both events are present at a height, the `before` must
/// precede the `found`; otherwise emit the violation produced by `mk`.
fn check_height_pair_order(
    height: &HeightTrajectory,
    violations: &mut Vec<GrammarViolation>,
    before: ConsensusBehaviorEventType,
    found: ConsensusBehaviorEventType,
    mk: impl FnOnce(ConsensusBehaviorEventType, ConsensusBehaviorEventType) -> GrammarViolation,
) {
    let (Some(before_idx), Some(found_idx)) = (
        first_event_index(&height.events, before),
        first_event_index(&height.events, found),
    ) else {
        return;
    };
    if before_idx > found_idx {
        violations.push(mk(before, found));
    }
}

pub fn validate_round_grammar(round: &RoundTrajectory) -> Vec<GrammarViolation> {
    let mut violations = Vec::new();
    if round.events.is_empty() {
        violations.push(GrammarViolation::EmptyRound {
            round: round.round_number,
        });
        return violations;
    }

    check_round_phase_order(round, &mut violations);
    check_round_commit_quorum_pairing(round, &mut violations);
    check_round_propose_outcome(round, &mut violations);
    check_round_timeout_round_advance(round, &mut violations);
    check_round_vote_commit_path(round, &mut violations);
    check_round_apply_lifecycle(round, &mut violations);

    violations
}

/// Phases inside a round must appear in order: Propose → PreVote → PreCommit → Commit.
fn check_round_phase_order(round: &RoundTrajectory, violations: &mut Vec<GrammarViolation>) {
    let has_phase = |t| round.phases.iter().any(|p| p.phase_type == t);
    let propose = has_phase(ConsensusPhaseType::Propose);
    let prevote = has_phase(ConsensusPhaseType::PreVote);
    let precommit = has_phase(ConsensusPhaseType::PreCommit);
    let commit = has_phase(ConsensusPhaseType::Commit);

    if prevote && !propose {
        violations.push(GrammarViolation::InvalidPhaseOrder {
            round: round.round_number,
            expected_before: ConsensusPhaseType::Propose,
            found: ConsensusPhaseType::PreVote,
        });
    }
    if precommit && !prevote {
        violations.push(GrammarViolation::InvalidPhaseOrder {
            round: round.round_number,
            expected_before: ConsensusPhaseType::PreVote,
            found: ConsensusPhaseType::PreCommit,
        });
    }
    if commit && !precommit {
        violations.push(GrammarViolation::InvalidPhaseOrder {
            round: round.round_number,
            expected_before: ConsensusPhaseType::PreCommit,
            found: ConsensusPhaseType::Commit,
        });
    }
}

/// CommitQuorumReached and BlockCommitted appear together or not at all within a round.
fn check_round_commit_quorum_pairing(
    round: &RoundTrajectory,
    violations: &mut Vec<GrammarViolation>,
) {
    let quorum = round_has_event(round, ConsensusBehaviorEventType::CommitQuorumReached);
    let commit = round_has_event(round, ConsensusBehaviorEventType::BlockCommitted);

    if commit && !quorum {
        violations.push(GrammarViolation::MissingCommitQuorum {
            round: round.round_number,
        });
    }
    if quorum && !commit {
        violations.push(GrammarViolation::MissingBlockCommit {
            round: round.round_number,
        });
    }
}

/// Every round must enter Propose and produce one of the propose outcomes
/// (ProposalCreated | ProposalReceived | StepTimeout); EnterPropose must come first.
fn check_round_propose_outcome(round: &RoundTrajectory, violations: &mut Vec<GrammarViolation>) {
    let propose = round
        .phases
        .iter()
        .any(|p| p.phase_type == ConsensusPhaseType::Propose);

    let outcome_types = [
        ConsensusBehaviorEventType::ProposalCreated,
        ConsensusBehaviorEventType::ProposalReceived,
        ConsensusBehaviorEventType::StepTimeout,
    ];

    if !propose {
        violations.push(GrammarViolation::MissingProposeEntry {
            round: round.round_number,
        });
    }

    if propose
        && !round
            .events
            .iter()
            .any(|e| outcome_types.contains(&e.event_type))
    {
        violations.push(GrammarViolation::MissingProposalOutcome {
            round: round.round_number,
        });
    }

    check_round_pair_order_any(
        round,
        violations,
        ConsensusBehaviorEventType::EnterPropose,
        &outcome_types,
    );
}

/// A StepTimeout must be followed by a round-advance event.
fn check_round_timeout_round_advance(
    round: &RoundTrajectory,
    violations: &mut Vec<GrammarViolation>,
) {
    let timeout = round_has_event(round, ConsensusBehaviorEventType::StepTimeout);
    let advance_types = [
        ConsensusBehaviorEventType::RoundAdvanced,
        ConsensusBehaviorEventType::HigherRoundObserved,
        ConsensusBehaviorEventType::EnterNewRound,
    ];
    let has_advance = round
        .events
        .iter()
        .any(|e| advance_types.contains(&e.event_type));

    if timeout && !has_advance {
        violations.push(GrammarViolation::MissingRoundAdvanceAfterTimeout {
            round: round.round_number,
        });
    }

    check_round_pair_order_any(
        round,
        violations,
        ConsensusBehaviorEventType::StepTimeout,
        &advance_types,
    );
}

/// When the round committed (BlockCommitted, CommitQuorumReached, or Commit phase),
/// the full vote-commit lifecycle must be present in order: enter-prevote → prevote-cast →
/// enter-precommit → precommit-cast → enter-commit → commit-quorum → block-committed.
fn check_round_vote_commit_path(round: &RoundTrajectory, violations: &mut Vec<GrammarViolation>) {
    let commit_phase = round
        .phases
        .iter()
        .any(|p| p.phase_type == ConsensusPhaseType::Commit);
    let needs_path = round_has_event(round, ConsensusBehaviorEventType::BlockCommitted)
        || round_has_event(round, ConsensusBehaviorEventType::CommitQuorumReached)
        || commit_phase;

    if !needs_path {
        return;
    }

    let required_entries = [
        (
            ConsensusBehaviorEventType::EnterPreVote,
            GrammarViolation::MissingPreVoteEntry {
                round: round.round_number,
            },
        ),
        (
            ConsensusBehaviorEventType::PreVoteCast,
            GrammarViolation::MissingPreVoteCast {
                round: round.round_number,
            },
        ),
        (
            ConsensusBehaviorEventType::EnterPreCommit,
            GrammarViolation::MissingPreCommitEntry {
                round: round.round_number,
            },
        ),
        (
            ConsensusBehaviorEventType::PreCommitCast,
            GrammarViolation::MissingPreCommitCast {
                round: round.round_number,
            },
        ),
        (
            ConsensusBehaviorEventType::EnterCommit,
            GrammarViolation::MissingCommitEntry {
                round: round.round_number,
            },
        ),
    ];
    for (event_type, missing_violation) in required_entries {
        if !round_has_event(round, event_type) {
            violations.push(missing_violation);
        }
    }

    let lifecycle_pairs = [
        (
            ConsensusBehaviorEventType::EnterPreVote,
            ConsensusBehaviorEventType::PreVoteCast,
        ),
        (
            ConsensusBehaviorEventType::PreVoteCast,
            ConsensusBehaviorEventType::EnterPreCommit,
        ),
        (
            ConsensusBehaviorEventType::EnterPreCommit,
            ConsensusBehaviorEventType::PreCommitCast,
        ),
        (
            ConsensusBehaviorEventType::PreCommitCast,
            ConsensusBehaviorEventType::EnterCommit,
        ),
        (
            ConsensusBehaviorEventType::EnterCommit,
            ConsensusBehaviorEventType::CommitQuorumReached,
        ),
        (
            ConsensusBehaviorEventType::CommitQuorumReached,
            ConsensusBehaviorEventType::BlockCommitted,
        ),
    ];
    for (before, after) in lifecycle_pairs {
        validate_ordering(
            violations,
            round.round_number,
            &round.events,
            before,
            after,
        );
    }
}

/// BlockCommitted must be followed by BlockApplyStarted, which must be followed by
/// BlockApplySucceeded or BlockApplyFailed.
fn check_round_apply_lifecycle(round: &RoundTrajectory, violations: &mut Vec<GrammarViolation>) {
    let commit = round_has_event(round, ConsensusBehaviorEventType::BlockCommitted);
    let apply_start = round_has_event(round, ConsensusBehaviorEventType::BlockApplyStarted);
    let outcome_types = [
        ConsensusBehaviorEventType::BlockApplySucceeded,
        ConsensusBehaviorEventType::BlockApplyFailed,
    ];
    let apply_outcome = round
        .events
        .iter()
        .any(|e| outcome_types.contains(&e.event_type));

    if commit && !apply_start {
        violations.push(GrammarViolation::MissingApplyStartAfterCommit {
            round: round.round_number,
        });
    }
    if apply_start && !apply_outcome {
        violations.push(GrammarViolation::MissingApplyOutcomeAfterStart {
            round: round.round_number,
        });
    }

    validate_ordering(
        violations,
        round.round_number,
        &round.events,
        ConsensusBehaviorEventType::BlockCommitted,
        ConsensusBehaviorEventType::BlockApplyStarted,
    );
    if let Some(outcome) = first_event_type_any(&round.events, &outcome_types) {
        validate_ordering(
            violations,
            round.round_number,
            &round.events,
            ConsensusBehaviorEventType::BlockApplyStarted,
            outcome,
        );
    }
}

/// Predicate helper: does this round contain any event of the given type?
fn round_has_event(round: &RoundTrajectory, event_type: ConsensusBehaviorEventType) -> bool {
    round.events.iter().any(|e| e.event_type == event_type)
}

/// Generic ordering check across an `any-of` set of follower event types: when the
/// `before` event and any `after` event are both present, `before` must precede the
/// first occurrence of any `after`. Used to express "X must come before any of {Y, Z}".
fn check_round_pair_order_any(
    round: &RoundTrajectory,
    violations: &mut Vec<GrammarViolation>,
    before: ConsensusBehaviorEventType,
    after_types: &[ConsensusBehaviorEventType],
) {
    let (Some(before_idx), Some(after_idx), Some(after)) = (
        first_event_index(&round.events, before),
        first_event_index_any(&round.events, after_types),
        first_event_type_any(&round.events, after_types),
    ) else {
        return;
    };
    if before_idx > after_idx {
        violations.push(GrammarViolation::InvalidEventOrder {
            round: round.round_number,
            expected_before: before,
            found: after,
        });
    }
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
