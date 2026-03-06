use serde::{Deserialize, Serialize};

use crate::observer::{
    build_height_trajectories, ConsensusBehaviorEventType, ConsensusNormalizedEvent,
    ConsensusPhaseType, HeightTrajectory, RoundTrajectory,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GrammarViolation {
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
}

pub fn parse_consensus_trajectories(events: &[ConsensusNormalizedEvent]) -> Vec<HeightTrajectory> {
    build_height_trajectories(events)
}

pub fn validate_height_grammar(height: &HeightTrajectory) -> Vec<GrammarViolation> {
    let mut violations = Vec::new();
    for round in &height.rounds {
        violations.extend(validate_round_grammar(round));
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

    violations
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
            ev(0, ConsensusBehaviorEventType::EnterPreVote, 2),
            ev(0, ConsensusBehaviorEventType::EnterPreCommit, 3),
            ev(0, ConsensusBehaviorEventType::EnterCommit, 4),
            ev(0, ConsensusBehaviorEventType::CommitQuorumReached, 5),
            ev(0, ConsensusBehaviorEventType::BlockCommitted, 6),
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
}
