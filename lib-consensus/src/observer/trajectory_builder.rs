use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::observer::{ConsensusBehaviorEventType, ConsensusNormalizedEvent};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConsensusPhaseType {
    Propose,
    PreVote,
    PreCommit,
    Commit,
    NewRound,
    Stalled,
    Recovering,
    ApplyingBlock,
    Fault,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PhaseTrajectory {
    pub phase_type: ConsensusPhaseType,
    pub start_event: ConsensusBehaviorEventType,
    pub end_event: ConsensusBehaviorEventType,
    pub duration: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoundTrajectory {
    pub round_number: u32,
    pub phases: Vec<PhaseTrajectory>,
    pub events: Vec<ConsensusNormalizedEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeightTrajectory {
    pub height: u64,
    pub rounds: Vec<RoundTrajectory>,
    pub events: Vec<ConsensusNormalizedEvent>,
}

pub fn build_height_trajectories(events: &[ConsensusNormalizedEvent]) -> Vec<HeightTrajectory> {
    let mut sorted = events.to_vec();
    sorted.sort_by_key(event_sort_key);

    let mut by_height: BTreeMap<u64, Vec<ConsensusNormalizedEvent>> = BTreeMap::new();
    for event in sorted {
        by_height.entry(event.height).or_default().push(event);
    }

    by_height
        .into_iter()
        .map(|(height, height_events)| {
            let mut by_round: BTreeMap<u32, Vec<ConsensusNormalizedEvent>> = BTreeMap::new();
            for event in &height_events {
                by_round.entry(event.round).or_default().push(event.clone());
            }

            let rounds = by_round
                .into_iter()
                .map(|(round_number, round_events)| {
                    build_round_trajectory(round_number, round_events)
                })
                .collect();

            HeightTrajectory {
                height,
                rounds,
                events: height_events,
            }
        })
        .collect()
}

pub fn build_round_trajectory(
    round_number: u32,
    mut events: Vec<ConsensusNormalizedEvent>,
) -> RoundTrajectory {
    events.sort_by_key(event_sort_key);
    let phases = build_phase_trajectories(&events);
    RoundTrajectory {
        round_number,
        phases,
        events,
    }
}

fn build_phase_trajectories(events: &[ConsensusNormalizedEvent]) -> Vec<PhaseTrajectory> {
    if events.is_empty() {
        return Vec::new();
    }

    let mut phases = Vec::new();
    let mut phase_start = 0usize;
    let mut current_phase = phase_for_event(events[0].event_type);

    for idx in 1..events.len() {
        let next_phase = phase_for_event(events[idx].event_type);
        if next_phase != current_phase {
            phases.push(build_phase(current_phase, phase_start, idx - 1, events));
            phase_start = idx;
            current_phase = next_phase;
        }
    }

    phases.push(build_phase(
        current_phase,
        phase_start,
        events.len() - 1,
        events,
    ));

    phases
}

fn build_phase(
    phase_type: ConsensusPhaseType,
    start_idx: usize,
    end_idx: usize,
    events: &[ConsensusNormalizedEvent],
) -> PhaseTrajectory {
    let start = &events[start_idx];
    let end = &events[end_idx];

    let duration = match (event_time(start), event_time(end)) {
        (Some(start_t), Some(end_t)) => end_t.saturating_sub(start_t),
        _ => (end_idx.saturating_sub(start_idx)) as u64,
    };

    PhaseTrajectory {
        phase_type,
        start_event: start.event_type,
        end_event: end.event_type,
        duration,
    }
}

fn phase_for_event(event_type: ConsensusBehaviorEventType) -> ConsensusPhaseType {
    match event_type {
        ConsensusBehaviorEventType::EnterPropose
        | ConsensusBehaviorEventType::ProposalCreated
        | ConsensusBehaviorEventType::ProposalReceived
        | ConsensusBehaviorEventType::InvalidProposalDetected => ConsensusPhaseType::Propose,

        ConsensusBehaviorEventType::EnterPreVote | ConsensusBehaviorEventType::PreVoteCast => {
            ConsensusPhaseType::PreVote
        }

        ConsensusBehaviorEventType::EnterPreCommit | ConsensusBehaviorEventType::PreCommitCast => {
            ConsensusPhaseType::PreCommit
        }

        ConsensusBehaviorEventType::EnterCommit
        | ConsensusBehaviorEventType::CommitVoteObserved
        | ConsensusBehaviorEventType::CommitQuorumReached
        | ConsensusBehaviorEventType::BlockCommitted => ConsensusPhaseType::Commit,

        ConsensusBehaviorEventType::EnterNewRound
        | ConsensusBehaviorEventType::RoundAdvanced
        | ConsensusBehaviorEventType::StepTimeout
        | ConsensusBehaviorEventType::HigherRoundObserved => ConsensusPhaseType::NewRound,

        ConsensusBehaviorEventType::ConsensusStalled => ConsensusPhaseType::Stalled,

        ConsensusBehaviorEventType::ConsensusRecovered
        | ConsensusBehaviorEventType::CatchupSyncStarted
        | ConsensusBehaviorEventType::CatchupSyncSucceeded
        | ConsensusBehaviorEventType::CatchupSyncFailed => ConsensusPhaseType::Recovering,

        ConsensusBehaviorEventType::BlockApplyStarted
        | ConsensusBehaviorEventType::BlockApplySucceeded
        | ConsensusBehaviorEventType::BlockApplyFailed
        | ConsensusBehaviorEventType::ParentHashMismatch => ConsensusPhaseType::ApplyingBlock,

        ConsensusBehaviorEventType::EquivocationDetected
        | ConsensusBehaviorEventType::ReplayDetected
        | ConsensusBehaviorEventType::PartitionSuspected => ConsensusPhaseType::Fault,
    }
}

fn event_time(event: &ConsensusNormalizedEvent) -> Option<u64> {
    event.logical_time.or(event.wallclock_time)
}

fn event_sort_key(event: &ConsensusNormalizedEvent) -> (u64, u32, u64, u64, u8, u16) {
    (
        event.height,
        event.round,
        event.logical_time.unwrap_or(u64::MAX),
        event.wallclock_time.unwrap_or(u64::MAX),
        if event.inferred { 1 } else { 0 },
        event_type_ordinal(event.event_type),
    )
}

fn event_type_ordinal(event_type: ConsensusBehaviorEventType) -> u16 {
    match event_type {
        ConsensusBehaviorEventType::EnterPropose => 1,
        ConsensusBehaviorEventType::EnterPreVote => 2,
        ConsensusBehaviorEventType::EnterPreCommit => 3,
        ConsensusBehaviorEventType::EnterCommit => 4,
        ConsensusBehaviorEventType::EnterNewRound => 5,
        ConsensusBehaviorEventType::RoundAdvanced => 6,
        ConsensusBehaviorEventType::ProposalCreated => 7,
        ConsensusBehaviorEventType::ProposalReceived => 8,
        ConsensusBehaviorEventType::PreVoteCast => 9,
        ConsensusBehaviorEventType::PreCommitCast => 10,
        ConsensusBehaviorEventType::CommitVoteObserved => 11,
        ConsensusBehaviorEventType::CommitQuorumReached => 12,
        ConsensusBehaviorEventType::BlockCommitted => 13,
        ConsensusBehaviorEventType::StepTimeout => 14,
        ConsensusBehaviorEventType::HigherRoundObserved => 15,
        ConsensusBehaviorEventType::ConsensusStalled => 16,
        ConsensusBehaviorEventType::ConsensusRecovered => 17,
        ConsensusBehaviorEventType::BlockApplyStarted => 18,
        ConsensusBehaviorEventType::BlockApplySucceeded => 19,
        ConsensusBehaviorEventType::BlockApplyFailed => 20,
        ConsensusBehaviorEventType::ParentHashMismatch => 21,
        ConsensusBehaviorEventType::CatchupSyncStarted => 22,
        ConsensusBehaviorEventType::CatchupSyncSucceeded => 23,
        ConsensusBehaviorEventType::CatchupSyncFailed => 24,
        ConsensusBehaviorEventType::EquivocationDetected => 25,
        ConsensusBehaviorEventType::ReplayDetected => 26,
        ConsensusBehaviorEventType::PartitionSuspected => 27,
        ConsensusBehaviorEventType::InvalidProposalDetected => 28,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(
        height: u64,
        round: u32,
        event_type: ConsensusBehaviorEventType,
        logical_time: u64,
    ) -> ConsensusNormalizedEvent {
        ConsensusNormalizedEvent {
            height,
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
    fn groups_trajectories_by_height_and_round() {
        let events = vec![
            ev(2, 1, ConsensusBehaviorEventType::EnterPropose, 2001),
            ev(1, 0, ConsensusBehaviorEventType::EnterPropose, 1000),
            ev(1, 1, ConsensusBehaviorEventType::EnterPreVote, 1010),
            ev(1, 0, ConsensusBehaviorEventType::PreVoteCast, 1002),
        ];

        let trajectories = build_height_trajectories(&events);
        assert_eq!(trajectories.len(), 2);
        assert_eq!(trajectories[0].height, 1);
        assert_eq!(trajectories[0].rounds.len(), 2);
        assert_eq!(trajectories[1].height, 2);
        assert_eq!(trajectories[1].rounds.len(), 1);
    }

    #[test]
    fn reconstructs_expected_phase_sequence_for_healthy_round() {
        let events = vec![
            ev(7, 0, ConsensusBehaviorEventType::EnterPropose, 7000),
            ev(7, 0, ConsensusBehaviorEventType::ProposalCreated, 7001),
            ev(7, 0, ConsensusBehaviorEventType::EnterPreVote, 7002),
            ev(7, 0, ConsensusBehaviorEventType::PreVoteCast, 7003),
            ev(7, 0, ConsensusBehaviorEventType::EnterPreCommit, 7004),
            ev(7, 0, ConsensusBehaviorEventType::PreCommitCast, 7005),
            ev(7, 0, ConsensusBehaviorEventType::EnterCommit, 7006),
            ev(7, 0, ConsensusBehaviorEventType::CommitQuorumReached, 7007),
            ev(7, 0, ConsensusBehaviorEventType::BlockCommitted, 7008),
        ];

        let round = build_round_trajectory(0, events);
        let phases: Vec<ConsensusPhaseType> = round.phases.iter().map(|p| p.phase_type).collect();
        assert_eq!(
            phases,
            vec![
                ConsensusPhaseType::Propose,
                ConsensusPhaseType::PreVote,
                ConsensusPhaseType::PreCommit,
                ConsensusPhaseType::Commit
            ]
        );
    }

    #[test]
    fn computes_duration_from_logical_time() {
        let round = build_round_trajectory(
            0,
            vec![
                ev(9, 0, ConsensusBehaviorEventType::EnterPropose, 9000),
                ev(9, 0, ConsensusBehaviorEventType::ProposalCreated, 9005),
            ],
        );

        assert_eq!(round.phases.len(), 1);
        assert_eq!(round.phases[0].duration, 5);
    }
}
