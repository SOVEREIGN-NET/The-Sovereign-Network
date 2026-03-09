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
            let inferred_events = infer_missing_events(&height_events);
            let rounds = split_rounds_with_inference(&inferred_events);
            let events = rounds
                .iter()
                .flat_map(|r| r.events.iter().cloned())
                .collect::<Vec<_>>();

            HeightTrajectory {
                height,
                rounds,
                events,
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

fn infer_missing_events(events: &[ConsensusNormalizedEvent]) -> Vec<ConsensusNormalizedEvent> {
    if events.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for i in 0..events.len() {
        let current = events[i].clone();
        let next = events.get(i + 1);
        out.push(current.clone());

        match current.event_type {
            ConsensusBehaviorEventType::StepTimeout => match next.map(|e| e.event_type) {
                Some(ConsensusBehaviorEventType::RoundAdvanced)
                | Some(ConsensusBehaviorEventType::HigherRoundObserved) => {}
                Some(ConsensusBehaviorEventType::EnterNewRound) => out.push(inferred_from(
                    &current,
                    ConsensusBehaviorEventType::RoundAdvanced,
                    current.round,
                )),
                _ => {
                    out.push(inferred_from(
                        &current,
                        ConsensusBehaviorEventType::RoundAdvanced,
                        current.round,
                    ));
                    out.push(inferred_from(
                        &current,
                        ConsensusBehaviorEventType::EnterNewRound,
                        current.round.saturating_add(1),
                    ));
                }
            },
            ConsensusBehaviorEventType::RoundAdvanced
            | ConsensusBehaviorEventType::HigherRoundObserved => {
                if !matches!(
                    next.map(|e| e.event_type),
                    Some(ConsensusBehaviorEventType::EnterNewRound)
                ) {
                    out.push(inferred_from(
                        &current,
                        ConsensusBehaviorEventType::EnterNewRound,
                        current.round.saturating_add(1),
                    ));
                }
            }
            ConsensusBehaviorEventType::BlockCommitted => {
                if !matches!(
                    next.map(|e| e.event_type),
                    Some(ConsensusBehaviorEventType::BlockApplyStarted)
                ) {
                    out.push(inferred_from(
                        &current,
                        ConsensusBehaviorEventType::BlockApplyStarted,
                        current.round,
                    ));
                }
            }
            _ => {}
        }
    }

    out
}

fn split_rounds_with_inference(events: &[ConsensusNormalizedEvent]) -> Vec<RoundTrajectory> {
    if events.is_empty() {
        return Vec::new();
    }

    let mut rounds = Vec::new();
    let mut current_events: Vec<ConsensusNormalizedEvent> = Vec::new();
    let mut current_round = events[0].round;

    for event in events {
        let mut start_new_round = false;
        let mut next_round = current_round;

        if !current_events.is_empty() {
            if event.event_type == ConsensusBehaviorEventType::EnterNewRound {
                start_new_round = true;
                next_round = if event.round > current_round {
                    event.round
                } else {
                    current_round.saturating_add(1)
                };
            } else if event.round > current_round {
                start_new_round = true;
                next_round = event.round;
            }
        }

        if start_new_round {
            rounds.push(build_round_trajectory(
                current_round,
                std::mem::take(&mut current_events),
            ));
            current_round = next_round;
        }

        let mut adjusted = event.clone();
        adjusted.round = current_round;
        current_events.push(adjusted);
    }

    if !current_events.is_empty() {
        rounds.push(build_round_trajectory(current_round, current_events));
    }

    rounds
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
    // Only use logical_time for deterministic scoring.
    // Wallclock time is not used to ensure reproducibility across nodes.
    event.logical_time
}

fn inferred_from(
    base: &ConsensusNormalizedEvent,
    event_type: ConsensusBehaviorEventType,
    round: u32,
) -> ConsensusNormalizedEvent {
    ConsensusNormalizedEvent {
        height: base.height,
        round,
        step: None,
        event_type,
        validator_id: None,
        logical_time: base.logical_time,
        wallclock_time: base.wallclock_time,
        peer_id: None,
        proposal_id: None,
        metadata: BTreeMap::new(),
        inferred: true,
    }
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
    fn infers_round_advance_and_new_round_after_timeout() {
        let events = vec![
            ev(3, 0, ConsensusBehaviorEventType::EnterPropose, 3000),
            ev(3, 0, ConsensusBehaviorEventType::StepTimeout, 3001),
            ev(3, 0, ConsensusBehaviorEventType::EnterPropose, 3002),
        ];

        let trajectories = build_height_trajectories(&events);
        let height = &trajectories[0];
        assert_eq!(height.rounds.len(), 2);

        let first_round_events: Vec<ConsensusBehaviorEventType> = height.rounds[0]
            .events
            .iter()
            .map(|e| e.event_type)
            .collect();
        assert!(first_round_events.contains(&ConsensusBehaviorEventType::RoundAdvanced));

        let second_round_events: Vec<ConsensusBehaviorEventType> = height.rounds[1]
            .events
            .iter()
            .map(|e| e.event_type)
            .collect();
        assert_eq!(
            second_round_events.first(),
            Some(&ConsensusBehaviorEventType::EnterNewRound)
        );
    }

    #[test]
    fn does_not_duplicate_explicit_round_advance_path_events() {
        let events = vec![
            ev(5, 0, ConsensusBehaviorEventType::EnterPropose, 5000),
            ev(5, 0, ConsensusBehaviorEventType::StepTimeout, 5001),
            ev(5, 0, ConsensusBehaviorEventType::RoundAdvanced, 5002),
            ev(5, 1, ConsensusBehaviorEventType::EnterNewRound, 5003),
            ev(5, 1, ConsensusBehaviorEventType::EnterPropose, 5004),
        ];

        let trajectories = build_height_trajectories(&events);
        let all_events: Vec<ConsensusBehaviorEventType> = trajectories[0]
            .events
            .iter()
            .map(|e| e.event_type)
            .collect();

        assert_eq!(
            all_events
                .iter()
                .filter(|event| **event == ConsensusBehaviorEventType::RoundAdvanced)
                .count(),
            1
        );
        assert_eq!(
            all_events
                .iter()
                .filter(|event| **event == ConsensusBehaviorEventType::EnterNewRound)
                .count(),
            1
        );
    }

    #[test]
    fn infers_block_apply_started_after_commit() {
        let events = vec![ev(4, 1, ConsensusBehaviorEventType::BlockCommitted, 4100)];
        let trajectories = build_height_trajectories(&events);
        let round = &trajectories[0].rounds[0];
        let round_events: Vec<ConsensusBehaviorEventType> =
            round.events.iter().map(|e| e.event_type).collect();
        assert_eq!(
            round_events,
            vec![
                ConsensusBehaviorEventType::BlockCommitted,
                ConsensusBehaviorEventType::BlockApplyStarted
            ]
        );
        assert!(round.events[1].inferred);
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
