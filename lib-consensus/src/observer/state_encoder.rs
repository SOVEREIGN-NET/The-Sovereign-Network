use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ParsedConsensusPhase {
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ParsedConsensusEvent {
    EnterPropose,
    ProposalCreated,
    ProposalReceived,
    StepTimeout,
    BlockApplyStarted,
    BlockApplySucceeded,
    BlockApplyFailed,
    EquivocationDetected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedPhaseTrajectory {
    pub phase: ParsedConsensusPhase,
    pub end_event: ParsedConsensusEvent,
    pub duration: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedRoundTrajectory {
    pub round_number: u32,
    pub phases: Vec<ParsedPhaseTrajectory>,
    pub events: Vec<ParsedConsensusEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedHeightTrajectory {
    pub height: u64,
    pub rounds: Vec<ParsedRoundTrajectory>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EncodedConsensusPhase {
    Propose,
    PreVote,
    PreCommit,
    Commit,
    NewRound,
    Stalled,
    Recovering,
    ApplyingBlock,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RoundClass {
    R0,
    R1,
    R2_3,
    R4Plus,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TimeClass {
    Early,
    Mid,
    Late,
    TimedOut,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProposalStatus {
    Unknown,
    Missing,
    Seen,
    Created,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExecutionStatus {
    None,
    ApplyStarted,
    ApplySucceeded,
    ApplyFailed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateEncoderConfig {
    /// Reference duration used for Early/Mid/Late classification.
    pub step_timeout_reference: u64,
    pub fallback_phase: EncodedConsensusPhase,
    pub fallback_time_class: TimeClass,
}

impl Default for StateEncoderConfig {
    fn default() -> Self {
        Self {
            step_timeout_reference: 3,
            fallback_phase: EncodedConsensusPhase::NewRound,
            fallback_time_class: TimeClass::Mid,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncodedConsensusState {
    pub height: u64,
    pub round: u32,
    pub phase: EncodedConsensusPhase,
    pub round_class: RoundClass,
    pub time_class: TimeClass,
    pub proposal_status: ProposalStatus,
    pub execution_status: ExecutionStatus,
}

pub fn encode_height_states(
    height: &ParsedHeightTrajectory,
    config: StateEncoderConfig,
) -> Vec<EncodedConsensusState> {
    let mut encoded = Vec::new();
    for round in &height.rounds {
        encoded.extend(encode_round_states(height.height, round, config));
    }
    encoded
}

pub fn encode_round_states(
    height: u64,
    round: &ParsedRoundTrajectory,
    config: StateEncoderConfig,
) -> Vec<EncodedConsensusState> {
    let round_class = classify_round(round.round_number);
    let proposal_status = derive_proposal_status(round);
    let execution_status = derive_execution_status(round);

    if round.phases.is_empty() {
        return vec![EncodedConsensusState {
            height,
            round: round.round_number,
            phase: config.fallback_phase,
            round_class,
            time_class: config.fallback_time_class,
            proposal_status,
            execution_status,
        }];
    }

    round
        .phases
        .iter()
        .map(|phase| EncodedConsensusState {
            height,
            round: round.round_number,
            phase: map_phase(phase.phase, config.fallback_phase),
            round_class,
            time_class: classify_time(
                phase.end_event,
                phase.duration,
                config.step_timeout_reference,
            ),
            proposal_status,
            execution_status,
        })
        .collect()
}

fn classify_round(round_number: u32) -> RoundClass {
    match round_number {
        0 => RoundClass::R0,
        1 => RoundClass::R1,
        2 | 3 => RoundClass::R2_3,
        _ => RoundClass::R4Plus,
    }
}

fn map_phase(
    phase: ParsedConsensusPhase,
    fallback: EncodedConsensusPhase,
) -> EncodedConsensusPhase {
    match phase {
        ParsedConsensusPhase::Propose => EncodedConsensusPhase::Propose,
        ParsedConsensusPhase::PreVote => EncodedConsensusPhase::PreVote,
        ParsedConsensusPhase::PreCommit => EncodedConsensusPhase::PreCommit,
        ParsedConsensusPhase::Commit => EncodedConsensusPhase::Commit,
        ParsedConsensusPhase::NewRound => EncodedConsensusPhase::NewRound,
        ParsedConsensusPhase::Stalled => EncodedConsensusPhase::Stalled,
        ParsedConsensusPhase::Recovering => EncodedConsensusPhase::Recovering,
        ParsedConsensusPhase::ApplyingBlock => EncodedConsensusPhase::ApplyingBlock,
        // Spec state model has no fault phase; fallback is explicit and deterministic.
        ParsedConsensusPhase::Fault => fallback,
    }
}

fn classify_time(
    phase_end_event: ParsedConsensusEvent,
    duration: u64,
    step_timeout_reference: u64,
) -> TimeClass {
    if phase_end_event == ParsedConsensusEvent::StepTimeout {
        return TimeClass::TimedOut;
    }

    if duration == 0 {
        return TimeClass::Early;
    }

    let timeout_ref = step_timeout_reference.max(1);
    let third = timeout_ref / 3;
    let two_thirds = (timeout_ref * 2) / 3;

    if duration <= third.max(1) {
        TimeClass::Early
    } else if duration <= two_thirds.max(1) {
        TimeClass::Mid
    } else {
        TimeClass::Late
    }
}

fn derive_proposal_status(round: &ParsedRoundTrajectory) -> ProposalStatus {
    if round
        .events
        .iter()
        .any(|e| *e == ParsedConsensusEvent::ProposalCreated)
    {
        return ProposalStatus::Created;
    }
    if round
        .events
        .iter()
        .any(|e| *e == ParsedConsensusEvent::ProposalReceived)
    {
        return ProposalStatus::Seen;
    }

    let has_propose = round
        .events
        .iter()
        .any(|e| *e == ParsedConsensusEvent::EnterPropose);
    let has_timeout = round
        .events
        .iter()
        .any(|e| *e == ParsedConsensusEvent::StepTimeout);

    if has_propose && has_timeout {
        ProposalStatus::Missing
    } else {
        ProposalStatus::Unknown
    }
}

fn derive_execution_status(round: &ParsedRoundTrajectory) -> ExecutionStatus {
    if round
        .events
        .iter()
        .any(|e| *e == ParsedConsensusEvent::BlockApplyFailed)
    {
        return ExecutionStatus::ApplyFailed;
    }
    if round
        .events
        .iter()
        .any(|e| *e == ParsedConsensusEvent::BlockApplySucceeded)
    {
        return ExecutionStatus::ApplySucceeded;
    }
    if round
        .events
        .iter()
        .any(|e| *e == ParsedConsensusEvent::BlockApplyStarted)
    {
        return ExecutionStatus::ApplyStarted;
    }
    ExecutionStatus::None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn phase(
        p: ParsedConsensusPhase,
        end_event: ParsedConsensusEvent,
        duration: u64,
    ) -> ParsedPhaseTrajectory {
        ParsedPhaseTrajectory {
            phase: p,
            end_event,
            duration,
        }
    }

    #[test]
    fn encodes_all_dimensions_with_spec_classes() {
        let height = ParsedHeightTrajectory {
            height: 7,
            rounds: vec![ParsedRoundTrajectory {
                round_number: 0,
                phases: vec![
                    phase(
                        ParsedConsensusPhase::Propose,
                        ParsedConsensusEvent::ProposalCreated,
                        1,
                    ),
                    phase(
                        ParsedConsensusPhase::PreVote,
                        ParsedConsensusEvent::ProposalReceived,
                        1,
                    ),
                    phase(
                        ParsedConsensusPhase::PreCommit,
                        ParsedConsensusEvent::ProposalReceived,
                        1,
                    ),
                    phase(
                        ParsedConsensusPhase::Commit,
                        ParsedConsensusEvent::ProposalReceived,
                        2,
                    ),
                    phase(
                        ParsedConsensusPhase::ApplyingBlock,
                        ParsedConsensusEvent::BlockApplySucceeded,
                        1,
                    ),
                ],
                events: vec![
                    ParsedConsensusEvent::EnterPropose,
                    ParsedConsensusEvent::ProposalCreated,
                    ParsedConsensusEvent::BlockApplyStarted,
                    ParsedConsensusEvent::BlockApplySucceeded,
                ],
            }],
        };

        let states = encode_height_states(&height, StateEncoderConfig::default());
        assert_eq!(states.len(), 5);
        assert!(states.iter().all(|s| s.height == 7));
        assert!(states.iter().all(|s| s.round_class == RoundClass::R0));
        assert!(states
            .iter()
            .all(|s| s.proposal_status == ProposalStatus::Created));
        assert!(states
            .iter()
            .all(|s| s.execution_status == ExecutionStatus::ApplySucceeded));
    }

    #[test]
    fn deterministic_for_identical_input() {
        let round = ParsedRoundTrajectory {
            round_number: 1,
            phases: vec![phase(
                ParsedConsensusPhase::Propose,
                ParsedConsensusEvent::StepTimeout,
                5,
            )],
            events: vec![
                ParsedConsensusEvent::EnterPropose,
                ParsedConsensusEvent::StepTimeout,
            ],
        };
        let height = ParsedHeightTrajectory {
            height: 11,
            rounds: vec![round],
        };
        let config = StateEncoderConfig::default();

        let first = encode_height_states(&height, config);
        let second = encode_height_states(&height, config);
        assert_eq!(first, second);
    }

    #[test]
    fn missing_values_use_explicit_fallback_classes() {
        let round = ParsedRoundTrajectory {
            round_number: 4,
            phases: vec![],
            events: vec![ParsedConsensusEvent::EquivocationDetected],
        };
        let config = StateEncoderConfig {
            fallback_phase: EncodedConsensusPhase::Stalled,
            fallback_time_class: TimeClass::Mid,
            ..StateEncoderConfig::default()
        };

        let states = encode_round_states(30, &round, config);
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].phase, EncodedConsensusPhase::Stalled);
        assert_eq!(states[0].time_class, TimeClass::Mid);
        assert_eq!(states[0].round_class, RoundClass::R4Plus);
        assert_eq!(states[0].proposal_status, ProposalStatus::Unknown);
        assert_eq!(states[0].execution_status, ExecutionStatus::None);
    }

    #[test]
    fn timeout_phase_maps_to_timed_out_class() {
        let round = ParsedRoundTrajectory {
            round_number: 0,
            phases: vec![phase(
                ParsedConsensusPhase::Propose,
                ParsedConsensusEvent::StepTimeout,
                10,
            )],
            events: vec![
                ParsedConsensusEvent::EnterPropose,
                ParsedConsensusEvent::StepTimeout,
            ],
        };

        let states = encode_round_states(1, &round, StateEncoderConfig::default());
        assert_eq!(states[0].time_class, TimeClass::TimedOut);
        assert_eq!(states[0].proposal_status, ProposalStatus::Missing);
    }

    #[test]
    fn round_class_encoding_matches_spec() {
        let config = StateEncoderConfig::default();
        let mk = |r| ParsedRoundTrajectory {
            round_number: r,
            phases: vec![],
            events: vec![],
        };

        assert_eq!(
            encode_round_states(1, &mk(0), config)[0].round_class,
            RoundClass::R0
        );
        assert_eq!(
            encode_round_states(1, &mk(1), config)[0].round_class,
            RoundClass::R1
        );
        assert_eq!(
            encode_round_states(1, &mk(2), config)[0].round_class,
            RoundClass::R2_3
        );
        assert_eq!(
            encode_round_states(1, &mk(3), config)[0].round_class,
            RoundClass::R2_3
        );
        assert_eq!(
            encode_round_states(1, &mk(4), config)[0].round_class,
            RoundClass::R4Plus
        );
    }
}
