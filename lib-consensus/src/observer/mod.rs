pub mod consensus_parser;
pub mod event_normalizer;
pub mod state_encoder;
pub mod trajectory_builder;

pub use consensus_parser::{
    parse_consensus_trajectories, validate_height_grammar, validate_round_grammar, GrammarViolation,
};
pub use event_normalizer::{
    normalize_audit_log, normalize_byzantine_evidence, normalize_consensus_event,
    normalize_operational_message, normalize_runtime_signal, ConsensusBehaviorEventType,
    ConsensusNormalizedEvent, NormalizationError, RuntimeConsensusSignal,
};
pub use trajectory_builder::{
    build_height_trajectories, ConsensusPhaseType, HeightTrajectory, PhaseTrajectory,
    RoundTrajectory,
};
pub use state_encoder::{
    encode_height_states, encode_round_states, EncodedConsensusPhase, EncodedConsensusState,
    ExecutionStatus, ParsedConsensusEvent, ParsedConsensusPhase, ParsedHeightTrajectory,
    ParsedPhaseTrajectory, ParsedRoundTrajectory, ProposalStatus, RoundClass, StateEncoderConfig,
    TimeClass,
};
