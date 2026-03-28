//! Consensus Observer Module
//!
//! Implements deterministic, passive observer layer for consensus behavior analysis.
//! See Epic #1781: Consensus Round Dynamics & Behavioral Grammar v0.1

pub mod consensus_parser;
pub mod event_normalizer;
pub mod height_scoring;
pub mod observer_service;
pub mod state_encoder;
pub mod surprisal_engine;
pub mod trajectory_builder;
pub mod transition_model;

// Re-export consensus parser types
pub use consensus_parser::{
    parse_consensus_trajectories, validate_height_grammar, validate_round_grammar, GrammarViolation,
};

// Re-export event normalizer types
pub use event_normalizer::{
    normalize_audit_log, normalize_byzantine_evidence, normalize_consensus_event,
    normalize_operational_message, normalize_runtime_signal, ConsensusBehaviorEventType,
    ConsensusNormalizedEvent, NormalizationError, RuntimeConsensusSignal,
};

// Re-export height scoring types
pub use height_scoring::{
    analyze_trend, compute_height_score, compute_network_health, ClassificationThresholds,
    ConsensusTrend, HeightClassification, HeightScore, HeightScoringConfig, NetworkHealthSummary,
    ScoreBreakdown, ValidatorAnomalyScore,
};

// Re-export observer service types
pub use observer_service::{
    create_observer_service, create_observer_service_with_config, HeightAnalysis, ObserverHandle,
    ObserverService, ObserverServiceConfig,
};

// Re-export state encoder types
pub use state_encoder::{
    encode_height_states, encode_round_states, EncodedConsensusPhase, EncodedConsensusState,
    ExecutionStatus, ParsedConsensusEvent, ParsedConsensusPhase, ParsedHeightTrajectory,
    ParsedPhaseTrajectory, ParsedRoundTrajectory, ProposalStatus, RoundClass, StateEncoderConfig,
    TimeClass,
};

// Re-export surprisal engine types
pub use surprisal_engine::{
    analyze_height_surprisal, compute_baseline_stats, sequence_surprisal, surprisal,
    HeightSurprisalAnalysis, Surprisal, SurprisalConfig, SurprisalLevel, SurprisalStats,
    TransitionSurprisal,
};

// Re-export trajectory builder types
pub use trajectory_builder::{
    build_height_trajectories, build_round_trajectory, ConsensusPhaseType, HeightTrajectory,
    PhaseTrajectory, RoundTrajectory,
};

// Re-export transition model types
pub use transition_model::{
    build_model_from_history, compute_sequence_probabilities, ConsensusStateKey, StateTransition,
    TransitionModel,
};
