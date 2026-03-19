//! Surprisal Engine for Consensus Observer
//!
//! Implements surprisal (information content) calculation for consensus transitions.
//! Surprisal S = -log2(P) where P is the transition probability.
//! Low-probability transitions have high surprisal, indicating anomalous behavior.

use serde::{Deserialize, Serialize};

use crate::observer::{
    state_encoder::EncodedConsensusState,
    transition_model::{compute_sequence_probabilities, TransitionModel},
};

/// Surprisal value in bits (log2).
pub type Surprisal = f64;

/// Configuration for surprisal calculation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SurprisalConfig {
    /// Minimum probability to avoid log(0) - values below this are clamped.
    pub min_probability: f64,
    /// Maximum surprisal to return (for numerical stability).
    pub max_surprisal: f64,
    /// Logarithm base: 2.0 for bits, 10.0 for dits, e for nats.
    pub log_base: f64,
}

impl Default for SurprisalConfig {
    fn default() -> Self {
        Self {
            min_probability: 1e-10, // Very small but non-zero
            max_surprisal: 100.0,   // Cap at 100 bits
            log_base: 2.0,          // Bits (information theory standard)
        }
    }
}

impl SurprisalConfig {
    /// Create config with base-2 logarithm (bits).
    pub fn bits() -> Self {
        Self {
            log_base: 2.0,
            ..Default::default()
        }
    }

    /// Create config with natural logarithm (nats).
    pub fn nats() -> Self {
        Self {
            log_base: std::f64::consts::E,
            ..Default::default()
        }
    }

    /// Create config with base-10 logarithm (dits/hartleys).
    pub fn dits() -> Self {
        Self {
            log_base: 10.0,
            ..Default::default()
        }
    }
}

/// Compute surprisal for a single transition.
///
/// Surprisal S = -log(P) where P is the transition probability.
/// Returns None if probability is invalid (negative, NaN, > 1.0, or infinite)
/// or if config has invalid log_base.
pub fn surprisal(probability: f64, config: &SurprisalConfig) -> Option<Surprisal> {
    // Validate probability is finite and in valid range [0, 1]
    if !probability.is_finite() || probability < 0.0 || probability > 1.0 {
        return None;
    }

    // Validate log_base: must be finite, > 0, and != 1.0
    let base = config.log_base;
    if !base.is_finite() || base <= 0.0 || (base - 1.0).abs() < f64::EPSILON {
        return None;
    }

    // Validate min_probability is in (0, 1]
    let min_p = config.min_probability;
    if !min_p.is_finite() || min_p <= 0.0 || min_p > 1.0 {
        return None;
    }

    // Clamp probability to [min_probability, 1.0] to avoid log(0)
    let p = probability.clamp(min_p, 1.0);

    // Compute -log_base(p) = -ln(p) / ln(base)
    let raw_surprisal = -p.ln() / base.ln();

    // Cap at maximum for numerical stability
    Some(raw_surprisal.min(config.max_surprisal))
}

/// Compute surprisal for a transition between two states.
pub fn transition_surprisal(
    from: &EncodedConsensusState,
    to: &EncodedConsensusState,
    model: &TransitionModel,
    config: &SurprisalConfig,
) -> Option<Surprisal> {
    let prob = model.transition_probability(from, to);
    surprisal(prob, config)
}

/// Surprisal result for a single transition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransitionSurprisal {
    pub from: EncodedConsensusState,
    pub to: EncodedConsensusState,
    pub probability: f64,
    pub surprisal: Surprisal,
}

/// Compute surprisal for a sequence of states.
///
/// Returns a vector of surprisal values, one per transition.
pub fn sequence_surprisal(
    states: &[EncodedConsensusState],
    model: &TransitionModel,
    config: &SurprisalConfig,
) -> Vec<TransitionSurprisal> {
    let probs = compute_sequence_probabilities(states, model);

    probs
        .into_iter()
        .filter_map(|(from, to, probability)| {
            surprisal(probability, config).map(|s| TransitionSurprisal {
                from,
                to,
                probability,
                surprisal: s,
            })
        })
        .collect()
}

/// Aggregate surprisal statistics for a sequence.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct SurprisalStats {
    pub total_surprisal: Surprisal,
    pub mean_surprisal: f64,
    pub max_surprisal: Surprisal,
    pub min_surprisal: Surprisal,
    pub transition_count: usize,
    pub high_surprisal_count: usize, // Count of surprisals above threshold
}

impl SurprisalStats {
    /// Compute statistics from a sequence of transition surprisals.
    pub fn from_transitions(transitions: &[TransitionSurprisal]) -> Self {
        if transitions.is_empty() {
            return Self::default();
        }

        let surprisals: Vec<f64> = transitions.iter().map(|t| t.surprisal).collect();
        let total: f64 = surprisals.iter().sum();
        let max: f64 = surprisals.iter().fold(0.0_f64, |a: f64, b: &f64| a.max(*b));
        let min: f64 = surprisals.iter().fold(f64::INFINITY, |a: f64, b: &f64| a.min(*b));

        // Count transitions with surprisal > 5 bits (low probability < 1/32)
        let high_count = surprisals.iter().filter(|&&s| s > 5.0).count();

        Self {
            total_surprisal: total,
            mean_surprisal: total / surprisals.len() as f64,
            max_surprisal: max,
            min_surprisal: min,
            transition_count: transitions.len(),
            high_surprisal_count: high_count,
        }
    }
}

/// Threshold-based classification for surprisal values.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum SurprisalLevel {
    /// Expected behavior (surprisal < 2 bits)
    Expected,
    /// Slightly unusual (2-4 bits)
    Unusual,
    /// Anomalous (4-8 bits)
    Anomalous,
    /// Highly anomalous (> 8 bits)
    Critical,
}

impl SurprisalLevel {
    /// Classify a surprisal value.
    pub fn from_surprisal(surprisal: Surprisal) -> Self {
        match surprisal {
            s if s < 2.0 => Self::Expected,
            s if s < 4.0 => Self::Unusual,
            s if s < 8.0 => Self::Anomalous,
            _ => Self::Critical,
        }
    }

    /// Get human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Expected => "expected behavior",
            Self::Unusual => "slightly unusual",
            Self::Anomalous => "anomalous",
            Self::Critical => "highly anomalous",
        }
    }

    /// Check if this level indicates potential issues.
    pub fn is_concerning(&self) -> bool {
        matches!(self, Self::Anomalous | Self::Critical)
    }
}

/// Surprisal analysis result for a height.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HeightSurprisalAnalysis {
    pub height: u64,
    pub stats: SurprisalStats,
    pub transitions: Vec<TransitionSurprisal>,
    pub max_level: SurprisalLevel,
    pub concerning_transitions: Vec<usize>, // Indices of concerning transitions
}

/// Analyze surprisal for a complete height trajectory.
pub fn analyze_height_surprisal(
    height: u64,
    states: &[EncodedConsensusState],
    model: &TransitionModel,
    config: &SurprisalConfig,
) -> HeightSurprisalAnalysis {
    let transitions = sequence_surprisal(states, model, config);
    let stats = SurprisalStats::from_transitions(&transitions);

    let max_level = SurprisalLevel::from_surprisal(stats.max_surprisal);

    let concerning_transitions: Vec<usize> = transitions
        .iter()
        .enumerate()
        .filter(|(_, t)| SurprisalLevel::from_surprisal(t.surprisal).is_concerning())
        .map(|(i, _)| i)
        .collect();

    HeightSurprisalAnalysis {
        height,
        stats,
        transitions,
        max_level,
        concerning_transitions,
    }
}

/// Batch analyzer for multiple heights.
pub fn analyze_heights_batch(
    heights: &[(u64, Vec<EncodedConsensusState>)],
    model: &TransitionModel,
    config: &SurprisalConfig,
) -> Vec<HeightSurprisalAnalysis> {
    heights
        .iter()
        .map(|(height, states)| analyze_height_surprisal(*height, states, model, config))
        .collect()
}

/// Compute baseline surprisal from a healthy reference dataset.
///
/// This establishes expected surprisal ranges for normal operation.
pub fn compute_baseline_stats(
    reference_sequences: &[Vec<EncodedConsensusState>],
    model: &TransitionModel,
    config: &SurprisalConfig,
) -> SurprisalStats {
    let all_transitions: Vec<TransitionSurprisal> = reference_sequences
        .iter()
        .flat_map(|seq| sequence_surprisal(seq, model, config))
        .collect();

    SurprisalStats::from_transitions(&all_transitions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observer::{
        state_encoder::{
            EncodedConsensusPhase, ExecutionStatus, ProposalStatus, RoundClass, TimeClass,
        },
        transition_model::TransitionModel,
    };

    fn test_state(
        height: u64,
        round: u32,
        phase: EncodedConsensusPhase,
    ) -> EncodedConsensusState {
        EncodedConsensusState {
            height,
            round,
            phase,
            round_class: RoundClass::R0,
            time_class: TimeClass::Early,
            proposal_status: ProposalStatus::Created,
            execution_status: ExecutionStatus::ApplySucceeded,
        }
    }

    #[test]
    fn surprisal_of_certain_event_is_zero() {
        let config = SurprisalConfig::bits();
        let s = surprisal(1.0, &config).ok();
        assert!(s.abs() < 0.001, "Surprisal of P=1 should be 0");
    }

    #[test]
    fn surprisal_of_unlikely_event_is_high() {
        let config = SurprisalConfig::bits();
        let s = surprisal(0.01, &config).ok(); // 1% probability
        // -log2(0.01) ≈ 6.64 bits
        assert!(s > 6.0 && s < 7.0, "Surprisal of P=0.01 should be ~6.64 bits");
    }

    #[test]
    fn surprisal_clamps_minimum_probability() {
        let config = SurprisalConfig::bits();
        let s = surprisal(0.0, &config).ok(); // Should use min_probability
        assert!(s > 0.0, "Surprisal should be positive even for P=0");
    }

    #[test]
    fn transition_surprisal_integration() {
        let mut model = TransitionModel::new();
        let s1 = test_state(1, 0, EncodedConsensusPhase::Propose);
        let s2 = test_state(1, 0, EncodedConsensusPhase::PreVote);

        // Observe transition many times (high probability)
        for _ in 0..100 {
            model.observe_transition(&s1, &s2);
        }

        // Also observe some other transitions
        let s3 = test_state(1, 0, EncodedConsensusPhase::PreCommit);
        model.observe_transition(&s1, &s3);

        let config = SurprisalConfig::bits();
        let surp = transition_surprisal(&s1, &s2, &model, &config).ok();

        // High probability transition should have low surprisal
        assert!(surp < 1.0, "Common transition should have low surprisal");
    }

    #[test]
    fn sequence_surprisal_computes_all_transitions() {
        let mut model = TransitionModel::new();
        let states = vec![
            test_state(1, 0, EncodedConsensusPhase::Propose),
            test_state(1, 0, EncodedConsensusPhase::PreVote),
            test_state(1, 0, EncodedConsensusPhase::PreCommit),
        ];

        // Bootstrap model with observations
        model.observe_sequence(&states);
        model.observe_sequence(&states);

        let config = SurprisalConfig::bits();
        let surprisals = sequence_surprisal(&states, &model, &config);

        assert_eq!(surprisals.len(), 2); // 3 states = 2 transitions
    }

    #[test]
    fn surprisal_stats_computes_correctly() {
        let transitions = vec![
            TransitionSurprisal {
                from: test_state(1, 0, EncodedConsensusPhase::Propose),
                to: test_state(1, 0, EncodedConsensusPhase::PreVote),
                probability: 0.5,
                surprisal: 1.0,
            },
            TransitionSurprisal {
                from: test_state(1, 0, EncodedConsensusPhase::PreVote),
                to: test_state(1, 0, EncodedConsensusPhase::PreCommit),
                probability: 0.25,
                surprisal: 2.0,
            },
        ];

        let stats = SurprisalStats::from_transitions(&transitions);

        assert_eq!(stats.total_surprisal, 3.0);
        assert_eq!(stats.mean_surprisal, 1.5);
        assert_eq!(stats.max_surprisal, 2.0);
        assert_eq!(stats.min_surprisal, 1.0);
        assert_eq!(stats.transition_count, 2);
    }

    #[test]
    fn surprisal_level_classification() {
        assert!(matches!(SurprisalLevel::from_surprisal(1.0), SurprisalLevel::Expected));
        assert!(matches!(SurprisalLevel::from_surprisal(3.0), SurprisalLevel::Unusual));
        assert!(matches!(SurprisalLevel::from_surprisal(5.0), SurprisalLevel::Anomalous));
        assert!(matches!(SurprisalLevel::from_surprisal(10.0), SurprisalLevel::Critical));
    }

    #[test]
    fn height_analysis_identifies_concerning_transitions() {
        let mut model = TransitionModel::new();
        let states = vec![
            test_state(1, 0, EncodedConsensusPhase::Propose),
            test_state(1, 0, EncodedConsensusPhase::PreVote),
            test_state(1, 0, EncodedConsensusPhase::PreCommit),
        ];

        // Bootstrap
        model.observe_sequence(&states);

        let config = SurprisalConfig::bits();
        let analysis = analyze_height_surprisal(1, &states, &model, &config);

        assert_eq!(analysis.height, 1);
        assert!(!analysis.transitions.is_empty());
    }

    #[test]
    fn different_log_bases() {
        let p = 0.5;

        let bits = surprisal(p, &SurprisalConfig::bits()).ok();
        let nats = surprisal(p, &SurprisalConfig::nats()).ok();
        let dits = surprisal(p, &SurprisalConfig::dits()).ok();

        // -log2(0.5) = 1 bit
        assert!((bits - 1.0).abs() < 0.001);

        // -ln(0.5) ≈ 0.693 nats
        assert!(nats < bits);

        // -log10(0.5) ≈ 0.301 dits
        assert!(dits < nats);
    }
}
