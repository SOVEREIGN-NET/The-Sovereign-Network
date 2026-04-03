//! Height Scoring and Classification
//!
//! Implements free-energy scoring F(height) and deterministic classification
//! labels for consensus behavior analysis.

use serde::{Deserialize, Serialize};

use crate::observer::{
    state_encoder::{EncodedConsensusState, ExecutionStatus, TimeClass},
    surprisal_engine::SurprisalStats,
};

/// Configuration for height scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeightScoringConfig {
    /// Weight for total surprisal term in free energy.
    pub surprisal_weight: f64,
    /// Weight for round penalty (more rounds = higher penalty).
    pub round_penalty_weight: f64,
    /// Weight for timeout penalties.
    pub timeout_penalty_weight: f64,
    /// Weight for execution failure penalties.
    pub failure_penalty_weight: f64,
    /// Reference number of rounds for penalty calculation.
    pub reference_rounds: u32,
    /// Thresholds for classification (low, medium, high).
    pub classification_thresholds: ClassificationThresholds,
}

impl Default for HeightScoringConfig {
    fn default() -> Self {
        Self {
            surprisal_weight: 1.0,
            round_penalty_weight: 2.0,
            timeout_penalty_weight: 5.0,
            failure_penalty_weight: 10.0,
            reference_rounds: 1,
            classification_thresholds: ClassificationThresholds::default(),
        }
    }
}

/// Classification thresholds for height scores.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationThresholds {
    pub healthy_max: f64,
    pub delayed_max: f64,
    pub stalled_max: f64,
}

impl Default for ClassificationThresholds {
    fn default() -> Self {
        Self {
            healthy_max: 5.0,
            delayed_max: 20.0,
            stalled_max: 50.0,
        }
    }
}

/// Height classification labels.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum HeightClassification {
    /// Optimal consensus (single round, no issues).
    Healthy,
    /// Slower than optimal but functional.
    Delayed,
    /// Multiple rounds or minor issues.
    Stalled,
    /// Significant consensus problems.
    Degraded,
    /// Critical failure modes.
    Critical,
}

impl HeightClassification {
    /// Get human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy consensus",
            Self::Delayed => "delayed consensus",
            Self::Stalled => "stalled consensus",
            Self::Degraded => "degraded consensus",
            Self::Critical => "critical consensus failure",
        }
    }

    /// Get severity level (0-4).
    pub fn severity(&self) -> u8 {
        match self {
            Self::Healthy => 0,
            Self::Delayed => 1,
            Self::Stalled => 2,
            Self::Degraded => 3,
            Self::Critical => 4,
        }
    }

    /// Check if this classification indicates problems.
    pub fn is_problematic(&self) -> bool {
        self.severity() >= 2
    }
}

/// Detailed score breakdown for a height.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ScoreBreakdown {
    pub surprisal_term: f64,
    pub round_penalty: f64,
    pub timeout_penalty: f64,
    pub failure_penalty: f64,
    pub total_score: f64,
}

/// Complete height score result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HeightScore {
    pub height: u64,
    pub free_energy: f64,
    pub breakdown: ScoreBreakdown,
    pub classification: HeightClassification,
    pub round_count: u32,
    pub timeout_count: u32,
    pub failure_detected: bool,
}

/// Compute free-energy score for a height.
///
/// F(height) = surprisal_term + round_penalty + timeout_penalty + failure_penalty
///
/// Lower scores indicate healthier consensus.
pub fn compute_height_score(
    height: u64,
    states: &[EncodedConsensusState],
    surprisal_stats: &SurprisalStats,
    config: &HeightScoringConfig,
) -> HeightScore {
    // Count rounds (unique round numbers)
    let round_count = states
        .iter()
        .map(|s| s.round)
        .collect::<std::collections::HashSet<_>>()
        .len() as u32;

    // Count timeouts
    let timeout_count = states
        .iter()
        .filter(|s| s.time_class == TimeClass::TimedOut)
        .count() as u32;

    // Check for failures
    let failure_detected = states
        .iter()
        .any(|s| s.execution_status == ExecutionStatus::ApplyFailed);

    // Compute penalty terms
    let surprisal_term = surprisal_stats.total_surprisal * config.surprisal_weight;

    let round_penalty = if round_count > config.reference_rounds {
        (round_count - config.reference_rounds) as f64 * config.round_penalty_weight
    } else {
        0.0
    };

    let timeout_penalty = timeout_count as f64 * config.timeout_penalty_weight;

    let failure_penalty = if failure_detected {
        config.failure_penalty_weight
    } else {
        0.0
    };

    let total_score = surprisal_term + round_penalty + timeout_penalty + failure_penalty;

    let breakdown = ScoreBreakdown {
        surprisal_term,
        round_penalty,
        timeout_penalty,
        failure_penalty,
        total_score,
    };

    let classification = classify_height(
        total_score,
        round_count,
        timeout_count,
        failure_detected,
        surprisal_stats,
        &config.classification_thresholds,
    );

    HeightScore {
        height,
        free_energy: total_score,
        breakdown,
        classification,
        round_count,
        timeout_count,
        failure_detected,
    }
}

/// Classify a height based on score and characteristics.
fn classify_height(
    score: f64,
    round_count: u32,
    timeout_count: u32,
    failure_detected: bool,
    surprisal_stats: &SurprisalStats,
    thresholds: &ClassificationThresholds,
) -> HeightClassification {
    // Critical: execution failure or very high score
    if failure_detected || score > thresholds.stalled_max {
        return HeightClassification::Critical;
    }

    // Degraded: multiple rounds with timeouts or high surprisal
    if round_count >= 4 || timeout_count >= 2 || surprisal_stats.high_surprisal_count >= 2 {
        return HeightClassification::Degraded;
    }

    // Stalled: multiple rounds or moderate score
    if round_count >= 2 || score > thresholds.delayed_max {
        return HeightClassification::Stalled;
    }

    // Delayed: single round but with timeout or elevated score
    if round_count == 1 && (timeout_count > 0 || score > thresholds.healthy_max) {
        return HeightClassification::Delayed;
    }

    // Healthy: single round, no issues
    HeightClassification::Healthy
}

/// Network-wide consensus health summary.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct NetworkHealthSummary {
    pub total_heights: usize,
    pub healthy_count: usize,
    pub delayed_count: usize,
    pub stalled_count: usize,
    pub degraded_count: usize,
    pub critical_count: usize,
    pub average_free_energy: f64,
    pub max_free_energy: f64,
    pub stall_rate: f64, // Fraction of non-healthy heights
    pub average_rounds: f64,
    pub partition_indicators: Vec<u64>, // Heights with potential partition
}

/// Compute network health summary from multiple height scores.
pub fn compute_network_health(scores: &[HeightScore]) -> NetworkHealthSummary {
    if scores.is_empty() {
        return NetworkHealthSummary::default();
    }

    let total_heights = scores.len();
    let healthy_count = scores
        .iter()
        .filter(|s| s.classification == HeightClassification::Healthy)
        .count();
    let delayed_count = scores
        .iter()
        .filter(|s| s.classification == HeightClassification::Delayed)
        .count();
    let stalled_count = scores
        .iter()
        .filter(|s| s.classification == HeightClassification::Stalled)
        .count();
    let degraded_count = scores
        .iter()
        .filter(|s| s.classification == HeightClassification::Degraded)
        .count();
    let critical_count = scores
        .iter()
        .filter(|s| s.classification == HeightClassification::Critical)
        .count();

    let free_energies: Vec<f64> = scores.iter().map(|s| s.free_energy).collect();
    let average_free_energy = free_energies.iter().sum::<f64>() / total_heights as f64;
    let max_free_energy: f64 = free_energies
        .iter()
        .fold(0.0_f64, |a: f64, b: &f64| a.max(*b));

    let stall_rate = (total_heights - healthy_count) as f64 / total_heights as f64;

    let average_rounds =
        scores.iter().map(|s| s.round_count as f64).sum::<f64>() / total_heights as f64;

    // Identify potential partition indicators (critical or degraded heights)
    let partition_indicators: Vec<u64> = scores
        .iter()
        .filter(|s| {
            s.classification == HeightClassification::Critical
                || s.classification == HeightClassification::Degraded
        })
        .map(|s| s.height)
        .collect();

    NetworkHealthSummary {
        total_heights,
        healthy_count,
        delayed_count,
        stalled_count,
        degraded_count,
        critical_count,
        average_free_energy,
        max_free_energy,
        stall_rate,
        average_rounds,
        partition_indicators,
    }
}

/// Trend analysis for height scores over time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConsensusTrend {
    Improving,
    Stable,
    Degrading,
    Oscillating,
}

/// Analyze trend from a series of height scores.
pub fn analyze_trend(scores: &[HeightScore], window_size: usize) -> ConsensusTrend {
    if scores.len() < window_size * 2 {
        return ConsensusTrend::Stable;
    }

    let recent: Vec<f64> = scores
        .iter()
        .rev()
        .take(window_size)
        .map(|s| s.free_energy)
        .collect();
    let previous: Vec<f64> = scores
        .iter()
        .rev()
        .skip(window_size)
        .take(window_size)
        .map(|s| s.free_energy)
        .collect();

    let recent_avg = recent.iter().sum::<f64>() / recent.len() as f64;
    let previous_avg = previous.iter().sum::<f64>() / previous.len() as f64;

    let recent_variance = recent
        .iter()
        .map(|&x| (x - recent_avg).powi(2))
        .sum::<f64>()
        / recent.len() as f64;

    // High variance indicates oscillation
    if recent_variance > (recent_avg * 0.5).powi(2) {
        return ConsensusTrend::Oscillating;
    }

    // Compare averages
    let threshold = previous_avg * 0.1; // 10% change threshold
    if recent_avg < previous_avg - threshold {
        ConsensusTrend::Improving
    } else if recent_avg > previous_avg + threshold {
        ConsensusTrend::Degrading
    } else {
        ConsensusTrend::Stable
    }
}

/// Validator anomaly scores (placeholder for future per-validator analysis).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ValidatorAnomalyScore {
    pub validator_id: String,
    pub anomaly_score: f64,
    pub suspicious_heights: Vec<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observer::{
        state_encoder::{
            EncodedConsensusPhase, ExecutionStatus, ProposalStatus, RoundClass, TimeClass,
        },
        surprisal_engine::SurprisalStats,
    };

    fn test_state(phase: EncodedConsensusPhase, time_class: TimeClass) -> EncodedConsensusState {
        EncodedConsensusState {
            height: 1,
            round: 0,
            phase,
            round_class: RoundClass::R0,
            time_class,
            proposal_status: ProposalStatus::Created,
            execution_status: ExecutionStatus::ApplySucceeded,
        }
    }

    fn test_surprisal_stats(total: f64) -> SurprisalStats {
        SurprisalStats {
            total_surprisal: total,
            mean_surprisal: total,
            max_surprisal: total,
            min_surprisal: total,
            transition_count: 1,
            high_surprisal_count: if total > 5.0 { 1 } else { 0 },
        }
    }

    #[test]
    fn healthy_height_classification() {
        let states = vec![test_state(EncodedConsensusPhase::Propose, TimeClass::Early)];
        let surprisal = test_surprisal_stats(0.5);
        let config = HeightScoringConfig::default();

        let score = compute_height_score(1, &states, &surprisal, &config);

        assert_eq!(score.classification, HeightClassification::Healthy);
        assert_eq!(score.round_count, 1);
    }

    #[test]
    fn delayed_height_with_timeout() {
        let states = vec![test_state(
            EncodedConsensusPhase::Propose,
            TimeClass::TimedOut,
        )];
        let surprisal = test_surprisal_stats(2.0);
        let config = HeightScoringConfig::default();

        let score = compute_height_score(1, &states, &surprisal, &config);

        assert_eq!(score.classification, HeightClassification::Delayed);
        assert_eq!(score.timeout_count, 1);
        assert!(score.breakdown.timeout_penalty > 0.0);
    }

    #[test]
    fn stalled_height_multiple_rounds() {
        let states = vec![
            EncodedConsensusState {
                height: 1,
                round: 0,
                phase: EncodedConsensusPhase::Propose,
                round_class: RoundClass::R0,
                time_class: TimeClass::TimedOut,
                proposal_status: ProposalStatus::Missing,
                execution_status: ExecutionStatus::None,
            },
            EncodedConsensusState {
                height: 1,
                round: 1,
                phase: EncodedConsensusPhase::Propose,
                round_class: RoundClass::R1,
                time_class: TimeClass::Early,
                proposal_status: ProposalStatus::Created,
                execution_status: ExecutionStatus::ApplySucceeded,
            },
        ];
        let surprisal = test_surprisal_stats(3.0);
        let config = HeightScoringConfig::default();

        let score = compute_height_score(1, &states, &surprisal, &config);

        assert_eq!(score.round_count, 2);
        assert!(score.breakdown.round_penalty > 0.0);
    }

    #[test]
    fn critical_height_with_failure() {
        let mut state = test_state(EncodedConsensusPhase::Commit, TimeClass::Late);
        state.execution_status = ExecutionStatus::ApplyFailed;

        let states = vec![state];
        let surprisal = test_surprisal_stats(1.0);
        let config = HeightScoringConfig::default();

        let score = compute_height_score(1, &states, &surprisal, &config);

        assert_eq!(score.classification, HeightClassification::Critical);
        assert!(score.failure_detected);
        assert!(score.breakdown.failure_penalty > 0.0);
    }

    #[test]
    fn network_health_summary_computation() {
        let scores = vec![
            HeightScore {
                height: 1,
                free_energy: 2.0,
                breakdown: ScoreBreakdown::default(),
                classification: HeightClassification::Healthy,
                round_count: 1,
                timeout_count: 0,
                failure_detected: false,
            },
            HeightScore {
                height: 2,
                free_energy: 15.0,
                breakdown: ScoreBreakdown::default(),
                classification: HeightClassification::Delayed,
                round_count: 1,
                timeout_count: 1,
                failure_detected: false,
            },
            HeightScore {
                height: 3,
                free_energy: 60.0,
                breakdown: ScoreBreakdown::default(),
                classification: HeightClassification::Critical,
                round_count: 5,
                timeout_count: 2,
                failure_detected: true,
            },
        ];

        let summary = compute_network_health(&scores);

        assert_eq!(summary.total_heights, 3);
        assert_eq!(summary.healthy_count, 1);
        assert_eq!(summary.critical_count, 1);
        assert!(summary.stall_rate > 0.5);
        assert_eq!(summary.partition_indicators, vec![3]);
    }

    #[test]
    fn trend_analysis() {
        let improving: Vec<HeightScore> = (0..10)
            .map(|i| HeightScore {
                height: i as u64,
                free_energy: 50.0 - i as f64 * 4.0, // Decreasing
                breakdown: ScoreBreakdown::default(),
                classification: HeightClassification::Healthy,
                round_count: 1,
                timeout_count: 0,
                failure_detected: false,
            })
            .collect();

        assert!(matches!(
            analyze_trend(&improving, 3),
            ConsensusTrend::Improving
        ));

        let degrading: Vec<HeightScore> = (0..10)
            .map(|i| HeightScore {
                height: i as u64,
                free_energy: 10.0 + i as f64 * 4.0, // Increasing
                breakdown: ScoreBreakdown::default(),
                classification: HeightClassification::Healthy,
                round_count: 1,
                timeout_count: 0,
                failure_detected: false,
            })
            .collect();

        assert!(matches!(
            analyze_trend(&degrading, 3),
            ConsensusTrend::Degrading
        ));
    }

    #[test]
    fn classification_severity_ordering() {
        assert!(
            HeightClassification::Healthy.severity() < HeightClassification::Delayed.severity()
        );
        assert!(
            HeightClassification::Delayed.severity() < HeightClassification::Stalled.severity()
        );
        assert!(
            HeightClassification::Stalled.severity() < HeightClassification::Degraded.severity()
        );
        assert!(
            HeightClassification::Degraded.severity() < HeightClassification::Critical.severity()
        );
    }
}
