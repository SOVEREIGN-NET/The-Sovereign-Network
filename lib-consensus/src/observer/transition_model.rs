//! Transition Probability Model for Consensus Observer
//!
//! Implements deterministic transition counting and probability computation
//! for consensus state sequences. P(State_t+1 | State_t) is computed from
//! observed transitions with additive smoothing for sparse data.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::observer::state_encoder::EncodedConsensusState;

/// Estimated total number of possible consensus state combinations.
/// Used for Laplace smoothing denominator when no observations exist.
/// Calculated as: 8 phases * 4 round classes * 4 time classes * 5 proposal statuses * 5 execution statuses
const ESTIMATED_STATE_SPACE: usize = 8 * 4 * 4 * 5 * 5; // = 3200

/// A composite state key for transition tracking.
/// Uses all 6 dimensions of EncodedConsensusState except height.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ConsensusStateKey {
    pub round: u32,
    pub phase: u8,         // EncodedConsensusPhase as u8
    pub round_class: u8,   // RoundClass as u8
    pub time_class: u8,    // TimeClass as u8
    pub proposal_status: u8, // ProposalStatus as u8
    pub execution_status: u8, // ExecutionStatus as u8
}

impl ConsensusStateKey {
    /// Create a state key from an EncodedConsensusState.
    pub fn from_state(state: &EncodedConsensusState) -> Self {
        Self {
            round: state.round,
            phase: state.phase as u8,
            round_class: state.round_class as u8,
            time_class: state.time_class as u8,
            proposal_status: state.proposal_status as u8,
            execution_status: state.execution_status as u8,
        }
    }
}

/// A transition between two consensus states.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct StateTransition {
    pub from: ConsensusStateKey,
    pub to: ConsensusStateKey,
}

/// Transition model with counting and probability computation.
///
/// This model tracks observed transitions and computes conditional
/// probabilities P(State_t+1 | State_t) using additive smoothing.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TransitionModel {
    /// Count of transitions from each state.
    transition_counts: HashMap<StateTransition, u64>,
    /// Total outgoing transitions from each source state.
    total_outgoing: HashMap<ConsensusStateKey, u64>,
    /// Additive smoothing parameter (Laplace smoothing).
    smoothing_alpha: f64,
    /// Total number of distinct states seen (for smoothing denominator).
    distinct_states: usize,
}

impl TransitionModel {
    /// Create a new transition model with default smoothing.
    pub fn new() -> Self {
        Self {
            transition_counts: HashMap::new(),
            total_outgoing: HashMap::new(),
            smoothing_alpha: 0.1, // Small smoothing for unseen transitions
            distinct_states: 0,
        }
    }

    /// Create a new transition model with custom smoothing parameter.
    pub fn with_smoothing(alpha: f64) -> Self {
        Self {
            transition_counts: HashMap::new(),
            total_outgoing: HashMap::new(),
            smoothing_alpha: alpha,
            distinct_states: 0,
        }
    }

    /// Record a single state transition observation.
    pub fn observe_transition(&mut self, from: &EncodedConsensusState, to: &EncodedConsensusState) {
        let from_key = ConsensusStateKey::from_state(from);
        let to_key = ConsensusStateKey::from_state(to);
        let transition = StateTransition {
            from: from_key,
            to: to_key,
        };

        *self.transition_counts.entry(transition).or_insert(0) += 1;
        *self.total_outgoing.entry(from_key).or_insert(0) += 1;

        // Update distinct states count
        let states_seen = self
            .transition_counts
            .keys()
            .flat_map(|t| [t.from, t.to])
            .collect::<std::collections::HashSet<_>>();
        self.distinct_states = states_seen.len();
    }

    /// Record multiple transitions from a sequence of states.
    pub fn observe_sequence(&mut self, states: &[EncodedConsensusState]) {
        for window in states.windows(2) {
            self.observe_transition(&window[0], &window[1]);
        }
    }

    /// Compute P(to | from) with additive smoothing.
    ///
    /// Returns the conditional probability of transitioning to `to`
    /// given the current state `from`, using Laplace smoothing.
    pub fn transition_probability(
        &self,
        from: &EncodedConsensusState,
        to: &EncodedConsensusState,
    ) -> f64 {
        let from_key = ConsensusStateKey::from_state(from);
        let to_key = ConsensusStateKey::from_state(to);
        let transition = StateTransition {
            from: from_key,
            to: to_key,
        };

        let count = self.transition_counts.get(&transition).copied().unwrap_or(0);
        let total = self.total_outgoing.get(&from_key).copied().unwrap_or(0);

        // Additive smoothing: (count + alpha) / (total + alpha * N)
        // where N is the number of distinct states (use estimated state space if empty)
        let n_states = if self.distinct_states > 0 {
            self.distinct_states
        } else {
            ESTIMATED_STATE_SPACE
        };
        let numerator = count as f64 + self.smoothing_alpha;
        let denominator = total as f64 + self.smoothing_alpha * n_states as f64;

        numerator / denominator
    }

    /// Get the empirical probability without smoothing (for debugging/analysis).
    pub fn empirical_probability(
        &self,
        from: &EncodedConsensusState,
        to: &EncodedConsensusState,
    ) -> Option<f64> {
        let from_key = ConsensusStateKey::from_state(from);
        let to_key = ConsensusStateKey::from_state(to);
        let transition = StateTransition {
            from: from_key,
            to: to_key,
        };

        let count = self.transition_counts.get(&transition)?;
        let total = self.total_outgoing.get(&from_key)?;

        Some(*count as f64 / *total as f64)
    }

    /// Get the raw transition count.
    pub fn transition_count(
        &self,
        from: &EncodedConsensusState,
        to: &EncodedConsensusState,
    ) -> u64 {
        let from_key = ConsensusStateKey::from_state(from);
        let to_key = ConsensusStateKey::from_state(to);
        let transition = StateTransition {
            from: from_key,
            to: to_key,
        };

        self.transition_counts.get(&transition).copied().unwrap_or(0)
    }

    /// Get total outgoing transitions from a state.
    pub fn total_outgoing_from(&self, state: &EncodedConsensusState) -> u64 {
        let key = ConsensusStateKey::from_state(state);
        self.total_outgoing.get(&key).copied().unwrap_or(0)
    }

    /// Get all transitions and their counts (for serialization/analysis).
    pub fn all_transitions(&self) -> &HashMap<StateTransition, u64> {
        &self.transition_counts
    }

    /// Get the number of distinct states in the model.
    pub fn distinct_state_count(&self) -> usize {
        self.distinct_states
    }

    /// Get the total number of transitions observed.
    pub fn total_transitions(&self) -> u64 {
        self.total_outgoing.values().sum()
    }

    /// Merge another transition model into this one.
    ///
    /// Used for aggregating observations across nodes or time periods.
    pub fn merge(&mut self, other: &TransitionModel) {
        for (transition, count) in &other.transition_counts {
            *self.transition_counts.entry(*transition).or_insert(0) += count;
        }
        for (state, total) in &other.total_outgoing {
            *self.total_outgoing.entry(*state).or_insert(0) += total;
        }

        // Recalculate distinct states
        let states_seen = self
            .transition_counts
            .keys()
            .flat_map(|t| [t.from, t.to])
            .collect::<std::collections::HashSet<_>>();
        self.distinct_states = states_seen.len();
    }

    /// Clear all observations.
    pub fn clear(&mut self) {
        self.transition_counts.clear();
        self.total_outgoing.clear();
        self.distinct_states = 0;
    }
}

/// Compute transition probabilities for a sequence of states.
///
/// Returns a vector of (from, to, probability) tuples for each transition.
pub fn compute_sequence_probabilities(
    states: &[EncodedConsensusState],
    model: &TransitionModel,
) -> Vec<(EncodedConsensusState, EncodedConsensusState, f64)> {
    let mut result = Vec::new();

    for window in states.windows(2) {
        let prob = model.transition_probability(&window[0], &window[1]);
        result.push((window[0].clone(), window[1].clone(), prob));
    }

    result
}

/// Build a transition model from historical consensus data.
///
/// This is a convenience function for bootstrapping the model from
/// existing consensus state sequences.
pub fn build_model_from_history(
    sequences: &[Vec<EncodedConsensusState>],
    smoothing_alpha: f64,
) -> TransitionModel {
    let mut model = TransitionModel::with_smoothing(smoothing_alpha);

    for sequence in sequences {
        model.observe_sequence(sequence);
    }

    model
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observer::state_encoder::{
        EncodedConsensusPhase, ExecutionStatus, ProposalStatus, RoundClass, TimeClass,
    };

    fn test_state(
        height: u64,
        round: u32,
        phase: EncodedConsensusPhase,
        time_class: TimeClass,
    ) -> EncodedConsensusState {
        EncodedConsensusState {
            height,
            round,
            phase,
            round_class: RoundClass::R0,
            time_class,
            proposal_status: ProposalStatus::Created,
            execution_status: ExecutionStatus::ApplySucceeded,
        }
    }

    #[test]
    fn observes_single_transition() {
        let mut model = TransitionModel::new();
        let s1 = test_state(1, 0, EncodedConsensusPhase::Propose, TimeClass::Early);
        let s2 = test_state(1, 0, EncodedConsensusPhase::PreVote, TimeClass::Early);

        model.observe_transition(&s1, &s2);

        assert_eq!(model.transition_count(&s1, &s2), 1);
        assert_eq!(model.total_outgoing_from(&s1), 1);
    }

    #[test]
    fn computes_probability_with_smoothing() {
        let mut model = TransitionModel::with_smoothing(1.0); // Higher smoothing for test
        let s1 = test_state(1, 0, EncodedConsensusPhase::Propose, TimeClass::Early);
        let s2 = test_state(1, 0, EncodedConsensusPhase::PreVote, TimeClass::Early);
        let s3 = test_state(1, 0, EncodedConsensusPhase::PreCommit, TimeClass::Early);

        // Observe s1 -> s2 three times, s1 -> s3 once
        model.observe_transition(&s1, &s2);
        model.observe_transition(&s1, &s2);
        model.observe_transition(&s1, &s2);
        model.observe_transition(&s1, &s3);

        // Empirical: P(s2|s1) = 3/4 = 0.75, P(s3|s1) = 1/4 = 0.25
        // With smoothing alpha=1.0 and N=3 distinct states:
        // P(s2|s1) = (3 + 1) / (4 + 3) = 4/7 ≈ 0.57
        // P(s3|s1) = (1 + 1) / (4 + 3) = 2/7 ≈ 0.29

        let prob_s2 = model.transition_probability(&s1, &s2);
        let prob_s3 = model.transition_probability(&s1, &s3);

        assert!((prob_s2 - 4.0 / 7.0).abs() < 0.001);
        assert!((prob_s3 - 2.0 / 7.0).abs() < 0.001);
    }

    #[test]
    fn handles_unseen_transitions() {
        let model = TransitionModel::with_smoothing(0.1);
        let s1 = test_state(1, 0, EncodedConsensusPhase::Propose, TimeClass::Early);
        let s2 = test_state(1, 0, EncodedConsensusPhase::PreVote, TimeClass::Early);

        // No observations, but smoothing gives non-zero probability
        let prob = model.transition_probability(&s1, &s2);
        assert!(prob > 0.0);
        assert!(prob < 0.1); // Should be small
    }

    #[test]
    fn observes_sequence() {
        let mut model = TransitionModel::new();
        let states = vec![
            test_state(1, 0, EncodedConsensusPhase::Propose, TimeClass::Early),
            test_state(1, 0, EncodedConsensusPhase::PreVote, TimeClass::Early),
            test_state(1, 0, EncodedConsensusPhase::PreCommit, TimeClass::Early),
            test_state(1, 0, EncodedConsensusPhase::Commit, TimeClass::Early),
        ];

        model.observe_sequence(&states);

        assert_eq!(model.total_transitions(), 3);
    }

    #[test]
    fn computes_sequence_probabilities() {
        let mut model = TransitionModel::new();
        let states = vec![
            test_state(1, 0, EncodedConsensusPhase::Propose, TimeClass::Early),
            test_state(1, 0, EncodedConsensusPhase::PreVote, TimeClass::Early),
            test_state(1, 0, EncodedConsensusPhase::PreCommit, TimeClass::Early),
        ];

        model.observe_sequence(&states);

        let probs = compute_sequence_probabilities(&states, &model);
        assert_eq!(probs.len(), 2);
        assert!(probs.iter().all(|(_, _, p)| *p > 0.0));
    }

    #[test]
    fn merges_models() {
        let mut model1 = TransitionModel::new();
        let mut model2 = TransitionModel::new();

        let s1 = test_state(1, 0, EncodedConsensusPhase::Propose, TimeClass::Early);
        let s2 = test_state(1, 0, EncodedConsensusPhase::PreVote, TimeClass::Early);

        model1.observe_transition(&s1, &s2);
        model2.observe_transition(&s1, &s2);

        model1.merge(&model2);

        assert_eq!(model1.transition_count(&s1, &s2), 2);
    }

    #[test]
    fn state_key_uniqueness() {
        let s1 = test_state(1, 0, EncodedConsensusPhase::Propose, TimeClass::Early);
        let s2 = test_state(1, 0, EncodedConsensusPhase::Propose, TimeClass::Early);
        let s3 = test_state(1, 0, EncodedConsensusPhase::PreVote, TimeClass::Early);

        let key1 = ConsensusStateKey::from_state(&s1);
        let key2 = ConsensusStateKey::from_state(&s2);
        let key3 = ConsensusStateKey::from_state(&s3);

        assert_eq!(key1, key2); // Same state -> same key
        assert_ne!(key1, key3); // Different phase -> different key
    }
}
