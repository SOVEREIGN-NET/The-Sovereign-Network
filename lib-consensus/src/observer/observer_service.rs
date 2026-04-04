//! Passive Observer Runtime Service
//!
//! Implements a read-only observer service that ingests consensus events,
//! computes trajectories, scores, and persists results without affecting
//! consensus behavior.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{debug, info, trace, warn};

use crate::observer::{
    build_height_trajectories, encode_height_states,
    event_normalizer::{
        normalize_consensus_event, ConsensusBehaviorEventType, ConsensusNormalizedEvent,
        RuntimeConsensusSignal,
    },
    height_scoring::{
        compute_height_score, HeightScore, HeightScoringConfig, NetworkHealthSummary,
    },
    state_encoder::{
        EncodedConsensusState, ParsedConsensusEvent, ParsedConsensusPhase, ParsedHeightTrajectory,
        ParsedPhaseTrajectory, ParsedRoundTrajectory, StateEncoderConfig,
    },
    surprisal_engine::{analyze_height_surprisal, SurprisalConfig, SurprisalStats},
    trajectory_builder::{ConsensusPhaseType, HeightTrajectory, PhaseTrajectory, RoundTrajectory},
    transition_model::TransitionModel,
};

/// Configuration for the observer service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserverServiceConfig {
    /// Configuration for state encoding.
    pub encoder_config: StateEncoderConfig,
    /// Configuration for surprisal calculation.
    pub surprisal_config: SurprisalConfig,
    /// Configuration for height scoring.
    pub scoring_config: HeightScoringConfig,
    /// Smoothing parameter for transition model.
    pub transition_smoothing: f64,
    /// Maximum number of heights to keep in memory.
    pub max_stored_heights: usize,
    /// Enable detailed logging.
    pub verbose_logging: bool,
}

impl Default for ObserverServiceConfig {
    fn default() -> Self {
        Self {
            encoder_config: StateEncoderConfig::default(),
            surprisal_config: SurprisalConfig::default(),
            scoring_config: HeightScoringConfig::default(),
            transition_smoothing: 0.1,
            max_stored_heights: 1000,
            verbose_logging: false,
        }
    }
}

/// Stored analysis for a single height.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeightAnalysis {
    pub height: u64,
    pub timestamp: u64,
    pub trajectory: HeightTrajectory,
    pub encoded_states: Vec<EncodedConsensusState>,
    pub surprisal_stats: SurprisalStats,
    pub score: HeightScore,
}

/// The observer service maintains read-only consensus analysis.
///
/// This service ingests events, builds trajectories, computes scores,
/// and stores results without any feedback to consensus.
pub struct ObserverService {
    config: ObserverServiceConfig,
    /// Transition model learned from observed behavior.
    transition_model: Arc<Mutex<TransitionModel>>,
    /// Stored analysis per height.
    height_analyses: Arc<Mutex<HashMap<u64, HeightAnalysis>>>,
    /// Pending events for current height.
    pending_events: Arc<Mutex<Vec<ConsensusNormalizedEvent>>>,
    /// Current height being processed.
    current_height: Arc<Mutex<u64>>,
}

impl ObserverService {
    /// Create a new observer service with default configuration.
    pub fn new() -> Self {
        Self::with_config(ObserverServiceConfig::default())
    }

    /// Create a new observer service with custom configuration.
    pub fn with_config(config: ObserverServiceConfig) -> Self {
        let transition_model = TransitionModel::with_smoothing(config.transition_smoothing);

        Self {
            config,
            transition_model: Arc::new(Mutex::new(transition_model)),
            height_analyses: Arc::new(Mutex::new(HashMap::new())),
            pending_events: Arc::new(Mutex::new(Vec::new())),
            current_height: Arc::new(Mutex::new(0)),
        }
    }

    /// Ingest a consensus event for observation.
    ///
    /// This is non-blocking and cannot fail - events are best-effort.
    pub fn ingest_event(&self, event: &crate::types::ConsensusEvent) {
        match normalize_consensus_event(event) {
            Ok(Some(normalized)) => {
                trace!("Observer ingested event: {:?}", normalized.event_type);
                if let Ok(mut pending) = self.pending_events.lock() {
                    pending.push(normalized);
                }
            }
            Ok(None) => {
                trace!("Observer skipped event (no mapping)");
            }
            Err(e) => {
                if self.config.verbose_logging {
                    warn!("Observer failed to normalize event: {}", e);
                }
            }
        }
    }

    /// Ingest a runtime signal for observation.
    pub fn ingest_runtime_signal(&self, signal: &RuntimeConsensusSignal) {
        use crate::observer::event_normalizer::normalize_runtime_signal;

        let normalized = normalize_runtime_signal(signal);
        trace!(
            "Observer ingested runtime signal: {:?}",
            normalized.event_type
        );

        if let Ok(mut pending) = self.pending_events.lock() {
            pending.push(normalized);
        }
    }

    /// Finalize analysis for the current height and start a new one.
    ///
    /// This should be called when consensus commits a block.
    pub fn finalize_height(&self, height: u64, timestamp: u64) {
        let events: Vec<ConsensusNormalizedEvent> = {
            let mut pending = match self.pending_events.lock() {
                Ok(p) => p,
                Err(_) => {
                    warn!("Observer: failed to lock pending events");
                    return;
                }
            };
            // Split events for this height from pending events
            let mut height_events = Vec::new();
            let mut remaining = Vec::new();
            for event in pending.drain(..) {
                if event.height == height {
                    height_events.push(event);
                } else {
                    remaining.push(event);
                }
            }
            *pending = remaining;
            height_events
        };

        if events.is_empty() {
            debug!("Observer: no events for height {}", height);
            return;
        }

        // Build trajectory
        let trajectories = build_height_trajectories(&events);
        let trajectory = match trajectories.into_iter().next() {
            Some(t) => t,
            None => {
                warn!("Observer: failed to build trajectory for height {}", height);
                return;
            }
        };

        // Convert to parsed trajectory for encoding
        let parsed_trajectory = convert_to_parsed_trajectory(&trajectory);

        // Encode states
        let encoded_states = encode_height_states(&parsed_trajectory, self.config.encoder_config);

        // Compute surprisal against the model *before* observing this height
        // to avoid data leakage that would artificially lower surprisal
        let surprisal_analysis = {
            let model = match self.transition_model.lock() {
                Ok(m) => m,
                Err(_) => {
                    warn!("Observer: failed to lock transition model for surprisal");
                    return;
                }
            };
            analyze_height_surprisal(
                height,
                &encoded_states,
                &model,
                &self.config.surprisal_config,
            )
        };

        // Update transition model with the new sequence for future heights
        {
            let mut model = match self.transition_model.lock() {
                Ok(m) => m,
                Err(_) => {
                    warn!("Observer: failed to lock transition model");
                    return;
                }
            };
            model.observe_sequence(&encoded_states);
        }

        // Compute height score
        let score = compute_height_score(
            height,
            &encoded_states,
            &surprisal_analysis.stats,
            &self.config.scoring_config,
        );

        // Store analysis
        let analysis = HeightAnalysis {
            height,
            timestamp,
            trajectory,
            encoded_states,
            surprisal_stats: surprisal_analysis.stats,
            score: score.clone(),
        };

        {
            let mut analyses = match self.height_analyses.lock() {
                Ok(a) => a,
                Err(_) => {
                    warn!("Observer: failed to lock height analyses");
                    return;
                }
            };

            analyses.insert(height, analysis);

            // Prune old heights if over limit (keep the most recent)
            if analyses.len() > self.config.max_stored_heights {
                let mut heights: Vec<u64> = analyses.keys().copied().collect();
                heights.sort_unstable();
                let to_remove: Vec<u64> = heights
                    .into_iter()
                    .take(analyses.len() - self.config.max_stored_heights)
                    .collect();
                for h in to_remove {
                    analyses.remove(&h);
                }
            }
        }

        // Update current height
        if let Ok(mut current) = self.current_height.lock() {
            *current = height;
        }

        info!(
            "Observer: finalized height {} - classification: {:?}, free_energy: {:.2}",
            height, score.classification, score.free_energy
        );
    }

    /// Get analysis for a specific height.
    pub fn get_height_analysis(&self, height: u64) -> Option<HeightAnalysis> {
        self.height_analyses
            .lock()
            .ok()
            .and_then(|analyses| analyses.get(&height).cloned())
    }

    /// Get the most recent analyses.
    pub fn get_recent_analyses(&self, count: usize) -> Vec<HeightAnalysis> {
        let analyses = match self.height_analyses.lock() {
            Ok(a) => a,
            Err(_) => return Vec::new(),
        };

        let mut heights: Vec<u64> = analyses.keys().copied().collect();
        heights.sort_unstable_by(|a, b| b.cmp(a)); // Descending

        heights
            .into_iter()
            .take(count)
            .filter_map(|h| analyses.get(&h).cloned())
            .collect()
    }

    /// Get network health summary for recent heights.
    pub fn get_network_health(&self, window_size: usize) -> Option<NetworkHealthSummary> {
        use crate::observer::height_scoring::compute_network_health;

        let analyses = self.get_recent_analyses(window_size);
        if analyses.is_empty() {
            return None;
        }

        let scores: Vec<_> = analyses.into_iter().map(|a| a.score).collect();
        Some(compute_network_health(&scores))
    }

    /// Get the current transition model (for analysis/serialization).
    pub fn get_transition_model(&self) -> Option<TransitionModel> {
        self.transition_model.lock().ok().map(|m| m.clone())
    }

    /// Get the current height.
    pub fn current_height(&self) -> u64 {
        match self.current_height.lock() {
            Ok(guard) => *guard,
            Err(_) => 0,
        }
    }

    /// Get total number of stored analyses.
    pub fn stored_height_count(&self) -> usize {
        self.height_analyses
            .lock()
            .ok()
            .map(|a| a.len())
            .unwrap_or(0)
    }

    /// Clear all stored data.
    pub fn clear(&self) {
        if let Ok(mut analyses) = self.height_analyses.lock() {
            analyses.clear();
        }
        if let Ok(mut pending) = self.pending_events.lock() {
            pending.clear();
        }
        if let Ok(mut model) = self.transition_model.lock() {
            model.clear();
        }
        info!("Observer: cleared all data");
    }
}

impl Default for ObserverService {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe handle to the observer service.
pub type ObserverHandle = Arc<ObserverService>;

/// Create a new observer service handle.
pub fn create_observer_service() -> ObserverHandle {
    Arc::new(ObserverService::new())
}

/// Create a new observer service handle with custom config.
pub fn create_observer_service_with_config(config: ObserverServiceConfig) -> ObserverHandle {
    Arc::new(ObserverService::with_config(config))
}

/// Convert trajectory builder types to state encoder types.
fn convert_to_parsed_trajectory(trajectory: &HeightTrajectory) -> ParsedHeightTrajectory {
    ParsedHeightTrajectory {
        height: trajectory.height,
        rounds: trajectory.rounds.iter().map(convert_round).collect(),
    }
}

fn convert_round(round: &RoundTrajectory) -> ParsedRoundTrajectory {
    ParsedRoundTrajectory {
        round_number: round.round_number,
        phases: round.phases.iter().map(convert_phase).collect(),
        events: round.events.iter().filter_map(convert_event).collect(),
    }
}

fn convert_phase(phase: &PhaseTrajectory) -> ParsedPhaseTrajectory {
    ParsedPhaseTrajectory {
        phase: convert_phase_type(phase.phase_type),
        end_event: convert_behavior_event(phase.end_event)
            .unwrap_or(ParsedConsensusEvent::EnterPropose),
        duration: phase.duration,
    }
}

fn convert_phase_type(phase: ConsensusPhaseType) -> ParsedConsensusPhase {
    match phase {
        ConsensusPhaseType::Propose => ParsedConsensusPhase::Propose,
        ConsensusPhaseType::PreVote => ParsedConsensusPhase::PreVote,
        ConsensusPhaseType::PreCommit => ParsedConsensusPhase::PreCommit,
        ConsensusPhaseType::Commit => ParsedConsensusPhase::Commit,
        ConsensusPhaseType::NewRound => ParsedConsensusPhase::NewRound,
        ConsensusPhaseType::Stalled => ParsedConsensusPhase::Stalled,
        ConsensusPhaseType::Recovering => ParsedConsensusPhase::Recovering,
        ConsensusPhaseType::ApplyingBlock => ParsedConsensusPhase::ApplyingBlock,
        ConsensusPhaseType::Fault => ParsedConsensusPhase::Fault,
    }
}

fn convert_behavior_event(event: ConsensusBehaviorEventType) -> Option<ParsedConsensusEvent> {
    match event {
        ConsensusBehaviorEventType::EnterPropose => Some(ParsedConsensusEvent::EnterPropose),
        ConsensusBehaviorEventType::ProposalCreated => Some(ParsedConsensusEvent::ProposalCreated),
        ConsensusBehaviorEventType::ProposalReceived => {
            Some(ParsedConsensusEvent::ProposalReceived)
        }
        ConsensusBehaviorEventType::StepTimeout => Some(ParsedConsensusEvent::StepTimeout),
        ConsensusBehaviorEventType::BlockApplyStarted => {
            Some(ParsedConsensusEvent::BlockApplyStarted)
        }
        ConsensusBehaviorEventType::BlockApplySucceeded => {
            Some(ParsedConsensusEvent::BlockApplySucceeded)
        }
        ConsensusBehaviorEventType::BlockApplyFailed => {
            Some(ParsedConsensusEvent::BlockApplyFailed)
        }
        // Commit/quorum events are consensus outcomes, not execution/apply outcomes.
        // Return None to avoid incorrectly signaling apply progress.
        _ => None,
    }
}

fn convert_event(event: &ConsensusNormalizedEvent) -> Option<ParsedConsensusEvent> {
    convert_behavior_event(event.event_type)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ConsensusEvent, ConsensusProof, ConsensusProposal, ConsensusType};
    use lib_crypto::{Hash, PostQuantumSignature};
    use lib_identity::IdentityId;

    fn test_proposal(height: u64, round: u32) -> ConsensusProposal {
        ConsensusProposal {
            id: Hash::from_bytes(&[1u8; 32]),
            proposer: IdentityId::from_bytes(&[2u8; 32]),
            height,
            round,
            protocol_version: 1,
            previous_hash: Hash::from_bytes(&[0u8; 32]),
            block_data: vec![0u8; 32],
            timestamp: 0,
            consensus_proof: ConsensusProof {
                consensus_type: ConsensusType::ByzantineFaultTolerance,
                stake_proof: None,
                storage_proof: None,
                work_proof: None,
                zk_did_proof: None,
                timestamp: 0,
            },
            signature: PostQuantumSignature::default(),
        }
    }

    #[test]
    fn service_ingests_events() {
        let service = ObserverService::new();

        let event = ConsensusEvent::ProposalReceived {
            proposal: test_proposal(1, 0),
        };

        service.ingest_event(&event);

        // Events are pending until height finalization
        assert_eq!(service.stored_height_count(), 0);
    }

    #[test]
    fn service_finalizes_height() {
        let service = ObserverService::new();

        // Simulate a simple consensus flow
        service.ingest_event(&ConsensusEvent::ProposalReceived {
            proposal: test_proposal(1, 0),
        });

        service.finalize_height(1, 1000);

        assert_eq!(service.stored_height_count(), 1);
        assert_eq!(service.current_height(), 1);

        let analysis = service.get_height_analysis(1);
        assert!(analysis.is_some());
    }

    #[test]
    fn service_prunes_old_heights() {
        let config = ObserverServiceConfig {
            max_stored_heights: 5,
            ..Default::default()
        };
        let service = ObserverService::with_config(config);

        // Finalize 10 heights
        for h in 1..=10 {
            service.ingest_event(&ConsensusEvent::ProposalReceived {
                proposal: test_proposal(h, 0),
            });
            service.finalize_height(h, h as u64 * 1000);
        }

        // Should only keep most recent 5
        assert_eq!(service.stored_height_count(), 5);

        // Height 1 should be pruned
        assert!(service.get_height_analysis(1).is_none());

        // Height 10 should exist
        assert!(service.get_height_analysis(10).is_some());
    }

    #[test]
    fn service_returns_recent_analyses() {
        let service = ObserverService::new();

        // Finalize 5 heights
        for h in 1..=5 {
            service.ingest_event(&ConsensusEvent::ProposalReceived {
                proposal: test_proposal(h, 0),
            });
            service.finalize_height(h, h as u64 * 1000);
        }

        let recent = service.get_recent_analyses(3);
        assert_eq!(recent.len(), 3);

        // Should be in descending height order
        assert_eq!(recent[0].height, 5);
        assert_eq!(recent[1].height, 4);
        assert_eq!(recent[2].height, 3);
    }

    #[test]
    fn service_clears_data() {
        let service = ObserverService::new();

        service.ingest_event(&ConsensusEvent::ProposalReceived {
            proposal: test_proposal(1, 0),
        });
        service.finalize_height(1, 1000);

        assert_eq!(service.stored_height_count(), 1);

        service.clear();

        assert_eq!(service.stored_height_count(), 0);
        assert!(service.get_height_analysis(1).is_none());
    }

    #[test]
    fn service_builds_transition_model() {
        let service = ObserverService::new();

        // Finalize multiple heights with multiple events to generate state transitions
        for h in 1..=5 {
            // Ingest events that will generate a trajectory with multiple states
            service.ingest_event(&ConsensusEvent::ProposalReceived {
                proposal: test_proposal(h, 0),
            });
            service.ingest_event(&ConsensusEvent::ConsensusStalled {
                height: h,
                round: 0,
                timed_out_validators: vec![],
                total_validators: 4,
                timestamp: h * 1000,
            });
            service.ingest_event(&ConsensusEvent::ConsensusRecovered {
                height: h,
                round: 1,
                timestamp: h * 1000 + 100,
            });
            service.finalize_height(h, h as u64 * 1000 + 200);
        }

        let model = service.get_transition_model();
        assert!(model.is_some());

        let model = model.unwrap();
        assert!(
            model.total_transitions() > 0,
            "Expected transitions to be observed"
        );
    }
}
