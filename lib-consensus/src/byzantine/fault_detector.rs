//! Byzantine fault detection system with evidence production

use crate::network::LivenessMonitor;
use crate::types::SlashType;
use crate::validators::ValidatorManager;
use anyhow::Result;
use lib_crypto::PostQuantumSignature;
use lib_identity::IdentityId;
use std::collections::{HashMap, VecDeque};

pub use super::evidence::{
    ByzantineEvidence, ConflictingVote, EquivocationEvidence, FirstVoteRecord, ForensicMessageType,
    ForensicRecord, PartitionSuspectedEvidence, ReplayEvidence, ReplayKey, ReplayMetadata,
    VoteTrackingKey,
};
pub use super::lru_cache::BoundedLruCache;

/// Byzantine fault detector with evidence production
#[derive(Debug, Clone)]
pub struct ByzantineFaultDetector {
    /// Detected double-signing events
    double_signs: HashMap<IdentityId, Vec<DoubleSignEvent>>,
    /// Liveness violations
    liveness_violations: HashMap<IdentityId, Vec<LivenessViolation>>,
    /// Invalid proposal attempts
    invalid_proposals: HashMap<IdentityId, Vec<InvalidProposalEvent>>,

    // NEW FIELDS FOR EVIDENCE PRODUCTION
    /// First vote tracker for equivocation detection
    /// Key: (validator, height, round, vote_type)
    /// Value: First vote data (proposal_id, signature, timestamp)
    first_votes: HashMap<VoteTrackingKey, FirstVoteRecord>,

    /// Replay detection cache with LRU + TTL
    /// Key: (validator, payload_hash)
    /// Value: (first_seen_at, count)
    replay_cache: BoundedLruCache<ReplayKey, ReplayMetadata>,

    /// Forensic records for auditing (bounded VecDeque)
    forensic_records: VecDeque<ForensicRecord>,
    forensic_max_size: usize,
    forensic_ttl_secs: u64,

    /// All detected evidence for reporting
    evidence_log: Vec<ByzantineEvidence>,

    /// Partition detection rate limiting
    last_partition_check: u64,
    partition_check_interval_secs: u64,

    /// Configuration
    config: FaultDetectorConfig,
}

/// Configuration for Byzantine fault detector
#[derive(Debug, Clone)]
pub struct FaultDetectorConfig {
    pub replay_cache_max_size: usize,
    pub replay_detection_window_secs: u64,
    pub forensic_max_records: usize,
    pub forensic_ttl_secs: u64,
    pub partition_check_interval_secs: u64,
}

/// Double signing event
#[derive(Debug, Clone)]
pub struct DoubleSignEvent {
    pub validator: IdentityId,
    pub height: u64,
    pub round: u32,
    pub first_signature: Vec<u8>,
    pub second_signature: Vec<u8>,
    pub detected_at: u64,
}

/// Liveness violation event
#[derive(Debug, Clone)]
pub struct LivenessViolation {
    pub validator: IdentityId,
    pub height: u64,
    pub expected_participation: bool,
    pub actual_participation: bool,
    pub missed_rounds: u32,
    pub detected_at: u64,
}

/// Invalid proposal event
#[derive(Debug, Clone)]
pub struct InvalidProposalEvent {
    pub validator: IdentityId,
    pub height: u64,
    pub proposal_hash: [u8; 32],
    pub violation_type: String,
    pub detected_at: u64,
}

impl ByzantineFaultDetector {
    /// Create a new Byzantine fault detector with default configuration
    pub fn new() -> Self {
        Self::with_config(FaultDetectorConfig {
            replay_cache_max_size: 10_000,
            replay_detection_window_secs: 300, // 5 minutes
            forensic_max_records: 50_000,
            forensic_ttl_secs: 86_400, // 24 hours
            partition_check_interval_secs: 10,
        })
    }

    /// Create a new Byzantine fault detector with custom configuration
    pub fn with_config(config: FaultDetectorConfig) -> Self {
        Self {
            double_signs: HashMap::new(),
            liveness_violations: HashMap::new(),
            invalid_proposals: HashMap::new(),
            first_votes: HashMap::new(),
            replay_cache: BoundedLruCache::new(config.replay_cache_max_size, config.replay_detection_window_secs),
            forensic_records: VecDeque::new(),
            forensic_max_size: config.forensic_max_records,
            forensic_ttl_secs: config.forensic_ttl_secs,
            evidence_log: Vec::new(),
            last_partition_check: 0,
            partition_check_interval_secs: config.partition_check_interval_secs,
            config,
        }
    }

    /// Detect Byzantine faults among validators
    pub fn detect_faults(&mut self, _validator_manager: &ValidatorManager) -> Result<Vec<ByzantineFault>> {
        let mut detected_faults = Vec::new();

        // Check for double signing
        for (validator_id, events) in &self.double_signs {
            if !events.is_empty() {
                detected_faults.push(ByzantineFault {
                    validator: validator_id.clone(),
                    fault_type: ByzantineFaultType::DoubleSign,
                    evidence: format!("Double signed {} times", events.len()),
                    severity: FaultSeverity::Critical,
                    detected_at: events.last().unwrap().detected_at,
                });
            }
        }

        // Check for liveness violations
        for (validator_id, violations) in &self.liveness_violations {
            let recent_violations = violations.iter().filter(|v| v.missed_rounds >= 3).count();

            if recent_violations > 0 {
                detected_faults.push(ByzantineFault {
                    validator: validator_id.clone(),
                    fault_type: ByzantineFaultType::Liveness,
                    evidence: format!("Missed {} rounds in recent violations", recent_violations),
                    severity: if recent_violations >= 10 {
                        FaultSeverity::Critical
                    } else {
                        FaultSeverity::Minor
                    },
                    detected_at: violations.last().unwrap().detected_at,
                });
            }
        }

        // Check for invalid proposals
        for (validator_id, events) in &self.invalid_proposals {
            if events.len() >= 3 {
                detected_faults.push(ByzantineFault {
                    validator: validator_id.clone(),
                    fault_type: ByzantineFaultType::InvalidProposal,
                    evidence: format!("Made {} invalid proposals", events.len()),
                    severity: FaultSeverity::Major,
                    detected_at: events.last().unwrap().detected_at,
                });
            }
        }

        Ok(detected_faults)
    }

    /// Record a double signing event
    pub fn record_double_sign(
        &mut self,
        validator: IdentityId,
        height: u64,
        round: u32,
        first_signature: Vec<u8>,
        second_signature: Vec<u8>,
    ) {
        let event = DoubleSignEvent {
            validator: validator.clone(),
            height,
            round,
            first_signature,
            second_signature,
            detected_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.double_signs
            .entry(validator)
            .or_insert_with(Vec::new)
            .push(event);
    }

    /// Record a liveness violation
    pub fn record_liveness_violation(
        &mut self,
        validator: IdentityId,
        height: u64,
        missed_rounds: u32,
    ) {
        let violation = LivenessViolation {
            validator: validator.clone(),
            height,
            expected_participation: true,
            actual_participation: false,
            missed_rounds,
            detected_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.liveness_violations
            .entry(validator)
            .or_insert_with(Vec::new)
            .push(violation);
    }

    /// Record an invalid proposal
    pub fn record_invalid_proposal(
        &mut self,
        validator: IdentityId,
        height: u64,
        proposal_hash: [u8; 32],
        violation_type: String,
    ) {
        let event = InvalidProposalEvent {
            validator: validator.clone(),
            height,
            proposal_hash,
            violation_type,
            detected_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.invalid_proposals
            .entry(validator)
            .or_insert_with(Vec::new)
            .push(event);
    }

    /// Process detected faults and apply penalties
    pub fn process_faults(
        &mut self,
        faults: Vec<ByzantineFault>,
        validator_manager: &mut ValidatorManager,
    ) -> Result<()> {
        for fault in faults {
            match fault.fault_type {
                ByzantineFaultType::DoubleSign => {
                    let slash_percentage = match fault.severity {
                        FaultSeverity::Critical => 10, // 10% slash for double signing
                        _ => 5,
                    };

                    if let Err(e) = validator_manager.slash_validator(
                        &fault.validator,
                        SlashType::DoubleSign,
                        slash_percentage,
                    ) {
                        tracing::warn!("Failed to slash validator for double signing: {}", e);
                    }
                }
                ByzantineFaultType::Liveness => {
                    let slash_percentage = match fault.severity {
                        FaultSeverity::Critical => 3, // 3% slash for severe liveness violations
                        _ => 1,                       // 1% slash for minor violations
                    };

                    if let Err(e) = validator_manager.slash_validator(
                        &fault.validator,
                        SlashType::Liveness,
                        slash_percentage,
                    ) {
                        tracing::warn!("Failed to slash validator for liveness violation: {}", e);
                    }
                }
                ByzantineFaultType::InvalidProposal => {
                    if let Err(e) = validator_manager.slash_validator(
                        &fault.validator,
                        SlashType::InvalidProposal,
                        2, // 2% slash for invalid proposals
                    ) {
                        tracing::warn!("Failed to slash validator for invalid proposal: {}", e);
                    }
                }
            }

            tracing::warn!(
                " Byzantine fault detected: {:?} by validator {:?} - {}",
                fault.fault_type,
                fault.validator,
                fault.evidence
            );
        }

        Ok(())
    }

    /// Detect equivocation (two conflicting votes for same H/R/type)
    ///
    /// Returns evidence if a second vote with different proposal_id is detected.
    /// First occurrence: stored, returns None.
    /// Same proposal_id as first: idempotent duplicate, returns None.
    /// Different proposal_id: EQUIVOCATION, returns evidence with both votes.
    pub fn detect_equivocation(
        &mut self,
        vote: &crate::types::ConsensusVote,
        proposal_id: &lib_crypto::Hash,
        current_time: u64,
        reported_by_peer: Option<IdentityId>,
    ) -> Option<EquivocationEvidence> {
        let key = VoteTrackingKey {
            validator: vote.voter.clone(),
            height: vote.height,
            round: vote.round,
            vote_type: vote.vote_type,
        };

        // Check if we've seen a vote with this key before
        if let Some(first_vote) = self.first_votes.get(&key) {
            // If same proposal_id: idempotent duplicate, no equivocation
            if &first_vote.proposal_id == proposal_id {
                return None;
            }

            // EQUIVOCATION DETECTED: Two different proposals for same (H, R, type)
            let evidence = EquivocationEvidence {
                validator: vote.voter.clone(),
                height: vote.height,
                round: vote.round,
                vote_type: vote.vote_type,
                vote_a: ConflictingVote {
                    vote_id: lib_crypto::Hash::from_bytes(&[0u8; 32]), // Placeholder - would need vote.id
                    proposal_id: first_vote.proposal_id.clone(),
                    timestamp: first_vote.timestamp,
                    signature: first_vote.signature.clone(),
                    received_at: 0, // Placeholder
                },
                vote_b: ConflictingVote {
                    vote_id: vote.id.clone(),
                    proposal_id: proposal_id.clone(),
                    timestamp: vote.timestamp,
                    signature: vote.signature.clone(),
                    received_at: current_time,
                },
                detected_at: current_time,
                reported_by_peer_a: None,
                reported_by_peer_b: reported_by_peer.clone(),
            };

            self.evidence_log.push(ByzantineEvidence::Equivocation(evidence.clone()));
            return Some(evidence);
        }

        // First occurrence: store and return None
        self.first_votes.insert(
            key,
            FirstVoteRecord {
                proposal_id: proposal_id.clone(),
                signature: vote.signature.clone(),
                timestamp: vote.timestamp,
                received_at: current_time,
            },
        );

        None
    }

    /// Detect replay attacks (duplicate payload delivery)
    ///
    /// Uses payload hash for identity (H(bincode::serialize(message))).
    /// Returns evidence on second and subsequent occurrences.
    /// After TTL expiry, same payload is no longer considered replay.
    pub fn detect_replay_attack(
        &mut self,
        validator: &IdentityId,
        payload_hash: lib_crypto::Hash,
        current_time: u64,
    ) -> Option<ReplayEvidence> {
        let key = ReplayKey {
            validator: validator.clone(),
            payload_hash: payload_hash.clone(),
        };

        // Check if we've seen this payload before
        if let Some(mut metadata) = self.replay_cache.get(&key, current_time) {
            // Increment count
            metadata.count += 1;

            let evidence = ReplayEvidence {
                validator: validator.clone(),
                payload_hash: payload_hash.clone(),
                first_seen_at: metadata.first_seen_at,
                last_seen_at: current_time,
                replay_count: metadata.count,
                detected_at: current_time,
            };

            // Update cache with new count
            self.replay_cache.insert(key, metadata, current_time);
            self.evidence_log.push(ByzantineEvidence::Replay(evidence.clone()));
            return Some(evidence);
        }

        // First occurrence: insert and return None
        self.replay_cache.insert(
            key,
            ReplayMetadata {
                first_seen_at: current_time,
                count: 1,
            },
            current_time,
        );

        None
    }

    /// Detect network partition (>1/3 validators timed out)
    ///
    /// Returns evidence when BFT quorum becomes impossible.
    /// Rate limited to prevent spam (only once per interval).
    pub fn detect_network_partition(
        &mut self,
        liveness_monitor: &LivenessMonitor,
        height: u64,
        round: u32,
        current_time: u64,
    ) -> Option<PartitionSuspectedEvidence> {
        // Rate limiting: only check every partition_check_interval_secs
        if current_time < self.last_partition_check + self.partition_check_interval_secs {
            return None;
        }
        self.last_partition_check = current_time;

        // Check if stalled (>1/3 validators timed out)
        if !liveness_monitor.is_stalled() {
            return None;
        }

        let timed_out = liveness_monitor.timed_out_validators();
        let evidence = PartitionSuspectedEvidence {
            height,
            round,
            timed_out_validators: timed_out.clone(),
            total_validators: liveness_monitor.total_validators,
            stall_threshold: liveness_monitor.stall_threshold,
            observation_window_secs: 10, // Default observation window
            detected_at: current_time,
        };

        self.evidence_log.push(ByzantineEvidence::PartitionSuspected(evidence.clone()));
        Some(evidence)
    }

    /// Record a message signature for forensic analysis
    ///
    /// Non-blocking append. Storage is bounded (size + TTL).
    /// Does NOT impact consensus path performance.
    pub fn record_message_signature(
        &mut self,
        message_id: lib_crypto::Hash,
        validator: IdentityId,
        signature: PostQuantumSignature,
        payload_hash: lib_crypto::Hash,
        message_type: ForensicMessageType,
        current_time: u64,
        peer_id: Option<IdentityId>,
    ) {
        // Enforce size limit: evict oldest if at capacity
        if self.forensic_records.len() >= self.forensic_max_size {
            self.forensic_records.pop_front();
        }

        let record = ForensicRecord {
            message_id,
            validator,
            signature,
            payload_hash,
            received_at: current_time,
            peer_id,
            message_type,
        };

        self.forensic_records.push_back(record);
    }

    /// Get all recorded evidence (caller should drain this)
    pub fn get_evidence_log(&mut self) -> Vec<ByzantineEvidence> {
        std::mem::take(&mut self.evidence_log)
    }

    /// Clear old fault records and cleanup caches
    pub fn cleanup_old_records(&mut self, current_time: u64) {
        let max_age_seconds = 86400; // 24 hours
        let cutoff_time = current_time.saturating_sub(max_age_seconds);

        // EXISTING: Clean double signs
        self.double_signs.retain(|_, events| {
            events.retain(|event| event.detected_at > cutoff_time);
            !events.is_empty()
        });

        // EXISTING: Clean liveness violations
        self.liveness_violations.retain(|_, violations| {
            violations.retain(|violation| violation.detected_at > cutoff_time);
            !violations.is_empty()
        });

        // EXISTING: Clean invalid proposals
        self.invalid_proposals.retain(|_, events| {
            events.retain(|event| event.detected_at > cutoff_time);
            !events.is_empty()
        });

        // NEW: Clean replay cache (TTL-based)
        self.replay_cache.cleanup_expired(current_time);

        // NEW: Clean forensic records (TTL + size based)
        let forensic_cutoff = current_time.saturating_sub(self.forensic_ttl_secs);
        self.forensic_records
            .retain(|record| record.received_at > forensic_cutoff);

        // NEW: Clean first votes (keep last 100 heights)
        if self.first_votes.len() > 400 {
            // Rough estimate: 4 vote types per height
            let min_height = self
                .first_votes
                .keys()
                .map(|k| k.height)
                .min()
                .unwrap_or(0);
            let cutoff_height = min_height + 100;

            self.first_votes
                .retain(|key, _| key.height >= cutoff_height);
        }
    }
}

/// Byzantine fault information
#[derive(Debug, Clone)]
pub struct ByzantineFault {
    pub validator: IdentityId,
    pub fault_type: ByzantineFaultType,
    pub evidence: String,
    pub severity: FaultSeverity,
    pub detected_at: u64,
}

/// Types of Byzantine faults
#[derive(Debug, Clone, PartialEq)]
pub enum ByzantineFaultType {
    /// Validator signed multiple blocks at the same height
    DoubleSign,
    /// Validator failed to participate in consensus
    Liveness,
    /// Validator made an invalid proposal
    InvalidProposal,
}

/// Severity levels for Byzantine faults
#[derive(Debug, Clone, PartialEq)]
pub enum FaultSeverity {
    /// Minor fault with small penalty
    Minor,
    /// Major fault with significant penalty
    Major,
    /// Critical fault requiring immediate action
    Critical,
}
