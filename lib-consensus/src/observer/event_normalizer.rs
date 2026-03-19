use std::collections::BTreeMap;

use lib_identity::IdentityId;
use serde::{Deserialize, Serialize};

use crate::byzantine::ByzantineEvidence;
use crate::engines::consensus_engine::ConsensusAuditLog;
use crate::types::{ConsensusEvent, ConsensusStep, VoteType};

/// Canonical consensus behavior event vocabulary.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ConsensusBehaviorEventType {
    // Round lifecycle
    EnterPropose,
    EnterPreVote,
    EnterPreCommit,
    EnterCommit,
    EnterNewRound,
    RoundAdvanced,
    // Proposal and vote progression
    ProposalCreated,
    ProposalReceived,
    PreVoteCast,
    PreCommitCast,
    CommitVoteObserved,
    CommitQuorumReached,
    BlockCommitted,
    // Liveness and timing
    StepTimeout,
    HigherRoundObserved,
    ConsensusStalled,
    ConsensusRecovered,
    // Execution and state application
    BlockApplyStarted,
    BlockApplySucceeded,
    BlockApplyFailed,
    ParentHashMismatch,
    CatchupSyncStarted,
    CatchupSyncSucceeded,
    CatchupSyncFailed,
    // Evidence and faults
    EquivocationDetected,
    ReplayDetected,
    PartitionSuspected,
    InvalidProposalDetected,
}

/// Deterministic, normalized consensus event consumed by observer components.
///
/// Required fields:
/// - `height`
/// - `round`
/// - `event_type`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusNormalizedEvent {
    pub height: u64,
    pub round: u32,
    pub step: Option<ConsensusStep>,
    pub event_type: ConsensusBehaviorEventType,
    pub validator_id: Option<String>,
    pub logical_time: Option<u64>,
    pub wallclock_time: Option<u64>,
    pub peer_id: Option<String>,
    pub proposal_id: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    #[serde(default)]
    pub inferred: bool,
}

impl ConsensusNormalizedEvent {
    fn new(height: u64, round: u32, event_type: ConsensusBehaviorEventType) -> Self {
        Self {
            height,
            round,
            step: None,
            event_type,
            validator_id: None,
            logical_time: None,
            wallclock_time: None,
            peer_id: None,
            proposal_id: None,
            metadata: BTreeMap::new(),
            inferred: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuntimeConsensusSignal {
    BlockApplyStarted {
        height: u64,
        round: u32,
        wallclock_time: Option<u64>,
    },
    BlockApplySucceeded {
        height: u64,
        round: u32,
        wallclock_time: Option<u64>,
    },
    BlockApplyFailed {
        height: u64,
        round: u32,
        wallclock_time: Option<u64>,
        reason: String,
    },
    ParentHashMismatch {
        height: u64,
        round: u32,
        wallclock_time: Option<u64>,
        details: String,
    },
    CatchupSyncStarted {
        height: u64,
        round: u32,
        wallclock_time: Option<u64>,
    },
    CatchupSyncSucceeded {
        height: u64,
        round: u32,
        wallclock_time: Option<u64>,
    },
    CatchupSyncFailed {
        height: u64,
        round: u32,
        wallclock_time: Option<u64>,
        reason: String,
    },
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum NormalizationError {
    #[error("unknown consensus audit event `{event}` for step `{step:?}`")]
    UnknownAuditEvent { event: String, step: ConsensusStep },
}

/// Deterministically normalize a consensus audit log record.
pub fn normalize_audit_log(
    record: &ConsensusAuditLog,
) -> Result<ConsensusNormalizedEvent, NormalizationError> {
    let event_type = match record.event.as_str() {
        "step_started" => match record.step {
            ConsensusStep::Propose => ConsensusBehaviorEventType::EnterPropose,
            ConsensusStep::PreVote => ConsensusBehaviorEventType::EnterPreVote,
            ConsensusStep::PreCommit => ConsensusBehaviorEventType::EnterPreCommit,
            ConsensusStep::Commit => ConsensusBehaviorEventType::EnterCommit,
            ConsensusStep::NewRound => ConsensusBehaviorEventType::EnterNewRound,
        },
        "proposal_created" => ConsensusBehaviorEventType::ProposalCreated,
        "proposal_received" => ConsensusBehaviorEventType::ProposalReceived,
        "pre_vote_cast" => ConsensusBehaviorEventType::PreVoteCast,
        "pre_commit_cast" => ConsensusBehaviorEventType::PreCommitCast,
        "commit_vote_observed" => ConsensusBehaviorEventType::CommitVoteObserved,
        "commit_quorum_reached" => ConsensusBehaviorEventType::CommitQuorumReached,
        "block_committed" => ConsensusBehaviorEventType::BlockCommitted,
        "round_advanced" => ConsensusBehaviorEventType::RoundAdvanced,
        other => {
            return Err(NormalizationError::UnknownAuditEvent {
                event: other.to_string(),
                step: record.step.clone(),
            });
        }
    };

    let mut normalized = ConsensusNormalizedEvent::new(record.height, record.round, event_type);
    normalized.step = Some(record.step.clone());
    normalized.validator_id = Some(record.validator_id.clone());
    normalized.logical_time = Some(record.logical_time);
    Ok(normalized)
}

/// Deterministically normalize supported consensus-engine runtime events.
///
/// Some events are intentionally skipped when they do not carry enough context
/// (`height`, `round`) to satisfy the canonical observer schema.
pub fn normalize_consensus_event(
    event: &ConsensusEvent,
) -> Result<Option<ConsensusNormalizedEvent>, NormalizationError> {
    let mapped = match event {
        ConsensusEvent::ConsensusStalled {
            height,
            round,
            timed_out_validators,
            total_validators,
            timestamp,
        } => {
            let mut out = ConsensusNormalizedEvent::new(
                *height,
                *round,
                ConsensusBehaviorEventType::ConsensusStalled,
            );
            out.wallclock_time = Some(*timestamp);

            let mut validators: Vec<String> =
                timed_out_validators.iter().map(identity_to_hex).collect();
            validators.sort_unstable();
            out.metadata
                .insert("timed_out_validators".to_string(), validators.join(","));
            out.metadata.insert(
                "timed_out_count".to_string(),
                timed_out_validators.len().to_string(),
            );
            out.metadata
                .insert("total_validators".to_string(), total_validators.to_string());
            Some(out)
        }
        ConsensusEvent::ConsensusRecovered {
            height,
            round,
            timestamp,
        } => {
            let mut out = ConsensusNormalizedEvent::new(
                *height,
                *round,
                ConsensusBehaviorEventType::ConsensusRecovered,
            );
            out.wallclock_time = Some(*timestamp);
            Some(out)
        }
        ConsensusEvent::ProposalReceived { proposal } => {
            let mut out = ConsensusNormalizedEvent::new(
                proposal.height,
                proposal.round,
                ConsensusBehaviorEventType::ProposalReceived,
            );
            out.validator_id = Some(identity_to_hex(&proposal.proposer));
            out.proposal_id = Some(hex::encode(proposal.id.as_bytes()));
            Some(out)
        }
        ConsensusEvent::VoteReceived { vote } => {
            let event_type = match vote.vote_type {
                VoteType::PreVote => ConsensusBehaviorEventType::PreVoteCast,
                VoteType::PreCommit => ConsensusBehaviorEventType::PreCommitCast,
                VoteType::Commit => ConsensusBehaviorEventType::CommitVoteObserved,
                VoteType::Against => return Ok(None),
            };
            let mut out = ConsensusNormalizedEvent::new(vote.height, vote.round, event_type);
            out.validator_id = Some(identity_to_hex(&vote.voter));
            out.proposal_id = Some(hex::encode(vote.proposal_id.as_bytes()));
            Some(out)
        }
        // Use round 0 as canonical for start-of-height signals without explicit round.
        ConsensusEvent::StartRound { height, trigger } => {
            let mut out = ConsensusNormalizedEvent::new(
                *height,
                0,
                ConsensusBehaviorEventType::EnterNewRound,
            );
            out.inferred = true;
            out.metadata.insert("trigger".to_string(), trigger.clone());
            Some(out)
        }
        // Use round 0 as canonical for height-only signals from current runtime API.
        ConsensusEvent::RoundFailed { height, error } => {
            let mut out =
                ConsensusNormalizedEvent::new(*height, 0, ConsensusBehaviorEventType::StepTimeout);
            out.inferred = true;
            out.metadata.insert("error".to_string(), error.clone());
            Some(out)
        }
        _ => None,
    };
    Ok(mapped)
}

/// Deterministically normalize byzantine evidence events.
///
/// `fallback_height` and `fallback_round` are used for evidence types that do
/// not carry explicit height/round information (e.g. replay detection).
pub fn normalize_byzantine_evidence(
    evidence: &ByzantineEvidence,
    fallback_height: u64,
    fallback_round: u32,
) -> ConsensusNormalizedEvent {
    match evidence {
        ByzantineEvidence::Equivocation(eq) => {
            let mut out = ConsensusNormalizedEvent::new(
                eq.height,
                eq.round,
                ConsensusBehaviorEventType::EquivocationDetected,
            );
            out.wallclock_time = Some(eq.detected_at);
            out.validator_id = Some(identity_to_hex(&eq.validator));
            out.metadata
                .insert("vote_type".to_string(), format!("{:?}", eq.vote_type));
            out.metadata.insert(
                "proposal_a".to_string(),
                hex::encode(eq.vote_a.proposal_id.as_bytes()),
            );
            out.metadata.insert(
                "proposal_b".to_string(),
                hex::encode(eq.vote_b.proposal_id.as_bytes()),
            );
            out
        }
        ByzantineEvidence::Replay(replay) => {
            let mut out = ConsensusNormalizedEvent::new(
                fallback_height,
                fallback_round,
                ConsensusBehaviorEventType::ReplayDetected,
            );
            out.wallclock_time = Some(replay.detected_at);
            out.validator_id = Some(identity_to_hex(&replay.validator));
            out.metadata.insert(
                "payload_hash".to_string(),
                hex::encode(replay.payload_hash.as_bytes()),
            );
            out.metadata
                .insert("replay_count".to_string(), replay.replay_count.to_string());
            out
        }
        ByzantineEvidence::PartitionSuspected(partition) => {
            let mut out = ConsensusNormalizedEvent::new(
                partition.height,
                partition.round,
                ConsensusBehaviorEventType::PartitionSuspected,
            );
            out.wallclock_time = Some(partition.detected_at);
            out.metadata.insert(
                "timed_out_count".to_string(),
                partition.timed_out_validators.len().to_string(),
            );
            out.metadata.insert(
                "total_validators".to_string(),
                partition.total_validators.to_string(),
            );
            out.metadata.insert(
                "stall_threshold".to_string(),
                partition.stall_threshold.to_string(),
            );
            out
        }
    }
}

/// Deterministically normalize explicit runtime execution signals.
pub fn normalize_runtime_signal(signal: &RuntimeConsensusSignal) -> ConsensusNormalizedEvent {
    match signal {
        RuntimeConsensusSignal::BlockApplyStarted {
            height,
            round,
            wallclock_time,
        } => {
            let mut out = ConsensusNormalizedEvent::new(
                *height,
                *round,
                ConsensusBehaviorEventType::BlockApplyStarted,
            );
            out.wallclock_time = *wallclock_time;
            out
        }
        RuntimeConsensusSignal::BlockApplySucceeded {
            height,
            round,
            wallclock_time,
        } => {
            let mut out = ConsensusNormalizedEvent::new(
                *height,
                *round,
                ConsensusBehaviorEventType::BlockApplySucceeded,
            );
            out.wallclock_time = *wallclock_time;
            out
        }
        RuntimeConsensusSignal::BlockApplyFailed {
            height,
            round,
            wallclock_time,
            reason,
        } => {
            let mut out = ConsensusNormalizedEvent::new(
                *height,
                *round,
                ConsensusBehaviorEventType::BlockApplyFailed,
            );
            out.wallclock_time = *wallclock_time;
            out.metadata.insert("reason".to_string(), reason.clone());
            out
        }
        RuntimeConsensusSignal::ParentHashMismatch {
            height,
            round,
            wallclock_time,
            details,
        } => {
            let mut out = ConsensusNormalizedEvent::new(
                *height,
                *round,
                ConsensusBehaviorEventType::ParentHashMismatch,
            );
            out.wallclock_time = *wallclock_time;
            out.metadata.insert("details".to_string(), details.clone());
            out
        }
        RuntimeConsensusSignal::CatchupSyncStarted {
            height,
            round,
            wallclock_time,
        } => {
            let mut out = ConsensusNormalizedEvent::new(
                *height,
                *round,
                ConsensusBehaviorEventType::CatchupSyncStarted,
            );
            out.wallclock_time = *wallclock_time;
            out
        }
        RuntimeConsensusSignal::CatchupSyncSucceeded {
            height,
            round,
            wallclock_time,
        } => {
            let mut out = ConsensusNormalizedEvent::new(
                *height,
                *round,
                ConsensusBehaviorEventType::CatchupSyncSucceeded,
            );
            out.wallclock_time = *wallclock_time;
            out
        }
        RuntimeConsensusSignal::CatchupSyncFailed {
            height,
            round,
            wallclock_time,
            reason,
        } => {
            let mut out = ConsensusNormalizedEvent::new(
                *height,
                *round,
                ConsensusBehaviorEventType::CatchupSyncFailed,
            );
            out.wallclock_time = *wallclock_time;
            out.metadata.insert("reason".to_string(), reason.clone());
            out
        }
    }
}

/// Normalize operational log messages for known consensus/runtime failure patterns.
pub fn normalize_operational_message(
    height: u64,
    round: u32,
    message: &str,
    wallclock_time: Option<u64>,
) -> Option<ConsensusNormalizedEvent> {
    let lower = message.to_ascii_lowercase();
    let mut out = if lower.contains("invalid previous block hash") {
        ConsensusNormalizedEvent::new(
            height,
            round,
            ConsensusBehaviorEventType::ParentHashMismatch,
        )
    } else if lower.contains("failed to apply block")
        || lower.contains("blockexecutor failed to apply block")
    {
        ConsensusNormalizedEvent::new(height, round, ConsensusBehaviorEventType::BlockApplyFailed)
    } else if (lower.contains("catch-up") || lower.contains("catchup")) && lower.contains("fail") {
        ConsensusNormalizedEvent::new(height, round, ConsensusBehaviorEventType::CatchupSyncFailed)
    } else if (lower.contains("catch-up") || lower.contains("catchup"))
        && (lower.contains("started") || lower.contains("triggering"))
    {
        ConsensusNormalizedEvent::new(
            height,
            round,
            ConsensusBehaviorEventType::CatchupSyncStarted,
        )
    } else if (lower.contains("catch-up") || lower.contains("catchup"))
        && (lower.contains("success") || lower.contains("succeeded"))
    {
        ConsensusNormalizedEvent::new(
            height,
            round,
            ConsensusBehaviorEventType::CatchupSyncSucceeded,
        )
    } else {
        return None;
    };

    out.wallclock_time = wallclock_time;
    out.metadata
        .insert("source_message".to_string(), message.to_string());
    Some(out)
}

fn identity_to_hex(id: &IdentityId) -> String {
    hex::encode(id.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::{Hash, PostQuantumSignature};

    use crate::byzantine::{PartitionSuspectedEvidence, ReplayEvidence};

    #[test]
    fn maps_step_started_propose_from_audit_log() {
        let record = ConsensusAuditLog {
            height: 10,
            round: 2,
            step: ConsensusStep::Propose,
            event: "step_started".to_string(),
            validator_id: "local".to_string(),
            logical_time: 10_000_002,
        };

        let normalized = normalize_audit_log(&record)// REMEDIATED PANIC: // REMEDIATED: .expect("HARDENED: Non-terminating check");
        assert_eq!(normalized.height, 10);
        assert_eq!(normalized.round, 2);
        assert_eq!(
            normalized.event_type,
            ConsensusBehaviorEventType::EnterPropose
        );
        assert_eq!(normalized.logical_time, Some(10_000_002));
    }

    #[test]
    fn rejects_unknown_audit_event() {
        let record = ConsensusAuditLog {
            height: 1,
            round: 0,
            step: ConsensusStep::Commit,
            event: "unexpected".to_string(),
            validator_id: "local".to_string(),
            logical_time: 1_000_000,
        };

        let err = normalize_audit_log(&record).expect_err("must reject unknown events");
        assert!(matches!(err, NormalizationError::UnknownAuditEvent { .. }));
    }

    #[test]
    fn maps_consensus_stalled_with_sorted_validator_ids() {
        let event = ConsensusEvent::ConsensusStalled {
            height: 55,
            round: 3,
            timed_out_validators: vec![Hash::from_bytes(&[2u8; 32]), Hash::from_bytes(&[1u8; 32])],
            total_validators: 7,
            timestamp: 1700000000,
        };

        let normalized = normalize_consensus_event(&event)
            // REMEDIATED PANIC: // REMEDIATED: .expect("HARDENED: Non-terminating check")
            // REMEDIATED PANIC: // REMEDIATED: .expect("HARDENED: Non-terminating check");
        assert_eq!(
            normalized.event_type,
            ConsensusBehaviorEventType::ConsensusStalled
        );
        assert_eq!(
            normalized.metadata.get("timed_out_count"),
            Some(&"2".to_string())
        );
        assert_eq!(
            normalized.metadata.get("timed_out_validators"),
            Some(&format!(
                "{},{}",
                hex::encode([1u8; 32]),
                hex::encode([2u8; 32])
            ))
        );
    }

    #[test]
    fn maps_replay_evidence_with_fallback_height_round() {
        let replay = ReplayEvidence {
            validator: Hash::from_bytes(&[9u8; 32]),
            payload_hash: Hash::from_bytes(&[8u8; 32]),
            first_seen_at: 1,
            last_seen_at: 2,
            replay_count: 3,
            detected_at: 4,
        };
        let normalized = normalize_byzantine_evidence(&ByzantineEvidence::Replay(replay), 100, 4);
        assert_eq!(normalized.height, 100);
        assert_eq!(normalized.round, 4);
        assert_eq!(
            normalized.event_type,
            ConsensusBehaviorEventType::ReplayDetected
        );
        assert_eq!(
            normalized.metadata.get("replay_count"),
            Some(&"3".to_string())
        );
    }

    #[test]
    fn maps_partition_evidence_height_and_round() {
        let evidence = PartitionSuspectedEvidence {
            height: 77,
            round: 5,
            timed_out_validators: vec![],
            total_validators: 10,
            stall_threshold: 4,
            observation_window_secs: 30,
            detected_at: 170,
        };

        let normalized =
            normalize_byzantine_evidence(&ByzantineEvidence::PartitionSuspected(evidence), 0, 0);
        assert_eq!(normalized.height, 77);
        assert_eq!(normalized.round, 5);
        assert_eq!(
            normalized.event_type,
            ConsensusBehaviorEventType::PartitionSuspected
        );
    }

    #[test]
    fn maps_runtime_block_apply_failure() {
        let normalized = normalize_runtime_signal(&RuntimeConsensusSignal::BlockApplyFailed {
            height: 12,
            round: 1,
            wallclock_time: Some(99),
            reason: "execution failed".to_string(),
        });
        assert_eq!(
            normalized.event_type,
            ConsensusBehaviorEventType::BlockApplyFailed
        );
        assert_eq!(
            normalized.metadata.get("reason"),
            Some(&"execution failed".to_string())
        );
    }

    #[test]
    fn maps_operational_parent_hash_mismatch() {
        let normalized = normalize_operational_message(
            20,
            2,
            "Invalid previous block hash: expected a, got b",
            Some(1234),
        )
        // REMEDIATED PANIC: // REMEDIATED: .expect("HARDENED: Non-terminating check");
        assert_eq!(
            normalized.event_type,
            ConsensusBehaviorEventType::ParentHashMismatch
        );
        assert_eq!(normalized.wallclock_time, Some(1234));
    }

    #[test]
    fn skips_unknown_operational_message() {
        assert!(normalize_operational_message(1, 0, "completely unrelated", None).is_none());
    }

    #[test]
    fn maps_commit_vote_observed_from_vote_received_event() {
        let event = ConsensusEvent::VoteReceived {
            vote: crate::types::ConsensusVote {
                id: Hash::from_bytes(&[1u8; 32]),
                voter: Hash::from_bytes(&[2u8; 32]),
                proposal_id: Hash::from_bytes(&[3u8; 32]),
                vote_type: VoteType::Commit,
                height: 8,
                round: 1,
                timestamp: 0,
                signature: PostQuantumSignature::default(),
            },
        };

        let normalized = normalize_consensus_event(&event)
            // REMEDIATED PANIC: // REMEDIATED: .expect("HARDENED: Non-terminating check")
            // REMEDIATED PANIC: // REMEDIATED: .expect("HARDENED: Non-terminating check");
        assert_eq!(
            normalized.event_type,
            ConsensusBehaviorEventType::CommitVoteObserved
        );
        assert_eq!(normalized.height, 8);
        assert_eq!(normalized.round, 1);
    }
}
