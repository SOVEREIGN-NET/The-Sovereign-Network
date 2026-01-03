//! Byzantine evidence structures for forensic analysis and fault detection
//!
//! This module defines cryptographically verifiable evidence for Byzantine faults:
//! - Equivocation: Two conflicting votes with same (validator, height, round, vote_type)
//! - Replay: Identical signed payload delivered multiple times
//! - Partition: Network partition when >1/3 validators timeout (quorum impossible)
//! - Forensics: Timestamped message signatures for post-mortem analysis
//!
//! ## Design Philosophy: "Evidence, Not Heuristics"
//!
//! Evidence is produced ONLY when there are observable, cryptographically verifiable facts:
//! - Equivocation requires TWO signed conflicting payloads
//! - Replay requires exact payload hash duplication
//! - Partition is based on observable timeout state from LivenessMonitor
//!
//! No machine learning, no probability scores, no fuzzy matching.

use lib_crypto::{Hash, PostQuantumSignature};
use lib_identity::IdentityId;

/// Top-level Byzantine evidence enum
///
/// All evidence variants represent cryptographically verifiable Byzantine behavior
/// or network anomalies that should be recorded for governance/slashing decisions.
#[derive(Clone, Debug)]
pub enum ByzantineEvidence {
    /// Two conflicting votes for same (H, R, type, validator)
    Equivocation(EquivocationEvidence),
    /// Duplicate payload delivery
    Replay(ReplayEvidence),
    /// >1/3 validators timed out (BFT quorum impossible)
    PartitionSuspected(PartitionSuspectedEvidence),
}

/// Equivocation evidence: Two signed votes with same (H, R, type) but different proposals
///
/// **Invariant**: Equivocation is proposal-scoped. Same (validator, height, round, vote_type)
/// with DIFFERENT proposal_id is equivocation. Same proposal_id is idempotent duplicate.
///
/// **Evidence**: Both votes include full PostQuantumSignature for cryptographic verification.
/// Evidence proves the validator signed contradictory statements on-chain.
#[derive(Clone, Debug)]
pub struct EquivocationEvidence {
    /// The validator who equivocated
    pub validator: IdentityId,
    /// Consensus height where equivocation occurred
    pub height: u64,
    /// Consensus round number
    pub round: u32,
    /// Vote type (PreVote, PreCommit, Commit)
    pub vote_type: crate::types::VoteType,
    /// First vote for this (H, R, type)
    pub vote_a: ConflictingVote,
    /// Second vote with different proposal_id (conflicts with vote_a)
    pub vote_b: ConflictingVote,
    /// Unix timestamp when equivocation was detected
    pub detected_at: u64,
    /// Optional peer who reported first conflicting vote
    pub reported_by_peer_a: Option<IdentityId>,
    /// Optional peer who reported second conflicting vote
    pub reported_by_peer_b: Option<IdentityId>,
}

/// A single conflicting vote (part of equivocation evidence)
///
/// Contains full signature for verification. Can be reconstructed from
/// vote pool records for on-chain verification.
#[derive(Clone, Debug)]
pub struct ConflictingVote {
    /// Vote message ID (collision-resistant hash)
    pub vote_id: Hash,
    /// Proposal this vote was for (differs between conflicting votes)
    pub proposal_id: Hash,
    /// Vote creation timestamp
    pub timestamp: u64,
    /// Full post-quantum signature for verification
    pub signature: PostQuantumSignature,
    /// When this vote was first received by our node
    pub received_at: u64,
}

/// Replay attack evidence: Identical signed payload delivered multiple times
///
/// **Invariant**: Replay is defined by repeated signed payload identity.
/// Uses H(bincode::serialize(signed_message)) not message_id (which is already a hash).
///
/// **Detection**: Bounded LRU cache with TTL tracks (validator, payload_hash).
/// After TTL expiry, same payload is NOT considered replay (network rebroadcast).
///
/// **Advisory**: Replay detection is advisory (doesn't block processing).
/// Indicates either misconfigured peer or network rebroadcast pattern.
#[derive(Clone, Debug)]
pub struct ReplayEvidence {
    /// Validator who sent duplicate payload
    pub validator: IdentityId,
    /// H(bincode::serialize(message)) - deterministic payload hash
    pub payload_hash: Hash,
    /// Unix timestamp of first payload arrival
    pub first_seen_at: u64,
    /// Unix timestamp of most recent duplicate arrival
    pub last_seen_at: u64,
    /// Total count of identical payloads received (including first)
    pub replay_count: u32,
    /// Unix timestamp when replay was detected
    pub detected_at: u64,
}

/// Partition detection evidence: >1/3 validators timed out
///
/// **Invariant**: Partition detection is SUSPICION, not proof of Byzantine behavior.
/// Based on observable timeout state. May also indicate slow network or clock skew.
///
/// **Threshold**: floor(n/3) + 1 validators must timeout to make BFT quorum impossible.
/// For 7 validators: floor(7/3) + 1 = 3 timeouts triggers partition evidence.
/// For 10 validators: floor(10/3) + 1 = 4 timeouts triggers partition evidence.
///
/// **Use Case**: Triggers automatic recovery mechanisms (future work):
/// - Round timeout acceleration
/// - Proposer rotation
/// - Emergency validator set update
#[derive(Clone, Debug)]
pub struct PartitionSuspectedEvidence {
    /// Consensus height when partition was suspected
    pub height: u64,
    /// Consensus round number
    pub round: u32,
    /// List of validators who failed to send heartbeat
    pub timed_out_validators: Vec<IdentityId>,
    /// Total validators in the current validator set
    pub total_validators: usize,
    /// Stall threshold: floor(total_validators / 3) + 1
    pub stall_threshold: usize,
    /// Duration of observation window in seconds
    pub observation_window_secs: u64,
    /// Unix timestamp when partition was detected
    pub detected_at: u64,
}

/// Forensic record: Timestamped message signature for post-mortem analysis
///
/// **Purpose**: Minimal persistent record of signed messages for:
/// - Post-mortem Byzantine fault analysis
/// - Cross-validation with other nodes' forensic records
/// - Evidence payload construction for governance
///
/// **Storage**: Bounded VecDeque with both size limit (50K records) and TTL (24 hrs).
/// When size exceeds limit: oldest records evicted (LRU).
/// When TTL exceeded: periodic cleanup removes expired records.
///
/// **Performance**: Non-blocking append (~1μs). Never impacts consensus path.
#[derive(Clone, Debug)]
pub struct ForensicRecord {
    /// Message ID from original message
    pub message_id: Hash,
    /// Validator who authored/signed the message
    pub validator: IdentityId,
    /// Full post-quantum signature for verification
    pub signature: PostQuantumSignature,
    /// H(bincode::serialize(message)) for replay detection
    pub payload_hash: Hash,
    /// When this message was received/recorded
    pub received_at: u64,
    /// Optional peer ID if available from network layer
    pub peer_id: Option<IdentityId>,
    /// Message type (Proposal, PreVote, PreCommit, etc.)
    pub message_type: ForensicMessageType,
}

/// Forensic message type classification
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum ForensicMessageType {
    /// Proposal (block proposal for height/round)
    Proposal,
    /// PreVote (first consensus phase vote)
    PreVote,
    /// PreCommit (second consensus phase vote)
    PreCommit,
    /// Commit (final confirmation vote)
    Commit,
    /// Round change (move to next round)
    RoundChange,
    /// Heartbeat (liveness indicator)
    Heartbeat,
}

impl std::fmt::Display for ForensicMessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proposal => write!(f, "Proposal"),
            Self::PreVote => write!(f, "PreVote"),
            Self::PreCommit => write!(f, "PreCommit"),
            Self::Commit => write!(f, "Commit"),
            Self::RoundChange => write!(f, "RoundChange"),
            Self::Heartbeat => write!(f, "Heartbeat"),
        }
    }
}

/// Vote tracking key for equivocation detection
///
/// Used to group votes by (validator, height, round, vote_type).
/// Multiple votes with same key but different proposal_id = equivocation.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct VoteTrackingKey {
    pub validator: IdentityId,
    pub height: u64,
    pub round: u32,
    pub vote_type: crate::types::VoteType,
}

/// First vote record for equivocation detection
///
/// Stores data from the FIRST vote with a given VoteTrackingKey.
/// Subsequent votes are compared against this record.
#[derive(Clone, Debug)]
pub struct FirstVoteRecord {
    pub vote_id: Hash,
    pub proposal_id: Hash,
    pub signature: PostQuantumSignature,
    pub timestamp: u64,
    pub received_at: u64,
}

/// Replay cache key
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ReplayKey {
    pub validator: IdentityId,
    pub payload_hash: Hash,
}

/// Replay cache metadata
#[derive(Clone, Debug)]
pub struct ReplayMetadata {
    pub first_seen_at: u64,
    pub count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_forensic_message_type_display() {
        assert_eq!(ForensicMessageType::Proposal.to_string(), "Proposal");
        assert_eq!(ForensicMessageType::PreVote.to_string(), "PreVote");
        assert_eq!(ForensicMessageType::PreCommit.to_string(), "PreCommit");
        assert_eq!(ForensicMessageType::Commit.to_string(), "Commit");
        assert_eq!(ForensicMessageType::RoundChange.to_string(), "RoundChange");
        assert_eq!(ForensicMessageType::Heartbeat.to_string(), "Heartbeat");
    }

    #[test]
    fn test_vote_tracking_key_hashable() {
        let key1 = VoteTrackingKey {
            validator: Hash::from_bytes(&[1u8; 32]),
            height: 10,
            round: 2,
            vote_type: crate::types::VoteType::PreVote,
        };

        let key2 = VoteTrackingKey {
            validator: Hash::from_bytes(&[1u8; 32]),
            height: 10,
            round: 2,
            vote_type: crate::types::VoteType::PreVote,
        };

        // Test that identical keys are equal
        assert_eq!(key1, key2);

        // Test that keys can be used in HashMap
        let mut map = HashMap::new();
        map.insert(key1, "test");
        assert_eq!(map.get(&key2), Some(&"test"));
    }

    #[test]
    fn test_replay_key_hashable() {
        let key1 = ReplayKey {
            validator: Hash::from_bytes(&[1u8; 32]),
            payload_hash: Hash::from_bytes(&[2u8; 32]),
        };

        let key2 = ReplayKey {
            validator: Hash::from_bytes(&[1u8; 32]),
            payload_hash: Hash::from_bytes(&[2u8; 32]),
        };

        assert_eq!(key1, key2);

        let mut map = HashMap::new();
        map.insert(key1, (1u64, 1u32));
        assert_eq!(map.get(&key2), Some(&(1u64, 1u32)));
    }
}
