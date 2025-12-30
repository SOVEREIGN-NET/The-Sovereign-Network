//! Validator P2P Protocol for BFT Consensus
//!
//! Defines message types and communication protocols for validators to participate
//! in Byzantine Fault Tolerance consensus rounds. Handles proposal, vote, and commit
//! message broadcasting between validators.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use lib_crypto::{Hash, PostQuantumSignature};
use lib_identity::IdentityId;

use crate::types::{ConsensusProposal, ConsensusStep, ConsensusVote, VoteType};
use crate::validators::ValidatorDiscoveryProtocol;

/// BFT consensus message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidatorMessage {
    /// Proposal message from block proposer
    Propose(ProposeMessage),
    /// Vote message from validators
    Vote(VoteMessage),
    /// Commit message for block finalization
    Commit(CommitMessage),
    /// Round change request
    RoundChange(RoundChangeMessage),
    /// Validator heartbeat
    Heartbeat(HeartbeatMessage),
}

/// Proposal message for new blocks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposeMessage {
    /// Message identifier
    pub message_id: Hash,
    /// Proposer validator identity
    pub proposer: IdentityId,
    /// Consensus proposal
    pub proposal: ConsensusProposal,
    /// Justification for this proposal (previous round votes)
    pub justification: Option<Justification>,
    /// Message timestamp
    pub timestamp: u64,
    /// Proposer signature over message
    pub signature: PostQuantumSignature,
}

/// Vote message for consensus proposals
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteMessage {
    /// Message identifier
    pub message_id: Hash,
    /// Voting validator identity
    pub voter: IdentityId,
    /// Consensus vote
    pub vote: ConsensusVote,
    /// Validator's current view of consensus state
    pub consensus_state: ConsensusStateView,
    /// Message timestamp
    pub timestamp: u64,
    /// Voter signature over message
    pub signature: PostQuantumSignature,
}

/// Commit message for block finalization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitMessage {
    /// Message identifier
    pub message_id: Hash,
    /// Committing validator identity
    pub committer: IdentityId,
    /// Committed proposal hash
    pub proposal_id: Hash,
    /// Block height being committed
    pub height: u64,
    /// Consensus round
    pub round: u32,
    /// Commitment proof (aggregate signatures)
    pub commitment_proof: CommitmentProof,
    /// Message timestamp
    pub timestamp: u64,
    /// Committer signature over message
    pub signature: PostQuantumSignature,
}

/// Round change message when consensus stalls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundChangeMessage {
    /// Message identifier
    pub message_id: Hash,
    /// Validator requesting round change
    pub validator: IdentityId,
    /// Current block height
    pub height: u64,
    /// New round number
    pub new_round: u32,
    /// Reason for round change
    pub reason: RoundChangeReason,
    /// Locked proposal from previous round (if any)
    pub locked_proposal: Option<Hash>,
    /// Message timestamp
    pub timestamp: u64,
    /// Validator signature over message
    pub signature: PostQuantumSignature,
}

/// Heartbeat message for liveness detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatMessage {
    /// Message identifier
    pub message_id: Hash,
    /// Validator sending heartbeat
    pub validator: IdentityId,
    /// Current block height
    pub height: u64,
    /// Current consensus round
    pub round: u32,
    /// Current consensus step
    pub step: ConsensusStep,
    /// Network view summary
    pub network_summary: NetworkSummary,
    /// Message timestamp
    pub timestamp: u64,
    /// Validator signature over message
    pub signature: PostQuantumSignature,
}

/// Justification for a proposal (votes from previous round)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Justification {
    /// Previous round number
    pub round: u32,
    /// Votes supporting this proposal
    pub votes: Vec<ConsensusVote>,
    /// Aggregate vote power
    pub vote_power: u64,
}

/// Validator's view of consensus state
///
/// **CRITICAL INVARIANT**: Uses BTreeMap instead of HashMap for vote_counts
/// to ensure canonical serialization order. This message is part of ValidatorMessage,
/// which is signable and hashable. Non-deterministic HashMap iteration order would
/// break signature/hash consensus across nodes. (CM-3, CM-4)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusStateView {
    /// Current block height
    pub height: u64,
    /// Current consensus round
    pub round: u32,
    /// Current consensus step
    pub step: ConsensusStep,
    /// Known proposals in this round
    pub known_proposals: Vec<Hash>,
    /// Vote counts by proposal (BTreeMap for canonical iteration order)
    pub vote_counts: BTreeMap<Hash, u32>,
}

/// Commitment proof with aggregate signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentProof {
    /// Aggregate signature from +2/3 validators
    pub aggregate_signature: Vec<u8>,
    /// Validator identities that signed
    pub signers: Vec<IdentityId>,
    /// Combined voting power
    pub voting_power: u64,
}

/// Reasons for requesting round change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoundChangeReason {
    /// Round timeout expired
    Timeout,
    /// Invalid proposal received
    InvalidProposal,
    /// Conflicting proposals detected
    ConflictingProposals,
    /// Insufficient votes received
    InsufficientVotes,
}

/// Network summary for heartbeats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSummary {
    /// Number of active validators
    pub active_validators: u32,
    /// Network health score (0.0-1.0)
    pub health_score: f64,
    /// Recent block production rate
    pub block_rate: f64,
}

/// Validator P2P Protocol Handler
pub struct ValidatorProtocol {
    /// Local validator identity
    validator_identity: Option<IdentityId>,

    /// Discovery protocol for finding other validators
    discovery: Arc<ValidatorDiscoveryProtocol>,

    /// Message handlers by validator identity
    peer_connections: Arc<RwLock<HashMap<IdentityId, ValidatorPeerConnection>>>,

    /// Message cache to prevent duplicates
    message_cache: Arc<RwLock<HashMap<Hash, u64>>>, // message_id -> timestamp

    /// Configuration
    config: ValidatorProtocolConfig,
}

/// Configuration for validator protocol
#[derive(Debug, Clone)]
pub struct ValidatorProtocolConfig {
    /// Maximum message cache size
    pub max_cache_size: usize,
    /// Message TTL in seconds
    pub message_ttl: u64,
    /// Maximum peers to broadcast to
    pub max_broadcast_peers: usize,
    /// Heartbeat interval in seconds
    pub heartbeat_interval: u64,
    /// Round timeout in seconds
    pub round_timeout: u64,
}

impl Default for ValidatorProtocolConfig {
    fn default() -> Self {
        Self {
            max_cache_size: 10000,
            message_ttl: 3600, // 1 hour
            max_broadcast_peers: 100,
            heartbeat_interval: 30,
            round_timeout: 60,
        }
    }
}

/// Connection to a peer validator
#[derive(Debug, Clone)]
pub struct ValidatorPeerConnection {
    /// Peer validator identity
    pub validator_id: IdentityId,
    /// Network endpoints
    pub endpoints: Vec<String>,
    /// Connection status
    pub status: PeerConnectionStatus,
    /// Last heartbeat received
    pub last_heartbeat: u64,
    /// Network latency (ms)
    pub latency_ms: u64,
}

/// Peer connection status
#[derive(Debug, Clone, PartialEq)]
pub enum PeerConnectionStatus {
    /// Connection is active
    Active,
    /// Connection is being established
    Connecting,
    /// Connection failed
    Failed,
    /// Peer is unreachable
    Unreachable,
}

impl ValidatorProtocol {
    /// Create new validator protocol instance
    pub fn new(
        discovery: Arc<ValidatorDiscoveryProtocol>,
        config: Option<ValidatorProtocolConfig>,
    ) -> Self {
        Self {
            validator_identity: None,
            discovery,
            peer_connections: Arc::new(RwLock::new(HashMap::new())),
            message_cache: Arc::new(RwLock::new(HashMap::new())),
            config: config.unwrap_or_default(),
        }
    }

    /// Set the local validator identity
    pub async fn set_validator_identity(&mut self, identity: IdentityId) {
        self.validator_identity = Some(identity.clone());
        info!("Validator protocol initialized for validator: {}", identity);
    }

    /// Broadcast a proposal to all connected validators
    pub async fn broadcast_proposal(
        &self,
        proposal: ConsensusProposal,
        justification: Option<Justification>,
    ) -> Result<()> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| anyhow!("Validator identity not set"))?;

        let message = ProposeMessage {
            message_id: self.generate_message_id(),
            proposer: validator_id.clone(),
            proposal,
            justification,
            timestamp: self.current_timestamp(),
            signature: PostQuantumSignature::default(), // TODO: Sign message
        };

        info!(
            "Broadcasting proposal for height {} from validator {}",
            message.proposal.height, validator_id
        );

        self.broadcast_message(ValidatorMessage::Propose(message))
            .await
    }

    /// Broadcast a vote to all connected validators
    pub async fn broadcast_vote(
        &self,
        vote: ConsensusVote,
        consensus_state: ConsensusStateView,
    ) -> Result<()> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| anyhow!("Validator identity not set"))?;

        let message = VoteMessage {
            message_id: self.generate_message_id(),
            voter: validator_id.clone(),
            vote,
            consensus_state,
            timestamp: self.current_timestamp(),
            signature: PostQuantumSignature::default(), // TODO: Sign message
        };

        debug!(
            "Broadcasting {} vote for proposal {} from validator {}",
            match message.vote.vote_type {
                VoteType::PreVote => "pre-vote",
                VoteType::PreCommit => "pre-commit",
                VoteType::Commit => "commit",
                VoteType::Against => "against",
            },
            message.vote.proposal_id,
            validator_id
        );

        self.broadcast_message(ValidatorMessage::Vote(message))
            .await
    }

    /// Broadcast a commit message to finalize a block
    pub async fn broadcast_commit(
        &self,
        proposal_id: Hash,
        height: u64,
        round: u32,
        commitment_proof: CommitmentProof,
    ) -> Result<()> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| anyhow!("Validator identity not set"))?;

        let message = CommitMessage {
            message_id: self.generate_message_id(),
            committer: validator_id.clone(),
            proposal_id: proposal_id.clone(),
            height,
            round,
            commitment_proof,
            timestamp: self.current_timestamp(),
            signature: PostQuantumSignature::default(), // TODO: Sign message
        };

        info!(
            "Broadcasting commit for proposal {} at height {} from validator {}",
            proposal_id, height, validator_id
        );

        self.broadcast_message(ValidatorMessage::Commit(message))
            .await
    }

    /// Request a round change due to timeout or other issues
    pub async fn request_round_change(
        &self,
        height: u64,
        new_round: u32,
        reason: RoundChangeReason,
        locked_proposal: Option<Hash>,
    ) -> Result<()> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| anyhow!("Validator identity not set"))?;

        let message = RoundChangeMessage {
            message_id: self.generate_message_id(),
            validator: validator_id.clone(),
            height,
            new_round,
            reason: reason.clone(),
            locked_proposal,
            timestamp: self.current_timestamp(),
            signature: PostQuantumSignature::default(), // TODO: Sign message
        };

        warn!(
            "Requesting round change to {} for height {} due to {:?}",
            new_round, height, reason
        );

        self.broadcast_message(ValidatorMessage::RoundChange(message))
            .await
    }

    /// Send periodic heartbeat to maintain liveness
    pub async fn send_heartbeat(
        &self,
        height: u64,
        round: u32,
        step: ConsensusStep,
        network_summary: NetworkSummary,
    ) -> Result<()> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| anyhow!("Validator identity not set"))?;

        let message = HeartbeatMessage {
            message_id: self.generate_message_id(),
            validator: validator_id.clone(),
            height,
            round,
            step,
            network_summary,
            timestamp: self.current_timestamp(),
            signature: PostQuantumSignature::default(), // TODO: Sign message
        };

        debug!("Sending heartbeat from validator {}", validator_id);

        self.broadcast_message(ValidatorMessage::Heartbeat(message))
            .await
    }

    /// Process incoming validator message
    pub async fn handle_message(&self, message: ValidatorMessage) -> Result<()> {
        // Check for duplicate messages
        let message_id = self.get_message_id(&message);
        if self.is_duplicate_message(&message_id).await? {
            debug!("Ignoring duplicate message: {}", message_id);
            return Ok(());
        }

        // Cache the message
        self.cache_message(message_id, self.current_timestamp())
            .await?;

        match message {
            ValidatorMessage::Propose(msg) => self.handle_propose_message(msg).await,
            ValidatorMessage::Vote(msg) => self.handle_vote_message(msg).await,
            ValidatorMessage::Commit(msg) => self.handle_commit_message(msg).await,
            ValidatorMessage::RoundChange(msg) => self.handle_round_change_message(msg).await,
            ValidatorMessage::Heartbeat(msg) => self.handle_heartbeat_message(msg).await,
        }
    }

    /// Connect to other validators in the network
    pub async fn connect_to_validators(&self) -> Result<()> {
        info!("Connecting to validator network...");

        // Discover active validators
        let validators = self
            .discovery
            .discover_validators(Default::default())
            .await?;

        let mut connections = self.peer_connections.write().await;

        for validator in validators {
            if let Some(ref local_id) = self.validator_identity {
                if validator.identity_id == *local_id {
                    continue; // Skip self
                }
            }

            let peer_connection = ValidatorPeerConnection {
                validator_id: validator.identity_id.clone(),
                endpoints: validator
                    .endpoints
                    .iter()
                    .map(|e| e.address.clone())
                    .collect(),
                status: PeerConnectionStatus::Connecting,
                last_heartbeat: 0,
                latency_ms: 0,
            };

            connections.insert(validator.identity_id.clone(), peer_connection);
        }

        info!("Connected to {} validators", connections.len());
        Ok(())
    }

    /// Get current network statistics
    pub async fn get_network_stats(&self) -> ValidatorNetworkStats {
        let connections = self.peer_connections.read().await;

        let active_peers = connections
            .values()
            .filter(|conn| conn.status == PeerConnectionStatus::Active)
            .count();

        let avg_latency = if active_peers > 0 {
            connections
                .values()
                .filter(|conn| conn.status == PeerConnectionStatus::Active)
                .map(|conn| conn.latency_ms)
                .sum::<u64>()
                / active_peers as u64
        } else {
            0
        };

        ValidatorNetworkStats {
            total_peers: connections.len(),
            active_peers,
            average_latency_ms: avg_latency,
            message_cache_size: self.message_cache.read().await.len(),
        }
    }

    // Private helper methods

    /// Broadcast message to all connected validators
    async fn broadcast_message(&self, _message: ValidatorMessage) -> Result<()> {
        let connections = self.peer_connections.read().await;
        let active_peers: Vec<_> = connections
            .values()
            .filter(|conn| conn.status == PeerConnectionStatus::Active)
            .take(self.config.max_broadcast_peers)
            .collect();

        info!(
            "Broadcasting message to {} active peers",
            active_peers.len()
        );

        // TODO: Implement actual network broadcasting
        // This would use lib-network to send messages to peer endpoints
        // For now, just log the broadcast intent

        Ok(())
    }

    /// Handle incoming proposal message
    async fn handle_propose_message(&self, message: ProposeMessage) -> Result<()> {
        info!(
            "Received proposal from {} for height {}",
            message.proposer, message.proposal.height
        );

        // TODO: Validate proposal and forward to consensus engine
        // This would integrate with BftEngine to process the proposal

        Ok(())
    }

    /// Handle incoming vote message
    async fn handle_vote_message(&self, message: VoteMessage) -> Result<()> {
        debug!(
            "Received vote from {} for proposal {}",
            message.voter, message.vote.proposal_id
        );

        // TODO: Validate vote and forward to consensus engine

        Ok(())
    }

    /// Handle incoming commit message
    async fn handle_commit_message(&self, message: CommitMessage) -> Result<()> {
        info!(
            "Received commit from {} for proposal {} at height {}",
            message.committer, message.proposal_id, message.height
        );

        // TODO: Validate commitment and forward to consensus engine

        Ok(())
    }

    /// Handle round change request
    async fn handle_round_change_message(&self, message: RoundChangeMessage) -> Result<()> {
        warn!(
            "Received round change request from {} for round {} due to {:?}",
            message.validator, message.new_round, message.reason
        );

        // TODO: Process round change and coordinate with consensus engine

        Ok(())
    }

    /// Handle heartbeat message
    async fn handle_heartbeat_message(&self, message: HeartbeatMessage) -> Result<()> {
        debug!(
            "Received heartbeat from {} at height {}",
            message.validator, message.height
        );

        // Update peer connection status
        let mut connections = self.peer_connections.write().await;
        if let Some(connection) = connections.get_mut(&message.validator) {
            connection.last_heartbeat = message.timestamp;
            connection.status = PeerConnectionStatus::Active;
        }

        Ok(())
    }

    /// Generate unique message ID
    fn generate_message_id(&self) -> Hash {
        let timestamp = self.current_timestamp();
        let nonce = lib_crypto::generate_nonce(); // 12 random bytes for uniqueness
        let mut data = format!("msg_{}", timestamp).into_bytes();
        data.extend_from_slice(&nonce);
        Hash::from_bytes(&lib_crypto::hash_blake3(&data))
    }

    /// Get message ID from validator message
    fn get_message_id(&self, message: &ValidatorMessage) -> Hash {
        match message {
            ValidatorMessage::Propose(msg) => msg.message_id.clone(),
            ValidatorMessage::Vote(msg) => msg.message_id.clone(),
            ValidatorMessage::Commit(msg) => msg.message_id.clone(),
            ValidatorMessage::RoundChange(msg) => msg.message_id.clone(),
            ValidatorMessage::Heartbeat(msg) => msg.message_id.clone(),
        }
    }

    /// Check if message is duplicate
    async fn is_duplicate_message(&self, message_id: &Hash) -> Result<bool> {
        let cache = self.message_cache.read().await;
        Ok(cache.contains_key(message_id))
    }

    /// Cache message to prevent duplicates
    async fn cache_message(&self, message_id: Hash, timestamp: u64) -> Result<()> {
        let mut cache = self.message_cache.write().await;

        // Clean old entries if cache is too large
        if cache.len() >= self.config.max_cache_size {
            let cutoff = timestamp - self.config.message_ttl;
            cache.retain(|_, ts| *ts > cutoff);
        }

        cache.insert(message_id, timestamp);
        Ok(())
    }

    /// Get current timestamp
    fn current_timestamp(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

/// Network statistics for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorNetworkStats {
    /// Total number of peer connections
    pub total_peers: usize,
    /// Number of active peer connections
    pub active_peers: usize,
    /// Average network latency in milliseconds
    pub average_latency_ms: u64,
    /// Size of message cache
    pub message_cache_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_validator_protocol_creation() {
        let discovery = Arc::new(ValidatorDiscoveryProtocol::new(3600));
        let protocol = ValidatorProtocol::new(discovery, None);

        assert!(protocol.validator_identity.is_none());
        assert_eq!(protocol.config.heartbeat_interval, 30);
    }

    #[tokio::test]
    async fn test_message_id_generation() {
        let discovery = Arc::new(ValidatorDiscoveryProtocol::new(3600));
        let protocol = ValidatorProtocol::new(discovery, None);

        let id1 = protocol.generate_message_id();
        let id2 = protocol.generate_message_id();

        // IDs should be different (due to timestamp)
        assert_ne!(id1, id2);
    }
}
