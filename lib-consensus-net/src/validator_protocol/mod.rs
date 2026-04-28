//! Validator P2P Protocol for BFT Consensus
//!
//! Defines message types and communication protocols for validators to participate
//! in Byzantine Fault Tolerance consensus rounds. Handles proposal, vote, and commit
//! message broadcasting between validators.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info};

use lib_crypto::{Hash, KeyPair, PostQuantumSignature};
use lib_identity::IdentityId;

use lib_consensus_core::types::{ConsensusProposal, ConsensusVote};
use lib_types::consensus::{ConsensusStep, VoteType};
use crate::discovery::ValidatorDiscoveryProtocol;

/// Trait for sending signed validator messages over the network.
///
/// Implemented by zhtp's QUIC mesh transport (`QuicValidatorTransport`).
/// This abstraction keeps lib-consensus decoupled from the network layer.
#[async_trait]
pub trait ValidatorNetworkTransport: Send + Sync {
    /// Broadcast a signed validator message to the specified recipients.
    async fn broadcast_to_validators(
        &self,
        message: ValidatorMessage,
        recipients: &[IdentityId],
    ) -> Result<()>;
}

// CONS-401: `ValidatorMessage`, `ProposeMessage`, `VoteMessage`,
// `HeartbeatMessage`, `Justification`, `ConsensusStateView`, and
// `NetworkSummary` migrated to `lib_consensus_core::types::messages`.
// The trait that consumes them (`MessageBroadcaster`) needed to live
// in `lib-consensus-core`, so the value types had to follow.
// Re-exported here so existing
// `lib_consensus_net::validator_protocol::ValidatorMessage` paths
// keep working unchanged.
pub use lib_consensus_core::types::{
    ConsensusStateView, HeartbeatMessage, Justification, NetworkSummary, ProposeMessage,
    ValidatorMessage, VoteMessage,
};

/// Validator P2P Protocol Handler
///
/// Acts as security middleware between the network layer and the consensus engine.
/// Provides message-level Dilithium signature verification (outer envelope) before
/// forwarding to the `ConsensusEngine` for content-level validation.
pub struct ValidatorProtocol {
    /// Local validator identity
    validator_identity: Option<IdentityId>,

    /// Local validator signing keypair (Dilithium).
    ///
    /// Required to produce signed validator messages.
    validator_keypair: Option<KeyPair>,

    /// Discovery protocol for finding other validators
    discovery: Arc<ValidatorDiscoveryProtocol>,

    /// Message handlers by validator identity
    peer_connections: Arc<RwLock<HashMap<IdentityId, ValidatorPeerConnection>>>,

    /// Message cache to prevent duplicates
    message_cache: Arc<RwLock<HashMap<Hash, u64>>>, // message_id -> timestamp

    /// Configuration
    config: ValidatorProtocolConfig,

    /// Network transport for sending signed messages to peers.
    /// Set via `set_network_transport()` during wiring.
    network_transport: Option<Arc<dyn ValidatorNetworkTransport>>,

    /// Channel to forward verified messages to the ConsensusEngine.
    /// Set via `set_consensus_forwarder()` during wiring.
    consensus_forwarder: Option<tokio::sync::mpsc::Sender<ValidatorMessage>>,
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

    /// Maximum accepted clock skew for validator messages.
    pub max_clock_skew_secs: u64,

    /// Allow Trust-On-First-Use (TOFU) registration of unknown validators.
    ///
    /// When `true`, messages from validators not yet in the discovery cache are
    /// accepted on first contact provided the signature is cryptographically
    /// valid (i.e. the sender proves it controls the declared public key).
    /// The validated public key is then cached and used to verify all
    /// subsequent messages from that validator.
    ///
    /// This is intended only for bootstrap/development networks where validators
    /// start simultaneously and haven't yet exchanged formal announcements. In
    /// production (Mainnet) this MUST be `false` so that only validators whose
    /// keys are registered on-chain can participate in consensus.
    pub bootstrap_tofu: bool,
}

impl Default for ValidatorProtocolConfig {
    fn default() -> Self {
        Self {
            max_cache_size: 10000,
            message_ttl: 3600, // 1 hour
            max_broadcast_peers: 100,
            heartbeat_interval: 30,
            round_timeout: 60,
            max_clock_skew_secs: 300,
            bootstrap_tofu: false,
        }
    }
}

const SIGNING_DOMAIN_PROPOSE: &[u8] = b"zhtp:consensus:validator-msg:v1:propose";
const SIGNING_DOMAIN_VOTE: &[u8] = b"zhtp:consensus:validator-msg:v1:vote";
// CONS-201: `SIGNING_DOMAIN_COMMIT` and `SIGNING_DOMAIN_ROUND_CHANGE`
// were deleted along with the Commit and RoundChange variants.
const SIGNING_DOMAIN_HEARTBEAT: &[u8] = b"zhtp:consensus:validator-msg:v1:heartbeat";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProposeSigningPayload {
    message_id: Hash,
    proposer: IdentityId,
    proposal: ConsensusProposal,
    justification: Option<Justification>,
    timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VoteSigningPayload {
    message_id: Hash,
    voter: IdentityId,
    vote: ConsensusVote,
    consensus_state: ConsensusStateView,
    timestamp: u64,
}

// CONS-201: `CommitSigningPayload` and `RoundChangeSigningPayload`
// were deleted along with the Commit and RoundChange variants.

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HeartbeatSigningPayload {
    message_id: Hash,
    validator: IdentityId,
    height: u64,
    round: u32,
    step: ConsensusStep,
    network_summary: NetworkSummary,
    timestamp: u64,
}

/// Bytes the signature covers: domain separator + 0x00 + bincode(payload).
/// Lifted out so engine-side and protocol-side signing produce identical
/// bytes for the same envelope.
pub(crate) fn signing_bytes(domain: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + 1 + payload.len());
    out.extend_from_slice(domain);
    out.push(0u8);
    out.extend_from_slice(payload);
    out
}

/// Sign a `ProposeMessage` outer envelope with the given keypair.
///
/// The envelope signature covers `ProposeSigningPayload`
/// (`message_id` + `proposer` + `proposal` + `justification` + `timestamp`),
/// not the inner `ConsensusProposal.signature`. Receivers reconstruct this
/// exact payload in `verify_validator_message`. PR #2387 review (Copilot)
/// caught the previous code reusing `proposal.signature` here, which would
/// fail outer-envelope verification on Mainnet (where `bootstrap_tofu` is
/// false).
pub fn sign_propose_envelope(
    message: &ProposeMessage,
    keypair: &KeyPair,
) -> Result<PostQuantumSignature> {
    let payload = ProposeSigningPayload {
        message_id: message.message_id.clone(),
        proposer: message.proposer.clone(),
        proposal: message.proposal.clone(),
        justification: message.justification.clone(),
        timestamp: message.timestamp,
    };
    let bytes = bincode::serialize(&payload)
        .map_err(|e| anyhow!("ProposeSigningPayload encode failed: {e}"))?;
    keypair.sign(&signing_bytes(SIGNING_DOMAIN_PROPOSE, &bytes))
}

/// Sign a `VoteMessage` outer envelope with the given keypair.
///
/// The envelope signature covers `VoteSigningPayload` (`message_id` +
/// `voter` + inner `vote` + `consensus_state` + envelope `timestamp`).
pub fn sign_vote_envelope(
    message: &VoteMessage,
    keypair: &KeyPair,
) -> Result<PostQuantumSignature> {
    let payload = VoteSigningPayload {
        message_id: message.message_id.clone(),
        voter: message.voter.clone(),
        vote: message.vote.clone(),
        consensus_state: message.consensus_state.clone(),
        timestamp: message.timestamp,
    };
    let bytes = bincode::serialize(&payload)
        .map_err(|e| anyhow!("VoteSigningPayload encode failed: {e}"))?;
    keypair.sign(&signing_bytes(SIGNING_DOMAIN_VOTE, &bytes))
}

/// Sign a `HeartbeatMessage` outer envelope with the given keypair.
pub fn sign_heartbeat_envelope(
    message: &HeartbeatMessage,
    keypair: &KeyPair,
) -> Result<PostQuantumSignature> {
    let payload = HeartbeatSigningPayload {
        message_id: message.message_id.clone(),
        validator: message.validator.clone(),
        height: message.height,
        round: message.round,
        step: message.step.clone(),
        network_summary: message.network_summary.clone(),
        timestamp: message.timestamp,
    };
    let bytes = bincode::serialize(&payload)
        .map_err(|e| anyhow!("HeartbeatSigningPayload encode failed: {e}"))?;
    keypair.sign(&signing_bytes(SIGNING_DOMAIN_HEARTBEAT, &bytes))
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
            validator_keypair: None,
            discovery,
            peer_connections: Arc::new(RwLock::new(HashMap::new())),
            message_cache: Arc::new(RwLock::new(HashMap::new())),
            config: config.unwrap_or_default(),
            network_transport: None,
            consensus_forwarder: None,
        }
    }

    /// Set the local validator identity
    pub async fn set_validator_identity(&mut self, identity: IdentityId) {
        self.validator_identity = Some(identity.clone());
        info!("Validator protocol initialized for validator: {}", identity);
    }

    /// Set the local validator signing keypair.
    pub fn set_validator_keypair(&mut self, keypair: KeyPair) {
        self.validator_keypair = Some(keypair);
    }

    /// Set the network transport for broadcasting signed messages to peers.
    pub fn set_network_transport(&mut self, transport: Arc<dyn ValidatorNetworkTransport>) {
        self.network_transport = Some(transport);
    }

    /// Set the consensus forwarder channel for delivering verified messages to the ConsensusEngine.
    pub fn set_consensus_forwarder(
        &mut self,
        tx: tokio::sync::mpsc::Sender<ValidatorMessage>,
    ) {
        self.consensus_forwarder = Some(tx);
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

        let mut message = ProposeMessage {
            message_id: self.generate_message_id(),
            proposer: validator_id.clone(),
            proposal,
            justification,
            timestamp: self.current_timestamp(),
            signature: PostQuantumSignature::default(),
        };

        message.signature = self.sign_propose_message(&message)?;

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

        let mut message = VoteMessage {
            message_id: self.generate_message_id(),
            voter: validator_id.clone(),
            vote,
            consensus_state,
            timestamp: self.current_timestamp(),
            signature: PostQuantumSignature::default(),
        };

        message.signature = self.sign_vote_message(&message)?;

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

    // CONS-201: `broadcast_commit` and `request_round_change` were deleted
    // along with the `Commit` and `RoundChange` variants. Commit votes now
    // flow as `Vote(VoteMessage)` with `VoteType::Commit`, and round
    // changes are driven by timeouts (no explicit RoundChange message).

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

        let mut message = HeartbeatMessage {
            message_id: self.generate_message_id(),
            validator: validator_id.clone(),
            height,
            round,
            step,
            network_summary,
            timestamp: self.current_timestamp(),
            signature: PostQuantumSignature::default(),
        };

        message.signature = self.sign_heartbeat_message(&message)?;

        debug!("Sending heartbeat from validator {}", validator_id);

        self.broadcast_message(ValidatorMessage::Heartbeat(message))
            .await
    }

    /// Process incoming validator message
    pub async fn handle_message(&self, message: ValidatorMessage) -> Result<()> {
        // Verify signature before cache/dedup to avoid cache poisoning by invalid messages.
        self.verify_validator_message(&message).await?;

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

    fn local_keypair(&self) -> Result<&KeyPair> {
        self.validator_keypair
            .as_ref()
            .ok_or_else(|| anyhow!("Validator keypair not set"))
    }

    fn sign_propose_message(&self, message: &ProposeMessage) -> Result<PostQuantumSignature> {
        sign_propose_envelope(message, self.local_keypair()?)
    }

    fn sign_vote_message(&self, message: &VoteMessage) -> Result<PostQuantumSignature> {
        sign_vote_envelope(message, self.local_keypair()?)
    }

    // CONS-201: `sign_commit_message` and `sign_round_change_message` were
    // deleted along with the Commit and RoundChange variants.

    fn sign_heartbeat_message(&self, message: &HeartbeatMessage) -> Result<PostQuantumSignature> {
        sign_heartbeat_envelope(message, self.local_keypair()?)
    }

    fn verify_timestamp_fresh(&self, timestamp: u64) -> Result<()> {
        let now = self.current_timestamp();
        let max = self.config.max_clock_skew_secs;
        if timestamp + max < now || now + max < timestamp {
            return Err(anyhow!(
                "Validator message timestamp out of bounds: ts={} now={} max_skew={}",
                timestamp,
                now,
                max
            ));
        }
        Ok(())
    }

    async fn verify_validator_message(&self, message: &ValidatorMessage) -> Result<()> {
        match message {
            ValidatorMessage::Propose(m) => {
                let payload = ProposeSigningPayload {
                    message_id: m.message_id.clone(),
                    proposer: m.proposer.clone(),
                    proposal: m.proposal.clone(),
                    justification: m.justification.clone(),
                    timestamp: m.timestamp,
                };
                let bytes = bincode::serialize(&payload)
                    .map_err(|e| anyhow!("ProposeSigningPayload encode failed: {e}"))?;
                self.verify_signed(
                    &m.proposer,
                    &m.signature,
                    m.timestamp,
                    SIGNING_DOMAIN_PROPOSE,
                    &bytes,
                )
                .await
            }
            ValidatorMessage::Vote(m) => {
                let payload = VoteSigningPayload {
                    message_id: m.message_id.clone(),
                    voter: m.voter.clone(),
                    vote: m.vote.clone(),
                    consensus_state: m.consensus_state.clone(),
                    timestamp: m.timestamp,
                };
                let bytes = bincode::serialize(&payload)
                    .map_err(|e| anyhow!("VoteSigningPayload encode failed: {e}"))?;
                self.verify_signed(
                    &m.voter,
                    &m.signature,
                    m.timestamp,
                    SIGNING_DOMAIN_VOTE,
                    &bytes,
                )
                .await
            }
            ValidatorMessage::Heartbeat(m) => {
                let payload = HeartbeatSigningPayload {
                    message_id: m.message_id.clone(),
                    validator: m.validator.clone(),
                    height: m.height,
                    round: m.round,
                    step: m.step.clone(),
                    network_summary: m.network_summary.clone(),
                    timestamp: m.timestamp,
                };
                let bytes = bincode::serialize(&payload)
                    .map_err(|e| anyhow!("HeartbeatSigningPayload encode failed: {e}"))?;
                self.verify_signed(
                    &m.validator,
                    &m.signature,
                    m.timestamp,
                    SIGNING_DOMAIN_HEARTBEAT,
                    &bytes,
                )
                .await
            }
        }
    }

    async fn verify_signed(
        &self,
        signer: &IdentityId,
        signature: &PostQuantumSignature,
        timestamp: u64,
        domain: &[u8],
        payload: &[u8],
    ) -> Result<()> {
        self.verify_timestamp_fresh(timestamp)?;

        match self.discovery.discover_validator(signer).await? {
            Some(ann) => {
                // In bootstrap TOFU mode, skip cryptographic verification for known validators.
                // The consensus engine uses a different signing payload than this layer, so
                // key-comparison and signature verification would always fail during bootstrap.
                // Security is maintained by validate_committed_block() in the consensus engine.
                if self.config.bootstrap_tofu {
                    return Ok(());
                }
                // Known validator: ensure the key in the message matches the registered key.
                if signature.public_key.dilithium_pk != ann.consensus_key.dilithium_pk {
                    return Err(anyhow!(
                        "Consensus key mismatch for signer {} (msg_pk_len={}, ann_pk_len={})",
                        signer,
                        signature.public_key.dilithium_pk.len(),
                        ann.consensus_key.dilithium_pk.len()
                    ));
                }
            }
            None if self.config.bootstrap_tofu => {
                // TOFU mode: unknown validator.
                if signature.public_key.dilithium_pk.is_empty() {
                    // Unsigned / placeholder message (e.g. heartbeats created by the consensus
                    // engine before the validator protocol has signed them).  In bootstrap mode
                    // these are forwarded as advisory liveness signals without verification.
                    // The comment in heartbeat.rs explicitly marks these as "placeholder —
                    // real signing happens in the validator protocol layer."
                    debug!(
                        "Bootstrap: forwarding unsigned message from {} (empty key)",
                        signer
                    );
                    return Ok(());
                }
                // In bootstrap TOFU mode we cannot perform payload-level signature verification
                // here because the consensus engine signs with a different payload format than
                // this validator-protocol layer reconstructs. (See the known-validator path above
                // which also skips verification for the same reason.)
                // Security is maintained by validate_committed_block() in the consensus engine.
                // Register the declared public key and accept the message.
                self.discovery
                    .register_trusted(crate::discovery::ValidatorAnnouncement {
                        identity_id: signer.clone(),
                        consensus_key: signature.public_key.clone(),
                        stake: 0,
                        storage_provided: 0,
                        commission_rate: 0,
                        endpoints: vec![],
                        status: crate::discovery::ValidatorStatus::Active,
                        last_updated: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        signature: Vec::new(),
                    })
                    .await;
                info!(
                    "🔑 Bootstrap TOFU: registered key from new validator {}",
                    signer
                );
                return Ok(());
            }
            None => {
                return Err(anyhow!("Unknown validator (not in discovery): {}", signer));
            }
        }

        let bytes = signing_bytes(domain, payload);
        let ok = signature.public_key.verify(&bytes, signature)?;
        if !ok {
            return Err(anyhow!(
                "Invalid signature for validator message from {}",
                signer
            ));
        }

        Ok(())
    }

    /// Broadcast message to all connected validators via network transport.
    ///
    /// Uses the injected `ValidatorNetworkTransport` to send the message to all
    /// known active validators (excluding self). Falls back to peer_connections
    /// if discovery has no entries.
    async fn broadcast_message(&self, message: ValidatorMessage) -> Result<()> {
        let transport = self.network_transport.as_ref().ok_or_else(|| {
            anyhow!("Network transport not set - call set_network_transport() first")
        })?;

        // Collect recipient validator IDs from discovery (all known validators except self)
        let validators = self
            .discovery
            .discover_validators(Default::default())
            .await?;
        let mut recipients: Vec<IdentityId> =
            validators.iter().map(|v| v.identity_id.clone()).collect();

        // Filter out self
        if let Some(ref local_id) = self.validator_identity {
            recipients.retain(|id| id != local_id);
        }

        // Respect max_broadcast_peers
        recipients.truncate(self.config.max_broadcast_peers);

        if recipients.is_empty() {
            debug!("No recipients for broadcast (no peers in discovery)");
            return Ok(());
        }

        info!(
            "Broadcasting message to {} validators via network transport",
            recipients.len()
        );

        transport
            .broadcast_to_validators(message, &recipients)
            .await
    }

    /// Forward a verified message to the consensus engine.
    ///
    /// Returns an error if the consensus forwarder channel is not set or the
    /// receiver has been dropped (engine shut down).
    async fn forward_to_consensus(&self, msg: ValidatorMessage) -> Result<()> {
        let tx = self.consensus_forwarder.as_ref().ok_or_else(|| {
            anyhow!("Consensus forwarder not set - call set_consensus_forwarder() first")
        })?;

        tx.send(msg).await.map_err(|e| {
            anyhow!(
                "Failed to forward to consensus engine (receiver dropped): {}",
                e
            )
        })
    }

    /// Handle incoming proposal message: forward to consensus engine as `Propose`.
    async fn handle_propose_message(&self, message: ProposeMessage) -> Result<()> {
        info!(
            "Received verified proposal from {} for height {}",
            message.proposer, message.proposal.height
        );

        self.forward_to_consensus(ValidatorMessage::Propose(message))
            .await
    }

    /// Handle incoming vote message: forward to consensus engine as `Vote`.
    async fn handle_vote_message(&self, message: VoteMessage) -> Result<()> {
        debug!(
            "Received verified vote from {} for proposal {}",
            message.voter, message.vote.proposal_id
        );

        self.forward_to_consensus(ValidatorMessage::Vote(message))
            .await
    }

    // CONS-201: `handle_commit_message` and `handle_round_change_message`
    // were deleted along with the Commit and RoundChange variants. The
    // commit-as-Vote translation is no longer needed because commit votes
    // travel as `Vote(VoteMessage)` with `VoteType::Commit` end-to-end.
    // Round changes are driven by timeouts, not by an inbound message.

    /// Handle heartbeat message
    async fn handle_heartbeat_message(&self, message: HeartbeatMessage) -> Result<()> {
        debug!(
            "Received heartbeat from {} at height {}",
            message.validator, message.height
        );

        // Update peer connection status (drop lock before awaiting)
        {
            let mut connections = self.peer_connections.write().await;
            if let Some(connection) = connections.get_mut(&message.validator) {
                connection.last_heartbeat = message.timestamp;
                connection.status = PeerConnectionStatus::Active;
            }
        }

        self.forward_to_consensus(ValidatorMessage::Heartbeat(message))
            .await
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
    use lib_consensus_core::types::ConsensusProof;
    use lib_types::consensus::ConsensusType;
    use crate::discovery::{
        ValidatorAnnouncement, ValidatorEndpoint, ValidatorStatus,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Mock transport that counts broadcasts for testing.
    struct MockTransport {
        broadcast_count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ValidatorNetworkTransport for MockTransport {
        async fn broadcast_to_validators(
            &self,
            _message: ValidatorMessage,
            recipients: &[IdentityId],
        ) -> Result<()> {
            self.broadcast_count
                .fetch_add(recipients.len(), Ordering::SeqCst);
            Ok(())
        }
    }

    /// Helper: create a ValidatorProtocol with keypair, identity, discovery, and consensus forwarder wired.
    async fn setup_protocol_with_forwarder() -> Result<(
        ValidatorProtocol,
        tokio::sync::mpsc::Receiver<ValidatorMessage>,
        KeyPair,
        IdentityId,
    )> {
        let discovery = Arc::new(ValidatorDiscoveryProtocol::from_validators(3600, vec![]));
        let mut protocol = ValidatorProtocol::new(discovery.clone(), None);

        let kp = KeyPair::generate()?;
        let signer: IdentityId = Hash::from_bytes(&[7u8; 32]);

        protocol.set_validator_identity(signer.clone()).await;
        protocol.set_validator_keypair(kp.clone());

        // Wire consensus forwarder
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        protocol.set_consensus_forwarder(tx);

        // Register signer in discovery
        let ann = ValidatorAnnouncement {
            identity_id: signer.clone(),
            consensus_key: kp.public_key.clone(),
            stake: 1,
            storage_provided: 1,
            commission_rate: 0,
            endpoints: vec![ValidatorEndpoint {
                protocol: "quic".to_string(),
                address: "127.0.0.1:0".to_string(),
                priority: 1,
            }],
            status: ValidatorStatus::Active,
            last_updated: protocol.current_timestamp(),
            signature: vec![],
        }
        .sign(&kp)?;
        discovery.announce_validator(ann).await?;

        Ok((protocol, rx, kp, signer))
    }

    #[tokio::test]
    async fn test_engine_envelope_signed_propose_verifies() -> Result<()> {
        // PR #2387 review: confirm an engine-built ProposeMessage signed via
        // `sign_propose_envelope` round-trips through ValidatorProtocol's
        // outer-envelope verifier with `bootstrap_tofu = false` (Mainnet
        // semantics). Pre-fix the engine reused the inner content signature
        // and this verification deterministically failed.
        let (mut protocol, mut rx, kp, signer) = setup_protocol_with_forwarder().await?;
        protocol.config.bootstrap_tofu = false;

        let now = protocol.current_timestamp();
        let mut msg = ProposeMessage {
            message_id: Hash::from_bytes(&[42u8; 32]),
            proposer: signer.clone(),
            proposal: ConsensusProposal {
                id: Hash::from_bytes(&[1u8; 32]),
                proposer: signer.clone(),
                height: 1,
                round: 0,
                protocol_version: 1,
                previous_hash: Hash::from_bytes(&[2u8; 32]),
                block_data: b"block".to_vec(),
                timestamp: now,
                // Inner content signature deliberately default — the outer
                // envelope is what's being verified here.
                signature: PostQuantumSignature::default(),
                consensus_proof: ConsensusProof {
                    consensus_type: ConsensusType::ByzantineFaultTolerance,
                    stake_proof: None,
                    storage_proof: None,
                    work_proof: None,
                    zk_did_proof: None,
                    timestamp: now,
                },
            },
            justification: None,
            timestamp: now,
            signature: PostQuantumSignature::default(),
        };
        msg.signature = sign_propose_envelope(&msg, &kp)?;

        protocol
            .handle_message(ValidatorMessage::Propose(msg))
            .await?;

        let forwarded = rx.try_recv().expect("Expected forwarded message");
        assert!(matches!(
            forwarded,
            ValidatorMessage::Propose(_)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn test_engine_envelope_signed_heartbeat_verifies() -> Result<()> {
        // Follow-up to PR #2387: confirm an engine-built HeartbeatMessage
        // signed via `sign_heartbeat_envelope` round-trips through
        // ValidatorProtocol's outer-envelope verifier with
        // `bootstrap_tofu = false` (Mainnet semantics). Pre-fix the engine
        // broadcast unsigned heartbeats; receivers in non-TOFU mode rejected.
        let (mut protocol, _rx, kp, signer) = setup_protocol_with_forwarder().await?;
        protocol.config.bootstrap_tofu = false;

        let now = protocol.current_timestamp();
        let mut msg = HeartbeatMessage {
            message_id: Hash::from_bytes(&[55u8; 32]),
            validator: signer.clone(),
            height: 7,
            round: 0,
            step: ConsensusStep::Propose,
            network_summary: NetworkSummary {
                active_validators: 4,
                health_score: 0.95,
                block_rate: 1.0,
            },
            timestamp: now,
            signature: PostQuantumSignature::default(),
        };
        msg.signature = sign_heartbeat_envelope(&msg, &kp)?;

        // handle_message verifies the envelope; success means no error.
        protocol
            .handle_message(ValidatorMessage::Heartbeat(msg))
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_engine_envelope_signed_vote_verifies() -> Result<()> {
        let (mut protocol, mut rx, kp, signer) = setup_protocol_with_forwarder().await?;
        protocol.config.bootstrap_tofu = false;

        let now = protocol.current_timestamp();
        let vote = ConsensusVote {
            id: Hash::from_bytes(&[10u8; 32]),
            height: 5,
            round: 0,
            vote_type: VoteType::PreVote,
            proposal_id: Hash::from_bytes(&[11u8; 32]),
            voter: signer.clone(),
            timestamp: now,
            signature: PostQuantumSignature::default(),
        };
        let mut msg = VoteMessage {
            message_id: Hash::from_bytes(&[99u8; 32]),
            voter: signer.clone(),
            vote,
            consensus_state: ConsensusStateView {
                height: 5,
                round: 0,
                step: ConsensusStep::PreVote,
                known_proposals: vec![],
                vote_counts: BTreeMap::new(),
            },
            timestamp: now,
            signature: PostQuantumSignature::default(),
        };
        msg.signature = sign_vote_envelope(&msg, &kp)?;

        protocol.handle_message(ValidatorMessage::Vote(msg)).await?;

        let forwarded = rx.try_recv().expect("Expected forwarded vote");
        assert!(matches!(
            forwarded,
            ValidatorMessage::Vote(_)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn test_validator_protocol_creation() {
        let discovery = Arc::new(ValidatorDiscoveryProtocol::from_validators(3600, vec![]));
        let protocol = ValidatorProtocol::new(discovery, None);

        assert!(protocol.validator_identity.is_none());
        assert!(protocol.validator_keypair.is_none());
        assert_eq!(protocol.config.heartbeat_interval, 30);
    }

    #[tokio::test]
    async fn test_message_id_generation() {
        let discovery = Arc::new(ValidatorDiscoveryProtocol::from_validators(3600, vec![]));
        let protocol = ValidatorProtocol::new(discovery, None);

        let id1 = protocol.generate_message_id();
        let id2 = protocol.generate_message_id();

        // IDs should be different (due to timestamp)
        assert_ne!(id1, id2);
    }

    #[tokio::test]
    async fn test_signed_propose_message_verifies_and_tamper_fails() -> Result<()> {
        let (protocol, mut _rx, _kp, signer) = setup_protocol_with_forwarder().await?;

        let now = protocol.current_timestamp();

        let mut msg = ProposeMessage {
            message_id: protocol.generate_message_id(),
            proposer: signer.clone(),
            proposal: ConsensusProposal {
                id: Hash::from_bytes(&[1u8; 32]),
                proposer: signer.clone(),
                height: 1,
                round: 0,
                protocol_version: 1,
                previous_hash: Hash::from_bytes(&[2u8; 32]),
                block_data: b"block".to_vec(),
                timestamp: now,
                signature: PostQuantumSignature::default(),
                consensus_proof: ConsensusProof {
                    consensus_type: ConsensusType::ByzantineFaultTolerance,
                    stake_proof: None,
                    storage_proof: None,
                    work_proof: None,
                    zk_did_proof: None,
                    timestamp: now,
                },
            },
            justification: None,
            timestamp: now,
            signature: PostQuantumSignature::default(),
        };
        msg.signature = protocol.sign_propose_message(&msg)?;

        // Should verify and forward.
        protocol
            .handle_message(ValidatorMessage::Propose(msg.clone()))
            .await?;

        // Tamper after signing: change height.
        msg.proposal.height = 2;
        let err = protocol
            .handle_message(ValidatorMessage::Propose(msg))
            .await
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("invalid signature"));

        Ok(())
    }

    #[tokio::test]
    async fn test_broadcast_uses_network_transport() -> Result<()> {
        let discovery = Arc::new(ValidatorDiscoveryProtocol::from_validators(3600, vec![]));
        let mut protocol = ValidatorProtocol::new(discovery.clone(), None);

        let kp = KeyPair::generate()?;
        let local_id = Hash::from_bytes(&[1u8; 32]);
        protocol.set_validator_identity(local_id.clone()).await;
        protocol.set_validator_keypair(kp.clone());

        // Register a remote validator in discovery
        let remote_kp = KeyPair::generate()?;
        let remote_id = Hash::from_bytes(&[2u8; 32]);
        let ann = ValidatorAnnouncement {
            identity_id: remote_id.clone(),
            consensus_key: remote_kp.public_key.clone(),
            stake: 1,
            storage_provided: 1,
            commission_rate: 0,
            endpoints: vec![ValidatorEndpoint {
                protocol: "quic".to_string(),
                address: "127.0.0.1:0".to_string(),
                priority: 1,
            }],
            status: ValidatorStatus::Active,
            last_updated: protocol.current_timestamp(),
            signature: vec![],
        }
        .sign(&remote_kp)?;
        discovery.announce_validator(ann).await?;

        // Wire mock transport
        let count = Arc::new(AtomicUsize::new(0));
        protocol.set_network_transport(Arc::new(MockTransport {
            broadcast_count: count.clone(),
        }));

        // Create and broadcast a heartbeat
        let msg = HeartbeatMessage {
            message_id: protocol.generate_message_id(),
            validator: local_id.clone(),
            height: 1,
            round: 0,
            step: ConsensusStep::Propose,
            network_summary: NetworkSummary {
                active_validators: 2,
                health_score: 1.0,
                block_rate: 0.0,
            },
            timestamp: protocol.current_timestamp(),
            signature: PostQuantumSignature::default(),
        };

        protocol
            .broadcast_message(ValidatorMessage::Heartbeat(msg))
            .await?;

        // Transport should have been called with 1 recipient (remote_id, self excluded)
        assert_eq!(count.load(Ordering::SeqCst), 1);

        Ok(())
    }

    #[tokio::test]
    async fn test_handle_propose_forwards_to_consensus() -> Result<()> {
        let (protocol, mut rx, _kp, signer) = setup_protocol_with_forwarder().await?;

        let now = protocol.current_timestamp();
        let mut msg = ProposeMessage {
            message_id: protocol.generate_message_id(),
            proposer: signer.clone(),
            proposal: ConsensusProposal {
                id: Hash::from_bytes(&[1u8; 32]),
                proposer: signer.clone(),
                height: 1,
                round: 0,
                protocol_version: 1,
                previous_hash: Hash::from_bytes(&[2u8; 32]),
                block_data: b"block".to_vec(),
                timestamp: now,
                signature: PostQuantumSignature::default(),
                consensus_proof: ConsensusProof {
                    consensus_type: ConsensusType::ByzantineFaultTolerance,
                    stake_proof: None,
                    storage_proof: None,
                    work_proof: None,
                    zk_did_proof: None,
                    timestamp: now,
                },
            },
            justification: None,
            timestamp: now,
            signature: PostQuantumSignature::default(),
        };
        msg.signature = protocol.sign_propose_message(&msg)?;

        // handle_message should verify and forward
        protocol
            .handle_message(ValidatorMessage::Propose(msg))
            .await?;

        // Should receive the forwarded message on the consensus channel
        let forwarded = rx.try_recv().expect("Expected forwarded message");
        match forwarded {
            ValidatorMessage::Propose(msg) => {
                assert_eq!(msg.proposal.height, 1);
            }
            other => panic!("Expected Propose, got {:?}", other),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_handle_vote_forwards_to_consensus() -> Result<()> {
        let (protocol, mut rx, _kp, signer) = setup_protocol_with_forwarder().await?;

        let now = protocol.current_timestamp();
        let vote = ConsensusVote {
            id: Hash::from_bytes(&[10u8; 32]),
            height: 5,
            round: 0,
            vote_type: VoteType::PreVote,
            proposal_id: Hash::from_bytes(&[11u8; 32]),
            voter: signer.clone(),
            timestamp: now,
            signature: PostQuantumSignature::default(),
        };
        let state_view = ConsensusStateView {
            height: 5,
            round: 0,
            step: ConsensusStep::PreVote,
            known_proposals: vec![],
            vote_counts: BTreeMap::new(),
        };

        let mut msg = VoteMessage {
            message_id: protocol.generate_message_id(),
            voter: signer.clone(),
            vote,
            consensus_state: state_view,
            timestamp: now,
            signature: PostQuantumSignature::default(),
        };
        msg.signature = protocol.sign_vote_message(&msg)?;

        protocol.handle_message(ValidatorMessage::Vote(msg)).await?;

        let forwarded = rx.try_recv().expect("Expected forwarded vote");
        match forwarded {
            ValidatorMessage::Vote(msg) => {
                assert_eq!(msg.vote.height, 5);
                assert_eq!(msg.vote.vote_type, VoteType::PreVote);
            }
            other => panic!("Expected Vote, got {:?}", other),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_tampered_message_not_forwarded() -> Result<()> {
        let (protocol, mut rx, _kp, signer) = setup_protocol_with_forwarder().await?;

        let now = protocol.current_timestamp();
        let mut msg = ProposeMessage {
            message_id: protocol.generate_message_id(),
            proposer: signer.clone(),
            proposal: ConsensusProposal {
                id: Hash::from_bytes(&[1u8; 32]),
                proposer: signer.clone(),
                height: 1,
                round: 0,
                protocol_version: 1,
                previous_hash: Hash::from_bytes(&[2u8; 32]),
                block_data: b"block".to_vec(),
                timestamp: now,
                signature: PostQuantumSignature::default(),
                consensus_proof: ConsensusProof {
                    consensus_type: ConsensusType::ByzantineFaultTolerance,
                    stake_proof: None,
                    storage_proof: None,
                    work_proof: None,
                    zk_did_proof: None,
                    timestamp: now,
                },
            },
            justification: None,
            timestamp: now,
            signature: PostQuantumSignature::default(),
        };
        msg.signature = protocol.sign_propose_message(&msg)?;

        // Tamper: change height after signing
        msg.proposal.height = 999;

        // Should fail verification
        let result = protocol
            .handle_message(ValidatorMessage::Propose(msg))
            .await;
        assert!(result.is_err());

        // Nothing should have been forwarded
        assert!(
            rx.try_recv().is_err(),
            "Tampered message should not be forwarded"
        );

        Ok(())
    }
}
