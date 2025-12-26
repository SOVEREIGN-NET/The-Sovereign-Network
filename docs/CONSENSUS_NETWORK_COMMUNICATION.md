# Consensus-Network Communication Gap Analysis

**Status**: ⏳ 40% Complete
**Component**: lib-consensus ↔ lib-network
**Priority**: CRITICAL (blocking mainnet deployment)

---

## Executive Summary

The consensus protocol currently **lacks peer-to-peer message distribution infrastructure**. The consensus engine can perform BFT voting internally but has no mechanism to broadcast proposals, votes, or blocks to validator nodes across the network, nor can it receive messages from peers.

---

## Current State

### What Works
✅ Internal BFT voting algorithm (4-phase voting)
✅ Message deserialization (from `types::ConsensusMessage`)
✅ Signature verification using Dilithium
✅ Voting power calculation
✅ Round progression logic
✅ Validator state management (registration, stake tracking)

### What's Missing
❌ Peer-to-peer message broadcasting
❌ Message gossip/propagation across validator network
❌ Validator discovery and peer management
❌ Vote aggregation from remote validators
❌ Proposal distribution to all validators
❌ Heartbeat/liveness detection
❌ Network-level Byzantine fault detection
❌ Connection management to validator nodes
❌ Message routing and relay logic
❌ Network partition handling

---

## Gap 1: Peer-to-Peer Message Broadcasting

### Problem
Currently, consensus produces votes and proposals internally but never sends them to other validators. The BFT algorithm assumes message delivery happens magically, but there's no actual network layer.

```rust
// Current: Vote is computed but never broadcast
let vote = ConsensusMessage::PreVote {
    round: self.current_round,
    block_hash: proposed_hash,
    validator_id: self.validator_id.clone(),
    signature: signature,
};

// Needed: Actually send to network
// network.broadcast_message(vote, EXCEPT_SELF).await?;
```

### What's Needed

#### 1.1 Message Distribution Trait
```rust
// In lib-network or new lib-consensus
pub trait MessageBroadcaster: Send + Sync {
    /// Broadcast message to all validators except self
    async fn broadcast_to_validators(
        &self,
        message: ConsensusMessage,
    ) -> Result<()>;

    /// Send message to specific validator
    async fn send_to_validator(
        &self,
        validator_id: &ValidatorId,
        message: ConsensusMessage,
    ) -> Result<()>;

    /// Broadcast block proposal to all validators
    async fn broadcast_proposal(
        &self,
        proposal: BlockProposal,
    ) -> Result<()>;

    /// Get number of connected validators
    fn connected_validator_count(&self) -> usize;

    /// Check if validator is reachable
    async fn is_validator_reachable(&self, validator_id: &ValidatorId) -> Result<bool>;
}
```

#### 1.2 Message Serialization & Framing
Ensure ConsensusMessage can be reliably transmitted:
```rust
pub trait ConsensusMessageCodec: Send + Sync {
    /// Serialize consensus message for network transmission
    fn encode(&self, msg: &ConsensusMessage) -> Result<Vec<u8>>;

    /// Deserialize message from network bytes
    fn decode(&self, bytes: &[u8]) -> Result<ConsensusMessage>;

    /// Frame message for streaming (add length prefix for framing)
    fn frame(&self, encoded: &[u8]) -> Result<Vec<u8>>;

    /// Unframe message from stream
    fn unframe(&self, framed: &[u8]) -> Result<(ConsensusMessage, usize)>;
}
```

#### 1.3 Encryption for Consensus Messages
All peer-to-peer consensus messages must be encrypted:
```rust
pub trait ConsensusMessageEncryption: Send + Sync {
    /// Encrypt message using validator's session key
    async fn encrypt(
        &self,
        message: &ConsensusMessage,
        peer_validator_id: &ValidatorId,
    ) -> Result<Vec<u8>>;

    /// Decrypt incoming message from peer
    async fn decrypt(
        &self,
        encrypted_bytes: &[u8],
        peer_validator_id: &ValidatorId,
    ) -> Result<ConsensusMessage>;
}
```

### Integration Points

**In `consensus_engine.rs` when voting:**
```rust
// Phase 2: PreVote - broadcast to network
async fn handle_pre_vote_phase(&mut self) -> Result<()> {
    let vote = self.create_pre_vote()?;

    // Before: vote exists only locally
    // After: broadcast to all validators
    self.broadcaster.broadcast_to_validators(
        ConsensusMessage::PreVote(vote)
    ).await?;

    // Update internal state
    self.votes.add_vote(vote)?;
    Ok(())
}

// Phase 3: PreCommit - broadcast commitment
async fn handle_pre_commit_phase(&mut self) -> Result<()> {
    let pre_commit = self.create_pre_commit()?;

    // Broadcast to network
    self.broadcaster.broadcast_to_validators(
        ConsensusMessage::PreCommit(pre_commit)
    ).await?;

    self.votes.add_vote(pre_commit)?;
    Ok(())
}
```

**In proposer when creating block proposal:**
```rust
async fn propose_block(&mut self) -> Result<()> {
    // Create block proposal
    let proposal = BlockProposal {
        height: self.height,
        round: self.current_round,
        block: self.create_block()?,
        proposer_signature: self.sign_proposal()?,
    };

    // Broadcast to all validators
    self.broadcaster.broadcast_proposal(proposal).await?;

    // Store locally for this round
    self.current_proposal = Some(proposal);
    Ok(())
}
```

---

## Gap 2: Message Gossip & Propagation

### Problem
Even if node A sends a message to node B, node C might not receive it. Consensus needs gossip protocol to ensure all validators eventually receive critical messages.

### What's Needed

#### 2.1 Gossip Protocol
```rust
pub trait GossipProtocol: Send + Sync {
    /// Propagate received message to random peers
    async fn gossip(
        &self,
        message: ConsensusMessage,
        exclude_peer: Option<&ValidatorId>,
    ) -> Result<()>;

    /// Get random subset of validators for gossip
    fn select_gossip_peers(&self, count: usize) -> Vec<ValidatorId>;

    /// Track seen messages to prevent re-gossip
    fn mark_message_seen(&mut self, message_hash: Hash256) -> Result<()>;

    /// Check if message was already gossiped
    fn is_message_seen(&self, message_hash: Hash256) -> bool;

    /// Set TTL for message propagation (max hops)
    fn set_message_ttl(&mut self, message_hash: Hash256, ttl: u8) -> Result<()>;
}
```

#### 2.2 Reliable Message Delivery
```rust
pub trait ReliableMessaging: Send + Sync {
    /// Send message with guaranteed delivery
    async fn send_reliable(
        &self,
        validator_id: &ValidatorId,
        message: ConsensusMessage,
    ) -> Result<()>;

    /// Receive acknowledgment of message delivery
    async fn wait_for_ack(
        &self,
        message_id: &Hash256,
        timeout: Duration,
    ) -> Result<()>;

    /// Resend unacknowledged messages periodically
    async fn retransmit_unacked(&mut self) -> Result<()>;

    /// Get delivery status of sent message
    fn get_delivery_status(&self, message_id: &Hash256) -> DeliveryStatus;
}

pub enum DeliveryStatus {
    Pending,
    Delivered,
    Failed,
    TimedOut,
}
```

#### 2.3 Integration in Consensus
```rust
// In consensus_engine.rs
async fn broadcast_to_network(&mut self, message: ConsensusMessage) -> Result<()> {
    // 1. Broadcast directly to all validators
    self.broadcaster.broadcast_to_validators(message.clone()).await?;

    // 2. Start gossip propagation
    self.gossip.gossip(message.clone(), None).await?;

    // 3. Set up reliable delivery with retransmission
    let message_hash = self.hash_message(&message)?;
    self.reliable_messaging.send_reliable(&message_hash).await?;

    Ok(())
}
```

---

## Gap 3: Validator Discovery & Peer Management

### Problem
Consensus has a hardcoded list of validators but no way to discover them on the network, connect to them, or detect when they go offline.

### What's Needed

#### 3.1 Validator Discovery
```rust
pub trait ValidatorDiscovery: Send + Sync {
    /// Discover active validators on network
    async fn discover_validators(&self) -> Result<Vec<ValidatorInfo>>;

    /// Watch for validator set changes
    async fn watch_validator_changes(
        &self,
    ) -> Result<mpsc::Receiver<ValidatorSetChange>>;

    /// Get current validator set with network addresses
    async fn get_validator_addresses(&self) -> Result<HashMap<ValidatorId, PeerAddress>>;

    /// Resolve validator ID to network address
    async fn resolve_validator(
        &self,
        validator_id: &ValidatorId,
    ) -> Result<Option<PeerAddress>>;

    /// Register self as active validator
    async fn register_self(&self, validator_info: ValidatorInfo) -> Result<()>;

    /// Announce validator availability
    async fn announce_availability(&self) -> Result<()>;
}

pub struct ValidatorInfo {
    pub validator_id: ValidatorId,
    pub public_key: PublicKey,
    pub peer_address: PeerAddress,
    pub stake: u64,
    pub status: ValidatorStatus,
    pub last_heartbeat: Instant,
}

pub enum ValidatorSetChange {
    ValidatorJoined(ValidatorId),
    ValidatorLeft(ValidatorId),
    StakeChanged(ValidatorId, u64),
    StatusChanged(ValidatorId, ValidatorStatus),
}
```

#### 3.2 Peer Connection Management
```rust
pub trait PeerConnectionManager: Send + Sync {
    /// Establish connection to validator
    async fn connect_to_validator(&mut self, validator_id: &ValidatorId) -> Result<()>;

    /// Disconnect from validator
    async fn disconnect_from_validator(&mut self, validator_id: &ValidatorId) -> Result<()>;

    /// Check if connected to validator
    fn is_connected(&self, validator_id: &ValidatorId) -> bool;

    /// Get number of active connections
    fn connection_count(&self) -> usize;

    /// Get list of connected validators
    fn connected_validators(&self) -> Vec<ValidatorId>;

    /// Handle connection drop
    async fn on_peer_disconnected(&mut self, validator_id: &ValidatorId) -> Result<()>;

    /// Attempt to reconnect to all validators
    async fn reconnect_all(&mut self) -> Result<()>;
}
```

#### 3.3 Integration in Consensus
```rust
// In consensus_engine.rs initialization
async fn initialize_network(&mut self) -> Result<()> {
    // 1. Discover validators on network
    let validators = self.discovery.discover_validators().await?;

    // 2. Connect to each validator
    for validator in validators {
        if validator.validator_id != self.validator_id {
            self.peer_manager.connect_to_validator(&validator.validator_id).await?;
        }
    }

    // 3. Watch for validator set changes
    let mut changes = self.discovery.watch_validator_changes().await?;
    tokio::spawn(async move {
        while let Some(change) = changes.recv().await {
            match change {
                ValidatorSetChange::ValidatorJoined(id) => {
                    // Try to connect to new validator
                    let _ = self.peer_manager.connect_to_validator(&id).await;
                }
                ValidatorSetChange::ValidatorLeft(id) => {
                    // Disconnect from leaving validator
                    let _ = self.peer_manager.disconnect_from_validator(&id).await;
                }
                _ => {}
            }
        }
    });

    Ok(())
}
```

---

## Gap 4: Vote Aggregation from Remote Validators

### Problem
Consensus only counts votes it generates locally. It never receives votes from other validators, so no consensus is actually reached across the network.

### What's Needed

#### 4.1 Message Reception
```rust
pub trait ConsensusMessageReceiver: Send + Sync {
    /// Receive incoming consensus message from peer
    async fn receive_message(&self) -> Result<IncomingMessage>;

    /// Create message receiver channel
    fn message_channel(&self) -> mpsc::Receiver<IncomingMessage>;

    /// Acknowledge receipt of message to sender
    async fn acknowledge_message(&self, message_id: &Hash256) -> Result<()>;
}

pub struct IncomingMessage {
    pub message: ConsensusMessage,
    pub from_validator_id: ValidatorId,
    pub timestamp: Instant,
    pub message_id: Hash256,
}
```

#### 4.2 Vote Validation & Aggregation
```rust
pub trait RemoteVoteValidator: Send + Sync {
    /// Validate vote from remote validator
    async fn validate_remote_vote(
        &self,
        vote: &Vote,
        from_validator: &ValidatorId,
    ) -> Result<()>;

    /// Check signature from remote validator
    fn verify_validator_signature(
        &self,
        message: &[u8],
        signature: &Signature,
        validator_public_key: &PublicKey,
    ) -> Result<()>;

    /// Aggregate votes into supermajority check
    fn check_supermajority(
        &self,
        votes: &[ValidatorVote],
        total_voting_power: u64,
    ) -> Result<bool>;  // Returns true if 2/3+ voting power
}
```

#### 4.3 Integration in Consensus Message Loop
```rust
// In consensus_engine.rs - new main loop
async fn run_consensus_with_network(&mut self) -> Result<()> {
    let mut message_receiver = self.setup_message_receiver().await?;

    loop {
        tokio::select! {
            // Advance consensus rounds
            _ = self.round_timer.tick() => {
                self.advance_round().await?;
            }

            // Process incoming network messages
            Some(incoming) = message_receiver.recv() => {
                match incoming.message {
                    ConsensusMessage::Proposal(proposal) => {
                        self.handle_remote_proposal(proposal, incoming.from_validator_id).await?;
                    }
                    ConsensusMessage::PreVote(vote) => {
                        // Validate vote signature
                        self.vote_validator.verify_validator_signature(
                            &vote.encode()?,
                            &vote.signature,
                            &self.get_validator_pubkey(&incoming.from_validator_id)?,
                        )?;

                        // Add to vote aggregate
                        self.votes.add_vote(vote)?;

                        // Check if reached supermajority
                        if self.votes.reached_supermajority()? {
                            self.advance_to_next_phase().await?;
                        }
                    }
                    ConsensusMessage::PreCommit(commit) => {
                        // Similar validation and aggregation
                        self.handle_remote_commit(commit, incoming.from_validator_id).await?;
                    }
                    ConsensusMessage::Commit(commit) => {
                        self.handle_remote_commit(commit, incoming.from_validator_id).await?;
                    }
                }

                // Acknowledge receipt
                self.message_receiver.acknowledge_message(&incoming.message_id).await?;
            }
        }
    }
}
```

---

## Gap 5: Heartbeat & Liveness Detection

### Problem
Without heartbeats, consensus can't detect when validators are offline or unreachable, leading to hung rounds and Byzantine faults.

### What's Needed

#### 5.1 Heartbeat Protocol
```rust
pub trait HeartbeatProtocol: Send + Sync {
    /// Send periodic heartbeat to indicate liveness
    async fn send_heartbeat(&self) -> Result<()>;

    /// Receive heartbeat from peer
    async fn receive_heartbeat(&self) -> Result<HeartbeatMessage>;

    /// Check validator liveness
    async fn is_validator_alive(&self, validator_id: &ValidatorId) -> Result<bool>;

    /// Get time since last heartbeat from validator
    fn last_heartbeat_age(&self, validator_id: &ValidatorId) -> Result<Duration>;

    /// Set liveness timeout threshold
    fn set_liveness_timeout(&mut self, timeout: Duration) -> Result<()>;
}

pub struct HeartbeatMessage {
    pub from_validator_id: ValidatorId,
    pub current_round: u32,
    pub current_height: u64,
    pub timestamp: Instant,
}
```

#### 5.2 Liveness Monitoring
```rust
pub trait LivenessMonitor: Send + Sync {
    /// Watch for validator timeouts
    async fn watch_timeouts(&self) -> mpsc::Receiver<ValidatorTimeout>;

    /// Report validator as timed out
    async fn report_timeout(&mut self, validator_id: &ValidatorId) -> Result<()>;

    /// Mark validator as responsive again
    async fn mark_responsive(&mut self, validator_id: &ValidatorId) -> Result<()>;

    /// Get validators currently in timeout
    fn timed_out_validators(&self) -> Vec<ValidatorId>;
}

pub struct ValidatorTimeout {
    pub validator_id: ValidatorId,
    pub reason: TimeoutReason,
    pub duration: Duration,
}

pub enum TimeoutReason {
    NoHeartbeat,
    NoVotes,
    RoundTimeout,
    ConnectionLost,
}
```

#### 5.3 Integration in Consensus
```rust
// In consensus_engine.rs
async fn run_with_liveness_monitoring(&mut self) -> Result<()> {
    let mut timeout_watcher = self.liveness_monitor.watch_timeouts();

    // Heartbeat task
    let heartbeat = self.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3));
        loop {
            interval.tick().await;
            let _ = heartbeat.send_heartbeat().await;
        }
    });

    // Main consensus loop
    loop {
        tokio::select! {
            // Heartbeat timeout for round
            _ = self.round_timeout.tick() => {
                let timed_out = self.liveness_monitor.timed_out_validators();
                if timed_out.len() > (self.validators.len() / 3) {
                    // More than 1/3 are timed out, can't reach consensus
                    warn!("Consensus stalled: {} validators timeout", timed_out.len());
                    // Could trigger leader election or skip to next round
                }
            }

            // Detect validator timeouts
            Some(timeout) = timeout_watcher.recv() => {
                warn!("Validator {} timeout: {:?}", timeout.validator_id, timeout.reason);
                // Could trigger validator slashing or skip their votes
            }
        }
    }
}
```

---

## Gap 6: Network-Level Byzantine Fault Detection

### Problem
Consensus can detect Byzantine behavior in voting, but can't detect or respond to network-level attacks like eclipse attacks or sybil attacks.

### What's Needed

#### 6.1 Network Anomaly Detection
```rust
pub trait ByzantineNetworkDetector: Send + Sync {
    /// Detect network partition (split brain)
    async fn detect_network_partition(&self) -> Result<Option<NetworkPartition>>;

    /// Detect message forgery
    async fn detect_message_forgery(
        &self,
        message: &ConsensusMessage,
        claimed_sender: &ValidatorId,
    ) -> Result<bool>;

    /// Detect equivocation (two conflicting messages from same validator)
    async fn detect_equivocation(
        &self,
        validator_id: &ValidatorId,
    ) -> Result<Option<EquivocationEvidence>>;

    /// Detect replay attacks
    fn detect_replay_attack(&self, message: &ConsensusMessage) -> Result<bool>;

    /// Track message signatures for forensics
    fn record_message_signature(
        &mut self,
        message: &ConsensusMessage,
        signature: &Signature,
    ) -> Result<()>;
}

pub struct NetworkPartition {
    pub side_a: Vec<ValidatorId>,
    pub side_b: Vec<ValidatorId>,
    pub detected_at: Instant,
}

pub struct EquivocationEvidence {
    pub validator_id: ValidatorId,
    pub message_1: ConsensusMessage,
    pub message_2: ConsensusMessage,
    pub timestamp: Instant,
}
```

#### 6.2 Peer Reputation System
```rust
pub trait PeerReputation: Send + Sync {
    /// Update reputation based on peer behavior
    async fn update_reputation(
        &mut self,
        validator_id: &ValidatorId,
        behavior: PeerBehavior,
    ) -> Result<()>;

    /// Get peer reputation score
    fn get_reputation_score(&self, validator_id: &ValidatorId) -> Result<f64>;

    /// Check if peer should be disconnected
    fn should_disconnect(&self, validator_id: &ValidatorId) -> Result<bool>;

    /// Ban peer for Byzantine behavior
    async fn ban_peer(&mut self, validator_id: &ValidatorId, reason: String) -> Result<()>;

    /// Unban peer after time window
    async fn unban_peer(&mut self, validator_id: &ValidatorId) -> Result<()>;
}

pub enum PeerBehavior {
    GoodVote,           // Correct vote for round
    BadVote,            // Invalid vote
    Equivocation,       // Conflicting votes
    TimedOut,           // Missed voting deadline
    MessageForgery,     // Unsigned or invalid message
    Helpful,            // Relayed useful messages
    Harmful,            // Tried Byzantine attack
}
```

#### 6.3 Integration in Consensus
```rust
// In consensus_engine.rs after receiving remote message
async fn handle_remote_message(&mut self, msg: IncomingMessage) -> Result<()> {
    let ConsensusMessage::PreVote(vote) = msg.message else { return Ok(()); };

    // 1. Check for replay attack
    if self.byzantine_detector.detect_replay_attack(&ConsensusMessage::PreVote(vote.clone()))? {
        self.peer_reputation.update_reputation(
            &msg.from_validator_id,
            PeerBehavior::MessageForgery,
        ).await?;
        return Ok(());
    }

    // 2. Check for equivocation
    if let Some(evidence) = self.byzantine_detector.detect_equivocation(&msg.from_validator_id).await? {
        warn!("Detected equivocation from validator {}", msg.from_validator_id);
        self.peer_reputation.update_reputation(
            &msg.from_validator_id,
            PeerBehavior::Equivocation,
        ).await?;
        // Could slash validator here
    }

    // 3. Validate and process vote
    if let Ok(()) = self.vote_validator.validate_remote_vote(&vote, &msg.from_validator_id).await {
        self.votes.add_vote(vote)?;
        self.peer_reputation.update_reputation(
            &msg.from_validator_id,
            PeerBehavior::GoodVote,
        ).await?;
    } else {
        self.peer_reputation.update_reputation(
            &msg.from_validator_id,
            PeerBehavior::BadVote,
        ).await?;
    }

    Ok(())
}
```

---

## Gap 7: Message Routing & Relay

### Problem
Validators might not be directly reachable from each other. Need message relay/routing through intermediate nodes.

### What's Needed

#### 7.1 Message Routing
```rust
pub trait MessageRouter: Send + Sync {
    /// Find route to validator (direct or via relays)
    async fn find_route(
        &self,
        destination: &ValidatorId,
    ) -> Result<MessageRoute>;

    /// Send message via routing path
    async fn send_via_route(
        &self,
        message: ConsensusMessage,
        route: &MessageRoute,
    ) -> Result<()>;

    /// Register as relay node
    async fn register_as_relay(&self) -> Result<()>;

    /// Forward message to next hop
    async fn forward_message(
        &self,
        message: ConsensusMessage,
        next_hop: &ValidatorId,
    ) -> Result<()>;
}

pub struct MessageRoute {
    pub hops: Vec<ValidatorId>,
    pub quality: f64,  // 0.0 to 1.0, based on latency/reliability
    pub next_hop: ValidatorId,
}
```

---

## Implementation Roadmap

### Phase 1: Basic Message Broadcasting (Week 1-2)
- [ ] Define MessageBroadcaster trait
- [ ] Implement message serialization/framing (ConsensusMessageCodec)
- [ ] Add message encryption for peer-to-peer
- [ ] Integrate broadcaster into consensus_engine.rs
- [ ] Test basic broadcast from proposer and voters

### Phase 2: Message Reception & Vote Aggregation (Week 3)
- [ ] Define ConsensusMessageReceiver trait
- [ ] Implement remote vote validation
- [ ] Add message channel to consensus main loop
- [ ] Replace internal-only voting with network-aware voting
- [ ] Test consensus reaching with 2+ validators

### Phase 3: Validator Discovery & Peer Management (Week 4-5)
- [ ] Define ValidatorDiscovery trait
- [ ] Implement PeerConnectionManager
- [ ] Add validator registration to blockchain
- [ ] Watch for validator set changes
- [ ] Handle dynamic validator sets
- [ ] Test joining/leaving validators

### Phase 4: Liveness & Byzantine Detection (Week 6-7)
- [ ] Implement HeartbeatProtocol
- [ ] Add LivenessMonitor with timeouts
- [ ] Implement ByzantineNetworkDetector
- [ ] Add PeerReputation tracking
- [ ] Detect equivocation and replay attacks
- [ ] Handle Byzantine validators gracefully

### Phase 5: Gossip & Reliable Delivery (Week 8)
- [ ] Implement GossipProtocol
- [ ] Add ReliableMessaging with retransmission
- [ ] Test message propagation across network
- [ ] Benchmark gossip efficiency
- [ ] Tune TTL and peer selection

### Phase 6: Integration Testing (Week 9-10)
- [ ] End-to-end consensus with 4+ validators
- [ ] Byzantine fault scenarios (1 malicious validator)
- [ ] Network partition scenarios
- [ ] Validator churn (join/leave during consensus)
- [ ] Performance benchmarking (message latency, throughput)
- [ ] Stress testing (high validator count)

---

## Success Criteria

- [ ] All consensus messages are broadcast to network (PreProposal, PreVote, PreCommit, Commit)
- [ ] Votes from all validators are received and aggregated correctly
- [ ] Consensus reaches finality with 2/3+ validator participation
- [ ] Byzantine validators detected and excluded from quorum
- [ ] Network partitions detected and handled
- [ ] Validator liveness monitored with heartbeats
- [ ] Messages reliably delivered even with network issues
- [ ] Gossip protocol ensures all validators eventually receive critical messages
- [ ] All tests pass (150+ network integration tests)
- [ ] Performance: message delivery latency < 500ms to 2/3+ validators
- [ ] Handles up to 1/3 Byzantine validators without consensus failure
- [ ] Graceful handling of network partitions and heals

---

## Critical Design Decisions

### Decision 1: Broadcast vs Multicast vs Gossip
**Broadcast only**: ❌ Doesn't scale to large validator sets
**Gossip only**: ❌ May miss critical votes
**Chosen**: ✅ Direct broadcast + gossip for redundancy

### Decision 2: Synchronous vs Asynchronous Consensus
**Synchronous (bounded time per phase)**: ✅ Matches current impl, simpler
**Asynchronous (no time bounds)**: ❌ Would require major redesign
**Chosen**: ✅ Keep synchronous with explicit timeouts

### Decision 3: Message Reliability
**Best-effort**: ❌ Votes could be lost
**Guaranteed delivery**: ✅ Each vote must be received by quorum
**Chosen**: ✅ Reliable messaging with retransmission

### Decision 4: Byzantine Detection Strategy
**Detection only**: ❌ Need to respond to faults
**Detection + response**: ✅ Auto-exclude or slash malicious validators
**Chosen**: ✅ Detection with peer reputation and optional slashing

### Decision 5: Validator Discovery Source
**Hardcoded**: ❌ Can't handle validator set changes
**From blockchain**: ✅ Validators tracked by consensus/blockchain
**From DHT**: ❌ Adds external dependency
**Chosen**: ✅ Blockchain-backed validator set with dynamic updates

---

## Related Issues

- [ ] Issue #X: lib-network peer-to-peer protocol
- [ ] Issue #X: Gossip protocol implementation
- [ ] Issue #X: Validator registry and discovery
- [ ] Issue #X: Byzantine fault detection
- [ ] Issue #X: Message serialization and framing

---

## References

- Tendermint P2P: https://tendermint.com/
- Cosmos Consensus: https://cosmos.network/
- Byzantine Broadcast Protocols: https://arxiv.org/abs/1901.08175
- Gossip Protocols: https://dl.acm.org/doi/10.1145/41840.41841
- Reputation Systems: https://en.wikipedia.org/wiki/Reputation_system
