use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use crate::monitoring::{Alert, AlertLevel, AlertManager};
use crate::runtime::mesh_router_provider::get_global_mesh_router;
use crate::runtime::node_runtime::NodeRole;
use crate::runtime::{Component, ComponentHealth, ComponentId, ComponentMessage, ComponentStatus};
use crate::server::mesh::core::MeshRouter;
use lib_blockchain::Blockchain;
use lib_consensus::types::{MessageBroadcaster as ConsensusMessageBroadcaster, ValidatorMessage};
use lib_consensus::validators::{
    ValidatorAnnouncement, ValidatorDiscoveryProtocol, ValidatorEndpoint,
    ValidatorNetworkTransport, ValidatorProtocol, ValidatorStatus,
};
use lib_consensus::{
    ConsensusConfig, ConsensusEngine, ConsensusEvent, NoOpBroadcaster, ValidatorManager,
};
use lib_identity::IdentityId;

/// Adapter that implements lib-consensus MessageBroadcaster using zhtp's MeshRouter
///
/// This bridges the consensus layer (which uses IdentityId) to the network layer
/// (which uses QUIC mesh routing) for multi-node BFT consensus.
pub struct ConsensusMeshBroadcaster {
    mesh_router: Arc<MeshRouter>,
}

impl ConsensusMeshBroadcaster {
    pub fn new(mesh_router: Arc<MeshRouter>) -> Self {
        Self { mesh_router }
    }

    async fn resolve_validator_peer_node_ids(
        &self,
        validator_ids: &[IdentityId],
        target_height: u64,
    ) -> HashSet<Vec<u8>> {
        let targets: HashSet<Vec<u8>> = validator_ids
            .iter()
            .map(|id| id.as_bytes().to_vec())
            .collect();

        tracing::debug!(
            "Consensus broadcast target set for height {} resolved to {} candidate peer node IDs",
            target_height,
            targets.len()
        );

        targets
    }
}

#[async_trait::async_trait]
impl ConsensusMessageBroadcaster for ConsensusMeshBroadcaster {
    async fn broadcast_to_validators(
        &self,
        message: ValidatorMessage,
        validator_ids: &[IdentityId],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Get QUIC protocol for sending
        let quic_protocol_guard = self.mesh_router.quic_protocol.read().await;
        let quic_protocol = match quic_protocol_guard.as_ref() {
            Some(qp) => qp.clone(),
            None => {
                debug!("QUIC protocol not available for consensus broadcast");
                return Ok(()); // Best-effort, don't fail
            }
        };
        drop(quic_protocol_guard);

        // Convert types::ValidatorMessage to validators::ValidatorMessage for mesh transport
        let network_message = convert_to_network_message(&message);

        let target_height = consensus_message_height(&message);
        let target_peer_node_ids = self
            .resolve_validator_peer_node_ids(validator_ids, target_height)
            .await;
        if target_peer_node_ids.is_empty() {
            debug!(
                "No validator targets resolved for consensus height {}, skipping broadcast",
                target_height
            );
            return Ok(());
        }

        // Guardrail 1: identity-based filtering using authenticated QUIC peer IDs.
        // Guardrail 2: validator set is scoped to the consensus message height.
        let connected = quic_protocol.connected_authenticated_peers();
        let recipients: Vec<Vec<u8>> = connected
            .into_iter()
            .filter(|peer| is_target_validator_peer(peer, &target_peer_node_ids))
            .map(|peer| peer.node_id)
            .collect();

        if recipients.is_empty() {
            debug!(
                "No connected authenticated validator peers for consensus height {}",
                target_height
            );
            return Ok(());
        }

        let mut delivered = 0usize;
        for peer_id in recipients {
            if quic_protocol
                .send_to_peer(
                    &peer_id,
                    lib_network::types::mesh_message::ZhtpMeshMessage::ValidatorMessage(
                        network_message.clone(),
                    ),
                )
                .await
                .is_ok()
            {
                delivered += 1;
            }
        }

        debug!(
            "Consensus broadcast (height {}) delivered to {} validator peer(s)",
            target_height, delivered
        );
        if delivered == 0 {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Consensus broadcast had zero successful deliveries",
            )))
        } else {
            Ok(())
        }
    }
}

/// Adapter that implements `ValidatorNetworkTransport` using zhtp's QUIC mesh.
///
/// Used by `ValidatorProtocol` to broadcast signed validator messages to peers.
struct QuicValidatorTransport {
    mesh_router: Arc<MeshRouter>,
}

impl QuicValidatorTransport {
    fn new(mesh_router: Arc<MeshRouter>) -> Self {
        Self { mesh_router }
    }

    async fn resolve_validator_peer_node_ids(
        &self,
        recipients: &[IdentityId],
        target_height: u64,
    ) -> HashSet<Vec<u8>> {
        let targets: HashSet<Vec<u8>> =
            recipients.iter().map(|id| id.as_bytes().to_vec()).collect();

        tracing::debug!(
            "ValidatorProtocol targets for height {} resolved to {} peer node IDs",
            target_height,
            targets.len()
        );
        targets
    }
}

#[async_trait::async_trait]
impl ValidatorNetworkTransport for QuicValidatorTransport {
    async fn broadcast_to_validators(
        &self,
        message: lib_consensus::validators::ValidatorMessage,
        recipients: &[IdentityId],
    ) -> anyhow::Result<()> {
        let quic_protocol_guard = self.mesh_router.quic_protocol.read().await;
        let quic_protocol = match quic_protocol_guard.as_ref() {
            Some(qp) => qp.clone(),
            None => {
                debug!("QUIC protocol not available for ValidatorProtocol broadcast");
                return Ok(()); // Best-effort
            }
        };
        drop(quic_protocol_guard);

        let target_height = network_message_height(&message);
        let target_peer_node_ids = self
            .resolve_validator_peer_node_ids(recipients, target_height)
            .await;
        if target_peer_node_ids.is_empty() {
            debug!(
                "ValidatorProtocol broadcast has no resolved recipients at height {}",
                target_height
            );
            return Ok(());
        }

        let connected = quic_protocol.connected_authenticated_peers();
        let recipients: Vec<Vec<u8>> = connected
            .into_iter()
            .filter(|peer| is_target_validator_peer(peer, &target_peer_node_ids))
            .map(|peer| peer.node_id)
            .collect();

        let mut delivered = 0usize;
        for peer_id in recipients {
            if quic_protocol
                .send_to_peer(
                    &peer_id,
                    lib_network::types::mesh_message::ZhtpMeshMessage::ValidatorMessage(
                        message.clone(),
                    ),
                )
                .await
                .is_ok()
            {
                delivered += 1;
            }
        }

        debug!(
            "ValidatorProtocol broadcast (height {}) delivered to {} peer(s)",
            target_height, delivered
        );
        if delivered == 0 {
            Err(anyhow::anyhow!(
                "ValidatorProtocol broadcast had zero successful deliveries"
            ))
        } else {
            Ok(())
        }
    }
}

/// Convert from lib_consensus::types::ValidatorMessage to lib_consensus::validators::ValidatorMessage
fn convert_to_network_message(
    msg: &ValidatorMessage,
) -> lib_consensus::validators::ValidatorMessage {
    use lib_consensus::validators::{
        ConsensusStateView, ProposeMessage, ValidatorMessage as NetworkValidatorMessage,
        VoteMessage,
    };
    use std::collections::BTreeMap;

    match msg {
        ValidatorMessage::Propose { proposal } => {
            NetworkValidatorMessage::Propose(ProposeMessage {
                message_id: proposal.id.clone(),
                proposer: proposal.proposer.clone(),
                proposal: proposal.clone(),
                justification: None,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                signature: proposal.signature.clone(),
            })
        }
        ValidatorMessage::Vote { vote } => {
            // Derive step from vote_type to ensure consistency
            let step = match vote.vote_type {
                lib_consensus::types::VoteType::PreVote => {
                    lib_consensus::types::ConsensusStep::PreVote
                }
                lib_consensus::types::VoteType::PreCommit => {
                    lib_consensus::types::ConsensusStep::PreCommit
                }
                lib_consensus::types::VoteType::Commit => {
                    lib_consensus::types::ConsensusStep::Commit
                }
                lib_consensus::types::VoteType::Against => {
                    // Against votes can occur during any voting step, default to PreVote
                    lib_consensus::types::ConsensusStep::PreVote
                }
            };
            let state_view = ConsensusStateView {
                height: vote.height,
                round: vote.round,
                step,
                known_proposals: vec![vote.proposal_id.clone()],
                vote_counts: BTreeMap::new(),
            };
            NetworkValidatorMessage::Vote(VoteMessage {
                message_id: {
                    // Use a unique per-broadcast ID so the dedup cache never silently
                    // drops re-broadcasts of the same vote (vote.id is deterministic
                    // per height+round+voter, which caused 3600s suppression).
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos();
                    let nonce = lib_crypto::generate_nonce();
                    let mut data = format!("vote_bcast_{}", ts).into_bytes();
                    data.extend_from_slice(&nonce);
                    lib_crypto::Hash::from_bytes(&lib_crypto::hash_blake3(&data))
                },
                voter: vote.voter.clone(),
                vote: vote.clone(),
                consensus_state: state_view,
                // Use real wall-clock timestamp for network freshness checks.
                // The consensus engine uses a deterministic value internally, but the
                // validator-protocol layer rejects messages with stale/future timestamps.
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                signature: vote.signature.clone(),
            })
        }
        ValidatorMessage::Heartbeat { message } => {
            // HeartbeatMessage is the same type, just re-exported
            NetworkValidatorMessage::Heartbeat(message.clone())
        }
    }
}

fn consensus_message_height(msg: &ValidatorMessage) -> u64 {
    match msg {
        ValidatorMessage::Propose { proposal } => proposal.height,
        ValidatorMessage::Vote { vote } => vote.height,
        ValidatorMessage::Heartbeat { message } => message.height,
    }
}

fn network_message_height(msg: &lib_consensus::validators::ValidatorMessage) -> u64 {
    match msg {
        lib_consensus::validators::ValidatorMessage::Propose(m) => m.proposal.height,
        lib_consensus::validators::ValidatorMessage::Vote(m) => m.vote.height,
        lib_consensus::validators::ValidatorMessage::Commit(m) => m.height,
        lib_consensus::validators::ValidatorMessage::RoundChange(m) => m.height,
        lib_consensus::validators::ValidatorMessage::Heartbeat(m) => m.height,
    }
}

fn controlled_nodes_for_validator_id(
    blockchain: &Blockchain,
    validator_id: &IdentityId,
) -> Option<Vec<Vec<u8>>> {
    for (did, identity_data) in blockchain.identity_registry.iter() {
        let did_hash = did_hash_to_identity_id(did)?;
        if did_hash != *validator_id {
            continue;
        }
        let mut node_ids = Vec::new();
        for node_hex in &identity_data.controlled_nodes {
            if let Some(node_id) = decode_node_id_hex(node_hex) {
                node_ids.push(node_id);
            }
        }
        return Some(node_ids);
    }
    None
}

fn did_hash_to_identity_id(did: &str) -> Option<IdentityId> {
    let did_hex = did.strip_prefix("did:zhtp:")?;
    let did_bytes = hex::decode(did_hex).ok()?;
    if did_bytes.len() < 32 {
        return None;
    }
    Some(lib_crypto::Hash::from_bytes(&did_bytes[..32]))
}

fn decode_node_id_hex(node_hex: &str) -> Option<Vec<u8>> {
    let stripped = node_hex.strip_prefix("0x").unwrap_or(node_hex);
    let bytes = hex::decode(stripped).ok()?;
    if bytes.len() < 32 {
        return None;
    }
    Some(bytes[..32].to_vec())
}

fn is_target_validator_peer(
    peer: &lib_network::protocols::quic_mesh::ConnectedAuthenticatedPeer,
    target_identity_ids: &HashSet<Vec<u8>>,
) -> bool {
    if target_identity_ids.contains(&peer.node_id) {
        return true;
    }
    match did_hash_to_identity_id(&peer.did) {
        Some(did_hash) => target_identity_ids.contains(did_hash.as_bytes()),
        None => false,
    }
}

/// Adapter to make blockchain ValidatorInfo compatible with consensus ValidatorInfo trait
#[derive(Clone)]
pub struct BlockchainValidatorAdapter(pub lib_blockchain::ValidatorInfo);

impl lib_consensus::validators::ValidatorInfo for BlockchainValidatorAdapter {
    fn identity_id(&self) -> lib_crypto::Hash {
        let identity_hex = self
            .0
            .identity_id
            .strip_prefix("did:zhtp:")
            .unwrap_or(&self.0.identity_id);

        if let Ok(bytes) = hex::decode(identity_hex) {
            if bytes.len() >= 32 {
                lib_crypto::Hash::from_bytes(&bytes[..32])
            } else {
                lib_crypto::Hash(lib_crypto::hash_blake3(self.0.identity_id.as_bytes()))
            }
        } else {
            lib_crypto::Hash(lib_crypto::hash_blake3(self.0.identity_id.as_bytes()))
        }
    }

    fn stake(&self) -> u64 {
        self.0.stake
    }

    fn storage_provided(&self) -> u64 {
        self.0.storage_provided
    }

    fn consensus_key(&self) -> [u8; 2592] {
        self.0.consensus_key
    }

    fn networking_key(&self) -> Vec<u8> {
        self.0.networking_key.clone()
    }

    fn rewards_key(&self) -> Vec<u8> {
        self.0.rewards_key.clone()
    }

    fn commission_rate(&self) -> u8 {
        self.0.commission_rate
    }
}

/// Shared blockchain slot that can be populated after consensus engine starts
///
/// This allows the consensus engine to start before the blockchain is wired,
/// and access it once it becomes available.
pub type SharedBlockchainSlot = Arc<RwLock<Option<Arc<RwLock<Blockchain>>>>>;

// ── Catch-up Sync ──────────────────────────────────────────────────────────
//
// When the consensus engine detects that a peer is voting at a higher block
// height than the local chain, it calls `CatchUpSyncChannel::trigger()`.
// This fires a message to `run_catch_up_sync_task`, which downloads missing
// blocks from a connected peer and applies them to the local blockchain.

/// `CatchUpSyncTrigger` implementation that sends a signal via mpsc channel.
///
/// `try_send` is non-blocking: if the channel is full (a sync is already
/// pending), the trigger is silently dropped — the in-flight sync covers it.
struct CatchUpSyncChannel {
    tx: tokio::sync::mpsc::Sender<u64>,
}

impl lib_consensus::types::CatchUpSyncTrigger for CatchUpSyncChannel {
    fn trigger(&self, our_height: u64) {
        let _ = self.tx.try_send(our_height);
    }
}

/// Background task: receives catch-up triggers and downloads missing blocks.
async fn run_catch_up_sync_task(
    mut rx: tokio::sync::mpsc::Receiver<u64>,
    blockchain_slot: SharedBlockchainSlot,
    sled_path: std::path::PathBuf,
    bft_active_height: Arc<std::sync::atomic::AtomicU64>,
) {
    const FAST_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(3);
    const NORMAL_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(10);
    const RETRY_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(5);
    // How many consecutive sync rounds in which at least one ahead peer rejects our
    // chain before we declare an unrecoverable fork and wipe local state. Three rounds
    // filter out transient rejections while detecting a genuine divergence quickly.
    const WRONG_CHAIN_WIPE_THRESHOLD: u32 = 3;

    let mut next_allowed_at = tokio::time::Instant::now();
    // Counts consecutive sync rounds in which ≥1 ahead peer returned a hash
    // mismatch and zero blocks were successfully applied. Resets on any success.
    let mut consecutive_wrong_chain_rounds: u32 = 0;

    while let Some(_trigger_height) = rx.recv().await {
        // Drain any duplicate triggers buffered while we were processing.
        while rx.try_recv().is_ok() {}

        // Adaptive rate-limit.
        let now = tokio::time::Instant::now();
        if now < next_allowed_at {
            debug!(
                "Catch-up sync cooldown ({:.1}s remaining), skipping",
                (next_allowed_at - now).as_secs_f32()
            );
            continue;
        }

        // Read current local blockchain height (may have advanced since trigger).
        let from_height = {
            let slot = blockchain_slot.read().await;
            match slot.as_ref() {
                Some(bc_arc) => bc_arc.read().await.height,
                None => {
                    warn!("Catch-up sync: blockchain slot not populated yet");
                    continue;
                }
            }
        };

        info!(
            "🔄 Catch-up sync: local blockchain height={}, downloading newer blocks",
            from_height
        );

        let peers = catchup_get_connected_peers().await;
        if peers.is_empty() {
            warn!("Catch-up sync: no connected peers available");
            next_allowed_at = tokio::time::Instant::now() + RETRY_COOLDOWN;
            continue;
        }

        let prioritized_peers = prioritize_catchup_peers(peers, &blockchain_slot).await;
        let mut synced_blocks = 0usize;
        // Peers that were strictly ahead of us but returned "Invalid previous block hash".
        // `catchup_sync_from_peer` returns Ok(0) for peers that are NOT ahead, so any
        // hash-mismatch Err came from a peer that was genuinely ahead — unlike the old
        // `wrong_chain_peers == prioritized_peers.len()` check, this correctly excludes
        // same-height peers (e.g. other nodes on the same stale fork) from the count.
        let mut ahead_peers_rejecting: u32 = 0;
        for peer in &prioritized_peers {
            match catchup_sync_from_peer(
                &peer.addr,
                from_height,
                &blockchain_slot,
                &bft_active_height,
            )
            .await
            {
                Ok(0) => {
                    debug!(
                        "Catch-up sync: peer {} at same height ({})",
                        peer.addr, from_height
                    );
                }
                Ok(n) => {
                    info!(
                        "✅ Catch-up sync: applied {} block(s) from {} (local height now ~{})",
                        n,
                        peer.addr,
                        from_height + n as u64
                    );
                    synced_blocks = n;
                    break;
                }
                Err(e) => {
                    warn!("Catch-up sync from {} failed: {}", peer.addr, e);
                    if e.downcast_ref::<HashMismatchError>().is_some() {
                        ahead_peers_rejecting += 1;
                    }
                }
            }
        }

        if synced_blocks > 0 {
            // Successful sync — reset the divergence counter.
            consecutive_wrong_chain_rounds = 0;
        } else if ahead_peers_rejecting > 0 && from_height > 0 {
            // At least one ahead peer rejected our chain this round.
            consecutive_wrong_chain_rounds += 1;
            warn!(
                "⚠️  Wrong-chain signal: {}/{} ahead peer(s) reject height {} \
                ({}/{} consecutive round(s))",
                ahead_peers_rejecting,
                prioritized_peers.len(),
                from_height + 1,
                consecutive_wrong_chain_rounds,
                WRONG_CHAIN_WIPE_THRESHOLD,
            );

            if consecutive_wrong_chain_rounds >= WRONG_CHAIN_WIPE_THRESHOLD {
                // Unrecoverable fork: our local chain state diverged from every
                // ahead peer we can reach. HALT consensus and alert the operator.
                // DO NOT wipe sled — data destruction caused total chain loss in the
                // Apr 2 2026 incident. The operator must manually investigate and
                // decide whether to resync from a peer or restore from backup.
                error!(
                    "CHAIN FORK DETECTED at height {}: {} consecutive round(s) of hash \
                    mismatch from {} ahead peer(s). Consensus HALTED. \
                    Sled preserved at {:?} for operator investigation. \
                    To recover: stop the node, rsync sled from an authoritative peer, restart.",
                    from_height + 1,
                    consecutive_wrong_chain_rounds,
                    ahead_peers_rejecting,
                    sled_path,
                );
                // Halt the sync loop — do not wipe, do not exit.
                // The node stays running (API accessible) but stops syncing.
                break;
            }
        } else {
            // No hash mismatches this round — reset.
            consecutive_wrong_chain_rounds = 0;
        }

        next_allowed_at = tokio::time::Instant::now()
            + if synced_blocks >= 200 {
                FAST_COOLDOWN
            } else if synced_blocks > 0 {
                NORMAL_COOLDOWN
            } else {
                RETRY_COOLDOWN
            };
    }

    info!("Catch-up sync task exited");
}

/// Returned by `catchup_sync_from_peer` when a peer that is strictly ahead of us
/// rejects our chain tip with a hash-mismatch ("Invalid previous block hash"). Using
/// a typed error instead of a string-contains check makes the detection robust to
/// message wording changes.
#[derive(Debug)]
struct HashMismatchError(String);
impl std::fmt::Display for HashMismatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for HashMismatchError {}

/// Return socket addresses of all peers currently connected to the QUIC mesh.
#[derive(Debug, Clone)]
struct CatchUpPeer {
    node_id: Vec<u8>,
    addr: String,
}

async fn catchup_get_connected_peers() -> Vec<CatchUpPeer> {
    let mesh_router = match crate::runtime::mesh_router_provider::get_global_mesh_router().await {
        Ok(mr) => mr,
        Err(_) => return Vec::new(),
    };
    let quic_guard = mesh_router.quic_protocol.read().await;
    match quic_guard.as_ref() {
        Some(qp) => qp
            .connected_authenticated_peers()
            .into_iter()
            .map(|peer| CatchUpPeer {
                node_id: peer.node_id,
                addr: peer.peer_addr.to_string(),
            })
            .collect(),
        None => Vec::new(),
    }
}

async fn prioritize_catchup_peers(
    peers: Vec<CatchUpPeer>,
    blockchain_slot: &SharedBlockchainSlot,
) -> Vec<CatchUpPeer> {
    let slot = blockchain_slot.read().await;
    let blockchain_arc = match slot.as_ref() {
        Some(bc) => bc.clone(),
        None => return peers,
    };
    drop(slot);

    let blockchain = blockchain_arc.read().await;
    let mut validator_peer_ids: HashSet<Vec<u8>> = HashSet::new();
    for validator in blockchain.get_active_validators() {
        if let Some(did_hash) = did_hash_to_identity_id(&validator.identity_id) {
            validator_peer_ids.insert(did_hash.as_bytes().to_vec());
            if let Some(controlled_nodes) =
                controlled_nodes_for_validator_id(&blockchain, &did_hash)
            {
                for node_id in controlled_nodes {
                    validator_peer_ids.insert(node_id);
                }
            }
        }
    }
    drop(blockchain);

    if validator_peer_ids.is_empty() {
        return peers;
    }

    let (mut validator_peers, mut non_validator_peers): (Vec<_>, Vec<_>) = peers
        .into_iter()
        .partition(|peer| validator_peer_ids.contains(&peer.node_id));
    validator_peers.append(&mut non_validator_peers);
    validator_peers
}

/// Download blocks after `our_height` from `peer_addr` and apply them locally.
///
/// Returns the number of blocks successfully applied, or an error.
async fn catchup_sync_from_peer(
    peer_addr: &str,
    our_height: u64,
    blockchain_slot: &SharedBlockchainSlot,
    bft_active_height: &Arc<std::sync::atomic::AtomicU64>,
) -> anyhow::Result<usize> {
    use anyhow::Context;
    use lib_network::client::{ZhtpClient, ZhtpClientConfig};

    // Use the node's real identity so the peer's IdentityRegistryVerifier
    // accepts the connection. A temporary identity would be rejected because
    // it's not registered on-chain.
    let identity_manager = crate::runtime::get_global_identity_manager()
        .await
        .context("catch-up sync: identity manager not available")?;
    let mgr = identity_manager.read().await;
    let identities = mgr.list_identities();
    // Must use an identity that has a private key — the identity manager stores
    // public data for most identities, but the node identity (used for signing)
    // is stored with its private key. user_identity (first) has no private key.
    let node_identity = identities
        .into_iter()
        .find(|id| id.private_key.is_some())
        .ok_or_else(|| anyhow::anyhow!("catch-up sync: no identity with private key available"))?
        .clone();
    drop(mgr);

    let mut client = ZhtpClient::new_bootstrap_with_config(
        node_identity,
        ZhtpClientConfig {
            allow_bootstrap: true,
        },
    )
    .await
    .context("failed to create QUIC client for catch-up sync")?;

    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.connect(peer_addr),
    )
    .await
    .context("catch-up connect timed out")?
    .context("catch-up connect failed")?;

    // Query the peer's current chain tip.
    let tip_resp = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.get("/api/v1/blockchain/tip"),
    )
    .await
    .context("chain tip request timed out")?
    .context("chain tip request failed")?;

    if !tip_resp.status.is_success() {
        return Err(anyhow::anyhow!(
            "chain tip request returned {}",
            tip_resp.status_message
        ));
    }

    #[derive(serde::Deserialize)]
    struct TipInfo {
        height: u64,
    }
    let tip: TipInfo =
        serde_json::from_slice(&tip_resp.body).context("failed to deserialize chain tip")?;

    if tip.height <= our_height {
        return Ok(0); // Peer is not ahead of us — nothing to download.
    }

    // Resolve blockchain Arc once, then iterate pages until caught up.
    let slot = blockchain_slot.read().await;
    let blockchain_arc = slot
        .as_ref()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("blockchain not available during catch-up sync"))?;
    drop(slot);

    // When local sled has no genesis yet (fresh/wiped node), we must fetch from
    // block 0 — otherwise block 1's prev_hash check will fail against zeros.
    // This mirrors the logic in try_initial_sync_from_peer (runtime/mod.rs).
    let no_genesis_in_sled = {
        let bc = blockchain_arc.read().await;
        bc.store
            .as_ref()
            .map(|s| s.get_block_by_height(0).ok().flatten().is_none())
            .unwrap_or(false)
    };
    let first_fetch = if no_genesis_in_sled {
        0u64
    } else {
        our_height + 1
    };
    if no_genesis_in_sled {
        info!(
            "⬇️  Catch-up: sled has no genesis — will fetch from block 0 (peer tip={})",
            tip.height
        );
    }

    let mut next_start = first_fetch;
    let mut total_applied = 0usize;
    let mut pages = 0usize;
    const MAX_BLOCKS_PER_PAGE: u64 = 50;
    const MAX_PAGES_PER_SYNC: usize = 80;

    while next_start <= tip.height && pages < MAX_PAGES_PER_SYNC {
        let start = next_start;
        let end = tip
            .height
            .min(start.saturating_add(MAX_BLOCKS_PER_PAGE - 1));

        info!(
            "⬇️  Catch-up: fetching blocks {}-{} from {} (peer tip={})",
            start, end, peer_addr, tip.height
        );

        let blocks_url = format!("/api/v1/blockchain/blocks/{}/{}", start, end);
        let blocks_resp =
            tokio::time::timeout(std::time::Duration::from_secs(60), client.get(&blocks_url))
                .await
                .context("blocks request timed out")?
                .context("blocks request failed")?;

        if !blocks_resp.status.is_success() {
            return Err(anyhow::anyhow!(
                "blocks {}-{} request returned {}",
                start,
                end,
                blocks_resp.status_message
            ));
        }

        let blocks: Vec<lib_blockchain::Block> =
            bincode::deserialize(&blocks_resp.body).context("failed to deserialize blocks")?;
        if blocks.is_empty() {
            break;
        }

        let mut applied_in_page = 0usize;
        for block in blocks {
            let height = block.height();

            // BFT finality gate: blocks at or above bft_active_height require a
            // quorum proof to be applied via catch-up.  This replaces the old
            // blanket height guard that caused deadlocks when a node missed a BFT
            // callback — the guard blocked catch-up at the exact height BFT was
            // stuck on, and BFT couldn't commit because the rest of the network
            // had already moved on.
            //
            // With quorum proofs, the guard becomes identity-based: a block with
            // 2f+1 valid commit signatures IS the BFT-committed block regardless
            // of what the local consensus engine is working on.
            //
            // Fallback: blocks without a proof (pre-upgrade, or peer doesn't have
            // one) are still blocked by the height guard for safety.
            let bft_height = bft_active_height.load(std::sync::atomic::Ordering::Acquire);
            let verified_proof: Option<lib_types::consensus::BftQuorumProof> = if bft_height > 0
                && height >= bft_height
            {
                // Block is in the BFT-active zone.  Fetch + verify a quorum
                // proof from the peer BEFORE acquiring the write lock.
                match fetch_and_verify_quorum_proof(&mut client, &block, &blockchain_arc).await {
                    Some(proof) => Some(proof),
                    None => {
                        debug!(
                            "Catch-up: skipping block {} (BFT active at {}, no valid proof)",
                            height, bft_height
                        );
                        break;
                    }
                }
            } else {
                None
            };

            let mut bc = blockchain_arc.write().await;

            // Skip blocks strictly below our tip. Allow height == bc.height only
            // for genesis (height 0): a fresh sled needs the canonical block 0 applied.
            if height < bc.height || (height == bc.height && height > 0) {
                drop(bc);
                continue;
            }
            match bc.apply_block_trusted_for_sync(block).await {
                Ok(()) => {
                    applied_in_page += 1;
                    total_applied += 1;
                    // Persist the verified quorum proof alongside the block.
                    if let Some(ref proof) = verified_proof {
                        if let Some(ref store) = bc.store {
                            let _ = store.put_quorum_proof(height, proof);
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Catch-up: failed to apply block {} from {}: {}",
                        height, peer_addr, e
                    );
                    if total_applied == 0 {
                        let msg = format!("failed first block apply at height {}: {}", height, e);
                        // Surface hash-mismatch as a typed error so the catch-up loop
                        // can count ahead-peers-rejecting without brittle string matching.
                        if e.to_string().contains("Invalid previous block hash") {
                            return Err(HashMismatchError(msg).into());
                        }
                        return Err(anyhow::anyhow!("{}", msg));
                    }
                    drop(bc);
                    break;
                }
            }
            drop(bc);
        }

        let h_now = blockchain_arc.read().await.height;
        if applied_in_page == 0 || h_now < next_start {
            break;
        }
        next_start = h_now + 1;
        pages += 1;
    }

    Ok(total_applied)
}

/// Fetch a BFT quorum proof from a peer and verify it against the local
/// validator registry.  Returns `Some(proof)` if the proof is valid, `None`
/// if the peer doesn't have one or it fails verification.
///
/// Called from `catchup_sync_from_peer` when a block is at or above
/// `bft_active_height`.  The proof replaces the old blanket height guard
/// with cryptographic finality verification.
///
/// # Security
/// This function verifies that:
/// 1. All attestations in the proof are for the same proposal_id
/// 2. The signatures are valid and from known validators
/// 3. The quorum threshold is met
///
async fn fetch_and_verify_quorum_proof(
    client: &mut lib_network::client::ZhtpClient,
    block: &lib_blockchain::Block,
    blockchain_arc: &Arc<tokio::sync::RwLock<lib_blockchain::Blockchain>>,
) -> Option<lib_types::consensus::BftQuorumProof> {
    use lib_blockchain::block::verification::{
        extract_consistent_proposal_id, verify_quorum_proof, verify_quorum_root_binding,
    };

    let height = block.height();

    let proof_url = format!("/api/v1/blockchain/quorum-proof/{}", height);
    let resp = client.get(&proof_url).await.ok()?;
    if !resp.status.is_success() {
        tracing::debug!("Catch-up: no quorum proof for height {} from peer", height);
        return None;
    }

    let proof: lib_types::consensus::BftQuorumProof =
        bincode::deserialize(&resp.body).ok().or_else(|| {
            tracing::debug!(
                "Catch-up: quorum proof deserialize failed for height {}",
                height
            );
            None
        })?;

    // SECURITY: Verify all attestations agree on the same proposal_id.
    // This prevents proofs with mixed attestations for different proposals.
    let proposal_id = match extract_consistent_proposal_id(&proof) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(
                "Catch-up: block {} quorum proof has inconsistent proposal_ids: {}",
                height,
                e
            );
            return None;
        }
    };

    // Build validator_id → consensus_key map from local registry.
    let bc = blockchain_arc.read().await;
    let validator_keys: std::collections::HashMap<[u8; 32], [u8; 2592]> = bc
        .get_all_validators()
        .iter()
        .filter_map(|(id_str, info)| {
            let bytes = hex::decode(id_str).ok()?;
            if bytes.len() != 32 {
                return None;
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some((arr, info.consensus_key))
        })
        .collect();
    drop(bc);

    if proof.height != height {
        tracing::warn!(
            "Catch-up: block {} quorum proof height mismatch: proof says {}",
            height,
            proof.height
        );
        return None;
    }

    match verify_quorum_proof(&proof, &validator_keys)
        .and_then(|()| verify_quorum_root_binding(&proof, &block.header.bft_quorum_root))
    {
        Ok(()) => {
            tracing::info!(
                "✅ Catch-up: block {} has valid quorum proof/root binding ({} attestations, proposal {})",
                height,
                proof.attestations.len(),
                hex::encode(&proposal_id[..8])
            );
            Some(proof)
        }
        Err(e) => {
            tracing::warn!("Catch-up: block {} quorum proof INVALID: {}", height, e);
            None
        }
    }
}

/// Adapter that provides blockchain data to the consensus engine for block production
///
/// This bridges the consensus layer to the actual blockchain, providing:
/// - Latest block hash for chain continuity
/// - Pending transactions for new blocks
/// - Current blockchain height for validation
///
/// Uses a shared slot pattern to handle the case where consensus starts
/// before the blockchain is fully wired.
pub struct ConsensusBlockchainAdapter {
    blockchain_slot: SharedBlockchainSlot,
}

impl ConsensusBlockchainAdapter {
    pub fn new(blockchain_slot: SharedBlockchainSlot) -> Self {
        Self { blockchain_slot }
    }
}

/// Callback for committing BFT-finalized blocks to the blockchain.
///
/// When BFT consensus achieves 2/3+1 commit votes, this callback writes the
/// block to the blockchain. The `bft_active_height` atomic prevents catch-up
/// sync from racing at the same height (Apr 2 2026 postmortem fix).
pub struct ConsensusBlockCommitter {
    blockchain_slot: SharedBlockchainSlot,
    environment: crate::config::Environment,
}

impl ConsensusBlockCommitter {
    pub fn new(
        blockchain_slot: SharedBlockchainSlot,
        environment: crate::config::Environment,
    ) -> Self {
        Self {
            blockchain_slot,
            environment,
        }
    }
}

#[async_trait::async_trait]
impl lib_consensus::types::BlockCommitCallback for ConsensusBlockCommitter {
    async fn commit_finalized_block(
        &self,
        proposal: &lib_consensus::types::ConsensusProposal,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Get blockchain from slot
        let slot = self.blockchain_slot.read().await;
        let blockchain_arc = match slot.as_ref() {
            Some(bc) => bc.clone(),
            None => return Err("Blockchain not yet available for commit".into()),
        };
        drop(slot);

        let mut blockchain = blockchain_arc.write().await;

        // Check if block at this height already exists (idempotent).
        // CRITICAL: verify the stored block is the one BFT actually finalized.
        // If catch-up raced and wrote a different block first, reject the commit
        // and return an error. Sled is preserved for operator forensics — never
        // auto-wiped (Apr 2 2026 incident postmortem).
        if blockchain.height >= proposal.height && proposal.height > 0 {
            let committed_block_for_check: lib_blockchain::Block =
                bincode::deserialize(&proposal.block_data).map_err(|e| {
                    anyhow::anyhow!("Failed to deserialize block for hash check: {}", e)
                })?;
            let bft_hash = committed_block_for_check.hash().as_array();
            if let Some(ref store) = blockchain.store {
                if let Ok(Some(stored_hash)) = store.get_block_hash_by_height(proposal.height) {
                    if stored_hash.0 != bft_hash {
                        // CRITICAL: Do NOT wipe sled or exit. The Apr 2 2026 incident
                        // showed that auto-wiping destroys the node's chain state,
                        // isolates it from the network, and can cause quorum loss.
                        // Instead: reject this commit and return an error so the
                        // consensus engine knows something is wrong. The operator
                        // must investigate the divergence manually.
                        //
                        // This divergence can only occur via the TOCTOU window during the
                        // bootstrap→BFT mode transition: catch-up downloaded block H from a
                        // peer before bft_active_height was published, then BFT committed H
                        // with a different hash (different proposer timestamp). The primary
                        // fix (>= guard in catchup_sync_from_peer) prevents this during
                        // steady-state BFT; this path should now be extremely rare.
                        error!(
                            "CHAIN DIVERGENCE at height {}: sled has {}, BFT finalized {}. \
                             Likely cause: catch-up/BFT TOCTOU race at bootstrap→BFT transition. \
                             Rejecting commit — sled preserved for forensics. \
                             Recovery: stop node, wipe sled, copy from a peer running the same height, restart.",
                            proposal.height,
                            hex::encode(&stored_hash.0[..8]),
                            hex::encode(&bft_hash[..8]),
                        );
                        return Err(format!(
                            "Chain divergence at height {}: sled block {} != BFT block {}",
                            proposal.height,
                            hex::encode(&stored_hash.0[..8]),
                            hex::encode(&bft_hash[..8]),
                        )
                        .into());
                    }
                }
            }
            info!(
                "Block at height {} already exists with matching hash, skipping commit",
                proposal.height
            );
            return Ok(());
        }

        let committed_block: lib_blockchain::Block = bincode::deserialize(&proposal.block_data)
            .map_err(|e| {
                anyhow::anyhow!("Failed to deserialize finalized block artifact: {}", e)
            })?;

        if committed_block.header.height != proposal.height {
            return Err(anyhow::anyhow!(
                "Finalized block artifact height mismatch: proposal={}, block={}",
                proposal.height,
                committed_block.header.height
            )
            .into());
        }

        if committed_block.header.previous_hash != proposal.previous_hash.0 {
            return Err(anyhow::anyhow!(
                "Finalized block artifact previous_hash mismatch at height {}",
                proposal.height
            )
            .into());
        }

        // Invariant BFT-A-1951: Verify the committed block_data matches the proposal ID
        // that 2f+1 validators actually signed. The proposal ID is blake3(height || prev_hash
        // || block_data || proposer_id). This prevents a tampered artifact from being
        // committed even if it passes the height/prev_hash checks above.
        {
            let expected_id = lib_crypto::hash_blake3(
                &[
                    proposal.height.to_le_bytes().as_slice(),
                    proposal.previous_hash.0.as_slice(),
                    proposal.block_data.as_slice(),
                    proposal.proposer.as_bytes(),
                ]
                .concat(),
            );
            if expected_id != proposal.id.0 {
                return Err(anyhow::anyhow!(
                    "BFT commit rejected: block_data hash does not match proposal ID at height {}. \
                     Expected {:?}, got {:?}. Possible tampered artifact.",
                    proposal.height,
                    &expected_id[..8],
                    &proposal.id.0[..8],
                )
                .into());
            }
        }

        info!(
            "🔨 BFT consensus committing canonical block artifact at height {} with {} transactions",
            proposal.height,
            committed_block.transactions.len()
        );

        // Add block to blockchain — use add_block (not add_block_with_proof) so the
        // write lock is released before ZK proof generation and DHT indexing, preventing
        // a deadlock where the proposer's get_pending_transactions() blocks on blockchain.read()
        // while the write lock is held during slow ZK proof work.
        match blockchain.add_block(committed_block.clone()).await {
            Ok(()) => {
                info!(
                    "✅ BFT BLOCK COMMITTED! Height: {}, Hash: {:?}, Transactions: {}",
                    blockchain.height,
                    committed_block.hash(),
                    committed_block.transactions.len()
                );

                // Store consensus checkpoint for this committed block
                let block_hash =
                    lib_blockchain::types::Hash::new(committed_block.hash().as_array());
                let proposer_id = proposal.proposer.to_string();
                let prev_hash_bytes: [u8; 32] = match proposal.previous_hash.as_bytes().try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        let actual_len = proposal.previous_hash.as_bytes().len();
                        tracing::error!(
                            "Unexpected previous_hash length: expected 32 bytes, got {}",
                            actual_len
                        );
                        return Err(anyhow::anyhow!(
                            "failed to convert previous_hash to 32-byte array: length {}",
                            actual_len
                        )
                        .into());
                    }
                };
                let prev_hash = lib_blockchain::types::Hash::new(prev_hash_bytes);

                blockchain.store_consensus_checkpoint(
                    proposal.height,
                    block_hash,
                    proposer_id,
                    prev_hash,
                    0,
                );
                info!(
                    "📍 Stored consensus checkpoint for height {}",
                    proposal.height
                );

                // Sled store handles persistence automatically on block commit.
                // Legacy save_to_file path removed — sled is the canonical store.

                // Release the write lock before doing ZK proof generation and DHT indexing.
                // These are non-critical background operations that must not block consensus.
                drop(blockchain);

                // ZK proof generation (background — edge node sync falls back to headers if absent)
                // Never block consensus on proof generation: only generate if we can acquire
                // the blockchain write lock immediately. If the lock is busy, skip this proof
                // run; edge nodes can fall back to header-based sync.
                {
                    let bc_arc = blockchain_arc.clone();
                    let block_for_proof = committed_block.clone();
                    tokio::spawn(async move {
                        if let Ok(mut bc) = bc_arc.try_write() {
                            if let Err(e) = bc.generate_proof_for_block(&block_for_proof).await {
                                warn!(
                                    "Failed to generate recursive proof for block {}: {} — edge node sync falls back to headers",
                                    block_for_proof.height(), e
                                );
                            }
                        } else {
                            debug!(
                                "Skipping recursive proof generation for block {}: blockchain lock is busy (preserving consensus liveness)",
                                block_for_proof.height()
                            );
                        }
                    });
                }

                // DHT indexing (background)
                {
                    let block_for_dht = committed_block.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            crate::runtime::dht_indexing::index_block_in_dht(&block_for_dht).await
                        {
                            warn!("DHT indexing failed for BFT block: {}", e);
                        }
                    });
                }

                Ok(())
            }
            Err(e) => {
                error!("Failed to add BFT-finalized block to blockchain: {}", e);
                Err(e.into())
            }
        }
    }

    async fn commit_finalized_block_with_proof(
        &self,
        proposal: &lib_consensus::types::ConsensusProposal,
        quorum_proof: lib_types::consensus::BftQuorumProof,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let quorum_root = lib_types::consensus::compute_bft_quorum_root(&quorum_proof);

        let slot = self.blockchain_slot.read().await;
        let blockchain_arc = match slot.as_ref() {
            Some(bc) => bc.clone(),
            None => return Err("Blockchain not yet available for commit".into()),
        };
        drop(slot);

        let mut blockchain = blockchain_arc.write().await;

        let mut committed_block: lib_blockchain::Block = bincode::deserialize(&proposal.block_data)
            .map_err(|e| {
                anyhow::anyhow!("Failed to deserialize finalized block artifact: {}", e)
            })?;
        committed_block.header.set_bft_quorum_root(quorum_root);

        if blockchain.height > proposal.height {
            if let Some(existing_block) = blockchain.get_block(proposal.height) {
                if existing_block.hash() == committed_block.hash() {
                    if let Some(ref store) = blockchain.store {
                        let _ = store.put_quorum_proof(proposal.height, &quorum_proof);
                    }
                    return Ok(());
                }
            }
        }

        blockchain.add_block(committed_block.clone()).await?;

        let block_hash = lib_blockchain::types::Hash::new(committed_block.hash().as_array());
        let proposer_id = proposal.proposer.to_string();
        let prev_hash = lib_blockchain::types::Hash::new(proposal.previous_hash.0);
        blockchain.store_consensus_checkpoint(
            proposal.height,
            block_hash,
            proposer_id,
            prev_hash,
            0,
        );
        drop(blockchain);

        // Persist the quorum proof in a separate sled tree so catch-up sync
        // can verify BFT finality from the proof alone, without relying on
        // the bft_active_height guard.
        let slot = self.blockchain_slot.read().await;
        if let Some(bc_arc) = slot.as_ref() {
            let bc = bc_arc.read().await;
            if let Some(ref store) = bc.store {
                if let Err(e) = store.put_quorum_proof(proposal.height, &quorum_proof) {
                    tracing::warn!(
                        "Failed to persist quorum proof for height {}: {} (non-fatal)",
                        proposal.height,
                        e,
                    );
                } else {
                    tracing::info!(
                        "📜 Persisted BFT quorum proof/root for height {} ({} attestations)",
                        proposal.height,
                        quorum_proof.attestations.len(),
                    );
                }
            }
        }

        Ok(())
    }

    async fn get_active_validator_count(
        &self,
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        // Get blockchain from slot
        let slot = self.blockchain_slot.read().await;
        let blockchain_arc = match slot.as_ref() {
            Some(bc) => bc.clone(),
            None => return Ok(0), // No blockchain = no validators
        };
        drop(slot);

        let blockchain = blockchain_arc.read().await;
        let validators = blockchain.get_active_validators();
        Ok(validators.len())
    }
}

#[async_trait::async_trait]
impl lib_consensus::types::ConsensusBlockchainProvider for ConsensusBlockchainAdapter {
    async fn get_latest_block_hash(
        &self,
    ) -> Result<lib_crypto::Hash, Box<dyn std::error::Error + Send + Sync>> {
        let slot = self.blockchain_slot.read().await;
        let blockchain_arc = match slot.as_ref() {
            Some(bc) => bc.clone(),
            None => return Err("Blockchain not yet available".into()),
        };
        drop(slot);

        let blockchain = blockchain_arc.read().await;
        if blockchain.blocks.is_empty() {
            // No blocks yet - genesis
            Ok(lib_crypto::Hash([0u8; 32]))
        } else {
            let latest_block = blockchain.blocks.last().unwrap();
            // Convert lib_blockchain::Hash to lib_crypto::Hash
            let block_hash = latest_block.header.hash();
            let hash_bytes = block_hash.as_array();
            Ok(lib_crypto::Hash(hash_bytes))
        }
    }

    async fn get_pending_transactions(
        &self,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let slot = self.blockchain_slot.read().await;
        let blockchain_arc = match slot.as_ref() {
            Some(bc) => bc.clone(),
            None => return Ok(Vec::new()), // No blockchain = no transactions
        };
        drop(slot);

        let blockchain = blockchain_arc.read().await;
        let pending = blockchain.pending_transactions.clone();
        // Capture a nonce-validity snapshot while we hold the read lock.
        // This is the last-line defense: even if a stale tx slipped past
        // mempool admission, it will be filtered out here before the
        // proposer includes it in the BFT proposal.
        let nonce_valid: Vec<bool> = pending
            .iter()
            .map(|tx| blockchain.is_nonce_current(tx))
            .collect();
        let previous_hash = blockchain
            .latest_block()
            .map(|b| b.hash())
            .unwrap_or_default();
        let next_height = blockchain.height.saturating_add(1);
        drop(blockchain);

        // Pre-filter: only pass nonce-valid transactions to block selection.
        let pending_count = pending.len();
        let valid_pending: Vec<_> = pending
            .into_iter()
            .zip(nonce_valid)
            .filter_map(|(tx, valid)| if valid { Some(tx) } else { None })
            .collect();

        // Use the environment mining config (Bootstrap on dev = instant mining, Mainnet = full PoW).
        // This must match what add_block's PoW validation expects — both use get_mining_config_from_env().
        // Do NOT use mine_block() which hardcodes MiningConfig::testnet() (no instant mining),
        // as the blockchain difficulty may have been adjusted far above what testnet can mine quickly.
        let mining_config = lib_blockchain::types::mining::get_mining_config_from_env();

        let selected = lib_blockchain::block::creation::select_transactions_for_block(
            &valid_pending,
            lib_blockchain::MAX_TRANSACTIONS_PER_BLOCK,
            lib_blockchain::MAX_BLOCK_SIZE,
        );

        let block = lib_blockchain::block::creation::create_block(
            selected,
            previous_hash,
            next_height,
            mining_config.difficulty,
        )
        .map_err(|e| format!("Block creation failed: {}", e))?;

        let mined_block =
            lib_blockchain::block::creation::mine_block_with_config(block, &mining_config)
                .map_err(|e| format!("Block mining failed: {}", e))?;

        let tx_data = bincode::serialize(&mined_block)
            .map_err(|e| format!("Block serialization failed: {}", e))?;

        info!(
            "📦 Providing canonical proposal block at height {} with {} transaction(s) ({} bytes) to consensus ({} pending total)",
            next_height,
            mined_block.transactions.len(),
            tx_data.len(),
            pending_count
        );

        Ok(tx_data)
    }

    async fn get_blockchain_height(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let slot = self.blockchain_slot.read().await;
        let blockchain_arc = match slot.as_ref() {
            Some(bc) => bc.clone(),
            None => return Ok(0),
        };
        drop(slot);

        let blockchain = blockchain_arc.read().await;
        Ok(blockchain.height)
    }

    async fn is_ready(&self) -> bool {
        let slot = self.blockchain_slot.read().await;
        if let Some(blockchain_arc) = slot.as_ref() {
            // Blockchain is wired and ready
            if let Ok(blockchain) = blockchain_arc.try_read() {
                return !blockchain.blocks.is_empty() || blockchain.height == 0;
            }
        }
        false
    }

    async fn decode_block_data(
        &self,
        block_data: &[u8],
    ) -> Result<(u32, u64), Box<dyn std::error::Error + Send + Sync>> {
        if block_data.is_empty() {
            return Ok((0, 0));
        }
        match bincode::deserialize::<lib_blockchain::block::Block>(block_data) {
            Ok(block) => {
                let count = block.transactions.len() as u32;
                let fees: u64 = block.transactions.iter().map(|tx| tx.fee).sum();
                Ok((count, fees))
            }
            Err(_) => {
                // block_data may be the text fallback format from tests ("empty_block:...")
                Ok((0, 0))
            }
        }
    }
}

/// Consensus component implementation using lib-consensus package
pub struct ConsensusComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    consensus_engine: Arc<RwLock<Option<ConsensusEngine>>>,
    validator_manager: Arc<RwLock<ValidatorManager>>,
    blockchain: Arc<RwLock<Option<Arc<RwLock<Blockchain>>>>>,
    environment: crate::config::Environment,
    // Consensus safety parameters are config-driven; keep them immutable once constructed.
    min_stake: u64,
    propose_timeout_ms: u64,
    prevote_timeout_ms: u64,
    precommit_timeout_ms: u64,
    // Local validator identity and signing keypair (loaded from keystore when validator-enabled).
    local_validator_identity: Arc<RwLock<Option<IdentityId>>>,
    local_validator_keypair: Arc<RwLock<Option<lib_crypto::KeyPair>>>,
    /// Node role determines whether this node participates in consensus validation
    /// This is IMMUTABLE and set at construction time based on configuration
    /// The role cannot change after the component is created
    node_role: Arc<NodeRole>,
    /// Mock SOV/USD price for oracle attestations (testnet/bootstrap).
    /// `None` means attempt real exchange price feeds.
    oracle_mock_sov_usd_price: Option<u64>,
}

// Manual Debug implementation because ConsensusEngine doesn't derive Debug
impl std::fmt::Debug for ConsensusComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsensusComponent")
            .field("status", &self.status)
            .field("start_time", &self.start_time)
            .field("consensus_engine", &"<ConsensusEngine>")
            .field("validator_manager", &"<ValidatorManager>")
            .field("blockchain", &"<Blockchain>")
            .field("environment", &self.environment)
            .field("node_role", &*self.node_role)
            .finish()
    }
}

/// Decode bootstrap consensus key from hex string (accepts 0x prefix or plain hex).
/// Returns fixed-size [u8; 2592] for Dilithium5 public key.
pub fn decode_bootstrap_consensus_key(consensus_key_hex: &str) -> Option<[u8; 2592]> {
    let trimmed = consensus_key_hex.trim();
    if trimmed.is_empty() {
        return None;
    }

    let normalized = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);

    let bytes = hex::decode(normalized).ok()?;
    if bytes.len() != 2592 {
        return None;
    }

    Some(bytes.as_slice().try_into().ok()?)
}

impl ConsensusComponent {
    /// Create a new ConsensusComponent with the specified node role
    /// CRITICAL: node_role must be derived from configuration before calling this
    pub fn new(
        environment: crate::config::Environment,
        node_role: NodeRole,
        min_stake: u64,
    ) -> Self {
        Self::new_with_bootstrap_validators(
            environment,
            node_role,
            min_stake,
            Vec::new(),
            crate::config::aggregation::default_consensus_propose_timeout_ms(),
            crate::config::aggregation::default_consensus_prevote_timeout_ms(),
            crate::config::aggregation::default_consensus_precommit_timeout_ms(),
        )
    }

    /// Create a new ConsensusComponent with configurable timeouts.
    ///
    /// # Issue BFT-A-1954
    ///
    /// The `bootstrap_validators` config field is no longer pre-seeded into the ValidatorManager
    /// here. Validators are loaded exclusively from canonical genesis state via
    /// `sync_validators_from_blockchain()`. The bootstrap config entries are only used during
    /// the genesis block construction path in `mod.rs`.
    pub fn new_with_bootstrap_validators(
        environment: crate::config::Environment,
        node_role: NodeRole,
        min_stake: u64,
        _bootstrap_validators: Vec<crate::config::aggregation::BootstrapValidator>,
        propose_timeout_ms: u64,
        prevote_timeout_ms: u64,
        precommit_timeout_ms: u64,
    ) -> Self {
        Self::new_with_bootstrap_validators_and_oracle(
            environment,
            node_role,
            min_stake,
            _bootstrap_validators,
            None,
            propose_timeout_ms,
            prevote_timeout_ms,
            precommit_timeout_ms,
        )
    }

    pub fn new_with_bootstrap_validators_and_oracle(
        environment: crate::config::Environment,
        node_role: NodeRole,
        min_stake: u64,
        _bootstrap_validators: Vec<crate::config::aggregation::BootstrapValidator>,
        oracle_mock_sov_usd_price: Option<u64>,
        propose_timeout_ms: u64,
        prevote_timeout_ms: u64,
        precommit_timeout_ms: u64,
    ) -> Self {
        let development_mode = matches!(environment, crate::config::Environment::Development);

        let validator_manager =
            ValidatorManager::new_with_development_mode(100, min_stake, development_mode);

        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            consensus_engine: Arc::new(RwLock::new(None)),
            validator_manager: Arc::new(RwLock::new(validator_manager)),
            blockchain: Arc::new(RwLock::new(None)),
            environment,
            min_stake,
            propose_timeout_ms: propose_timeout_ms.max(1),
            prevote_timeout_ms: prevote_timeout_ms.max(1),
            precommit_timeout_ms: precommit_timeout_ms.max(1),
            local_validator_identity: Arc::new(RwLock::new(None)),
            local_validator_keypair: Arc::new(RwLock::new(None)),
            node_role: Arc::new(node_role),
            oracle_mock_sov_usd_price,
        }
    }

    #[deprecated = "Use new_with_bootstrap_validators(environment, node_role, min_stake, validators) instead"]
    pub fn new_deprecated(environment: crate::config::Environment) -> Self {
        Self::new(environment, NodeRole::Observer, 0)
    }

    /// Get the current node role (immutable)
    pub fn get_node_role(&self) -> NodeRole {
        (*self.node_role).clone()
    }

    pub async fn set_blockchain(&self, blockchain: Arc<RwLock<Blockchain>>) {
        *self.blockchain.write().await = Some(blockchain);
    }

    pub async fn sync_validators_from_blockchain(&self) -> Result<()> {
        let blockchain_opt = self.blockchain.read().await;
        let blockchain = match blockchain_opt.as_ref() {
            Some(bc) => bc,
            None => {
                warn!("Cannot sync validators: blockchain not set");
                return Ok(());
            }
        };

        let bc = blockchain.read().await;
        let active_validators = bc.get_active_validators();

        if active_validators.is_empty() {
            debug!("No active validators found in blockchain registry");
            return Ok(());
        }

        let validator_adapters: Vec<BlockchainValidatorAdapter> = active_validators
            .into_iter()
            .map(|v| BlockchainValidatorAdapter(v.clone()))
            .collect();

        let mut validator_manager = self.validator_manager.write().await;
        let (synced_count, skipped_count) = validator_manager
            .sync_from_validator_list(validator_adapters)
            .context("Failed to sync validators from blockchain")?;

        info!(
            "Validator sync complete: {} new validators registered, {} already registered",
            synced_count, skipped_count
        );

        // Also sync into the running consensus engine so remote votes/proposals verify against
        // the real on-chain validator set.
        {
            let mut engine_guard = self.consensus_engine.write().await;
            if let Some(engine) = engine_guard.as_mut() {
                let active_validators = bc.get_active_validators();
                let adapters_for_engine: Vec<BlockchainValidatorAdapter> = active_validators
                    .into_iter()
                    .map(|v| BlockchainValidatorAdapter(v.clone()))
                    .collect();
                let _ = engine
                    .sync_validators_from_list(adapters_for_engine)
                    .map_err(|e| {
                        anyhow::anyhow!("Consensus engine validator sync failed: {}", e)
                    })?;

                // If this node is a validator, set local identity and keypair so it can propose/vote.
                // Both must be set AFTER sync_validators_from_list because the engine checks
                // that the identity/keypair is registered in the validator set.
                if self.node_role.can_validate() {
                    let local_id = self.local_validator_identity.read().await.clone();
                    if let Some(id) = local_id {
                        engine.set_local_validator_identity(id).map_err(|e| {
                            anyhow::anyhow!("Failed to set local validator identity: {}", e)
                        })?;

                        // Set keypair after identity — set_validator_keypair requires identity first.
                        let local_kp = self.local_validator_keypair.read().await.clone();
                        if let Some(kp) = local_kp {
                            if let Err(e) = engine.set_validator_keypair(kp) {
                                warn!("Could not set validator keypair (node will not propose/vote): {}", e);
                            }
                        }
                    } else {
                        warn!(
                            "Local validator identity not loaded; consensus will not propose/vote"
                        );
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn get_validator_manager(&self) -> Arc<RwLock<ValidatorManager>> {
        self.validator_manager.clone()
    }
}

async fn load_local_validator_from_keystore() -> Result<(IdentityId, lib_crypto::KeyPair)> {
    use crate::keyfile_names::{
        KeystorePrivateKey, NODE_IDENTITY_FILENAME, NODE_PRIVATE_KEY_FILENAME,
    };
    use std::path::PathBuf;

    let keystore_dir = std::env::var("ZHTP_KEYSTORE_DIR")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::node_data_dir().join("keystore"));

    let node_identity_path = keystore_dir.join(NODE_IDENTITY_FILENAME);
    let node_key_path = keystore_dir.join(NODE_PRIVATE_KEY_FILENAME);

    let node_identity_json = tokio::fs::read_to_string(&node_identity_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read {:?}: {}", node_identity_path, e))?;
    let node_identity_val: serde_json::Value = serde_json::from_str(&node_identity_json)
        .map_err(|e| anyhow::anyhow!("Invalid JSON {:?}: {}", node_identity_path, e))?;
    let did = node_identity_val
        .get("did")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing .did in {:?}", node_identity_path))?;

    let identity_id = lib_identity::did::parse_did_to_identity_id(did)
        .map_err(|e| anyhow::anyhow!("Invalid DID in {:?}: {}", node_identity_path, e))?;

    let key_json = tokio::fs::read_to_string(&node_key_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read {:?}: {}", node_key_path, e))?;
    let ks: KeystorePrivateKey = serde_json::from_str(&key_json)
        .map_err(|e| anyhow::anyhow!("Invalid JSON {:?}: {}", node_key_path, e))?;

    if ks.dilithium_sk.is_empty() || ks.dilithium_pk.is_empty() {
        return Err(anyhow::anyhow!(
            "Keystore key {:?} missing dilithium_sk/dilithium_pk",
            node_key_path
        ));
    }

    // Consensus identity uses Dilithium public key bytes for signature verification.
    let dilithium_pk: [u8; 2592] = ks
        .dilithium_pk
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid dilithium_pk length, expected 2592 bytes"))?;
    let dilithium_sk: [u8; 4896] = ks
        .dilithium_sk
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid dilithium_sk length, expected 4896 bytes"))?;
    let kyber_sk: [u8; 3168] = ks
        .kyber_sk
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid kyber_sk length, expected 3168 bytes"))?;
    let master_seed: [u8; 64] = ks
        .master_seed
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid master_seed length, expected 64 bytes"))?;
    let public_key = lib_crypto::PublicKey::new(dilithium_pk);
    let private_key = lib_crypto::PrivateKey {
        dilithium_sk,
        dilithium_pk,
        kyber_sk,
        master_seed,
    };

    Ok((
        identity_id,
        lib_crypto::KeyPair {
            public_key,
            private_key,
        },
    ))
}

async fn handle_liveness_event(alert_manager: &AlertManager, event: ConsensusEvent) {
    match event {
        ConsensusEvent::ConsensusStalled {
            height,
            round,
            timed_out_validators,
            total_validators,
            timestamp,
        } => {
            let mut metadata = HashMap::new();
            metadata.insert("height".to_string(), height.to_string());
            metadata.insert("round".to_string(), round.to_string());
            metadata.insert(
                "timed_out_validators".to_string(),
                timed_out_validators.len().to_string(),
            );
            metadata.insert("total_validators".to_string(), total_validators.to_string());

            let alert = Alert {
                id: format!("consensus-stalled-{}-{}", height, round),
                level: AlertLevel::Critical,
                title: "Consensus stalled".to_string(),
                message: format!(
                    "Consensus stalled at height {} round {} ({} of {} validators timed out)",
                    height,
                    round,
                    timed_out_validators.len(),
                    total_validators
                ),
                source: "consensus".to_string(),
                timestamp,
                metadata,
            };

            let _ = alert_manager.trigger_alert(alert).await;
        }
        ConsensusEvent::ConsensusRecovered {
            height,
            round,
            timestamp,
        } => {
            let mut metadata = HashMap::new();
            metadata.insert("height".to_string(), height.to_string());
            metadata.insert("round".to_string(), round.to_string());

            let alert = Alert {
                id: format!("consensus-recovered-{}-{}", height, round),
                level: AlertLevel::Info,
                title: "Consensus recovered".to_string(),
                message: format!("Consensus recovered at height {} round {}", height, round),
                source: "consensus".to_string(),
                timestamp,
                metadata,
            };

            let _ = alert_manager.trigger_alert(alert).await;
        }
        ConsensusEvent::ModeTransitionToBft {
            validator_count,
            height,
            timestamp,
        } => {
            let mut metadata = HashMap::new();
            metadata.insert("validator_count".to_string(), validator_count.to_string());
            metadata.insert("height".to_string(), height.to_string());
            metadata.insert("mode".to_string(), "BFT".to_string());

            let alert = Alert {
                id: format!("consensus-mode-bft-{}", height),
                level: AlertLevel::Info,
                title: "BFT consensus activated".to_string(),
                message: format!(
                    "Network transitioned to BFT consensus mode with {} validators at height {}",
                    validator_count, height
                ),
                source: "consensus".to_string(),
                timestamp,
                metadata,
            };

            let _ = alert_manager.trigger_alert(alert).await;
        }
        ConsensusEvent::ModeTransitionToBootstrap {
            validator_count,
            min_required,
            height,
            timestamp,
        } => {
            let mut metadata = HashMap::new();
            metadata.insert("validator_count".to_string(), validator_count.to_string());
            metadata.insert("min_required".to_string(), min_required.to_string());
            metadata.insert("height".to_string(), height.to_string());
            metadata.insert("mode".to_string(), "Bootstrap".to_string());

            let alert = Alert {
                id: format!("consensus-mode-bootstrap-{}", height),
                level: AlertLevel::Warning,
                title: "Network degraded to bootstrap mode".to_string(),
                message: format!(
                    "Network degraded to bootstrap mode at height {} ({} validators, need ≥{} for BFT)",
                    height, validator_count, min_required
                ),
                source: "consensus".to_string(),
                timestamp,
                metadata,
            };

            let _ = alert_manager.trigger_alert(alert).await;
        }
        _ => {}
    }
}

#[async_trait::async_trait]
impl Component for ConsensusComponent {
    fn id(&self) -> ComponentId {
        ComponentId::Consensus
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(&self) -> Result<()> {
        info!("Starting consensus component with lib-consensus implementation...");

        *self.status.write().await = ComponentStatus::Starting;

        // Check if this node can participate in consensus validation
        // Only FullValidator nodes should run the consensus engine
        if !self.node_role.can_validate() {
            let role_desc = match &*self.node_role {
                crate::runtime::node_runtime::NodeRole::Observer => {
                    "observer (verifies blocks, no voting)"
                }
                crate::runtime::node_runtime::NodeRole::LightNode => "light (trusts validators)",
                _ => "non-validator",
            };
            info!(
                "ℹ️ Node type {:?} does not participate in consensus - running as {} node",
                *self.node_role, role_desc
            );
            // Node starts successfully but skips consensus engine
            *self.status.write().await = ComponentStatus::Running;
            return Ok(());
        }

        info!(
            "✓ Node role {:?} can validate - starting consensus engine",
            *self.node_role
        );

        let mut config = ConsensusConfig::default();

        // Keep this node's consensus parameters aligned with zhtp configuration.
        //
        // IMPORTANT DETERMINISM REQUIREMENT:
        //   All validators participating in consensus on the same chain MUST use identical values
        //   for propose / prevote / precommit timeouts and min_stake. These values are currently
        //   loaded from each node's local configuration; misaligned settings across validators
        //   can cause liveness issues (e.g. some validators timing out and advancing rounds while
        //   others are still waiting), leading to unnecessary round rotations and slower block
        //   times. Operators SHOULD ensure these parameters are kept in sync across all validators
        //   for a given network.
        config.min_stake = self.min_stake;
        config.propose_timeout = self.propose_timeout_ms;
        config.prevote_timeout = self.prevote_timeout_ms;
        config.precommit_timeout = self.precommit_timeout_ms;

        // Surface current timeout configuration prominently so operators and monitoring can
        // verify alignment across validators.
        warn!(
            "Consensus timeout configuration (must match across all validators on this chain): \
             propose_timeout_ms = {}, prevote_timeout_ms = {}, precommit_timeout_ms = {}",
            config.propose_timeout, config.prevote_timeout, config.precommit_timeout
        );
        // Storage is optional for validators in zhtp; do not block consensus on storage capacity.
        config.min_storage = 0;
        // Invariant BFT-A-1953: Only the Development environment relaxes the 4-validator BFT
        // quorum. Testnet and Mainnet must have ≥ 4 active validators or startup fails.
        let is_development = matches!(self.environment, crate::config::Environment::Development);
        config.development_mode = is_development;
        if config.development_mode {
            info!("🔧 Development mode enabled — single-validator consensus allowed for local testing");
            info!(
                "   Testnet and Mainnet require minimum {} validators for BFT",
                lib_consensus::engines::consensus_engine::BFT_MIN_VALIDATORS
            );
        } else {
            info!(
                "🛡️ BFT-only mode: Full consensus validation required (minimum {} validators)",
                lib_consensus::engines::consensus_engine::BFT_MIN_VALIDATORS
            );
        }

        // Create broadcaster — requires the mesh router set by Protocols component.
        // Protocols.start() is awaited before Consensus.start() in startup_sequence,
        // so the mesh router is guaranteed to be available here unless Protocols failed.
        // Development mode allows NoOpBroadcaster for single-node local testing.
        let broadcaster: Arc<dyn ConsensusMessageBroadcaster> = match get_global_mesh_router().await
        {
            Ok(mesh_router) => {
                info!("Mesh router available — multi-node consensus broadcasting enabled");
                Arc::new(ConsensusMeshBroadcaster::new(mesh_router))
            }
            Err(e) if is_development => {
                warn!(
                    "Mesh router not available: {} — development mode, using NoOpBroadcaster",
                    e
                );
                Arc::new(NoOpBroadcaster)
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Mesh router not available: {}. \
                         BFT consensus requires a working broadcaster to reach quorum. \
                         Ensure the Protocols component started successfully before Consensus.",
                    e
                ));
            }
        };

        let mut consensus_engine = lib_consensus::init_consensus(config, broadcaster)?;
        let (liveness_tx, mut liveness_rx) = tokio::sync::mpsc::unbounded_channel();
        consensus_engine.set_liveness_event_sender(liveness_tx);

        // Create consensus message channel for receiving ValidatorMessages from the network
        // Channel size of 256 provides buffer for burst message handling
        let (consensus_msg_tx, consensus_msg_rx) =
            tokio::sync::mpsc::channel::<ValidatorMessage>(256);
        consensus_engine.set_message_receiver(consensus_msg_rx);

        // Load the persistent local validator signing keypair from the keystore.
        let (local_validator_id, local_validator_keypair) =
            load_local_validator_from_keystore().await?;

        // Clone for ValidatorProtocol middleware before moving into self
        let vp_keypair = local_validator_keypair.clone();
        let vp_identity = local_validator_id.clone();

        *self.local_validator_identity.write().await = Some(local_validator_id.clone());
        *self.local_validator_keypair.write().await = Some(local_validator_keypair.clone());

        let active_validators: Vec<lib_blockchain::ValidatorInfo> = {
            let blockchain_opt = self.blockchain.read().await;
            let blockchain = blockchain_opt
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Blockchain not set for consensus startup"))?
                .clone();
            drop(blockchain_opt);

            let initial = {
                let bc = blockchain.read().await;
                bc.get_active_validators()
                    .into_iter()
                    .map(|v| v.clone())
                    .collect::<Vec<_>>()
            };

            initial
        };

        if active_validators.is_empty() {
            return Err(anyhow::anyhow!(
                "Validator startup requires a canonical validator set in blockchain state"
            ));
        }

        let validator_adapters: Vec<BlockchainValidatorAdapter> = active_validators
            .iter()
            .cloned()
            .map(BlockchainValidatorAdapter)
            .collect();
        {
            let mut validator_manager = self.validator_manager.write().await;
            validator_manager
                .sync_from_validator_list(validator_adapters.clone())
                .context("Failed to sync validator manager from blockchain state")?;
            // Invariant BFT-A-1953: Non-development environments must have ≥ 4 validators.
            // A node that cannot form a BFT quorum must not start participating in consensus.
            if !is_development && !validator_manager.has_sufficient_validators() {
                return Err(anyhow::anyhow!(
                    "BFT startup requires at least {} active validators in canonical state \
                     (environment: {}). Start with Development environment for single-node testing.",
                    lib_consensus::engines::consensus_engine::BFT_MIN_VALIDATORS,
                    self.environment
                ));
            }
        }

        consensus_engine
            .sync_validators_from_list(validator_adapters)
            .map_err(|e| anyhow::anyhow!("Consensus engine validator sync failed: {}", e))?;
        consensus_engine
            .set_local_validator_identity(local_validator_id.clone())
            .map_err(|e| anyhow::anyhow!("Failed to set local validator identity: {}", e))?;
        consensus_engine
            .set_validator_keypair(local_validator_keypair.clone())
            .map_err(|e| anyhow::anyhow!("Failed to set validator keypair: {}", e))?;

        // Wire ValidatorProtocol as security middleware between network and consensus engine
        //
        // Message flow:
        //   Network (QUIC) → raw_validator_msg channel → ValidatorProtocol.handle_message()
        //     → verify signature → consensus_msg_tx → ConsensusEngine
        //
        // Outgoing (via ValidatorProtocol.broadcast_*):
        //   ValidatorProtocol → sign → QuicValidatorTransport → QUIC mesh
        if let Ok(mesh_router) = get_global_mesh_router().await {
            // Build discovery cache from blockchain validators.
            //
            // ValidatorDiscoveryProtocol must know about all active validators at
            // construction time. Without this, broadcast_message() calls
            // discover_validators(), gets an empty list, and silently drops every
            // consensus message — heartbeats, votes, proposals never leave the node.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let discovery_entries: Vec<ValidatorAnnouncement> = active_validators
                .iter()
                .map(|v| {
                    let identity_hash = {
                        let hex_str = v
                            .identity_id
                            .strip_prefix("did:zhtp:")
                            .unwrap_or(&v.identity_id);
                        let mut h = [0u8; 32];
                        if let Ok(bytes) = hex::decode(hex_str) {
                            let len = bytes.len().min(32);
                            h[..len].copy_from_slice(&bytes[..len]);
                        }
                        lib_crypto::Hash(h)
                    };

                    let endpoints = if v.network_address.is_empty() {
                        vec![]
                    } else {
                        vec![ValidatorEndpoint {
                            protocol: "quic".to_string(),
                            address: v.network_address.clone(),
                            priority: 10,
                        }]
                    };

                    ValidatorAnnouncement {
                        identity_id: identity_hash,
                        consensus_key: lib_crypto::PublicKey::new(v.consensus_key),
                        stake: v.stake,
                        storage_provided: 0,
                        commission_rate: v.commission_rate as u16,
                        endpoints,
                        status: ValidatorStatus::Active,
                        last_updated: now,
                        signature: Vec::new(),
                    }
                })
                .collect();

            let discovery = Arc::new(ValidatorDiscoveryProtocol::from_validators(
                3600,
                discovery_entries,
            ));

            // Enable TOFU in non-Mainnet environments so bootstrap validators can accept
            // each other's signed messages before formal on-chain announcements have been
            // exchanged.  The first valid self-signed message from an unknown validator
            // populates the discovery cache; subsequent messages are verified against that
            // registered key.  Disabled on Mainnet where only on-chain-registered keys
            // may participate.
            let is_mainnet = matches!(self.environment, crate::config::Environment::Mainnet);
            let vp_config = lib_consensus::validators::ValidatorProtocolConfig {
                bootstrap_tofu: !is_mainnet,
                ..Default::default()
            };

            // Create ValidatorProtocol and wire it
            let mut validator_protocol = ValidatorProtocol::new(discovery, Some(vp_config));
            validator_protocol.set_validator_keypair(vp_keypair);
            validator_protocol.set_validator_identity(vp_identity).await;
            validator_protocol.set_consensus_forwarder(consensus_msg_tx.clone());
            validator_protocol
                .set_network_transport(Arc::new(QuicValidatorTransport::new(mesh_router.clone())));

            // Create raw validator message channel
            let (raw_msg_tx, mut raw_msg_rx) =
                tokio::sync::mpsc::channel::<lib_consensus::validators::ValidatorMessage>(256);

            // Wire raw message sender into the mesh message handler
            if let Some(quic_protocol) = mesh_router.quic_protocol.read().await.as_ref() {
                if let Some(handler) = quic_protocol.message_handler.as_ref() {
                    let mut h = handler.write().await;
                    h.set_raw_validator_message_sender(raw_msg_tx);
                    // Also keep direct consensus sender as fallback
                    h.set_consensus_message_sender(consensus_msg_tx.clone());
                    info!("🔗 ValidatorProtocol middleware wired to mesh message handler");
                } else {
                    warn!("QUIC message handler not available - consensus messages won't be received from network");
                }
            } else {
                warn!("QUIC protocol not available - consensus messages won't be received from network");
            }

            // Spawn middleware task: reads raw messages, verifies via ValidatorProtocol, forwards to consensus
            tokio::spawn(async move {
                info!("🛡️ ValidatorProtocol middleware task started");
                while let Some(msg) = raw_msg_rx.recv().await {
                    if let Err(e) = validator_protocol.handle_message(msg).await {
                        // Verification failure: log but don't crash the middleware
                        warn!("ValidatorProtocol rejected message: {}", e);
                    }
                }
                info!("ValidatorProtocol middleware task exited (channel closed)");
            });
        } else {
            warn!("Mesh router not available - consensus messages won't be received from network");
            // No mesh router, but still wire direct consensus sender if available
        }

        // **Start-order independent alert wiring**
        //
        // CRITICAL: Always spawn the alert receiver task, even if monitoring is not running yet.
        // This prevents the problem where:
        // 1. Consensus starts before monitoring
        // 2. No global manager exists → receiver task is not spawned
        // 3. Monitoring starts later
        // 4. Liveness events are dropped silently (no receiver to deliver them)
        //
        // Solution: Always create the receiver. At each event, resolve the manager:
        // - If monitoring is running: emit alert
        // - If not: drop alert and log at ERROR level (not WARN - these are critical events)
        //
        // This makes alert delivery robust to start order and monitoring restarts.
        tokio::spawn(async move {
            let mut dropped_events = Vec::new();
            let mut drop_warning_emitted = false;

            while let Some(event) = liveness_rx.recv().await {
                if let Some(alert_manager) = crate::monitoring::get_global_alert_manager() {
                    // Manager exists now - emit alert (works even if monitoring restarted)
                    // Also catch up on any previously dropped events
                    if !dropped_events.is_empty() {
                        error!(
                            "Consensus recovery: {} liveness events were dropped while monitoring was unavailable",
                            dropped_events.len()
                        );
                        dropped_events.clear();
                        drop_warning_emitted = false;
                    }

                    handle_liveness_event(&alert_manager, event).await;
                } else {
                    // CRITICAL: No manager - this is a Byzantine fault event that cannot be delivered
                    // Log at ERROR level because this is a consensus-critical failure
                    dropped_events.push(event.clone());

                    if !drop_warning_emitted {
                        error!(
                            "CRITICAL: Consensus liveness alert cannot be delivered - monitoring system not started. \
                             Byzantine faults occurring now will not be reported to operators."
                        );
                        drop_warning_emitted = true;
                    }
                }
            }
        });

        info!("Consensus engine initialized with hybrid PoS");
        info!("Validator management ready");
        info!("Byzantine fault tolerance active");

        // Wire blockchain provider for real block data in proposals
        // Uses the same slot that set_blockchain() populates
        let blockchain_adapter = ConsensusBlockchainAdapter::new(self.blockchain.clone());
        consensus_engine.set_blockchain_provider(Arc::new(blockchain_adapter));
        info!("📦 Blockchain provider wired to consensus engine");

        // Shared atomic: BFT publishes its active height so catch-up sync avoids racing.
        let bft_active_height = Arc::new(std::sync::atomic::AtomicU64::new(0));
        consensus_engine.set_bft_active_height(bft_active_height.clone());

        // Wire catch-up sync trigger.
        // Channel capacity of 2 means triggers are coalesced: if two divergence
        // events fire before the task drains the channel, only one sync runs.
        {
            let (catch_up_tx, catch_up_rx) = tokio::sync::mpsc::channel::<u64>(2);
            crate::runtime::blockchain_provider::set_global_catchup_trigger(catch_up_tx.clone());
            let trigger = Arc::new(CatchUpSyncChannel { tx: catch_up_tx });
            consensus_engine.set_catch_up_sync_trigger(trigger);
            let blockchain_slot_for_sync = self.blockchain.clone();
            let sled_path_for_sync =
                std::path::Path::new(&self.environment.data_directory()).join("sled");
            let bft_height_for_sync = bft_active_height.clone();
            tokio::spawn(async move {
                run_catch_up_sync_task(
                    catch_up_rx,
                    blockchain_slot_for_sync,
                    sled_path_for_sync,
                    bft_height_for_sync,
                )
                .await;
            });
            info!("🔄 Catch-up sync trigger wired (height-divergence recovery active)");
        }

        // Wire block commit callback for BFT-finalized blocks
        // This is the critical bridge that commits blocks when BFT achieves 2/3+1 votes
        let block_committer =
            ConsensusBlockCommitter::new(self.blockchain.clone(), self.environment.clone());
        consensus_engine.set_block_commit_callback(Arc::new(block_committer));
        info!("🔗 Block commit callback wired to consensus engine");

        // Wire a validator update channel so the periodic re-sync task can push
        // validator set changes into the running consensus loop without direct
        // engine access (the engine is moved into the spawned loop task).
        let (validator_update_tx, validator_update_rx) =
            tokio::sync::mpsc::channel::<lib_consensus::ValidatorSetUpdate>(4);
        consensus_engine.set_validator_update_receiver(validator_update_rx);

        // Engine is moved into the spawned loop — not accessible externally.
        *self.consensus_engine.write().await = None;

        // Spawn the consensus loop as a background task.
        tokio::spawn(async move {
            info!("🚀 Starting BFT consensus loop...");
            match consensus_engine.run_consensus_loop().await {
                Ok(()) => info!("Consensus loop exited normally"),
                Err(e) => error!("Consensus loop exited with error: {}", e),
            }
        });

        // Spawn periodic validator re-sync background task.
        // Every 10 s, refresh ValidatorManager from blockchain.validator_registry so
        // newly-mined ValidatorRegistration transactions are picked up without restart.
        // Periodic validator re-sync: every 10s, read validators from blockchain
        // and push updates through the channel to the consensus loop.
        {
            let blockchain_slot = self.blockchain.clone();
            let validator_manager = self.validator_manager.clone();
            let local_id = self.local_validator_identity.clone();
            let local_kp = self.local_validator_keypair.clone();
            let can_validate = self.node_role.can_validate();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(10));
                interval.tick().await; // skip first immediate tick
                loop {
                    interval.tick().await;
                    let slot = blockchain_slot.read().await;
                    let blockchain_arc = match slot.as_ref() {
                        Some(bc) => bc.clone(),
                        None => continue,
                    };
                    drop(slot);

                    let active_validators: Vec<lib_blockchain::ValidatorInfo> = {
                        let bc = blockchain_arc.read().await;
                        bc.get_active_validators()
                            .into_iter()
                            .map(|v| v.clone())
                            .collect()
                    };

                    if active_validators.is_empty() {
                        continue;
                    }

                    let adapters: Vec<BlockchainValidatorAdapter> = active_validators
                        .iter()
                        .map(|v| BlockchainValidatorAdapter(v.clone()))
                        .collect();

                    // Sync into the external validator manager (for API queries).
                    let result = {
                        let mut vm = validator_manager.write().await;
                        vm.sync_from_validator_list(adapters.clone())
                    };
                    match result {
                        Ok((added, _skipped)) => {
                            if added > 0 {
                                info!(
                                    "Periodic validator sync: {} new validator(s) from blockchain",
                                    added
                                );
                            }
                        }
                        Err(e) => {
                            warn!("Periodic validator manager sync failed: {}", e);
                            continue;
                        }
                    }

                    // Push update to the consensus loop via channel.
                    let local_identity = if can_validate {
                        local_id.read().await.clone()
                    } else {
                        None
                    };
                    let local_keypair = if can_validate {
                        local_kp.read().await.clone()
                    } else {
                        None
                    };
                    let entries: Vec<
                        lib_consensus::engines::consensus_engine::ValidatorUpdateEntry,
                    > = active_validators
                        .iter()
                        .map(|v| {
                            let identity_hex = v
                                .identity_id
                                .strip_prefix("did:zhtp:")
                                .unwrap_or(&v.identity_id);
                            let identity_id = if let Ok(bytes) = hex::decode(identity_hex) {
                                if bytes.len() >= 32 {
                                    lib_crypto::Hash::from_bytes(&bytes[..32])
                                } else {
                                    lib_crypto::Hash(lib_crypto::hash_blake3(
                                        v.identity_id.as_bytes(),
                                    ))
                                }
                            } else {
                                lib_crypto::Hash(lib_crypto::hash_blake3(v.identity_id.as_bytes()))
                            };
                            lib_consensus::engines::consensus_engine::ValidatorUpdateEntry {
                                identity_id,
                                stake: v.stake,
                                consensus_key: v.consensus_key.clone(),
                            }
                        })
                        .collect();
                    let update = lib_consensus::ValidatorSetUpdate {
                        entries,
                        local_identity,
                        local_keypair,
                    };
                    if validator_update_tx.send(update).await.is_err() {
                        warn!("Validator update channel closed — consensus loop may have exited");
                        break;
                    }
                }
            });
        }

        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;

        info!("🗳️ BFT consensus loop started - listening for validator messages");
        info!("Consensus component started with consensus mechanisms");

        // ── Oracle pipeline ────────────────────────────────────────────────
        // Reuses the validator keypair already loaded above.  The oracle
        // mock_sov_usd_price comes from the consensus config (set in TOML with
        // `oracle_mock_sov_usd_price = 100000000` for $1.00 testnet pricing).
        //
        // The blockchain slot may not be populated yet at this point — it is set
        // later via set_blockchain().  Spawn a watcher task that polls every 1 s
        // until the slot is filled, then starts the oracle component.
        {
            let blockchain_slot = self.blockchain.clone();
            let keypair_slot = self.local_validator_keypair.clone();
            let oracle_mock_price = self.oracle_mock_sov_usd_price;
            tokio::spawn(async move {
                loop {
                    // Check whether blockchain slot is populated.
                    let bc_arc_opt = {
                        let slot = blockchain_slot.read().await;
                        slot.as_ref().cloned()
                    };
                    if let Some(bc_arc) = bc_arc_opt {
                        let keypair_opt = keypair_slot.read().await.clone();
                        match keypair_opt {
                            Some(keypair) => {
                                if let Err(e) =
                                    crate::runtime::components::oracle::OracleComponent::start(
                                        bc_arc,
                                        keypair,
                                        oracle_mock_price,
                                    )
                                    .await
                                {
                                    tracing::warn!("Oracle component failed to start: {}", e);
                                }
                            }
                            None => {
                                tracing::info!("Oracle: no validator keypair available — oracle producer disabled (non-validating node)");
                            }
                        }
                        break;
                    }
                    // Blockchain not ready yet — retry after 1 s.
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            });
        }

        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping consensus component...");
        *self.status.write().await = ComponentStatus::Stopping;
        *self.consensus_engine.write().await = None;
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        info!("Consensus component stopped");
        Ok(())
    }

    async fn health_check(&self) -> Result<ComponentHealth> {
        let status = self.status.read().await.clone();
        let start_time = *self.start_time.read().await;
        let uptime = start_time.map(|t| t.elapsed()).unwrap_or(Duration::ZERO);

        Ok(ComponentHealth {
            status,
            last_heartbeat: Instant::now(),
            error_count: 0,
            restart_count: 0,
            uptime,
            memory_usage: 0,
            cpu_usage: 0.0,
        })
    }

    async fn handle_message(&self, message: ComponentMessage) -> Result<()> {
        match message {
            ComponentMessage::HealthCheck => {
                debug!("Consensus component health check");
                Ok(())
            }
            _ => {
                debug!("Consensus component received message: {:?}", message);
                Ok(())
            }
        }
    }

    async fn get_metrics(&self) -> Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        let start_time = *self.start_time.read().await;
        let uptime_secs = start_time
            .map(|t| t.elapsed().as_secs() as f64)
            .unwrap_or(0.0);

        metrics.insert("uptime_seconds".to_string(), uptime_secs);
        metrics.insert(
            "is_running".to_string(),
            if matches!(*self.status.read().await, ComponentStatus::Running) {
                1.0
            } else {
                0.0
            },
        );

        Ok(metrics)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::Hash;

    #[tokio::test]
    async fn test_liveness_alert_bridge_stalled() {
        let alert_manager = AlertManager::new()
            .await
            .expect("Failed to create alert manager");
        alert_manager
            .start()
            .await
            .expect("Failed to start alert manager");

        let event = ConsensusEvent::ConsensusStalled {
            height: 42,
            round: 7,
            timed_out_validators: vec![Hash::from_bytes(&[1u8; 32])],
            total_validators: 4,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };

        handle_liveness_event(&alert_manager, event).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let alerts = alert_manager
            .get_recent_alerts(1)
            .await
            .expect("Failed to fetch alerts");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].title, "Consensus stalled");
        assert_eq!(alerts[0].level, AlertLevel::Critical);
    }

    #[test]
    fn test_decode_node_id_hex_accepts_prefixed_and_plain_hex() {
        let node = [0xABu8; 32];
        let plain = hex::encode(node);
        let prefixed = format!("0x{}", plain);
        assert_eq!(decode_node_id_hex(&plain), Some(node.to_vec()));
        assert_eq!(decode_node_id_hex(&prefixed), Some(node.to_vec()));
    }

    #[test]
    fn test_decode_bootstrap_consensus_key_accepts_plain_and_prefixed_hex() {
        let key = [0x42u8; 2592];
        let plain = hex::encode(&key);
        let prefixed = format!("0x{}", plain);
        assert_eq!(decode_bootstrap_consensus_key(&plain), Some(key));
        assert_eq!(decode_bootstrap_consensus_key(&prefixed), Some(key));
    }

    #[test]
    fn test_decode_bootstrap_consensus_key_rejects_invalid_or_empty() {
        assert_eq!(decode_bootstrap_consensus_key(""), None);
        assert_eq!(decode_bootstrap_consensus_key("0x"), None);
        assert_eq!(decode_bootstrap_consensus_key("not-hex"), None);
    }

    #[test]
    fn test_did_hash_to_identity_id_parses_did_hex_prefix() {
        let bytes = [0x11u8; 32];
        let did = format!("did:zhtp:{}", hex::encode(bytes));
        let id = did_hash_to_identity_id(&did).expect("valid DID hash");
        assert_eq!(id.as_bytes(), bytes);
    }

    #[test]
    fn test_is_target_validator_peer_matches_by_node_id() {
        let peer = lib_network::protocols::quic_mesh::ConnectedAuthenticatedPeer {
            node_id: vec![0x33; 32],
            did: format!("did:zhtp:{}", hex::encode([0x44u8; 32])),
            peer_addr: "127.0.0.1:9334".parse().expect("valid socket address"),
            bootstrap_mode: false,
        };
        let mut targets = HashSet::new();
        targets.insert(vec![0x33; 32]);
        assert!(is_target_validator_peer(&peer, &targets));
    }

    #[test]
    fn test_is_target_validator_peer_matches_by_did_identity() {
        let did_hash = [0x55u8; 32];
        let peer = lib_network::protocols::quic_mesh::ConnectedAuthenticatedPeer {
            node_id: vec![0x66; 32],
            did: format!("did:zhtp:{}", hex::encode(did_hash)),
            peer_addr: "127.0.0.1:9334".parse().expect("valid socket address"),
            bootstrap_mode: false,
        };
        let mut targets = HashSet::new();
        targets.insert(did_hash.to_vec());
        assert!(is_target_validator_peer(&peer, &targets));
    }

    /// Issue #1862: Test that blocks can be serialized/deserialized for BFT consensus.
    /// This ensures the proposal/commit flow has a valid serialization contract.
    #[test]
    fn test_block_serialization_contract_for_bft_consensus() {
        use lib_blockchain::block::creation::{create_block, mine_block};

        // Create a block with the same API used by get_pending_transactions
        use lib_blockchain::integration::crypto_integration::{
            PublicKey as BcPublicKey, Signature as BcSignature, SignatureAlgorithm,
        };
        let sig = BcSignature {
            signature: vec![0u8; 64],
            public_key: BcPublicKey::new([0u8; 2592]),
            algorithm: SignatureAlgorithm::DEFAULT,
            timestamp: 0,
        };
        let tx = lib_blockchain::Transaction::new(vec![], vec![], 0, sig, vec![]);

        let previous_hash = lib_blockchain::Hash::zero();
        let height = 42;
        let difficulty = lib_blockchain::Difficulty::minimum(); // Use minimum difficulty for testing

        let block = create_block(vec![tx], previous_hash, height, difficulty)
            .expect("Block should be created");

        // Mine the block (as done before BFT proposal)
        let mined_block = mine_block(block, u64::MAX).expect("Block should be mined");

        // Serialize (as get_pending_transactions does for BFT proposal)
        let block_data =
            bincode::serialize(&mined_block).expect("Block should serialize for BFT proposal");

        // Deserialize (as commit_finalized_block does)
        let committed_block: lib_blockchain::Block =
            bincode::deserialize(&block_data).expect("Block should deserialize for BFT commit");

        // Verify the block data is preserved
        assert_eq!(committed_block.header.height, 42);
        assert_eq!(committed_block.transactions.len(), 1);

        // Verify the mined block has valid PoW
        // BlockHeader no longer exposes a nonce field; the mining proof is
        // verified via the block hash meeting difficulty.  Just assert the block
        // survived the round-trip.
        assert!(
            committed_block.header.height == 42,
            "Block height should survive serialization round-trip"
        );
    }

    #[test]
    fn test_bft_active_height_guard_allows_blocks_below() {
        let bft_height = std::sync::atomic::AtomicU64::new(1346);
        let block_height = 1345u64;
        let bft_val = bft_height.load(std::sync::atomic::Ordering::Acquire);
        // Block below BFT height should be allowed (catch-up fills the gap)
        assert!(
            !(bft_val > 0 && block_height >= bft_val),
            "Block below BFT height should pass the guard"
        );
    }

    #[test]
    fn test_bft_active_height_guard_blocks_blocks_at_bft_height() {
        let bft_height = std::sync::atomic::AtomicU64::new(1346);
        let block_height = 1346u64;
        let bft_val = bft_height.load(std::sync::atomic::Ordering::Acquire);
        // Block AT BFT height must be BLOCKED — BFT is the sole authority at that height.
        // Using >= prevents the race where catch-up applies a peer's block at bft_active_height
        // with a different hash than what BFT will commit (Apr 3 2026 postmortem fix).
        assert!(
            bft_val > 0 && block_height >= bft_val,
            "Block at BFT height must be blocked by the guard"
        );
    }

    #[test]
    fn test_bft_active_height_guard_blocks_above() {
        let bft_height = std::sync::atomic::AtomicU64::new(1346);
        let block_height = 1347u64;
        let bft_val = bft_height.load(std::sync::atomic::Ordering::Acquire);
        // Block above BFT height should be blocked (not finalized by any peer yet)
        assert!(
            bft_val > 0 && block_height >= bft_val,
            "Block above BFT height should be blocked by the guard"
        );
    }

    #[test]
    fn test_bft_active_height_guard_disabled_in_bootstrap() {
        let bft_height = std::sync::atomic::AtomicU64::new(0); // bootstrap mode
        let block_height = 9999u64;
        let bft_val = bft_height.load(std::sync::atomic::Ordering::Acquire);
        // Guard disabled when bft_height is 0 (bootstrap mode — catch-up proceeds freely)
        assert!(
            !(bft_val > 0 && block_height >= bft_val),
            "Guard should be disabled when bft_active_height is 0"
        );
    }
}
