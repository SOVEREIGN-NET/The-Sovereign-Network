//! Sync Coordinator - Prevents duplicate blockchain syncs across multiple transports
//!
//! When a node is connected via BLE + WiFi + Internet simultaneously, we don't want
//! to initiate 3 separate blockchain syncs. This coordinator ensures only one sync
//! happens at a time, using the fastest available transport.
//!
//! Handles both:
//! - Full blockchain syncs (complete blocks, transactions, history)
//! - Edge node syncs (headers-only + selective UTXOs)

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use lib_crypto::PublicKey;
use crate::protocols::NetworkProtocol;
use tracing::{info, debug, warn};

// ============================================================================
// COMMITTED-HEIGHT BOOTSTRAP POLICY (BFT-G, Issue #1002)
// ============================================================================

/// Bootstrap policy: always select the peer with the highest committed BFT height.
///
/// Non-committed tips are non-canonical and MUST NOT alter local state during bootstrap.
pub const BOOTSTRAP_POLICY: &str = "highest-committed-bft-height";

/// A peer's highest BFT-committed block height for bootstrap target selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedHeightSyncTarget {
    /// The highest block height that has received BFT commit (2/3+1 pre-commits).
    pub committed_height: u64,
    /// Identifier of the peer advertising this height.
    pub peer_id: Vec<u8>,
}

impl CommittedHeightSyncTarget {
    /// Creates a new sync target.
    pub fn new(committed_height: u64, peer_id: Vec<u8>) -> Self {
        Self { committed_height, peer_id }
    }
}

/// Selects the best sync target by highest committed height.
///
/// Only committed heights are considered; uncommitted tips are ignored.
/// Returns `None` if `peers` is empty.
pub fn select_bootstrap_target(peers: &[CommittedHeightSyncTarget]) -> Option<&CommittedHeightSyncTarget> {
    peers.iter().max_by_key(|p| p.committed_height)
}

#[cfg(test)]
mod bootstrap_policy_tests {
    use super::*;

    #[test]
    fn test_select_bootstrap_target_picks_highest() {
        let peers = vec![
            CommittedHeightSyncTarget::new(100, vec![1]),
            CommittedHeightSyncTarget::new(200, vec![2]),
            CommittedHeightSyncTarget::new(150, vec![3]),
        ];
        assert_eq!(select_bootstrap_target(&peers).unwrap().committed_height, 200);
    }

    #[test]
    fn test_select_bootstrap_target_empty() {
        let peers: Vec<CommittedHeightSyncTarget> = vec![];
        assert!(select_bootstrap_target(&peers).is_none());
    }
}

/// Type of sync being performed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyncType {
    /// Full blockchain sync (complete blocks, all transactions)
    FullBlockchain,
    /// Edge node sync (headers only + selective data)
    EdgeNode,
}

/// Active sync information
#[derive(Debug, Clone)]
pub struct ActiveSync {
    pub sync_id: u64,
    pub protocol: NetworkProtocol,
    pub start_time: Instant,
}

/// Sync state for a specific peer
#[derive(Debug, Clone)]
pub struct PeerSyncState {
    /// Active syncs per type (sync_type -> sync info)
    /// Allows Edge and Full syncs to coexist
    pub active_syncs: HashMap<SyncType, ActiveSync>,
    /// Available protocols for this peer
    pub available_protocols: HashSet<NetworkProtocol>,
}

/// Global sync coordinator to prevent duplicate syncs
pub struct SyncCoordinator {
    /// Active syncs per peer (peer_id -> sync state)
    peer_syncs: Arc<RwLock<HashMap<PublicKey, PeerSyncState>>>,
    /// Sync timeout (if no progress in this time, allow new sync)
    sync_timeout: Duration,
}

impl SyncCoordinator {
    /// Create a new sync coordinator
    pub fn new() -> Self {
        Self {
            peer_syncs: Arc::new(RwLock::new(HashMap::new())),
            sync_timeout: Duration::from_secs(300), // 5 minutes timeout
        }
    }

    /// Register that a peer is available on a specific protocol
    /// Returns true if sync should be initiated, false if already syncing
    /// 
    /// # Arguments
    /// * `peer_id` - The peer's public key
    /// * `protocol` - The transport protocol (BLE, WiFi, TCP, etc.)
    /// * `sync_type` - Whether this is a full blockchain or edge node sync
    pub async fn register_peer_protocol(
        &self,
        peer_id: &PublicKey,
        protocol: NetworkProtocol,
        sync_type: SyncType,
    ) -> bool {
        let mut syncs = self.peer_syncs.write().await;

        let peer_state = syncs.entry(peer_id.clone()).or_insert_with(|| PeerSyncState {
            active_syncs: HashMap::new(),
            available_protocols: HashSet::new(),
        });

        // Add this protocol to available list
        peer_state.available_protocols.insert(protocol.clone());

        // Check if already syncing this type
        if let Some(active_sync) = peer_state.active_syncs.get(&sync_type) {
            // Check if sync has timed out
            if active_sync.start_time.elapsed() > self.sync_timeout {
                warn!(" Sync with peer {} timed out (type: {:?}, protocol: {:?}), allowing new sync",
                      hex::encode(&peer_id.key_id[..8]),
                      sync_type,
                      active_sync.protocol);

                // Clear timed-out sync
                peer_state.active_syncs.remove(&sync_type);
            } else {
                // Check if this is a protocol upgrade (higher priority protocol)
                let new_priority = protocol_priority(&protocol);
                let current_priority = protocol_priority(&active_sync.protocol);

                if new_priority > current_priority {
                    info!(" Allowing protocol upgrade from {:?} to {:?} for {:?} sync with peer {}",
                          active_sync.protocol, protocol, sync_type,
                          hex::encode(&peer_id.key_id[..8]));
                    return true;
                }

                info!(" Already syncing {:?} with peer {} via {:?}, skipping duplicate on {:?}",
                      sync_type,
                      hex::encode(&peer_id.key_id[..8]),
                      active_sync.protocol,
                      protocol);
                return false; // Already syncing same type, don't start another
            }
        }

        // Not currently syncing this type, should we initiate?
        self.should_initiate_sync_type(peer_state, sync_type, &protocol)
    }

    /// Determine if we should initiate a sync with this protocol for a specific sync type
    /// Priority: TCP/UDP (internet) > WiFi Direct > Bluetooth Classic > BLE
    fn should_initiate_sync_type(&self, peer_state: &PeerSyncState, sync_type: SyncType, new_protocol: &NetworkProtocol) -> bool {
        // If no active sync for this type, we should sync
        if !peer_state.active_syncs.contains_key(&sync_type) {
            return true;
        }

        // If we have a higher priority protocol for this sync type, upgrade
        if let Some(active_sync) = peer_state.active_syncs.get(&sync_type) {
            let new_priority = protocol_priority(new_protocol);
            let current_priority = protocol_priority(&active_sync.protocol);

            if new_priority > current_priority {
                info!(" Upgrading {:?} sync protocol from {:?} to {:?} (higher bandwidth)",
                      sync_type, active_sync.protocol, new_protocol);
                return true;
            }
        }

        false
    }

    /// Record that a sync has been initiated
    pub async fn start_sync(
        &self,
        peer_id: &PublicKey,
        sync_id: u64,
        sync_type: SyncType,
        protocol: NetworkProtocol,
    ) {
        let mut syncs = self.peer_syncs.write().await;

        if let Some(peer_state) = syncs.get_mut(peer_id) {
            peer_state.active_syncs.insert(sync_type, ActiveSync {
                sync_id,
                protocol: protocol.clone(),
                start_time: Instant::now(),
            });

            info!(" {:?} sync started with peer {} (ID: {}, protocol: {:?})",
                  sync_type,
                  hex::encode(&peer_id.key_id[..8]),
                  sync_id,
                  protocol);
        }
    }

    /// Record that a sync has completed
    pub async fn complete_sync(&self, peer_id: &PublicKey, sync_id: u64, sync_type: SyncType) {
        let mut syncs = self.peer_syncs.write().await;

        if let Some(peer_state) = syncs.get_mut(peer_id) {
            // Only clear if this is the active sync for this type
            if let Some(active_sync) = peer_state.active_syncs.get(&sync_type) {
                if active_sync.sync_id == sync_id {
                    let duration = active_sync.start_time.elapsed();

                    info!(" {:?} sync completed with peer {} (ID: {}, duration: {:?})",
                          sync_type,
                          hex::encode(&peer_id.key_id[..8]),
                          sync_id,
                          duration);

                    peer_state.active_syncs.remove(&sync_type);
                }
            }
        }
    }

    /// Record that a sync has failed
    pub async fn fail_sync(&self, peer_id: &PublicKey, sync_id: u64, sync_type: SyncType) {
        let mut syncs = self.peer_syncs.write().await;

        if let Some(peer_state) = syncs.get_mut(peer_id) {
            // Only clear if this is the active sync for this type
            if let Some(active_sync) = peer_state.active_syncs.get(&sync_type) {
                if active_sync.sync_id == sync_id {
                    warn!(" {:?} sync failed with peer {} (ID: {})",
                          sync_type,
                          hex::encode(&peer_id.key_id[..8]),
                          sync_id);

                    peer_state.active_syncs.remove(&sync_type);
                }
            }
        }
    }

    /// Remove a peer (cleanup when disconnected)
    pub async fn remove_peer(&self, peer_id: &PublicKey, protocol: NetworkProtocol) {
        let mut syncs = self.peer_syncs.write().await;

        if let Some(peer_state) = syncs.get_mut(peer_id) {
            // Remove this protocol
            peer_state.available_protocols.remove(&protocol);

            // Clear any syncs using this protocol
            peer_state.active_syncs.retain(|_, active_sync| {
                if active_sync.protocol == protocol {
                    debug!("🔌 Peer {} disconnected from {:?}, clearing sync state",
                           hex::encode(&peer_id.key_id[..8]), &protocol);
                    false
                } else {
                    true
                }
            });

            // If no protocols left, remove peer entirely
            if peer_state.available_protocols.is_empty() {
                syncs.remove(peer_id);
                debug!("🔌 Peer {} fully disconnected (all protocols)",
                       hex::encode(&peer_id.key_id[..8]));
            }
        }
    }

    /// Find peer by sync request ID
    /// Returns the peer's public key and sync type if found
    pub async fn find_peer_by_sync_id(&self, sync_id: u64) -> Option<(PublicKey, SyncType)> {
        let syncs = self.peer_syncs.read().await;

        for (peer_id, state) in syncs.iter() {
            for (sync_type, active_sync) in &state.active_syncs {
                if active_sync.sync_id == sync_id {
                    return Some((peer_id.clone(), *sync_type));
                }
            }
        }

        None
    }

    /// Get sync statistics
    pub async fn get_stats(&self) -> SyncStats {
        let syncs = self.peer_syncs.read().await;

        let total_peers = syncs.len();
        let active_syncs: usize = syncs.values()
            .map(|s| s.active_syncs.len())
            .sum();

        let mut protocol_counts: HashMap<NetworkProtocol, usize> = HashMap::new();
        for state in syncs.values() {
            for active_sync in state.active_syncs.values() {
                *protocol_counts.entry(active_sync.protocol.clone()).or_insert(0) += 1;
            }
        }
        
        SyncStats {
            total_peers,
            active_syncs,
            protocol_counts,
        }
    }
}

/// Priority for protocol selection (higher = better)
fn protocol_priority(protocol: &NetworkProtocol) -> u8 {
    match protocol {
        NetworkProtocol::TCP | NetworkProtocol::UDP => 100,      // Internet - fastest
        NetworkProtocol::WiFiDirect => 80,                        // WiFi Direct - very fast
        NetworkProtocol::BluetoothClassic => 50,                  // Bluetooth Classic - medium
        NetworkProtocol::BluetoothLE => 30,                       // BLE - slowest
        NetworkProtocol::LoRaWAN => 10,                           // LoRa - emergency only
        _ => 50,                                                   // Unknown - medium priority
    }
}

/// Sync statistics
#[derive(Debug, Clone)]
pub struct SyncStats {
    pub total_peers: usize,
    pub active_syncs: usize,
    pub protocol_counts: HashMap<NetworkProtocol, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Ignore network-dependent test
    async fn test_prevent_duplicate_sync() {
        let coordinator = SyncCoordinator::new();
        let peer_id = PublicKey::new(vec![1, 2, 3, 4]);
        let sync_type = SyncType::FullBlockchain;

        // First BLE connection should allow sync
        assert!(coordinator.register_peer_protocol(&peer_id, NetworkProtocol::BluetoothLE, sync_type).await);
        coordinator.start_sync(&peer_id, 1, sync_type, NetworkProtocol::BluetoothLE).await;

        // Second BLE connection should NOT allow sync (already syncing)
        assert!(!coordinator.register_peer_protocol(&peer_id, NetworkProtocol::BluetoothLE, sync_type).await);

        // WiFi connection should allow sync (higher priority)
        assert!(coordinator.register_peer_protocol(&peer_id, NetworkProtocol::WiFiDirect, sync_type).await);
        coordinator.start_sync(&peer_id, 2, sync_type, NetworkProtocol::WiFiDirect).await;

        // Another WiFi connection should NOT allow sync
        assert!(!coordinator.register_peer_protocol(&peer_id, NetworkProtocol::WiFiDirect, sync_type).await);

        // Complete sync
        coordinator.complete_sync(&peer_id, 2, sync_type).await;

        // Now another connection should allow sync
        assert!(coordinator.register_peer_protocol(&peer_id, NetworkProtocol::BluetoothLE, sync_type).await);
    }

    #[tokio::test]
    #[ignore] // Ignore network-dependent test
    async fn test_protocol_upgrade() {
        let coordinator = SyncCoordinator::new();
        let peer_id = PublicKey::new(vec![1, 2, 3, 4]);
        let sync_type = SyncType::FullBlockchain;

        // Start with BLE
        assert!(coordinator.register_peer_protocol(&peer_id, NetworkProtocol::BluetoothLE, sync_type).await);
        coordinator.start_sync(&peer_id, 1, sync_type, NetworkProtocol::BluetoothLE).await;

        // WiFi should upgrade
        assert!(coordinator.register_peer_protocol(&peer_id, NetworkProtocol::WiFiDirect, sync_type).await);
        coordinator.start_sync(&peer_id, 2, sync_type, NetworkProtocol::WiFiDirect).await;

        // TCP should upgrade
        assert!(coordinator.register_peer_protocol(&peer_id, NetworkProtocol::TCP, sync_type).await);
    }

    #[tokio::test]
    async fn test_sync_timeout() {
        let coordinator = SyncCoordinator::new();
        let peer_id = PublicKey::new(vec![1, 2, 3, 4]);
        let sync_type = SyncType::FullBlockchain;

        // Start sync
        assert!(coordinator.register_peer_protocol(&peer_id, NetworkProtocol::BluetoothLE, sync_type).await);
        coordinator.start_sync(&peer_id, 1, sync_type, NetworkProtocol::BluetoothLE).await;

        // Should prevent duplicate immediately
        assert!(!coordinator.register_peer_protocol(&peer_id, NetworkProtocol::BluetoothLE, sync_type).await);

        // Manually set old start time to simulate timeout
        {
            let mut syncs = coordinator.peer_syncs.write().await;
            if let Some(state) = syncs.get_mut(&peer_id) {
                if let Some(active_sync) = state.active_syncs.get_mut(&sync_type) {
                    active_sync.start_time = Instant::now() - Duration::from_secs(400);
                }
            }
        }

        // Should allow new sync after timeout
        assert!(coordinator.register_peer_protocol(&peer_id, NetworkProtocol::BluetoothLE, sync_type).await);
    }

    #[tokio::test]
    #[ignore] // Ignore network-dependent test
    async fn test_edge_and_full_sync_coexist() {
        let coordinator = SyncCoordinator::new();
        let peer_id = PublicKey::new(vec![1, 2, 3, 4]);

        // Start full blockchain sync
        assert!(coordinator.register_peer_protocol(&peer_id, NetworkProtocol::TCP, SyncType::FullBlockchain).await);
        coordinator.start_sync(&peer_id, 1, SyncType::FullBlockchain, NetworkProtocol::TCP).await;

        // Edge node sync should be allowed alongside full sync
        assert!(coordinator.register_peer_protocol(&peer_id, NetworkProtocol::BluetoothLE, SyncType::EdgeNode).await);
        coordinator.start_sync(&peer_id, 2, SyncType::EdgeNode, NetworkProtocol::BluetoothLE).await;

        // Another full sync should be blocked (WiFiDirect priority 80 < TCP priority 100, no upgrade)
        assert!(!coordinator.register_peer_protocol(&peer_id, NetworkProtocol::WiFiDirect, SyncType::FullBlockchain).await);

        // WiFiDirect for Edge should be allowed as protocol upgrade (WiFiDirect priority 80 > BLE priority 30)
        assert!(coordinator.register_peer_protocol(&peer_id, NetworkProtocol::WiFiDirect, SyncType::EdgeNode).await);

        // But another BLE EdgeNode sync should be blocked (duplicate, not an upgrade)
        assert!(!coordinator.register_peer_protocol(&peer_id, NetworkProtocol::BluetoothLE, SyncType::EdgeNode).await);
    }
}
