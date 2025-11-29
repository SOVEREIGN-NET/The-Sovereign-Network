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

/// Type of sync being performed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncType {
    /// Full blockchain sync (complete blocks, all transactions)
    FullBlockchain,
    /// Edge node sync (headers only + selective data)
    EdgeNode,
}

/// Sync state for a specific peer
#[derive(Debug, Clone)]
pub struct PeerSyncState {
    /// Currently active sync request ID (if any)
    pub active_sync_id: Option<u64>,
    /// Type of sync being performed
    pub sync_type: Option<SyncType>,
    /// Protocol being used for sync
    pub sync_protocol: Option<NetworkProtocol>,
    /// When the sync started
    pub sync_start_time: Option<Instant>,
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
            active_sync_id: None,
            sync_type: None,
            sync_protocol: None,
            sync_start_time: None,
            available_protocols: HashSet::new(),
        });

        // Add this protocol to available list
        peer_state.available_protocols.insert(protocol.clone());

        // Check if already syncing
        if let Some(active_sync_start) = peer_state.sync_start_time {
            // Check if sync has timed out
            if active_sync_start.elapsed() > self.sync_timeout {
                warn!(" Sync with peer {} timed out (type: {:?}, protocol: {:?}), allowing new sync", 
                      hex::encode(&peer_id.key_id[..8]), 
                      peer_state.sync_type,
                      peer_state.sync_protocol);
                
                // Clear timed-out sync
                peer_state.active_sync_id = None;
                peer_state.sync_type = None;
                peer_state.sync_protocol = None;
                peer_state.sync_start_time = None;
            } else {
                // Check if sync types are compatible
                if let Some(active_sync_type) = peer_state.sync_type {
                    if active_sync_type != sync_type {
                        // Different sync type - allow both (edge and full can coexist)
                        info!(" Allowing {:?} sync alongside existing {:?} sync with peer {}",
                              sync_type,
                              active_sync_type,
                              hex::encode(&peer_id.key_id[..8]));
                        return true;
                    }
                }
                
                info!(" Already syncing {:?} with peer {} via {:?}, skipping duplicate on {:?}",
                      peer_state.sync_type.unwrap_or(sync_type),
                      hex::encode(&peer_id.key_id[..8]),
                      peer_state.sync_protocol,
                      protocol);
                return false; // Already syncing same type, don't start another
            }
        }

        // Not currently syncing, should we initiate?
        self.should_initiate_sync(peer_state, &protocol)
    }

    /// Determine if we should initiate a sync with this protocol
    /// Priority: TCP/UDP (internet) > WiFi Direct > Bluetooth Classic > BLE
    fn should_initiate_sync(&self, peer_state: &PeerSyncState, new_protocol: &NetworkProtocol) -> bool {
        // If no active sync, we should sync
        if peer_state.active_sync_id.is_none() {
            return true;
        }

        // If we have a higher priority protocol, upgrade
        if let Some(current_protocol) = &peer_state.sync_protocol {
            let new_priority = protocol_priority(new_protocol);
            let current_priority = protocol_priority(current_protocol);
            
            if new_priority > current_priority {
                info!(" Upgrading sync protocol from {:?} to {:?} (higher bandwidth)",
                      current_protocol, new_protocol);
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
            peer_state.active_sync_id = Some(sync_id);
            peer_state.sync_type = Some(sync_type);
            peer_state.sync_protocol = Some(protocol.clone());
            peer_state.sync_start_time = Some(Instant::now());
            
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
            // Only clear if this is the active sync
            if peer_state.active_sync_id == Some(sync_id) && peer_state.sync_type == Some(sync_type) {
                let duration = peer_state.sync_start_time.map(|t| t.elapsed());
                
                info!(" {:?} sync completed with peer {} (ID: {}, duration: {:?})",
                      sync_type,
                      hex::encode(&peer_id.key_id[..8]), 
                      sync_id,
                      duration);
                
                peer_state.active_sync_id = None;
                peer_state.sync_type = None;
                peer_state.sync_protocol = None;
                peer_state.sync_start_time = None;
            }
        }
    }

    /// Record that a sync has failed
    pub async fn fail_sync(&self, peer_id: &PublicKey, sync_id: u64, sync_type: SyncType) {
        let mut syncs = self.peer_syncs.write().await;
        
        if let Some(peer_state) = syncs.get_mut(peer_id) {
            // Only clear if this is the active sync
            if peer_state.active_sync_id == Some(sync_id) && peer_state.sync_type == Some(sync_type) {
                warn!(" {:?} sync failed with peer {} (ID: {})",
                      sync_type,
                      hex::encode(&peer_id.key_id[..8]), 
                      sync_id);
                
                peer_state.active_sync_id = None;
                peer_state.sync_type = None;
                peer_state.sync_protocol = None;
                peer_state.sync_start_time = None;
            }
        }
    }

    /// Remove a peer (cleanup when disconnected)
    pub async fn remove_peer(&self, peer_id: &PublicKey, protocol: NetworkProtocol) {
        let mut syncs = self.peer_syncs.write().await;
        
        if let Some(peer_state) = syncs.get_mut(peer_id) {
            // Remove this protocol
            peer_state.available_protocols.remove(&protocol);
            
            // If this was the protocol we were syncing on, clear the sync
            if peer_state.sync_protocol.as_ref() == Some(&protocol) {
                debug!("🔌 Peer {} disconnected from {:?}, clearing sync state",
                       hex::encode(&peer_id.key_id[..8]), &protocol);
                
                peer_state.active_sync_id = None;
                peer_state.sync_protocol = None;
                peer_state.sync_start_time = None;
            }
            
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
            if state.active_sync_id == Some(sync_id) {
                if let Some(sync_type) = state.sync_type {
                    return Some((peer_id.clone(), sync_type));
                }
            }
        }
        
        None
    }

    /// Get sync statistics
    pub async fn get_stats(&self) -> SyncStats {
        let syncs = self.peer_syncs.read().await;
        
        let total_peers = syncs.len();
        let active_syncs = syncs.values()
            .filter(|s| s.active_sync_id.is_some())
            .count();
        
        let mut protocol_counts: HashMap<NetworkProtocol, usize> = HashMap::new();
        for state in syncs.values() {
            if let Some(protocol) = &state.sync_protocol {
                *protocol_counts.entry(protocol.clone()).or_insert(0) += 1;
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
                state.sync_start_time = Some(Instant::now() - Duration::from_secs(400));
            }
        }

        // Should allow new sync after timeout
        assert!(coordinator.register_peer_protocol(&peer_id, NetworkProtocol::BluetoothLE, sync_type).await);
    }

    #[tokio::test]
    async fn test_edge_and_full_sync_coexist() {
        let coordinator = SyncCoordinator::new();
        let peer_id = PublicKey::new(vec![1, 2, 3, 4]);

        // Start full blockchain sync
        assert!(coordinator.register_peer_protocol(&peer_id, NetworkProtocol::TCP, SyncType::FullBlockchain).await);
        coordinator.start_sync(&peer_id, 1, SyncType::FullBlockchain, NetworkProtocol::TCP).await;

        // Edge node sync should be allowed alongside full sync
        assert!(coordinator.register_peer_protocol(&peer_id, NetworkProtocol::BluetoothLE, SyncType::EdgeNode).await);
        coordinator.start_sync(&peer_id, 2, SyncType::EdgeNode, NetworkProtocol::BluetoothLE).await;

        // Another full sync should be blocked
        assert!(!coordinator.register_peer_protocol(&peer_id, NetworkProtocol::WiFiDirect, SyncType::FullBlockchain).await);

        // Another edge sync should be blocked
        assert!(!coordinator.register_peer_protocol(&peer_id, NetworkProtocol::WiFiDirect, SyncType::EdgeNode).await);
    }
}
