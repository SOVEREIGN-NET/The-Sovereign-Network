//! DHT Peer Management
//! 
//! Handles peer discovery, connection management, and peer reputation tracking.

use crate::types::dht_types::{DhtNode, PeerInfo, PeerStats};
use crate::types::NodeId;
use crate::dht::routing::KademliaRouter;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH, Duration};

/// DHT peer manager
#[derive(Debug)]
pub struct DhtPeerManager {
    /// Local node ID
    local_id: NodeId,
    /// Connected peers
    peers: HashMap<NodeId, PeerInfo>,
    /// Peer statistics
    peer_stats: HashMap<NodeId, PeerStats>,
    /// Maximum number of peers to maintain
    max_peers: usize,
    /// Minimum reputation score for peers
    min_reputation: u32,
    /// Kademlia router for intelligent peer selection
    router: KademliaRouter,
}

impl DhtPeerManager {
    /// Create a new peer manager
    pub fn new(local_id: NodeId, max_peers: usize, min_reputation: u32) -> Self {
        Self {
            local_id: local_id.clone(),
            peers: HashMap::new(),
            peer_stats: HashMap::new(),
            max_peers,
            min_reputation,
            router: KademliaRouter::new(local_id, 20),
        }
    }
    
    /// Add a new peer
    ///
    /// **MIGRATION (Ticket #145):** Uses `node.peer.node_id()` for peer tracking
    pub async fn add_peer(&mut self, node: DhtNode) -> Result<()> {
        // Check if peer meets reputation requirements
        if node.reputation < self.min_reputation {
            return Err(anyhow!("Peer reputation {} below minimum {}", node.reputation, self.min_reputation));
        }
        
        let node_id = node.peer.node_id();
        
        // Don't add ourselves
        if *node_id == self.local_id {
            return Err(anyhow!("Cannot add self as peer"));
        }
        
        // Check if we're at capacity
        if self.peers.len() >= self.max_peers && !self.peers.contains_key(node_id) {
            // Remove lowest reputation peer
            self.evict_worst_peer().await?;
        }
        
        let peer_info = PeerInfo {
            node: node.clone(),
            connection_time: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            last_seen: node.last_seen,
            status: crate::types::dht_types::PeerStatus::Connected,
            capabilities: Vec::new(), // Would be negotiated during handshake
        };
        
        let node_id = node.peer.node_id().clone();
        self.peers.insert(node_id.clone(), peer_info);
        
        // Initialize peer statistics
        let stats = PeerStats {
            messages_sent: 0,
            messages_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            successful_requests: 0,
            failed_requests: 0,
            avg_response_time: 0.0,
            uptime_percentage: 100.0,
            last_updated: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        };
        
        self.peer_stats.insert(node_id, stats);
        
        // Add to routing table for intelligent peer selection
        self.router.add_node(node).await?;
        
        Ok(())
    }
    
    /// Remove a peer
    pub fn remove_peer(&mut self, peer_id: &NodeId) -> Option<PeerInfo> {
        self.peer_stats.remove(peer_id);
        self.router.remove_node(peer_id);
        self.peers.remove(peer_id)
    }
    
    /// Get peer information
    pub fn get_peer(&self, peer_id: &NodeId) -> Option<&PeerInfo> {
        self.peers.get(peer_id)
    }
    
    /// Get all connected peers
    pub fn get_all_peers(&self) -> Vec<&DhtNode> {
        self.peers.values().map(|info| &info.node).collect()
    }
    
    /// Get peers with specific capabilities
    pub fn get_peers_with_capability(&self, capability: &str) -> Vec<&DhtNode> {
        self.peers.values()
            .filter(|info| info.capabilities.contains(&capability.to_string()))
            .map(|info| &info.node)
            .collect()
    }
    
    /// Update peer statistics
    pub fn update_peer_stats(&mut self, peer_id: &NodeId, bytes_sent: u64, bytes_received: u64, response_time: f64, success: bool) -> Result<()> {
        if let Some(stats) = self.peer_stats.get_mut(peer_id) {
            stats.messages_sent += if bytes_sent > 0 { 1 } else { 0 };
            stats.messages_received += if bytes_received > 0 { 1 } else { 0 };
            stats.bytes_sent += bytes_sent;
            stats.bytes_received += bytes_received;
            
            if success {
                stats.successful_requests += 1;
            } else {
                stats.failed_requests += 1;
            }
            
            // Update average response time
            let total_requests = stats.successful_requests + stats.failed_requests;
            if total_requests > 0 {
                stats.avg_response_time = (stats.avg_response_time * (total_requests - 1) as f64 + response_time) / total_requests as f64;
            }
            
            stats.last_updated = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        }
        
        Ok(())
    }
    
    /// Mark peer as unresponsive
    pub fn mark_peer_unresponsive(&mut self, peer_id: &NodeId) {
        if let Some(peer_info) = self.peers.get_mut(peer_id) {
            peer_info.status = crate::types::dht_types::PeerStatus::Disconnected;
        }
    }
    
    /// Get peer statistics
    pub fn get_peer_stats(&self, peer_id: &NodeId) -> Option<&PeerStats> {
        self.peer_stats.get(peer_id)
    }
    
    /// Get best peers for routing (highest reputation and lowest latency)
    ///
    /// **MIGRATION (Ticket #145):** Uses `node.peer.node_id()` for stats lookup
    pub fn get_best_peers(&self, count: usize) -> Vec<&DhtNode> {
        let mut peer_scores: Vec<_> = self.peers.values()
            .map(|info| {
                let stats = self.peer_stats.get(info.node.peer.node_id());
                let latency_score = stats.map(|s| 1.0 / (s.avg_response_time + 1.0)).unwrap_or(0.0);
                let reputation_score = info.node.reputation as f64 / 1000.0; // Normalize to 0-1
                let combined_score = latency_score + reputation_score;
                (info, combined_score)
            })
            .collect();
        
        peer_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        
        peer_scores.into_iter()
            .take(count)
            .map(|(info, _)| &info.node)
            .collect()
    }
    
    /// Cleanup disconnected peers
    pub async fn cleanup_disconnected(&mut self, timeout: Duration) -> Result<usize> {
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let timeout_secs = timeout.as_secs();
        
        let disconnected_peers: Vec<NodeId> = self.peers.iter()
            .filter_map(|(id, info)| {
                if matches!(info.status, crate::types::dht_types::PeerStatus::Disconnected) &&
                   current_time.saturating_sub(info.last_seen) > timeout_secs {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();
        
        let count = disconnected_peers.len();
        for peer_id in disconnected_peers {
            self.remove_peer(&peer_id);
        }
        
        Ok(count)
    }
    
    /// Evict the worst performing peer
    async fn evict_worst_peer(&mut self) -> Result<()> {
        let worst_peer_id = self.peers.iter()
            .min_by_key(|(_, info)| info.node.reputation)
            .map(|(id, _)| id.clone());
        
        if let Some(peer_id) = worst_peer_id {
            self.remove_peer(&peer_id);
        }
        
        Ok(())
    }
    
    /// Find closest peers to a target using Kademlia routing
    ///
    /// **MIGRATION (Ticket #145):** Uses `node.peer.node_id()` for peer lookup
    pub fn find_closest_peers(&self, target: &NodeId, count: usize) -> Vec<&DhtNode> {
        self.router.find_closest_nodes(target, count)
            .iter()
            .filter_map(|node| self.peers.get(node.peer.node_id()).map(|info| &info.node))
            .collect()
    }

    /// Update peer responsiveness in routing table
    pub fn update_peer_responsiveness(&mut self, peer_id: &NodeId, responsive: bool) -> Result<()> {
        if responsive {
            self.router.mark_node_responsive(peer_id)?;
        } else {
            self.router.mark_node_failed(peer_id);
        }
        Ok(())
    }

    /// Get peer management statistics
    pub fn get_management_stats(&self) -> PeerManagementStats {
        let total_peers = self.peers.len();
        let connected_peers = self.peers.values()
            .filter(|info| matches!(info.status, crate::types::dht_types::PeerStatus::Connected))
            .count();
        
        let avg_reputation = if total_peers > 0 {
            let total_reputation: u32 = self.peers.values()
                .map(|info| info.node.reputation)
                .sum();
            total_reputation as f64 / total_peers as f64
        } else {
            0.0
        };
        
        PeerManagementStats {
            total_peers,
            connected_peers,
            avg_reputation,
            max_peers: self.max_peers,
        }
    }
}

/// Peer management statistics
#[derive(Debug)]
pub struct PeerManagementStats {
    pub total_peers: usize,
    pub connected_peers: usize,
    pub avg_reputation: f64,
    pub max_peers: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_identity::{ZhtpIdentity, IdentityType};
    use crate::types::dht_types::DhtPeerIdentity;

    fn dummy_pq_signature() -> lib_crypto::PostQuantumSignature {
        lib_crypto::PostQuantumSignature {
            algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
            signature: vec![],
            public_key: lib_crypto::PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: [0u8; 32],
            },
            timestamp: 0,
        }
    }

    fn create_test_peer(device_name: &str) -> DhtPeerIdentity {
        let identity = ZhtpIdentity::new_unified(
            IdentityType::Device,
            None,
            None,
            device_name,
            None,
        ).expect("Failed to create test identity");
        
        DhtPeerIdentity {
            node_id: identity.node_id.clone(),
            public_key: identity.public_key.clone(),
            did: identity.did.clone(),
            device_id: device_name.to_string(),
        }
    }

    fn build_node(peer: DhtPeerIdentity, reputation: u32) -> DhtNode {
        DhtNode {
            peer,
            addresses: vec!["127.0.0.1:33442".to_string()],
            public_key: dummy_pq_signature(),
            last_seen: 0,
            reputation,
            storage_info: None,
        }
    }
    
    #[tokio::test]
    async fn test_peer_manager_creation() {
        let local_id = NodeId::from_bytes([1u8; 32]);
        let manager = DhtPeerManager::new(local_id, 100, 500);
        
        assert_eq!(manager.max_peers, 100);
        assert_eq!(manager.min_reputation, 500);
        assert_eq!(manager.peers.len(), 0);
    }
    
    #[tokio::test]
    async fn test_add_peer() {
        let local_id = NodeId::from_bytes([1u8; 32]);
        let mut manager = DhtPeerManager::new(local_id, 100, 500);
        
        let test_peer = create_test_peer("test-device");
        let test_node = build_node(test_peer.clone(), 1000);
        
        manager.add_peer(test_node.clone()).await.unwrap();
        
        assert_eq!(manager.peers.len(), 1);
        assert!(manager.get_peer(test_peer.node_id()).is_some());
    }
    
    #[tokio::test]
    async fn test_reject_low_reputation_peer() {
        let local_id = NodeId::from_bytes([1u8; 32]);
        let mut manager = DhtPeerManager::new(local_id, 100, 500);
        
        let low_rep_peer = create_test_peer("low-rep-device");
        let low_rep_node = build_node(low_rep_peer, 100); // Below minimum of 500
        
        let result = manager.add_peer(low_rep_node).await;
        assert!(result.is_err());
        assert_eq!(manager.peers.len(), 0);
    }
    
    #[tokio::test]
    async fn test_update_peer_stats() {
        let local_id = NodeId::from_bytes([1u8; 32]);
        let mut manager = DhtPeerManager::new(local_id, 100, 500);
        
        let test_peer = create_test_peer("test-device");
        let test_node = build_node(test_peer.clone(), 1000);
        
        manager.add_peer(test_node.clone()).await.unwrap();
        manager.update_peer_stats(test_peer.node_id(), 100, 50, 0.5, true).unwrap();
        
        let stats = manager.get_peer_stats(test_peer.node_id()).unwrap();
        assert_eq!(stats.bytes_sent, 100);
        assert_eq!(stats.bytes_received, 50);
        assert_eq!(stats.successful_requests, 1);
        assert_eq!(stats.avg_response_time, 0.5);
    }
}
