//! ZHTP Peer Discovery for DHT
//! 
//! Blockchain-verified peer discovery system for ZHTP mesh networking.
//! Nodes register their capabilities, blockchain identity, and reputation
//! in the DHT, enabling secure peer-to-peer content relay.

use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn, debug};

use lib_crypto::{PublicKey, hash_blake3};
use lib_crypto::post_quantum::dilithium::{dilithium2_verify};
use lib_identity::ZhtpIdentity;

use crate::protocols::zhtp_auth::NodeCapabilities;

/// Default TTL for peer registry entries (24 hours)
const DEFAULT_PEER_TTL: u64 = 86400;

/// Minimum reputation score for peer inclusion (0.0 - 1.0)
const MIN_REPUTATION_THRESHOLD: f64 = 0.3;

/// Maximum number of peers to return in a single query
const MAX_PEERS_PER_QUERY: usize = 20;

/// ZHTP Peer information stored in DHT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpPeerInfo {
    /// Blockchain identity public key
    pub blockchain_pubkey: PublicKey,
    
    /// Dilithium2 post-quantum signature public key
    pub dilithium_pubkey: Vec<u8>,
    
    /// Node capabilities (DHT hosting, relay, etc.)
    pub capabilities: NodeCapabilities,
    
    /// Network addresses for this peer
    pub addresses: Vec<String>,
    
    /// Reputation score (0.0 - 1.0)
    pub reputation: f64,
    
    /// Last seen timestamp (Unix epoch)
    pub last_seen: u64,
    
    /// Registration timestamp
    pub registered_at: u64,
    
    /// TTL for this entry (seconds)
    pub ttl: u64,
    
    /// Signature of peer data (signed with blockchain key)
    pub signature: Vec<u8>,
}

impl ZhtpPeerInfo {
    /// Verify the blockchain signature on this peer info
    pub fn verify_signature(&self) -> Result<bool> {
        // Serialize peer data without signature
        let mut peer_data = self.clone();
        peer_data.signature = vec![];
        
        let serialized = bincode::serialize(&peer_data)
            .map_err(|e| anyhow!("Failed to serialize peer data: {}", e))?;
        
        let data_hash = hash_blake3(&serialized);
        
        // Verify Dilithium2 signature
        match dilithium2_verify(&data_hash, &self.signature, &self.dilithium_pubkey) {
            Ok(valid) => Ok(valid),
            Err(e) => {
                warn!("Signature verification failed: {}", e);
                Ok(false)
            }
        }
    }
    
    /// Check if this peer entry has expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        now > (self.registered_at + self.ttl)
    }
    
    /// Check if peer meets minimum reputation threshold
    pub fn meets_reputation_threshold(&self) -> bool {
        self.reputation >= MIN_REPUTATION_THRESHOLD
    }
}

/// Peer query filter criteria
#[derive(Debug, Clone, Default)]
pub struct PeerQueryFilter {
    /// Require DHT hosting capability
    pub requires_dht: bool,
    
    /// Require relay capability
    pub requires_relay: bool,
    
    /// Minimum bandwidth (bytes/sec)
    pub min_bandwidth: Option<u64>,
    
    /// Minimum reputation score
    pub min_reputation: Option<f64>,
    
    /// Required protocol support
    pub required_protocols: Vec<String>,
    
    /// Require post-quantum security
    pub require_quantum_secure: bool,
    
    /// Maximum results to return
    pub max_results: usize,
}

/// ZHTP Peer Registry - manages blockchain-verified peers
#[derive(Debug, Clone)]
pub struct ZhtpPeerRegistry {
    /// Registered peers by node ID
    peers: Arc<RwLock<HashMap<[u8; 32], ZhtpPeerInfo>>>,
    
    /// Reputation scores by node ID
    reputation_scores: Arc<RwLock<HashMap<[u8; 32], f64>>>,
    
    /// Local node identity
    identity: ZhtpIdentity,
}

impl ZhtpPeerRegistry {
    /// Create a new peer registry
    pub fn new(identity: ZhtpIdentity) -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            reputation_scores: Arc::new(RwLock::new(HashMap::new())),
            identity,
        }
    }
    
    /// Register a new peer (or update existing)
    pub async fn register_peer(&self, peer_info: ZhtpPeerInfo) -> Result<()> {
        // Verify signature before accepting
        if !peer_info.verify_signature()? {
            return Err(anyhow!("Invalid peer signature"));
        }
        
        // Check if expired
        if peer_info.is_expired() {
            return Err(anyhow!("Peer registration expired"));
        }
        
        // Generate node ID from blockchain public key
        let node_id = self.generate_node_id(&peer_info.blockchain_pubkey);
        
        // Update last_seen timestamp
        let mut updated_peer = peer_info.clone();
        updated_peer.last_seen = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Store peer info
        let mut peers = self.peers.write().await;
        peers.insert(node_id, updated_peer.clone());
        
        // Update reputation score
        let mut scores = self.reputation_scores.write().await;
        scores.insert(node_id, updated_peer.reputation);
        
        info!(
            "Registered peer {} with reputation {:.2}",
            hex::encode(&node_id[..8]),
            updated_peer.reputation
        );
        
        Ok(())
    }
    
    /// Find peers matching the given filter criteria
    pub async fn find_peers(&self, filter: PeerQueryFilter) -> Result<Vec<ZhtpPeerInfo>> {
        let peers = self.peers.read().await;
        let mut matching_peers = Vec::new();
        
        for (node_id, peer_info) in peers.iter() {
            // Skip expired peers
            if peer_info.is_expired() {
                debug!("Skipping expired peer {}", hex::encode(&node_id[..8]));
                continue;
            }
            
            // Check DHT capability
            if filter.requires_dht && !peer_info.capabilities.has_dht {
                continue;
            }
            
            // Check relay capability
            if filter.requires_relay && !peer_info.capabilities.can_relay {
                continue;
            }
            
            // Check bandwidth requirement
            if let Some(min_bw) = filter.min_bandwidth {
                if peer_info.capabilities.max_bandwidth < min_bw {
                    continue;
                }
            }
            
            // Check reputation requirement
            if let Some(min_rep) = filter.min_reputation {
                if peer_info.reputation < min_rep {
                    continue;
                }
            }
            
            // Check protocol support
            if !filter.required_protocols.is_empty() {
                let has_all_protocols = filter.required_protocols.iter()
                    .all(|proto| peer_info.capabilities.protocols.contains(proto));
                
                if !has_all_protocols {
                    continue;
                }
            }
            
            // Check quantum security
            if filter.require_quantum_secure && !peer_info.capabilities.quantum_secure {
                continue;
            }
            
            matching_peers.push(peer_info.clone());
        }
        
        // Sort by reputation (highest first)
        matching_peers.sort_by(|a, b| {
            b.reputation.partial_cmp(&a.reputation).unwrap_or(std::cmp::Ordering::Equal)
        });
        
        // Limit results
        let max_results = filter.max_results.min(MAX_PEERS_PER_QUERY);
        matching_peers.truncate(max_results);
        
        info!(
            "Found {} peers matching filter (out of {} total)",
            matching_peers.len(),
            peers.len()
        );
        
        Ok(matching_peers)
    }
    
    /// Get a specific peer by node ID
    pub async fn get_peer(&self, node_id: &[u8; 32]) -> Result<Option<ZhtpPeerInfo>> {
        let peers = self.peers.read().await;
        
        if let Some(peer_info) = peers.get(node_id) {
            // Check if expired
            if peer_info.is_expired() {
                return Ok(None);
            }
            
            Ok(Some(peer_info.clone()))
        } else {
            Ok(None)
        }
    }
    
    /// Update reputation score for a peer
    pub async fn update_reputation(&self, node_id: &[u8; 32], new_reputation: f64) -> Result<()> {
        // Clamp reputation to [0.0, 1.0]
        let clamped_reputation = new_reputation.max(0.0).min(1.0);
        
        let mut peers = self.peers.write().await;
        
        if let Some(peer_info) = peers.get_mut(node_id) {
            peer_info.reputation = clamped_reputation;
            peer_info.last_seen = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            
            // Update reputation scores
            let mut scores = self.reputation_scores.write().await;
            scores.insert(*node_id, clamped_reputation);
            
            debug!(
                "Updated reputation for peer {} to {:.2}",
                hex::encode(&node_id[..8]),
                clamped_reputation
            );
            
            Ok(())
        } else {
            Err(anyhow!("Peer not found"))
        }
    }
    
    /// Remove a peer from the registry
    pub async fn remove_peer(&self, node_id: &[u8; 32]) -> Result<()> {
        let mut peers = self.peers.write().await;
        let mut scores = self.reputation_scores.write().await;
        
        peers.remove(node_id);
        scores.remove(node_id);
        
        info!("Removed peer {}", hex::encode(&node_id[..8]));
        
        Ok(())
    }
    
    /// Clean up expired peers
    pub async fn cleanup_expired_peers(&self) -> Result<usize> {
        let mut peers = self.peers.write().await;
        let mut scores = self.reputation_scores.write().await;
        
        let expired_nodes: Vec<[u8; 32]> = peers.iter()
            .filter(|(_, peer_info)| peer_info.is_expired())
            .map(|(node_id, _)| *node_id)
            .collect();
        
        let count = expired_nodes.len();
        
        for node_id in expired_nodes {
            peers.remove(&node_id);
            scores.remove(&node_id);
        }
        
        if count > 0 {
            info!("Cleaned up {} expired peers", count);
        }
        
        Ok(count)
    }
    
    /// Get total peer count
    pub async fn peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers.len()
    }
    
    /// Get all peer IDs
    pub async fn get_all_peer_ids(&self) -> Vec<[u8; 32]> {
        let peers = self.peers.read().await;
        peers.keys().copied().collect()
    }
    
    /// Generate node ID from blockchain public key
    fn generate_node_id(&self, pubkey: &PublicKey) -> [u8; 32] {
        // Hash the public key to create a 32-byte node ID
        let pubkey_bytes = bincode::serialize(pubkey).unwrap_or_default();
        hash_blake3(&pubkey_bytes)
    }
}

/// Convenience function to find ZHTP peers with DHT capability
pub async fn find_zhtp_peers(
    registry: &ZhtpPeerRegistry,
    capability: &str,
    min_reputation: f64,
) -> Result<Vec<ZhtpPeerInfo>> {
    let filter = PeerQueryFilter {
        requires_dht: capability.contains("dht"),
        requires_relay: capability.contains("relay"),
        min_reputation: Some(min_reputation),
        require_quantum_secure: true,
        max_results: 10,
        ..Default::default()
    };
    
    registry.find_peers(filter).await
}

/// Convenience function to find best relay peer
pub async fn find_best_relay_peer(
    registry: &ZhtpPeerRegistry,
    min_reputation: f64,
) -> Result<Option<ZhtpPeerInfo>> {
    let filter = PeerQueryFilter {
        requires_dht: true,
        requires_relay: true,
        min_reputation: Some(min_reputation),
        require_quantum_secure: true,
        max_results: 1,
        ..Default::default()
    };
    
    let peers = registry.find_peers(filter).await?;
    Ok(peers.into_iter().next())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::KeyPair;
    use lib_identity::IdentityType;
    
    async fn create_test_registry() -> ZhtpPeerRegistry {
        let keypair = KeyPair::generate().unwrap();
        let identity = ZhtpIdentity::new(
            IdentityType::Human,
            keypair.public_key.clone(),
            keypair.private_key.clone(),
            "peer-registry".to_string(),
            Some(30),
            Some("Testland".to_string()),
            true,
            lib_proofs::ZeroKnowledgeProof::default(),
        )
        .unwrap();
        ZhtpPeerRegistry::new(identity)
    }
    
    fn create_test_peer_info() -> ZhtpPeerInfo {
        let keypair = KeyPair::generate().unwrap();
        let dilithium_pubkey = keypair.public_key.dilithium_pk.clone();
        let dilithium_privkey = keypair.private_key.dilithium_sk.clone();
        
        let capabilities = NodeCapabilities {
            has_dht: true,
            can_relay: true,
            max_bandwidth: 1_000_000,
            protocols: vec!["zhtp".to_string(), "web4".to_string()],
            reputation: 80,
            quantum_secure: true,
        };
        
        let blockchain_pubkey = keypair.public_key.clone();
        
        let mut peer_info = ZhtpPeerInfo {
            blockchain_pubkey: blockchain_pubkey.clone(),
            dilithium_pubkey: dilithium_pubkey.clone(),
            capabilities,
            addresses: vec!["127.0.0.1:8080".to_string()],
            reputation: 0.8,
            last_seen: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            registered_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ttl: DEFAULT_PEER_TTL,
            signature: vec![],
        };
        
        // Sign the peer info
        let serialized = bincode::serialize(&peer_info).unwrap();
        let data_hash = hash_blake3(&serialized);
        let signature = lib_crypto::post_quantum::dilithium::dilithium2_sign(&data_hash, &dilithium_privkey).unwrap();
        
        peer_info.signature = signature;
        peer_info
    }
    
    #[tokio::test]
    async fn test_register_and_find_peer() {
        let registry = create_test_registry().await;
        let peer_info = create_test_peer_info();
        
        // Register peer
        registry.register_peer(peer_info.clone()).await.unwrap();
        
        // Verify peer count
        assert_eq!(registry.peer_count().await, 1);
        
        // Find peers with DHT capability
        let peers = find_zhtp_peers(&registry, "dht", 0.5).await.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].reputation, 0.8);
    }
    
    #[tokio::test]
    async fn test_peer_filtering() {
        let registry = create_test_registry().await;
        
        // Register multiple peers with different capabilities
        let peer1 = create_test_peer_info();
        registry.register_peer(peer1).await.unwrap();
        
        // Find peers with high reputation
        let peers = find_zhtp_peers(&registry, "relay", 0.9).await.unwrap();
        assert_eq!(peers.len(), 0); // No peers meet 0.9 threshold
        
        // Find peers with lower reputation threshold
        let peers = find_zhtp_peers(&registry, "relay", 0.5).await.unwrap();
        assert_eq!(peers.len(), 1);
    }
}
