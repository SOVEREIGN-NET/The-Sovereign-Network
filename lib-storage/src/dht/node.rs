//! DHT Node Management
//! 
//! Handles DHT node lifecycle, reputation scoring, and capability management.

use crate::types::dht_types::{DhtNode, StorageCapabilities, StorageTier};
use crate::types::{NodeId, DhtStats};
use crate::dht::storage::DhtStorage;
use crate::dht::network::DhtNetwork;
use lib_crypto::{Hash, PostQuantumSignature};
use anyhow::{Result, anyhow};
use std::time::{SystemTime, UNIX_EPOCH};
use std::net::SocketAddr;

/// Message statistics for tracking DHT network activity
#[derive(Debug, Clone, Default)]
pub struct MessageStats {
    pub sent_count: u64,
    pub received_count: u64,
}

/// DHT node manager for handling node lifecycle and capabilities with storage integration
#[derive(Debug)]
pub struct DhtNodeManager {
    /// Local node information
    local_node: DhtNode,
    /// DHT storage with networking
    storage: Option<DhtStorage>,
    /// Direct network interface for advanced operations
    network: Option<DhtNetwork>,
    /// Node reputation tracking
    reputation_scores: std::collections::HashMap<NodeId, u32>,
    /// Local nodes collection when storage is not available
    local_nodes: std::collections::HashMap<NodeId, DhtNode>,
    /// Message statistics
    message_stats: MessageStats,
}

impl DhtNodeManager {
    /// Create a new DHT node manager
    pub fn new(local_id: NodeId, addresses: Vec<String>) -> Result<Self> {
        let local_node = Self::create_local_node(local_id, addresses)?;
        
        Ok(Self {
            local_node,
            storage: None,
            network: None,
            reputation_scores: std::collections::HashMap::new(),
            local_nodes: std::collections::HashMap::new(),
            message_stats: MessageStats::default(),
        })
    }

    /// Create DHT node manager with networking enabled
    pub async fn new_with_network(
        local_id: NodeId, 
        addresses: Vec<String>,
        bind_addr: SocketAddr,
        max_storage_size: u64
    ) -> Result<Self> {
        let local_node = Self::create_local_node(local_id, addresses)?;
        let storage = DhtStorage::new_with_network(local_node.clone(), bind_addr, max_storage_size).await?;
        let network = DhtNetwork::new(local_node.clone(), bind_addr)?;
        
        Ok(Self {
            local_node,
            storage: Some(storage),
            network: Some(network),
            reputation_scores: std::collections::HashMap::new(),
            local_nodes: std::collections::HashMap::new(),
            message_stats: MessageStats::default(),
        })
    }
    
    /// Create local node with default capabilities
    fn create_local_node(local_id: NodeId, addresses: Vec<String>) -> Result<DhtNode> {
        Ok(DhtNode {
            id: local_id,
            addresses,
            public_key: PostQuantumSignature {
                algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
                signature: vec![],
                public_key: lib_crypto::PublicKey {
                    dilithium_pk: vec![],
                    kyber_pk: vec![],
                    key_id: [0u8; 32],
                },
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            },
            last_seen: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            reputation: 1000, // Starting reputation
            storage_info: Some(StorageCapabilities {
                available_space: 1024 * 1024 * 1024 * 1024, // 1TB default
                total_capacity: 1024 * 1024 * 1024 * 1024,
                price_per_gb_day: crate::types::STORAGE_PRICE_PER_GB_DAY,
                supported_tiers: vec![StorageTier::Hot, StorageTier::Warm, StorageTier::Cold],
                region: "global".to_string(),
                uptime: 1.0,
            }),
        })
    }
    
    /// Get local node information
    pub fn local_node(&self) -> &DhtNode {
        &self.local_node
    }
    
    /// Add a node to the DHT network
    pub async fn add_node(&mut self, node: DhtNode) -> Result<()> {
        let node_id = node.id.clone();
        
        // Initialize reputation if new node
        if !self.reputation_scores.contains_key(&node_id) {
            self.reputation_scores.insert(node_id.clone(), 1000);
        }
        
        // Add to storage layer if available
        if let Some(storage) = &mut self.storage {
            storage.add_dht_node(node.clone()).await?;
        }
        
        // Always add to local collection for availability when storage is not present
        self.local_nodes.insert(node_id, node);
        
        Ok(())
    }
    
    /// Get a node by ID from storage layer or local collection
    pub fn get_node(&self, node_id: &NodeId) -> Option<&DhtNode> {
        if let Some(storage) = &self.storage {
            storage.get_known_nodes().into_iter().find(|n| n.id == *node_id)
        } else {
            // Check local collection when storage is not available
            self.local_nodes.get(node_id)
        }
    }
    
    /// Update node reputation
    pub fn update_reputation(&mut self, node_id: &NodeId, delta: i32) {
        if let Some(score) = self.reputation_scores.get_mut(node_id) {
            if delta < 0 {
                *score = score.saturating_sub((-delta) as u32);
            } else {
                *score = score.saturating_add(delta as u32);
            }
            
            // Note: Node reputation is managed here in the reputation_scores map
            // The actual node data is stored in DHT storage/routing table
        }
    }
    
    /// Get node reputation
    pub fn get_reputation(&self, node_id: &NodeId) -> u32 {
        self.reputation_scores.get(node_id).copied().unwrap_or(0)
    }
    
    /// Remove a node
    pub fn remove_node(&mut self, node_id: &NodeId) {
        self.reputation_scores.remove(node_id);
        self.local_nodes.remove(node_id);
    }
    
    /// Get all known nodes from storage layer and local collection
    pub fn all_nodes(&self) -> Vec<&DhtNode> {
        if let Some(storage) = &self.storage {
            storage.get_known_nodes()
        } else {
            // Return nodes from local collection when storage is not available
            self.local_nodes.values().collect()
        }
    }
    
    /// Get nodes with storage capabilities
    pub fn storage_nodes(&self) -> Vec<&DhtNode> {
        self.all_nodes()
            .into_iter()
            .filter(|node| node.storage_info.is_some())
            .collect()
    }
    
    /// Get high-reputation nodes
    pub fn high_reputation_nodes(&self, min_reputation: u32) -> Vec<&DhtNode> {
        self.all_nodes()
            .into_iter()
            .filter(|node| {
                self.reputation_scores.get(&node.id)
                    .map(|&rep| rep >= min_reputation)
                    .unwrap_or(false)
            })
            .collect()
    }
    
    /// Get DHT statistics including storage and routing info
    pub fn get_statistics(&self) -> DhtStats {
        let (total_nodes, storage_utilization, routing_table_size) = if let Some(storage) = &self.storage {
            let routing_stats = storage.get_routing_stats();
            let storage_stats = storage.get_storage_stats();
            let utilization = (storage_stats.total_size as f64 / storage_stats.max_capacity as f64) * 100.0;
            
            (routing_stats.total_nodes, utilization, routing_stats.total_nodes)
        } else {
            (0, 0.0, 0)
        };
        
        DhtStats {
            total_nodes,
            total_connections: total_nodes, // Simplified - all known nodes are considered connected
            total_messages_sent: self.message_stats.sent_count,
            total_messages_received: self.message_stats.received_count,
            routing_table_size,
            storage_utilization,
            network_health: if total_nodes > 0 { 1.0 } else { 0.0 }, // Simplified health metric
        }
    }

    /// Start DHT network processing (should be run in background task)
    pub async fn start_network_processing(&mut self) -> Result<()> {
        if let Some(storage) = &mut self.storage {
            storage.start_network_processing().await
        } else {
            Err(anyhow!("Network not enabled"))
        }
    }

    /// Perform maintenance on DHT network
    pub async fn perform_maintenance(&mut self) -> Result<()> {
        if let Some(storage) = &mut self.storage {
            storage.perform_maintenance().await
        } else {
            Ok(())
        }
    }

    /// Store data in DHT
    pub async fn store_data(&mut self, content_hash: Hash, data: Vec<u8>) -> Result<()> {
        if let Some(storage) = &mut self.storage {
            storage.store_data(content_hash, data).await
        } else {
            Err(anyhow!("Storage not available"))
        }
    }

    /// Retrieve data from DHT
    pub async fn retrieve_data(&mut self, content_hash: Hash) -> Result<Option<Vec<u8>>> {
        if let Some(storage) = &mut self.storage {
            storage.retrieve_data(content_hash).await
        } else {
            Ok(None)
        }
    }

    /// Send direct network message to a peer
    pub async fn send_network_message(&self, target: &DhtNode, message: crate::types::dht_types::DhtMessage) -> Result<()> {
        if let Some(network) = &self.network {
            network.send_message(target, message).await
        } else {
            Err(anyhow!("Network not available"))
        }
    }

    /// Ping a specific node through direct network interface
    pub async fn ping_node(&self, target: &DhtNode) -> Result<bool> {
        if let Some(network) = &self.network {
            network.ping(target).await
        } else {
            Err(anyhow!("Network not available"))
        }
    }

    /// Find nodes through direct network interface
    pub async fn find_network_nodes(&self, target: &DhtNode, query_id: crate::types::NodeId) -> Result<Vec<DhtNode>> {
        if let Some(network) = &self.network {
            network.find_node(target, query_id).await
        } else {
            Err(anyhow!("Network not available"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_node_manager_creation() {
        let node_id = Hash::from_bytes(&[1u8; 32]);
        let addresses = vec!["127.0.0.1:33442".to_string()];
        
        let manager = DhtNodeManager::new(node_id.clone(), addresses).unwrap();
        
        assert_eq!(manager.local_node().id, node_id);
        assert_eq!(manager.all_nodes().len(), 0);
    }
    
    #[tokio::test]
    async fn test_add_and_get_node() {
        let node_id = Hash::from_bytes(&[1u8; 32]);
        let addresses = vec!["127.0.0.1:33442".to_string()];
        let mut manager = DhtNodeManager::new(node_id, addresses).unwrap();
        
        let test_node = DhtNode {
            id: Hash::from_bytes(&[2u8; 32]),
            addresses: vec!["127.0.0.1:33443".to_string()],
            public_key: PostQuantumSignature {
                algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
                signature: vec![],
                public_key: lib_crypto::PublicKey {
                    dilithium_pk: vec![],
                    kyber_pk: vec![],
                    key_id: [0u8; 32],
                },
                timestamp: 0,
            },
            last_seen: 0,
            reputation: 1000,
            storage_info: None,
        };
        
        manager.add_node(test_node.clone()).await.unwrap();
        
        assert_eq!(manager.all_nodes().len(), 1);
        assert!(manager.get_node(&test_node.id).is_some());
    }
    
    #[test]
    fn test_reputation_management() {
        let node_id = Hash::from_bytes(&[1u8; 32]);
        let addresses = vec!["127.0.0.1:33442".to_string()];
        let mut manager = DhtNodeManager::new(node_id, addresses).unwrap();
        
        let test_node_id = Hash::from_bytes(&[2u8; 32]);
        
        // Add reputation for new node
        manager.reputation_scores.insert(test_node_id.clone(), 1000);
        
        // Test reputation increase
        manager.update_reputation(&test_node_id, 100);
        assert_eq!(manager.get_reputation(&test_node_id), 1100);
        
        // Test reputation decrease
        manager.update_reputation(&test_node_id, -200);
        assert_eq!(manager.get_reputation(&test_node_id), 900);
    }
}
