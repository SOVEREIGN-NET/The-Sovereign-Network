//! Shard distribution protocol for ZHTP network
//!
//! This module defines the protocol for storing and fetching shards across the mesh network.
//! It integrates with the existing ZHTP protocol handlers in lib-network.
//!
//! ## Protocol Messages
//!
//! - **STORE_SHARD**: Store a shard on a remote node
//! - **FETCH_SHARD**: Retrieve a shard from a remote node
//! - **QUERY_NODES**: Find which nodes have a specific shard
//! - **REPLICATE**: Trigger replication of a shard to maintain redundancy
//!
//! ## Integration with ZHTP
//!
//! This protocol extends the existing ZHTP handshake with shard-specific capabilities.
//! Nodes advertise their storage capacity and shard hosting capabilities during handshake.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Shard identifier (32-byte BLAKE3 hash)
pub type ShardId = [u8; 32];

/// Node identifier
pub type NodeId = String;

/// Shard protocol version
pub const SHARD_PROTOCOL_VERSION: u32 = 1;

/// Maximum shard size (64 MB)
pub const MAX_SHARD_SIZE: usize = 64 * 1024 * 1024;

/// Protocol messages for shard operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShardProtocolMessage {
    /// Request to store a shard on this node
    StoreRequest {
        /// Protocol version
        version: u32,
        /// Shard identifier
        shard_id: ShardId,
        /// Shard data (compressed)
        data: Bytes,
        /// Time-to-live in seconds
        ttl_seconds: u64,
        /// Requesting node ID
        requester: NodeId,
    },
    
    /// Response to store request
    StoreResponse {
        /// Shard identifier
        shard_id: ShardId,
        /// Whether storage succeeded
        stored: bool,
        /// This node's ID
        node_id: NodeId,
        /// Expiration timestamp
        expires_at: u64,
        /// Optional error message
        error: Option<String>,
    },
    
    /// Request to fetch a shard
    FetchRequest {
        /// Protocol version
        version: u32,
        /// Shard identifier
        shard_id: ShardId,
        /// Requesting node ID
        requester: NodeId,
    },
    
    /// Response with shard data
    FetchResponse {
        /// Shard identifier
        shard_id: ShardId,
        /// Shard data if found
        data: Option<Bytes>,
        /// Source node ID
        source_node: NodeId,
        /// Optional error message
        error: Option<String>,
    },
    
    /// Query which nodes are storing this shard
    QueryNodesRequest {
        /// Protocol version
        version: u32,
        /// Shard identifier
        shard_id: ShardId,
        /// Maximum nodes to return
        max_results: usize,
    },
    
    /// Response with node list
    QueryNodesResponse {
        /// Shard identifier
        shard_id: ShardId,
        /// List of (node_id, address) pairs
        nodes: Vec<(NodeId, SocketAddr)>,
    },
    
    /// Request shard replication for redundancy
    ReplicateRequest {
        /// Shard identifier
        shard_id: ShardId,
        /// Target node to replicate to
        target_node: NodeId,
        /// Source node hosting the shard
        source_node: NodeId,
    },
    
    /// Response to replication request
    ReplicateResponse {
        /// Shard identifier
        shard_id: ShardId,
        /// Whether replication succeeded
        success: bool,
        /// Optional error message
        error: Option<String>,
    },
}

/// Statistics for shard protocol operations
#[derive(Debug, Clone, Default)]
pub struct ShardProtocolStats {
    /// Total store requests received
    pub store_requests: u64,
    /// Successful stores
    pub store_success: u64,
    /// Failed stores
    pub store_failures: u64,
    /// Total fetch requests received
    pub fetch_requests: u64,
    /// Successful fetches
    pub fetch_success: u64,
    /// Failed fetches (shard not found)
    pub fetch_failures: u64,
    /// Total query requests
    pub query_requests: u64,
    /// Total replications
    pub replications: u64,
    /// Total bytes stored
    pub bytes_stored: u64,
    /// Total bytes served
    pub bytes_served: u64,
}

/// Local storage for shards on this node
#[derive(Debug)]
struct ShardStorage {
    /// Map of shard_id -> (data, expiration_timestamp)
    shards: HashMap<ShardId, (Bytes, u64)>,
    /// Maximum storage capacity in bytes
    max_capacity: usize,
    /// Current storage usage in bytes
    current_usage: usize,
}

impl ShardStorage {
    fn new(max_capacity: usize) -> Self {
        Self {
            shards: HashMap::new(),
            max_capacity,
            current_usage: 0,
        }
    }
    
    fn store(&mut self, shard_id: ShardId, data: Bytes, expires_at: u64) -> Result<(), String> {
        let size = data.len();
        
        // Check capacity
        if self.current_usage + size > self.max_capacity {
            return Err("Storage capacity exceeded".into());
        }
        
        // Store shard
        self.shards.insert(shard_id, (data, expires_at));
        self.current_usage += size;
        
        Ok(())
    }
    
    fn fetch(&self, shard_id: &ShardId) -> Option<Bytes> {
        self.shards.get(shard_id).map(|(data, _)| data.clone())
    }
    
    fn remove_expired(&mut self, now: u64) {
        let mut to_remove: Vec<(ShardId, usize)> = Vec::new();
        
        for (shard_id, (data, expires_at)) in &self.shards {
            if *expires_at < now {
                to_remove.push((*shard_id, data.len()));
            }
        }
        
        for (shard_id, size) in to_remove {
            self.shards.remove(&shard_id);
            self.current_usage -= size;
        }
    }
}

/// Handler for shard protocol messages
///
/// This integrates with the ZHTP mesh network to provide shard storage and retrieval.
/// In Phase 2, this will be registered as a protocol handler in lib-network.
pub struct ShardProtocolHandler {
    /// Local node ID
    local_node_id: NodeId,
    
    /// Local shard storage
    storage: Arc<RwLock<ShardStorage>>,
    
    /// Protocol statistics
    stats: Arc<RwLock<ShardProtocolStats>>,
    
    /// DHT manager for node discovery (optional)
    /// In Phase 2, this will be integrated with lib-storage DHT
    dht_nodes: Arc<RwLock<HashMap<ShardId, Vec<(NodeId, SocketAddr)>>>>,
}

impl ShardProtocolHandler {
    /// Create new protocol handler
    pub fn new(local_node_id: NodeId, storage_capacity: usize) -> Self {
        info!(
            "Initializing ShardProtocolHandler for node {} with {} MB capacity",
            local_node_id,
            storage_capacity / (1024 * 1024)
        );
        
        Self {
            local_node_id,
            storage: Arc::new(RwLock::new(ShardStorage::new(storage_capacity))),
            stats: Arc::new(RwLock::new(ShardProtocolStats::default())),
            dht_nodes: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Handle incoming shard protocol message
    pub async fn handle_message(
        &self,
        message: ShardProtocolMessage,
        peer_id: NodeId,
    ) -> Result<ShardProtocolMessage, String> {
        match message {
            ShardProtocolMessage::StoreRequest {
                version,
                shard_id,
                data,
                ttl_seconds,
                requester,
            } => self.handle_store_request(version, shard_id, data, ttl_seconds, requester).await,
            
            ShardProtocolMessage::FetchRequest {
                version,
                shard_id,
                requester,
            } => self.handle_fetch_request(version, shard_id, requester).await,
            
            ShardProtocolMessage::QueryNodesRequest {
                version,
                shard_id,
                max_results,
            } => self.handle_query_nodes(version, shard_id, max_results).await,
            
            ShardProtocolMessage::ReplicateRequest {
                shard_id,
                target_node,
                source_node,
            } => self.handle_replicate_request(shard_id, target_node, source_node).await,
            
            _ => Err("Invalid message type".into()),
        }
    }
    
    async fn handle_store_request(
        &self,
        version: u32,
        shard_id: ShardId,
        data: Bytes,
        ttl_seconds: u64,
        requester: NodeId,
    ) -> Result<ShardProtocolMessage, String> {
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.store_requests += 1;
        }
        
        // Validate version
        if version != SHARD_PROTOCOL_VERSION {
            return Ok(ShardProtocolMessage::StoreResponse {
                shard_id,
                stored: false,
                node_id: self.local_node_id.clone(),
                expires_at: 0,
                error: Some(format!("Unsupported protocol version: {}", version)),
            });
        }
        
        // Validate size
        if data.len() > MAX_SHARD_SIZE {
            return Ok(ShardProtocolMessage::StoreResponse {
                shard_id,
                stored: false,
                node_id: self.local_node_id.clone(),
                expires_at: 0,
                error: Some(format!("Shard too large: {} bytes", data.len())),
            });
        }
        
        let now: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expires_at = now + ttl_seconds;
        
        // Store shard
        let mut storage = self.storage.write().await;
        match storage.store(shard_id, data.clone(), expires_at) {
            Ok(()) => {
                debug!(
                    "Stored shard {:?} from {} ({} bytes, expires in {}s)",
                    &shard_id[..8],
                    requester,
                    data.len(),
                    ttl_seconds
                );
                
                let mut stats = self.stats.write().await;
                stats.store_success += 1;
                stats.bytes_stored += data.len() as u64;
                
                Ok(ShardProtocolMessage::StoreResponse {
                    shard_id,
                    stored: true,
                    node_id: self.local_node_id.clone(),
                    expires_at,
                    error: None,
                })
            },
            Err(e) => {
                warn!("Failed to store shard: {}", e);
                
                let mut stats = self.stats.write().await;
                stats.store_failures += 1;
                
                Ok(ShardProtocolMessage::StoreResponse {
                    shard_id,
                    stored: false,
                    node_id: self.local_node_id.clone(),
                    expires_at: 0,
                    error: Some(e),
                })
            }
        }
    }
    
    async fn handle_fetch_request(
        &self,
        version: u32,
        shard_id: ShardId,
        requester: NodeId,
    ) -> Result<ShardProtocolMessage, String> {
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.fetch_requests += 1;
        }
        
        // Validate version
        if version != SHARD_PROTOCOL_VERSION {
            return Ok(ShardProtocolMessage::FetchResponse {
                shard_id,
                data: None,
                source_node: self.local_node_id.clone(),
                error: Some(format!("Unsupported protocol version: {}", version)),
            });
        }
        
        // Fetch from storage
        let storage = self.storage.read().await;
        match storage.fetch(&shard_id) {
            Some(data) => {
                debug!(
                    "Serving shard {:?} to {} ({} bytes)",
                    &shard_id[..8],
                    requester,
                    data.len()
                );
                
                let mut stats = self.stats.write().await;
                stats.fetch_success += 1;
                stats.bytes_served += data.len() as u64;
                
                Ok(ShardProtocolMessage::FetchResponse {
                    shard_id,
                    data: Some(data),
                    source_node: self.local_node_id.clone(),
                    error: None,
                })
            },
            None => {
                debug!("Shard {:?} not found for {}", &shard_id[..8], requester);
                
                let mut stats = self.stats.write().await;
                stats.fetch_failures += 1;
                
                Ok(ShardProtocolMessage::FetchResponse {
                    shard_id,
                    data: None,
                    source_node: self.local_node_id.clone(),
                    error: Some("Shard not found".into()),
                })
            }
        }
    }
    
    async fn handle_query_nodes(
        &self,
        version: u32,
        shard_id: ShardId,
        max_results: usize,
    ) -> Result<ShardProtocolMessage, String> {
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.query_requests += 1;
        }
        
        // Query DHT for nodes storing this shard
        let dht = self.dht_nodes.read().await;
        let nodes = dht.get(&shard_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .take(max_results)
            .collect();
        
        Ok(ShardProtocolMessage::QueryNodesResponse {
            shard_id,
            nodes,
        })
    }
    
    async fn handle_replicate_request(
        &self,
        shard_id: ShardId,
        target_node: NodeId,
        source_node: NodeId,
    ) -> Result<ShardProtocolMessage, String> {
        // TODO: Implement shard replication logic
        // For now, return success placeholder
        
        let mut stats = self.stats.write().await;
        stats.replications += 1;
        
        Ok(ShardProtocolMessage::ReplicateResponse {
            shard_id,
            success: true,
            error: None,
        })
    }
    
    /// Clean up expired shards periodically
    pub async fn cleanup_expired(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut storage = self.storage.write().await;
        let before = storage.current_usage;
        storage.remove_expired(now);
        let after = storage.current_usage;
        
        if before != after {
            info!(
                "Cleaned up expired shards: freed {} bytes",
                before - after
            );
        }
    }
    
    /// Get protocol statistics
    pub async fn get_stats(&self) -> ShardProtocolStats {
        self.stats.read().await.clone()
    }
    
    /// Register a node as storing a shard (for DHT integration)
    pub async fn register_node_for_shard(
        &self,
        shard_id: ShardId,
        node_id: NodeId,
        address: SocketAddr,
    ) {
        let mut dht = self.dht_nodes.write().await;
        dht.entry(shard_id)
            .or_insert_with(Vec::new)
            .push((node_id, address));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_protocol_handler_creation() {
        let handler = ShardProtocolHandler::new("test-node".into(), 1024 * 1024 * 100);
        assert_eq!(handler.local_node_id, "test-node");
    }
    
    #[tokio::test]
    async fn test_store_and_fetch() {
        let handler = ShardProtocolHandler::new("test-node".into(), 1024 * 1024 * 100);
        
        let shard_id = [1u8; 32];
        let data = Bytes::from(vec![1, 2, 3, 4, 5]);
        
        // Store shard
        let store_msg = ShardProtocolMessage::StoreRequest {
            version: SHARD_PROTOCOL_VERSION,
            shard_id,
            data: data.clone(),
            ttl_seconds: 3600,
            requester: "requester".into(),
        };
        
        let response = handler.handle_message(store_msg, "peer".into()).await.unwrap();
        match response {
            ShardProtocolMessage::StoreResponse { stored, .. } => {
                assert!(stored, "Shard should be stored successfully");
            },
            _ => panic!("Expected StoreResponse"),
        }
        
        // Fetch shard
        let fetch_msg = ShardProtocolMessage::FetchRequest {
            version: SHARD_PROTOCOL_VERSION,
            shard_id,
            requester: "requester".into(),
        };
        
        let response = handler.handle_message(fetch_msg, "peer".into()).await.unwrap();
        match response {
            ShardProtocolMessage::FetchResponse { data: Some(fetched_data), .. } => {
                assert_eq!(fetched_data, data, "Fetched data should match stored data");
            },
            _ => panic!("Expected FetchResponse with data"),
        }
    }
    
    #[tokio::test]
    async fn test_fetch_not_found() {
        let handler = ShardProtocolHandler::new("test-node".into(), 1024 * 1024 * 100);
        
        let shard_id = [2u8; 32];
        
        let fetch_msg = ShardProtocolMessage::FetchRequest {
            version: SHARD_PROTOCOL_VERSION,
            shard_id,
            requester: "requester".into(),
        };
        
        let response = handler.handle_message(fetch_msg, "peer".into()).await.unwrap();
        match response {
            ShardProtocolMessage::FetchResponse { data: None, .. } => {
                // Expected behavior
            },
            _ => panic!("Expected FetchResponse with None"),
        }
    }
    
    #[tokio::test]
    async fn test_stats_tracking() {
        let handler = ShardProtocolHandler::new("test-node".into(), 1024 * 1024 * 100);
        
        let shard_id = [3u8; 32];
        let data = Bytes::from(vec![1, 2, 3]);
        
        // Store
        let store_msg = ShardProtocolMessage::StoreRequest {
            version: SHARD_PROTOCOL_VERSION,
            shard_id,
            data,
            ttl_seconds: 3600,
            requester: "requester".into(),
        };
        handler.handle_message(store_msg, "peer".into()).await.unwrap();
        
        let stats = handler.get_stats().await;
        assert_eq!(stats.store_requests, 1);
        assert_eq!(stats.store_success, 1);
        assert_eq!(stats.bytes_stored, 3);
    }
}
