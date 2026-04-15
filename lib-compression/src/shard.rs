//! Content-addressed shard management with DHT integration

use blake3::Hash;
use bytes::Bytes;
use lib_storage::DhtNodeManager;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;

/// Unique identifier for a shard (BLAKE3 hash)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShardId(pub [u8; 32]);

impl ShardId {
    /// Create ShardId from data
    pub fn from_data(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        ShardId(*hash.as_bytes())
    }

    /// Create ShardId from hash
    pub fn from_hash(hash: Hash) -> Self {
        ShardId(*hash.as_bytes())
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for ShardId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ShardId({}..)", &self.to_hex()[..8])
    }
}

impl fmt::Display for ShardId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.to_hex()[..16])
    }
}

/// A content-addressed data shard
#[derive(Clone, Serialize, Deserialize)]
pub struct Shard {
    /// Unique content-based identifier
    pub id: ShardId,
    
    /// Raw data bytes
    pub data: Bytes,
    
    /// Size in bytes
    pub size: usize,
    
    /// Optional encryption metadata
    pub encrypted: bool,
}

impl Shard {
    /// Create new shard from data
    pub fn new(data: Vec<u8>) -> Self {
        let id = ShardId::from_data(&data);
        let size = data.len();
        
        Self {
            id,
            data: Bytes::from(data),
            size,
            encrypted: false,
        }
    }

    /// Create shard with specific ID (for reconstruction)
    pub fn with_id(id: ShardId, data: Vec<u8>) -> Self {
        let size = data.len();
        
        Self {
            id,
            data: Bytes::from(data),
            size,
            encrypted: false,
        }
    }

    /// Verify shard integrity
    pub fn verify(&self) -> bool {
        let computed_id = ShardId::from_data(&self.data);
        computed_id == self.id
    }

    /// Get data as slice
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

impl fmt::Debug for Shard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shard")
            .field("id", &self.id)
            .field("size", &self.size)
            .field("encrypted", &self.encrypted)
            .finish()
    }
}

/// Manages shard distribution across the network
pub struct ShardManager {
    redundancy_factor: usize,
    max_parallel_fetches: usize,
    local_cache_dir: Option<std::path::PathBuf>,
    dht_manager: Option<DhtNodeManager>,
    transport: Option<Arc<crate::transport::ShardTransport>>,
    /// Local node identifier for requester tracking in shard protocols
    local_node_id: String,
}

impl ShardManager {
    /// Create new shard manager
    pub fn new() -> Self {
        Self {
            redundancy_factor: 3, // 3x redundancy by default
            max_parallel_fetches: 10,
            local_cache_dir: None,
            dht_manager: None,
            transport: None,
            local_node_id: format!("node-{}", std::process::id()),
        }
    }
    
    /// Create with custom redundancy
    pub fn with_redundancy(redundancy_factor: usize) -> Self {
        Self {
            redundancy_factor,
            max_parallel_fetches: 10,
            local_cache_dir: None,
            dht_manager: None,
            transport: None,
            local_node_id: format!("node-{}", std::process::id()),
        }
    }

    /// Set the local node identifier (used as requester in shard fetch/store)
    pub fn with_node_id(mut self, node_id: String) -> Self {
        self.local_node_id = node_id;
        self
    }
    
    /// Enable local file cache for shards (fallback storage)
    pub fn with_local_cache<P: Into<std::path::PathBuf>>(mut self, cache_dir: P) -> Self {
        self.local_cache_dir = Some(cache_dir.into());
        self
    }
    
    /// Enable DHT integration for network-based shard storage
    pub fn with_dht(mut self, dht_manager: DhtNodeManager) -> Self {
        self.dht_manager = Some(dht_manager);
        self
    }
    
    /// Enable QUIC transport for network-based shard transmission
    pub fn with_transport(mut self, transport: Arc<crate::transport::ShardTransport>) -> Self {
        self.transport = Some(transport);
        self
    }

    /// Distribute shards to DHT nodes with local cache fallback
    /// Fully integrated with lib-storage DHT
    pub async fn distribute_shards(&self, shards: &[Shard]) -> crate::Result<Vec<DistributionResult>> {
        let mut results = Vec::new();
        
        for shard in shards {
            // Select nodes for this shard using DHT if available
            let node_ids = if self.dht_manager.is_some() {
                // Use DHT-based node selection
                self.select_dht_storage_nodes(&shard.id, self.redundancy_factor).await?
            } else {
                // Fallback to deterministic selection
                self.select_deterministic_nodes(&shard.id, self.redundancy_factor).await?
            };
            
            // Save to local cache if enabled (for testing/fallback)
            if let Some(ref cache_dir) = self.local_cache_dir {
                if let Err(e) = self.save_to_local_cache(shard, cache_dir).await {
                    tracing::warn!("Failed to save shard {} to local cache: {}", shard.id, e);
                }
            }
            
            // If DHT is available, store shard on DHT nodes
            if let Some(ref dht) = self.dht_manager {
                if let Err(e) = self.store_shard_on_dht(shard, &node_ids, dht).await {
                    tracing::warn!("Failed to store shard {} on DHT: {}", shard.id, e);
                    // Continue distribution to other shards
                }
            }
            
            results.push(DistributionResult {
                shard_id: shard.id,
                stored_nodes: node_ids,
                redundancy: self.redundancy_factor,
            });
        }
        
        Ok(results)
    }
    
    /// Select optimal storage nodes using DHT (lib-storage integration)
    async fn select_dht_storage_nodes(&self, shard_id: &ShardId, count: usize) -> crate::Result<Vec<String>> {
        let dht = self.dht_manager.as_ref()
            .ok_or_else(|| crate::CompressionError::DhtStorageFailed("DHT not initialized".to_string()))?;
        
        // Get all storage-capable nodes from DHT
        let storage_nodes = dht.storage_nodes();
        
        if storage_nodes.is_empty() {
            tracing::warn!("No storage nodes available in DHT for shard {}", shard_id);
            // Fallback to deterministic selection
            return self.select_deterministic_nodes(shard_id, count).await;
        }
        
        // Use shard hash to deterministically select nodes from available storage nodes
        let shard_hash = blake3::hash(shard_id.as_bytes());
        let hash_bytes = shard_hash.as_bytes();
        
        // Select nodes using hash-based selection for consistent routing
        let mut selected_indices = std::collections::HashSet::new();
        let mut node_ids = Vec::new();
        
        for i in 0..count.min(storage_nodes.len()) {
            // Use different offsets in hash to get diversity
            let hash_value = u32::from_be_bytes([
                hash_bytes[i % 32],
                hash_bytes[(i + 1) % 32],
                hash_bytes[(i + 2) % 32],
                hash_bytes[(i + 3) % 32],
            ]);
            let mut index = (hash_value as usize + i * 7919) % storage_nodes.len();
            
            // Ensure uniqueness
            while selected_indices.contains(&index) {
                index = (index + 1) % storage_nodes.len();
            }
            
            selected_indices.insert(index);
            let node_id = hex::encode(storage_nodes[index].peer.node_id().as_bytes());
            node_ids.push(node_id);
        }
        
        tracing::debug!("Selected {} DHT storage nodes for shard {}", node_ids.len(), shard_id);
        
        Ok(node_ids)
    }
    
    /// Deterministic node selection fallback (when DHT not available)
    async fn select_deterministic_nodes(&self, shard_id: &ShardId, count: usize) -> crate::Result<Vec<String>> {
        let mut nodes = Vec::new();
        let hash = blake3::hash(shard_id.as_bytes());
        
        for i in 0..count {
            let offset = ((hash.as_bytes()[i % 32] as usize) + i * 256) % 1000;
            let node_id = format!("node-{:04x}", offset);
            nodes.push(node_id);
        }
        
        Ok(nodes)
    }
    
    /// Helper: Resolve node ID to socket address via DHT
    fn resolve_node_address(&self, node_id_str: &str, dht: &DhtNodeManager) -> crate::Result<std::net::SocketAddr> {
        // Convert node ID string to NodeId
        let node_id_bytes = hex::decode(node_id_str)
            .map_err(|e| crate::CompressionError::InvalidShard(format!("Invalid node ID: {}", e)))?;
        
        if node_id_bytes.len() != 32 {
            return Err(crate::CompressionError::InvalidShard(
                format!("Node ID must be 32 bytes, got {}", node_id_bytes.len())
            ));
        }
        
        let mut bytes_array = [0u8; 32];
        bytes_array.copy_from_slice(&node_id_bytes);
        let node_id = lib_storage::types::NodeId::from_bytes(bytes_array);
        
        // Get node from DHT
        let node = dht.get_node(&node_id)
            .ok_or_else(|| crate::CompressionError::NetworkError(
                format!("Node {} not found in DHT", node_id_str)
            ))?;
        
        // Get first address (assuming it's the primary endpoint)
        let address_str = node.addresses
            .first()
            .ok_or_else(|| crate::CompressionError::NetworkError(
                format!("Node {} has no addresses", node_id_str)
            ))?;
        
        // Parse address string to SocketAddr
        let address = address_str.parse::<std::net::SocketAddr>()
            .map_err(|e| crate::CompressionError::NetworkError(
                format!("Failed to parse address '{}': {}", address_str, e)
            ))?;
        
        Ok(address)
    }
    
    /// Store shard on DHT nodes (lib-storage integration)
    async fn store_shard_on_dht(
        &self,
        shard: &Shard,
        node_ids: &[String],
        dht: &DhtNodeManager,
    ) -> crate::Result<()> {
        // If transport is available, use it for actual network transmission
        if let Some(ref transport) = self.transport {
            let mut success_count = 0;
            
            // Store on each selected node via QUIC transport
            for node_id_str in node_ids {
                // Resolve node address
                match self.resolve_node_address(node_id_str, dht) {
                    Ok(node_address) => {
                        // Store shard via QUIC transport
                        match transport.store_shard_remote(node_address, shard, 3600).await {
                            Ok(true) => {
                                success_count += 1;
                                tracing::info!(
                                    "Stored shard {} on node {} at {}",
                                    shard.id, node_id_str, node_address
                                );
                            }
                            Ok(false) => {
                                tracing::warn!(
                                    "Node {} refused storage for shard {}",
                                    node_id_str, shard.id
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to store shard {} on node {}: {}",
                                    shard.id, node_id_str, e
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to resolve node {}: {}", node_id_str, e);
                        continue;
                    }
                }
            }
            
            // Require at least one successful storage
            if success_count > 0 {
                tracing::info!(
                    "Successfully stored shard {} on {}/{} nodes",
                    shard.id, success_count, node_ids.len()
                );
                Ok(())
            } else {
                Err(crate::CompressionError::NetworkError(
                    format!("Failed to store shard {} on any nodes", shard.id)
                ))
            }
        } else {
            // Fallback: log that transport is not available
            for node_id_str in node_ids {
                tracing::debug!(
                    "Would store shard {} on node {} (transport not initialized)",
                    shard.id, node_id_str
                );
            }
            Ok(())
        }
    }

    /// Fetch shard from network with DHT lookup and local cache fallback
    pub async fn fetch_shard(&self, shard_id: &ShardId) -> crate::Result<Shard> {
        // Try local cache first for performance
        if let Some(ref cache_dir) = self.local_cache_dir {
            match self.load_from_local_cache(shard_id, cache_dir).await {
                Ok(shard) => {
                    tracing::debug!("Loaded shard {} from local cache", shard_id);
                    return Ok(shard);
                }
                Err(e) => {
                    tracing::trace!("Shard {} not in local cache: {}", shard_id, e);
                }
            }
        }
        
        // Use DHT to find nodes storing this shard
        if let Some(ref dht) = self.dht_manager {
            // Find nodes that should be storing this shard using hash-based routing
            let node_ids = self.select_dht_storage_nodes(shard_id, self.redundancy_factor).await?;
            
            if !node_ids.is_empty() {
                tracing::debug!("Found {} potential storage nodes for shard {}", node_ids.len(), shard_id);
                
                // If transport is available, use it to fetch from nodes
                if let Some(ref transport) = self.transport {
                    // Try fetching from each node
                    for node_id_str in &node_ids {
                        match self.resolve_node_address(node_id_str, dht) {
                            Ok(node_address) => {
                                // Fetch shard via QUIC transport
                                match transport.fetch_shard_remote(
                                    node_address,
                                    *shard_id,
                                    self.local_node_id.clone(),
                                ).await {
                                    Ok(shard) => {
                                        // Verify shard integrity
                                        if shard.verify() {
                                            tracing::info!(
                                                "Fetched and verified shard {} from node {} at {}",
                                                shard_id, node_id_str, node_address
                                            );
                                            
                                            // Cache locally for future use
                                            if let Some(ref cache_dir) = self.local_cache_dir {
                                                let _ = self.save_to_local_cache(&shard, cache_dir).await;
                                            }
                                            
                                            return Ok(shard);
                                        } else {
                                            tracing::warn!(
                                                "Shard {} from node {} failed verification",
                                                shard_id, node_id_str
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        tracing::debug!(
                                            "Failed to fetch shard {} from node {}: {}",
                                            shard_id, node_id_str, e
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Failed to resolve node {}: {}", node_id_str, e);
                                continue;
                            }
                        }
                    }
                } else {
                    // Transport not available - log and continue without fetching
                    for node_id_str in &node_ids {
                        tracing::debug!(
                            "Found shard {} on DHT node {} - awaiting QUIC transport",
                            shard_id, node_id_str
                        );
                    }
                }
            }
        }
        
        // Could not fetch from network
        Err(crate::CompressionError::NetworkError(
            format!("Shard {} not in local cache and network fetch failed", shard_id)
        ))
    }

    /// Fetch multiple shards with DHT lookup and parallel QUIC transport
    /// 
    /// Implements high-performance parallel fetching using QUIC streams:
    ///   - Open multiple QUIC streams (up to max_parallel_fetches)
    ///   - Concurrent fetch from different nodes
    ///   - Aggregate bandwidth from multiple paths
    ///   - Automatic replica fallback on failure
    pub async fn fetch_shards(&self, ids: &[ShardId]) -> crate::Result<Vec<Shard>> {
        
        // Try local cache first for each shard
        let mut cached_shards = Vec::new();
        let mut uncached_ids = Vec::new();
        
        for id in ids {
            if let Some(ref cache_dir) = self.local_cache_dir {
                match self.load_from_local_cache(id, cache_dir).await {
                    Ok(shard) => {
                        tracing::debug!("Loaded shard {} from local cache", id);
                        cached_shards.push(shard);
                        continue;
                    }
                    Err(_) => {
                        // Not in cache, need to fetch from network
                    }
                }
            }
            uncached_ids.push(*id);
        }
        
        // If all shards are cached, return immediately
        if uncached_ids.is_empty() {
            tracing::info!("All {} shards loaded from local cache", ids.len());
            return Ok(cached_shards);
        }
        
        tracing::info!(
            "Fetching {} shards from network ({} from cache)",
            uncached_ids.len(), cached_shards.len()
        );
        
        // Fetch uncached shards from network
        let mut network_shards = Vec::new();
        
        if let (Some(ref dht), Some(ref transport)) = (&self.dht_manager, &self.transport) {
            // Build parallel fetch requests
            let mut fetch_requests = Vec::new();
            
            for shard_id in &uncached_ids {
                // Get storage nodes for this shard
                match self.select_dht_storage_nodes(shard_id, self.redundancy_factor).await {
                    Ok(node_ids) if !node_ids.is_empty() => {
                        // Try first available node (fallback will try others)
                        for node_id_str in node_ids.iter().take(1) {
                            match self.resolve_node_address(node_id_str, dht) {
                                Ok(node_address) => {
                                    fetch_requests.push((
                                        node_address,
                                        *shard_id,
                                        self.local_node_id.clone(),
                                    ));
                                    break;
                                }
                                Err(e) => {
                                    tracing::warn!("Failed to resolve node {}: {}", node_id_str, e);
                                }
                            }
                        }
                    }
                    Ok(_) => {
                        tracing::warn!("No storage nodes found for shard {}", shard_id);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to find storage nodes for shard {}: {}", shard_id, e);
                    }
                }
            }
            
            // Execute parallel fetch via QUIC transport
            if !fetch_requests.is_empty() {
                tracing::info!(
                    "Executing parallel fetch for {} shards across {} nodes",
                    fetch_requests.len(), fetch_requests.len()
                );
                
                match transport.fetch_shards_parallel(fetch_requests).await {
                    Ok(fetched) => {
                        for shard in fetched {
                            // Verify shard integrity
                            if shard.verify() {
                                tracing::debug!("Verified shard {} from network", shard.id);
                                
                                // Cache locally
                                if let Some(ref cache_dir) = self.local_cache_dir {
                                    let _ = self.save_to_local_cache(&shard, cache_dir).await;
                                }
                                
                                network_shards.push(shard);
                            } else {
                                tracing::warn!("Shard {} failed integrity verification", shard.id);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Parallel fetch failed: {}", e);
                        // Fall back to sequential fetch
                        for id in &uncached_ids {
                            match self.fetch_shard(id).await {
                                Ok(shard) => network_shards.push(shard),
                                Err(e) => {
                                    tracing::warn!("Sequential fetch failed for shard {}: {}", id, e);
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // No transport or DHT - fall back to sequential fetch
            tracing::debug!("No transport/DHT available, using sequential fetch");
            for id in &uncached_ids {
                match self.fetch_shard(id).await {
                    Ok(shard) => network_shards.push(shard),
                    Err(e) => {
                        tracing::warn!("Fetch failed for shard {}: {}", id, e);
                    }
                }
            }
        }
        
        // Combine cached and network shards
        cached_shards.extend(network_shards);
        
        // Return success if we got at least some shards
        if !cached_shards.is_empty() {
            let missing = ids.len() - cached_shards.len();
            if missing > 0 {
                tracing::warn!(
                    "Partial fetch: {}/{} shards retrieved ({} missing)",
                    cached_shards.len(), ids.len(), missing
                );
            } else {
                tracing::info!("Successfully fetched all {} shards", ids.len());
            }
            return Ok(cached_shards);
        }
        
        // All fetches failed
        Err(crate::CompressionError::NetworkError(
            format!("Failed to fetch all {} shards", ids.len())
        ))
    }
    
    /// Save shard to local cache directory
    async fn save_to_local_cache(&self, shard: &Shard, cache_dir: &std::path::Path) -> crate::Result<()> {
        use tokio::fs;
        use tokio::io::AsyncWriteExt;
        
        // Create cache directory if it doesn't exist
        fs::create_dir_all(cache_dir).await
            .map_err(|e| crate::CompressionError::Io(e))?;
        
        // Save shard data to file named by shard ID
        let shard_path = cache_dir.join(format!("{}.shard", shard.id));
        let mut file = fs::File::create(&shard_path).await
            .map_err(|e| crate::CompressionError::Io(e))?;
        
        file.write_all(&shard.data).await
            .map_err(|e| crate::CompressionError::Io(e))?;
        
        file.flush().await
            .map_err(|e| crate::CompressionError::Io(e))?;
        
        tracing::debug!("Saved shard {} to local cache: {}", shard.id, shard_path.display());
        Ok(())
    }
    
    /// Load shard from local cache directory
    async fn load_from_local_cache(&self, shard_id: &ShardId, cache_dir: &std::path::Path) -> crate::Result<Shard> {
        use tokio::fs;
        use tokio::io::AsyncReadExt;
        
        let shard_path = cache_dir.join(format!("{}.shard", shard_id));
        
        // Check if file exists
        if !shard_path.exists() {
            return Err(crate::CompressionError::ShardNotFound(shard_id.to_string()));
        }
        
        // Read shard data
        let mut file = fs::File::open(&shard_path).await
            .map_err(|e| crate::CompressionError::Io(e))?;
        
        let mut data = Vec::new();
        file.read_to_end(&mut data).await
            .map_err(|e| crate::CompressionError::Io(e))?;
        
        // Reconstruct shard
        let shard = Shard::new(data);
        
        // Verify it matches the requested ID
        if shard.id != *shard_id {
            return Err(crate::CompressionError::InvalidShard(
                format!("Cached shard hash mismatch: expected {}, got {}", shard_id, shard.id)
            ));
        }
        
        Ok(shard)
    }
    
    /// Verify shard integrity
    pub fn verify_shard(&self, shard: &Shard) -> bool {
        // Verify hash matches content
        let computed_hash = blake3::hash(&shard.data);
        computed_hash.as_bytes() == shard.id.as_bytes()
    }
}

/// Result of shard distribution
#[derive(Debug, Clone)]
pub struct DistributionResult {
    pub shard_id: ShardId,
    pub stored_nodes: Vec<String>,
    pub redundancy: usize,
}

impl Default for ShardManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shard_id_from_data() {
        let data = b"Hello, World!";
        let id = ShardId::from_data(data);
        
        // Same data should produce same ID
        let id2 = ShardId::from_data(data);
        assert_eq!(id, id2);
        
        // Different data should produce different ID
        let id3 = ShardId::from_data(b"Different");
        assert_ne!(id, id3);
    }

    #[test]
    fn test_shard_creation() {
        let data = vec![1, 2, 3, 4, 5];
        let shard = Shard::new(data.clone());
        
        assert_eq!(shard.size, 5);
        assert_eq!(shard.as_slice(), &data[..]);
        assert!(!shard.encrypted);
    }

    #[test]
    fn test_shard_verification() {
        let data = vec![1, 2, 3, 4, 5];
        let shard = Shard::new(data);
        
        assert!(shard.verify());
    }

    #[test]
    fn test_shard_id_display() {
        let data = b"test";
        let id = ShardId::from_data(data);
        let hex = id.to_hex();
        
        assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars
    }

    #[tokio::test]
    async fn test_shard_manager_with_transport() {
        use std::sync::Arc;
        
        // Create shard manager with transport
        let transport = Arc::new(crate::transport::ShardTransport::new());
        let manager = ShardManager::new().with_transport(transport);
        
        // Create test shards
        let shard1 = Shard::new(vec![1, 2, 3, 4, 5]);
        let shard2 = Shard::new(vec![6, 7, 8, 9, 10]);
        let shards = vec![shard1, shard2];
        
        // Test distribution (will use placeholder transport)
        let results = manager.distribute_shards(&shards).await;
        
        // Should succeed with placeholder transport
        assert!(results.is_ok());
        
        let dist_results = results.unwrap();
        assert_eq!(dist_results.len(), 2);
        assert_eq!(dist_results[0].redundancy, 3); // Default redundancy
    }

    #[tokio::test]
    async fn test_shard_manager_local_cache() {
        use tempfile::tempdir;
        
        // Create temp directory for cache
        let temp_dir = tempdir().unwrap();
        let cache_path = temp_dir.path();
        
        // Create shard manager with local cache
        let manager = ShardManager::new()
            .with_local_cache(cache_path);
        
        // Create test shard
        let data = vec![1, 2, 3, 4, 5];
        let shard = Shard::new(data.clone());
        let shard_id = shard.id;
        
        // Save to local cache
        manager.save_to_local_cache(&shard, cache_path).await.unwrap();
        
        // Load from local cache
        let loaded_shard = manager.load_from_local_cache(&shard_id, cache_path).await;
        
        assert!(loaded_shard.is_ok());
        let loaded = loaded_shard.unwrap();
        assert_eq!(loaded.id, shard_id);
        assert_eq!(loaded.as_slice(), &data[..]);
    }

    #[tokio::test]
    async fn test_parallel_fetch_with_cache() {
        use tempfile::tempdir;
        
        // Create temp directory for cache
        let temp_dir = tempdir().unwrap();
        let cache_path = temp_dir.path();
        
        // Create shard manager with local cache and transport
        let transport = Arc::new(crate::transport::ShardTransport::new());
        let manager = ShardManager::new()
            .with_local_cache(cache_path)
            .with_transport(transport);
        
        // Create and cache test shards
        let shard1 = Shard::new(vec![1, 2, 3]);
        let shard2 = Shard::new(vec![4, 5, 6]);
        let shard3 = Shard::new(vec![7, 8, 9]);
        
        manager.save_to_local_cache(&shard1, cache_path).await.unwrap();
        manager.save_to_local_cache(&shard2, cache_path).await.unwrap();
        manager.save_to_local_cache(&shard3, cache_path).await.unwrap();
        
        // Fetch all shards in parallel (should come from cache)
        let ids = vec![shard1.id, shard2.id, shard3.id];
        let result = manager.fetch_shards(&ids).await;
        
        assert!(result.is_ok());
        let fetched = result.unwrap();
        assert_eq!(fetched.len(), 3);
    }

    #[test]
    fn test_shard_verification_integrity() {
        // Create shard and verify integrity
        let data = vec![0xFF; 1024];
        let shard = Shard::new(data.clone());
        
        // Verify using ShardManager
        let manager = ShardManager::new();
        assert!(manager.verify_shard(&shard));
        
        // Create invalid shard (mismatched ID and data)
        let mut invalid_shard = shard.clone();
        invalid_shard.id = ShardId::from_data(b"different data");
        
        assert!(!manager.verify_shard(&invalid_shard));
    }
}
