//! DHT Integration
//!
//! `ZkDHTIntegration` provides the DHT API surface for lib-network consumers
//! (ContentPublisher, DomainRegistry, mesh server). Storage is delegated to
//! an injected `DhtBackend` (in-memory for tests, sled-persistent in production).
//! Peer queries and replication are delegated to an optional `DhtNetworkTransport`.

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::backend::{DhtBackend, InMemoryDhtBackend};

/// DHT Network Status
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DHTNetworkStatus {
    pub total_nodes: u32,
    pub connected_nodes: u32,
    pub storage_used_bytes: u64,
    pub total_keys: u32,
}

/// DHT Peer Information
#[derive(Debug, Clone)]
pub struct DhtPeerInfo {
    pub node_id: [u8; 32],
    pub address: Option<std::net::SocketAddr>,
    pub capabilities: Vec<String>,
    pub last_seen: u64,
}

/// Transport for DHT network operations (replication, remote queries).
///
/// Injected by the application layer. Without a transport, replication and
/// remote content lookup are no-ops (single-node mode).
#[async_trait]
pub trait DhtNetworkTransport: Send + Sync {
    /// Send a DHT store request to a peer.
    async fn send_store(&self, peer: &DhtPeerInfo, key: &str, value: &[u8], ttl_secs: u64) -> Result<()>;

    /// Query a peer for content by key. Returns the value if the peer has it.
    async fn query_content(&self, peer: &DhtPeerInfo, key: &str) -> Result<Option<Vec<u8>>>;
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// ZkDHTIntegration — DHT API surface backed by a pluggable storage backend
/// and optional network transport for multi-node operation.
#[derive(Clone)]
pub struct ZkDHTIntegration {
    backend: Arc<dyn DhtBackend>,
    peer_registry: Arc<RwLock<HashMap<[u8; 32], DhtPeerInfo>>>,
    transport: Arc<RwLock<Option<Arc<dyn DhtNetworkTransport>>>>,
    local_node_id: [u8; 32],
    max_storage_bytes: u64,
}

impl ZkDHTIntegration {
    /// Create with in-memory backend (tests / single-node).
    pub fn new() -> Self {
        Self {
            backend: Arc::new(InMemoryDhtBackend::new()),
            peer_registry: Arc::new(RwLock::new(HashMap::new())),
            transport: Arc::new(RwLock::new(None)),
            local_node_id: [0u8; 32],
            max_storage_bytes: 1024 * 1024 * 1024,
        }
    }

    /// Create with a specific backend and node ID.
    pub fn with_backend(
        backend: Arc<dyn DhtBackend>,
        node_id: [u8; 32],
        max_storage_bytes: u64,
    ) -> Self {
        Self {
            backend,
            peer_registry: Arc::new(RwLock::new(HashMap::new())),
            transport: Arc::new(RwLock::new(None)),
            local_node_id: node_id,
            max_storage_bytes,
        }
    }

    /// Backwards-compatible constructor.
    pub fn with_node_id(node_id: [u8; 32], max_storage_bytes: u64) -> Self {
        Self::with_backend(Arc::new(InMemoryDhtBackend::new()), node_id, max_storage_bytes)
    }

    /// Set the network transport for replication and remote queries.
    pub async fn set_network_transport(&self, transport: Arc<dyn DhtNetworkTransport>) {
        *self.transport.write().await = Some(transport);
        info!("DHT network transport wired for replication and remote queries");
    }

    pub async fn initialize(&mut self, identity: lib_identity::ZhtpIdentity) -> Result<()> {
        self.local_node_id = *identity.node_id.as_bytes();
        info!(
            "DHT integration initialized with node ID: {:?}",
            &self.local_node_id[..8]
        );
        Ok(())
    }

    /// Store content with TTL. Replicates to nearest peers if transport is wired.
    pub async fn store_content(
        &self,
        domain: &str,
        path: &str,
        content: Vec<u8>,
        ttl_secs: u64,
    ) -> Result<String> {
        let key = format!("{}:{}", domain, path);
        info!(
            "Storing content at key: {} ({} bytes, TTL: {}s)",
            key,
            content.len(),
            ttl_secs
        );

        // Check storage limit
        let current_usage = self.backend.storage_bytes().await;
        if current_usage + content.len() as u64 > self.max_storage_bytes {
            warn!("DHT storage limit reached, cleaning up expired entries");
            self.cleanup_expired().await?;
        }

        // Store via backend
        self.backend.store(&key, content.clone(), ttl_secs).await?;

        // Replicate to nearest peers if transport available
        let transport_guard = self.transport.read().await;
        if let Some(ref transport) = *transport_guard {
            let closest = self.find_closest_peers(&self.local_node_id, 3).await;
            let mut replicated = 0usize;
            for peer in &closest {
                match transport.send_store(peer, &key, &content, ttl_secs).await {
                    Ok(()) => replicated += 1,
                    Err(e) => debug!("Replication to peer failed: {}", e),
                }
            }
            if !closest.is_empty() {
                info!("Replicated {} to {}/{} peers", key, replicated, closest.len());
            }
        }

        Ok(key)
    }

    /// Retrieve content by key. Falls back to peer queries if not found locally.
    pub async fn fetch_content(&self, key: &str) -> Result<Option<Vec<u8>>> {
        debug!("Fetching content for key: {}", key);

        // Check local backend
        if let Some(value) = self.backend.get(key).await? {
            return Ok(Some(value));
        }

        // Query nearest peers if transport available
        let transport_guard = self.transport.read().await;
        if let Some(ref transport) = *transport_guard {
            let closest = self.find_closest_peers(&self.local_node_id, 3).await;
            for peer in &closest {
                match transport.query_content(peer, key).await {
                    Ok(Some(value)) => {
                        debug!("Content found on peer {:?}", &peer.node_id[..4]);
                        // Cache locally
                        let _ = self.backend.store(key, value.clone(), 300).await;
                        return Ok(Some(value));
                    }
                    Ok(None) => continue,
                    Err(e) => debug!("Peer query failed: {}", e),
                }
            }
        }

        debug!("Content not found: {}", key);
        Ok(None)
    }

    /// Resolve content by domain and path.
    pub async fn resolve_content(&self, domain: &str, path: &str) -> Result<Option<Vec<u8>>> {
        let key = format!("{}:{}", domain, path);
        self.fetch_content(&key).await
    }

    /// Discover peers in the DHT.
    pub async fn discover_peers(&self) -> Result<Vec<String>> {
        let peer_registry = self.peer_registry.read().await;
        let peers: Vec<String> = peer_registry
            .values()
            .filter_map(|peer| peer.address.map(|addr| addr.to_string()))
            .collect();
        Ok(peers)
    }

    /// Get network status.
    pub async fn get_network_status(&self) -> Result<DHTNetworkStatus> {
        let peer_count = self.peer_registry.read().await.len() as u32;
        Ok(DHTNetworkStatus {
            total_nodes: peer_count,
            connected_nodes: peer_count,
            storage_used_bytes: self.backend.storage_bytes().await,
            total_keys: self.backend.key_count().await as u32,
        })
    }

    /// Clear cache.
    pub async fn clear_cache(&self) -> Result<()> {
        // InMemoryDhtBackend doesn't expose a clear method, but cleanup_expired
        // with a zero-TTL store cycle achieves the same. For now, we rely on the
        // backend's cleanup_expired.
        self.cleanup_expired().await?;
        info!("DHT content cache cleared");
        Ok(())
    }

    /// Connect to a peer.
    pub async fn connect_to_peer(&self, peer_addr: &str) -> Result<()> {
        let addr: std::net::SocketAddr = peer_addr.parse()?;
        // Derive a deterministic node_id from the address so each peer gets a unique entry.
        let node_id = lib_crypto::hash_blake3(peer_addr.as_bytes());
        let peer_info = DhtPeerInfo {
            node_id,
            address: Some(addr),
            capabilities: vec!["dht".to_string()],
            last_seen: now_secs(),
        };
        self.peer_registry.write().await.insert(peer_info.node_id, peer_info);
        info!("Connected to peer: {}", peer_addr);
        Ok(())
    }

    /// Send DHT query to a peer.
    pub async fn send_dht_query(&self, peer_addr: &str, query: String) -> Result<Vec<String>> {
        warn!("DHT query to {} not yet implemented: {}", peer_addr, query);
        Ok(Vec::new())
    }

    /// Get DHT statistics.
    pub async fn get_dht_statistics(&self) -> Result<HashMap<String, f64>> {
        let status = self.get_network_status().await?;
        let mut stats = HashMap::new();
        stats.insert("total_nodes".to_string(), status.total_nodes as f64);
        stats.insert("connected_nodes".to_string(), status.connected_nodes as f64);
        stats.insert("storage_used_bytes".to_string(), status.storage_used_bytes as f64);
        stats.insert("total_keys".to_string(), status.total_keys as f64);
        Ok(stats)
    }

    /// Get storage system reference (returns self).
    pub fn get_storage_system(&self) -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(self.clone()))
    }

    /// Register a peer in the DHT.
    pub async fn register_peer(
        &self,
        node_id: [u8; 32],
        address: std::net::SocketAddr,
        capabilities: Vec<String>,
    ) -> Result<()> {
        let peer_info = DhtPeerInfo {
            node_id,
            address: Some(address),
            capabilities,
            last_seen: now_secs(),
        };
        self.peer_registry.write().await.insert(node_id, peer_info);
        Ok(())
    }

    /// Find closest peers to a target node ID (XOR distance).
    pub async fn find_closest_peers(
        &self,
        target_node_id: &[u8; 32],
        count: usize,
    ) -> Vec<DhtPeerInfo> {
        let peer_registry = self.peer_registry.read().await;
        let mut peers: Vec<_> = peer_registry.values().collect();
        peers.sort_by(|a, b| {
            let dist_a = xor_distance(target_node_id, &a.node_id);
            let dist_b = xor_distance(target_node_id, &b.node_id);
            dist_a.cmp(&dist_b)
        });
        peers.into_iter().take(count).cloned().collect()
    }

    /// Replicate content to nearest peers.
    pub async fn replicate_content(&self, key: &str, replication_factor: u8) -> Result<u8> {
        let content = self.backend.get(key).await?;
        let Some(value) = content else {
            return Err(anyhow::anyhow!("Content not found for replication: {}", key));
        };

        let transport_guard = self.transport.read().await;
        let transport = match *transport_guard {
            Some(ref t) => t,
            None => {
                debug!("No network transport — replication skipped for {}", key);
                return Ok(0);
            }
        };

        let closest_peers = self
            .find_closest_peers(&self.local_node_id, replication_factor as usize)
            .await;

        let mut replicated_count = 0u8;
        for peer in &closest_peers {
            match transport.send_store(peer, key, &value, 3600).await {
                Ok(()) => replicated_count += 1,
                Err(e) => debug!("Replication to peer {:?} failed: {}", &peer.node_id[..4], e),
            }
        }

        info!("Replicated {} to {} peers", key, replicated_count);
        Ok(replicated_count)
    }

    /// Clean up expired content.
    pub async fn cleanup_expired(&self) -> Result<usize> {
        let removed = self.backend.cleanup_expired().await?;
        if removed > 0 {
            info!("Cleaned up {} expired DHT entries", removed);
        }
        Ok(removed)
    }
}

impl Default for ZkDHTIntegration {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate XOR distance between two node IDs.
fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> u128 {
    let mut distance = 0u128;
    for (i, (&byte_a, &byte_b)) in a.iter().zip(b.iter()).enumerate() {
        let xor = byte_a ^ byte_b;
        if xor != 0 {
            distance = ((32 - i) * 8 - xor.leading_zeros() as usize) as u128;
            break;
        }
    }
    distance
}

/// DHT Client wrapper.
pub struct DHTClient {
    inner: ZkDHTIntegration,
}

impl DHTClient {
    pub async fn new(identity: lib_identity::ZhtpIdentity) -> Result<Self> {
        let node_id = *identity.node_id.as_bytes();
        let mut integration = ZkDHTIntegration::with_node_id(node_id, 1024 * 1024 * 1024);
        integration.initialize(identity).await?;
        Ok(Self { inner: integration })
    }

    pub fn from_integration(inner: ZkDHTIntegration) -> Self {
        Self { inner }
    }

    pub fn get_storage_system(&self) -> Arc<RwLock<ZkDHTIntegration>> {
        self.inner.get_storage_system()
    }

    pub async fn get_network_status(&self) -> Result<DHTNetworkStatus> {
        self.inner.get_network_status().await
    }

    pub async fn store_content(
        &self,
        domain: &str,
        path: &str,
        content: Vec<u8>,
        ttl_secs: u64,
    ) -> Result<String> {
        self.inner.store_content(domain, path, content, ttl_secs).await
    }

    pub async fn fetch_content(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.inner.fetch_content(key).await
    }

    pub async fn resolve_content(&self, domain: &str, path: &str) -> Result<Option<Vec<u8>>> {
        self.inner.resolve_content(domain, path).await
    }

    pub async fn discover_peers(&self) -> Result<Vec<String>> {
        self.inner.discover_peers().await
    }

    pub async fn clear_cache(&self) -> Result<()> {
        self.inner.clear_cache().await
    }

    pub async fn cleanup_expired(&self) -> Result<usize> {
        self.inner.cleanup_expired().await
    }
}

/// Resolve content via the DHT client.
pub async fn call_native_dht_client(
    client: &DHTClient,
    domain: &str,
    path: &str,
) -> Result<Option<Vec<u8>>> {
    client.resolve_content(domain, path).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_identity() -> lib_identity::ZhtpIdentity {
        lib_identity::ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Human,
            Some(25),
            Some("US".to_string()),
            "test-device",
            None,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_store_and_retrieve_content() {
        let dht = ZkDHTIntegration::new();

        let content = b"Hello, DHT!".to_vec();
        let key = dht
            .store_content("test.zhtp", "/hello", content.clone(), 300)
            .await
            .unwrap();

        let retrieved = dht.fetch_content(&key).await.unwrap();
        assert_eq!(retrieved, Some(content));
    }

    #[tokio::test]
    async fn test_content_expiration() {
        let dht = ZkDHTIntegration::new();

        let content = b"Expiring content".to_vec();
        let key = dht
            .store_content("test.zhtp", "/expire", content.clone(), 1)
            .await
            .unwrap();

        let retrieved = dht.fetch_content(&key).await.unwrap();
        assert_eq!(retrieved, Some(content));

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let retrieved = dht.fetch_content(&key).await.unwrap();
        assert_eq!(retrieved, None);
    }

    #[tokio::test]
    async fn test_network_status() {
        let dht = ZkDHTIntegration::new();

        let status = dht.get_network_status().await.unwrap();
        assert_eq!(status.total_nodes, 0);
        assert_eq!(status.total_keys, 0);

        dht.store_content("test.zhtp", "/test", b"test".to_vec(), 300)
            .await
            .unwrap();

        let status = dht.get_network_status().await.unwrap();
        assert!(status.total_keys > 0);
        assert!(status.storage_used_bytes > 0);
    }

    #[tokio::test]
    async fn test_peer_discovery() {
        let dht = ZkDHTIntegration::new();

        let peers = dht.discover_peers().await.unwrap();
        assert!(peers.is_empty());

        dht.connect_to_peer("127.0.0.1:9334").await.unwrap();

        let peers = dht.discover_peers().await.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0], "127.0.0.1:9334");
    }

    #[tokio::test]
    async fn test_peer_discovery_multiple_peers() {
        let dht = ZkDHTIntegration::new();

        dht.connect_to_peer("127.0.0.1:9334").await.unwrap();
        dht.connect_to_peer("127.0.0.1:9335").await.unwrap();

        let peers = dht.discover_peers().await.unwrap();
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&"127.0.0.1:9334".to_string()));
        assert!(peers.contains(&"127.0.0.1:9335".to_string()));
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let dht = ZkDHTIntegration::new();

        dht.store_content("test.zhtp", "/expire1", b"test1".to_vec(), 1)
            .await
            .unwrap();
        dht.store_content("test.zhtp", "/expire2", b"test2".to_vec(), 1)
            .await
            .unwrap();
        dht.store_content("test.zhtp", "/keep", b"keep".to_vec(), 300)
            .await
            .unwrap();

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let removed = dht.cleanup_expired().await.unwrap();
        assert_eq!(removed, 2);

        let status = dht.get_network_status().await.unwrap();
        assert_eq!(status.total_keys, 1);
    }

    #[tokio::test]
    async fn test_dht_client_creation() {
        let identity = create_test_identity();
        let client = DHTClient::new(identity).await.unwrap();

        let status = client.get_network_status().await.unwrap();
        assert_eq!(status.total_nodes, 0);
    }

    #[tokio::test]
    async fn test_with_custom_backend() {
        let backend = Arc::new(InMemoryDhtBackend::new());
        let dht = ZkDHTIntegration::with_backend(backend, [0x42; 32], 1024 * 1024);

        let key = dht
            .store_content("custom.zhtp", "/test", b"custom backend".to_vec(), 300)
            .await
            .unwrap();

        let retrieved = dht.fetch_content(&key).await.unwrap();
        assert_eq!(retrieved, Some(b"custom backend".to_vec()));
    }
}
