//! Integration-layer DHT adapter backed by lib-storage.
//!
//! This replaces direct usage of lib-network DHT stubs in zhtp runtime paths.

use anyhow::Result;
use lib_identity::ZhtpIdentity;
use lib_storage::dht::backend::{HashMapBackend, SledBackend};
use lib_storage::dht::DhtStorage;
use lib_storage::types::NodeId;
use serde::{Deserialize, Serialize};
use crate::compression::{compress_for_wire, decompress_from_wire, DataCategory};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::{debug, info, warn};

const DEFAULT_MAX_STORAGE_BYTES: u64 = 10_000_000_000;

/// DHT Network Status used by zhtp API layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DHTNetworkStatus {
    pub total_nodes: u32,
    pub connected_nodes: u32,
    pub storage_used_bytes: u64,
    pub total_keys: u32,
}

impl Default for DHTNetworkStatus {
    fn default() -> Self {
        Self {
            total_nodes: 0,
            connected_nodes: 0,
            storage_used_bytes: 0,
            total_keys: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DhtPeerInfo {
    pub node_id: [u8; 32],
    pub address: Option<SocketAddr>,
    pub capabilities: Vec<String>,
    pub last_seen: u64,
}

#[derive(Debug)]
enum StorageBackend {
    Persistent(DhtStorage<SledBackend>),
    Memory(DhtStorage<HashMapBackend>),
}

impl StorageBackend {
    async fn store(&mut self, key: String, value: Vec<u8>) -> Result<()> {
        match self {
            StorageBackend::Persistent(s) => s.store(key, value, None).await,
            StorageBackend::Memory(s) => s.store(key, value, None).await,
        }
    }

    async fn get(&mut self, key: &str) -> Result<Option<Vec<u8>>> {
        match self {
            StorageBackend::Persistent(s) => s.get(key).await,
            StorageBackend::Memory(s) => s.get(key).await,
        }
    }

    async fn set_expiry(&mut self, key: &str, expiry: u64) -> Result<()> {
        match self {
            StorageBackend::Persistent(s) => s.set_expiry(key, expiry).await,
            StorageBackend::Memory(s) => s.set_expiry(key, expiry).await,
        }
    }

    async fn clear_all(&mut self) -> Result<()> {
        match self {
            StorageBackend::Persistent(s) => s.clear_all().await,
            StorageBackend::Memory(s) => s.clear_all().await,
        }
    }

    async fn cleanup_expired(&mut self) -> Result<usize> {
        match self {
            StorageBackend::Persistent(s) => s.cleanup_expired().await,
            StorageBackend::Memory(s) => s.cleanup_expired().await,
        }
    }

    fn stats(&self) -> lib_storage::dht::storage::StorageStats {
        match self {
            StorageBackend::Persistent(s) => s.get_storage_stats(),
            StorageBackend::Memory(s) => s.get_storage_stats(),
        }
    }
}

/// Production integration adapter for DHT operations.
pub struct DhtIntegrationAdapter {
    storage: StorageBackend,
    peer_registry: HashMap<[u8; 32], DhtPeerInfo>,
    local_node_id: [u8; 32],
    max_storage_bytes: u64,
}

impl DhtIntegrationAdapter {
    pub fn new() -> Self {
        let node_id = [0u8; 32];
        let storage = StorageBackend::Memory(DhtStorage::new(
            NodeId::default(),
            DEFAULT_MAX_STORAGE_BYTES,
        ));

        Self {
            storage,
            peer_registry: HashMap::new(),
            local_node_id: node_id,
            max_storage_bytes: DEFAULT_MAX_STORAGE_BYTES,
        }
    }

    pub async fn initialize(&mut self, identity: ZhtpIdentity) -> Result<()> {
        let node_id = identity.node_id.clone();
        self.local_node_id = *node_id.as_bytes();
        let persist_path = Self::default_persist_path();

        if let Some(parent) = persist_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                warn!(
                    "Unable to create DHT persistence dir {:?} ({}), falling back to in-memory backend",
                    parent, e
                );
                self.storage =
                    StorageBackend::Memory(DhtStorage::new(node_id, self.max_storage_bytes));
                return Ok(());
            }
        }

        self.storage = match DhtStorage::<SledBackend>::new_persistent(
            node_id.clone(),
            self.max_storage_bytes,
            &persist_path,
        ) {
            Ok(storage) => {
                info!(
                    "DHT adapter initialized with persistent backend at {:?}",
                    persist_path
                );
                StorageBackend::Persistent(storage)
            }
            Err(e) => {
                warn!(
                    "Persistent DHT backend unavailable ({}), falling back to in-memory backend",
                    e
                );
                StorageBackend::Memory(DhtStorage::new(node_id, self.max_storage_bytes))
            }
        };

        info!(
            "DHT integration adapter initialized with node ID: {:?}",
            &self.local_node_id[..8]
        );
        Ok(())
    }

    pub async fn store_content(
        &mut self,
        domain: &str,
        path: &str,
        content: Vec<u8>,
        ttl_secs: u64,
    ) -> Result<String> {
        let key = format!("{}:{}", domain, path);
        // SovereignCodec compression — Neural Mesh compresses ALL DHT content
        let compressed = compress_for_wire(&content, DataCategory::Dht);
        self.storage.store(key.clone(), compressed).await?;;

        if ttl_secs > 0 {
            let expiry = now_secs().saturating_add(ttl_secs);
            self.storage.set_expiry(&key, expiry).await?;
        }

        Ok(key)
    }

    pub async fn fetch_content(&mut self, key: &str) -> Result<Option<Vec<u8>>> {
        match self.storage.get(key).await? {
            Some(data) => {
                // Transparently decompress SFC-compressed DHT content
                let decompressed = decompress_from_wire(&data).unwrap_or(data);
                Ok(Some(decompressed))
            }
            None => Ok(None),
        }
    }

    pub async fn resolve_content(&mut self, domain: &str, path: &str) -> Result<Option<Vec<u8>>> {
        let key = format!("{}:{}", domain, path);
        self.fetch_content(&key).await
    }

    pub async fn discover_peers(&self) -> Result<Vec<String>> {
        Ok(self
            .peer_registry
            .values()
            .filter_map(|peer| peer.address.map(|addr| addr.to_string()))
            .collect())
    }

    pub async fn get_network_status(&self) -> Result<DHTNetworkStatus> {
        let stats = self.storage.stats();
        Ok(DHTNetworkStatus {
            total_nodes: self.peer_registry.len() as u32,
            connected_nodes: self.peer_registry.len() as u32,
            storage_used_bytes: stats.total_size,
            total_keys: stats.total_entries as u32,
        })
    }

    pub async fn clear_cache(&mut self) -> Result<()> {
        self.storage.clear_all().await
    }

    pub async fn connect_to_peer(&mut self, peer_addr: &str) -> Result<()> {
        let addr: SocketAddr = peer_addr.parse()?;
        let node_id = socket_addr_to_peer_key(&addr);
        self.register_peer(node_id, addr, vec!["dht".to_string()])
            .await
    }

    pub async fn send_dht_query(&self, peer_addr: &str, query: String) -> Result<Vec<String>> {
        debug!(
            "DHT query placeholder called for peer {} with query '{}'",
            peer_addr, query
        );
        Ok(Vec::new())
    }

    pub async fn get_dht_statistics(&self) -> Result<HashMap<String, f64>> {
        let status = self.get_network_status().await?;
        let mut stats = HashMap::new();

        stats.insert("total_nodes".to_string(), status.total_nodes as f64);
        stats.insert("connected_nodes".to_string(), status.connected_nodes as f64);
        stats.insert(
            "storage_used_bytes".to_string(),
            status.storage_used_bytes as f64,
        );
        stats.insert("total_keys".to_string(), status.total_keys as f64);
        // Backward-compatible counters for API consumers that already read these keys.
        stats.insert("queries_sent".to_string(), 0.0);
        stats.insert("queries_received".to_string(), 0.0);
        stats.insert("content_stored".to_string(), status.total_keys as f64);
        stats.insert("content_retrieved".to_string(), 0.0);
        stats.insert("cache_hits".to_string(), 0.0);
        stats.insert("cache_misses".to_string(), 0.0);
        stats.insert("peers_discovered".to_string(), status.total_nodes as f64);
        stats.insert("storage_operations".to_string(), status.total_keys as f64);

        Ok(stats)
    }

    pub async fn register_peer(
        &mut self,
        node_id: [u8; 32],
        address: SocketAddr,
        capabilities: Vec<String>,
    ) -> Result<()> {
        let peer_info = DhtPeerInfo {
            node_id,
            address: Some(address),
            capabilities,
            last_seen: now_secs(),
        };
        self.peer_registry.insert(node_id, peer_info);
        Ok(())
    }

    pub async fn cleanup_expired(&mut self) -> Result<usize> {
        self.storage.cleanup_expired().await
    }

    fn default_persist_path() -> PathBuf {
        crate::node_data_dir()
            .join("storage")
            .join("dht_adapter.sled")
    }
}

impl Default for DhtIntegrationAdapter {
    fn default() -> Self {
        Self::new()
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn socket_addr_to_peer_key(addr: &SocketAddr) -> [u8; 32] {
    let mut key = [0u8; 32];
    match addr {
        SocketAddr::V4(v4) => {
            key[..4].copy_from_slice(&v4.ip().octets());
            key[4..6].copy_from_slice(&v4.port().to_le_bytes());
        }
        SocketAddr::V6(v6) => {
            key[..16].copy_from_slice(&v6.ip().octets());
            key[16..18].copy_from_slice(&v6.port().to_le_bytes());
        }
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_identity::IdentityType;

    fn create_test_identity() -> ZhtpIdentity {
        ZhtpIdentity::new_unified(IdentityType::Device, None, None, "dht-adapter-test", None)
            .expect("test identity")
    }

    #[tokio::test]
    async fn stores_and_fetches_content() {
        let mut dht = DhtIntegrationAdapter::new();
        dht.initialize(create_test_identity()).await.expect("init");

        let key = dht
            .store_content("test.zhtp", "/hello", b"hello".to_vec(), 300)
            .await
            .expect("store");
        let value = dht.fetch_content(&key).await.expect("fetch");

        assert_eq!(value, Some(b"hello".to_vec()));
    }

    #[tokio::test]
    async fn expires_content_by_ttl() {
        let mut dht = DhtIntegrationAdapter::new();
        dht.initialize(create_test_identity()).await.expect("init");

        let key = dht
            .store_content("test.zhtp", "/expire", b"value".to_vec(), 1)
            .await
            .expect("store");
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let value = dht.fetch_content(&key).await.expect("fetch");
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn tracks_connected_peers() {
        let mut dht = DhtIntegrationAdapter::new();
        dht.initialize(create_test_identity()).await.expect("init");
        dht.connect_to_peer("127.0.0.1:9334")
            .await
            .expect("connect peer");

        let peers = dht.discover_peers().await.expect("discover");
        assert_eq!(peers, vec!["127.0.0.1:9334".to_string()]);
    }

    #[tokio::test]
    async fn clears_cache_without_breaking_status() {
        let mut dht = DhtIntegrationAdapter::new();
        dht.initialize(create_test_identity()).await.expect("init");
        dht.store_content("test.zhtp", "/a", b"a".to_vec(), 300)
            .await
            .expect("store");
        dht.clear_cache().await.expect("clear");

        let status = dht.get_network_status().await.expect("status");
        assert_eq!(status.total_keys, 0);
    }
}
