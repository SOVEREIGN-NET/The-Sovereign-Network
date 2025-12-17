//! DHT (Distributed Hash Table) Implementation
//! 
//! **ARCHITECTURE NOTE:**
//! This module is a thin transport/protocol layer that uses lib-storage's DHT as the backend.
//! 
//! - **lib-storage/dht**: Core Kademlia implementation (routing tables, storage, replication)
//! - **lib-network/dht**: Transport protocols and enhancements (BLE, WiFi Direct, relay, mDNS, caching)
//! 
//! All DHT storage operations internally use `lib_storage::dht::DhtStorage`.
//! This module adds protocol-agnostic transport layers that work over:
//! - UDP (traditional)
//! - Bluetooth LE (for edge devices)
//! - WiFi Direct
//! - LoRaWAN
//! 
//! This enables pure BLE devices to fully participate in DHT without UDP/WiFi.

pub mod protocol;
pub mod relay;
pub mod cache;
pub mod bootstrap;
pub mod peer_discovery;
pub mod monitoring;
pub mod transport;

use anyhow::Result;
use serde::{Serialize, Deserialize};
use lib_identity::ZhtpIdentity;
use tokio::sync::RwLock;
use std::sync::Arc;
use lib_crypto::hashing::hash_blake3;
use hex;

// Re-export lib-storage's public DHT types
// Note: DhtStorage is NOT accessible - it's internal to lib-storage.
// Use lib_storage::UnifiedStorageSystem for all storage operations.
pub use lib_storage::dht::{
    routing::KademliaRouter,
};
pub use lib_storage::types::dht_types::DhtNode;

// Import UnifiedStorageSystem for lib-network's internal use
use lib_storage::UnifiedStorageSystem;

// Re-export our new transport layer
pub use transport::{DhtTransport, PeerId, UdpDhtTransport, BleDhtTransport, MultiDhtTransport, PeerAddressResolver};

// Re-export main types
pub use relay::ZhtpRelayProtocol;
// Note: DhtCache is internal, not re-exported

/// Wrapper for DHT integration with mesh networking
/// 
/// **Note**: This now uses UnifiedStorageSystem internally (the canonical storage API).
pub struct ZkDHTIntegration {
    storage: Arc<RwLock<UnifiedStorageSystem>>,
}

impl ZkDHTIntegration {
    pub async fn new() -> Result<Self> {
        // Create default UnifiedStorageSystem
        let config = lib_storage::UnifiedStorageConfig::default();
        let storage = UnifiedStorageSystem::new(config).await?;
        
        Ok(Self {
            storage: Arc::new(RwLock::new(storage)),
        })
    }

    /// Create an integration from an existing UnifiedStorageSystem.
    pub fn from_storage(storage: UnifiedStorageSystem) -> Self {
        Self { storage: Arc::new(RwLock::new(storage)) }
    }
    
    pub async fn initialize(&mut self, _identity: ZhtpIdentity) -> Result<()> {
        // DHT storage is already initialized in new_default()
        Ok(())
    }
    
    pub async fn resolve_content(&mut self, domain: &str, path: &str) -> Result<Option<Vec<u8>>> {
        let key = format!("{}{}", domain, path);
        let mut storage = self.storage.write().await;
        storage.get(&key).await
    }

    pub async fn store_content(&mut self, domain: &str, path: &str, content: Vec<u8>) -> Result<String> {
        let key = format!("{}{}", domain, path);
        let hash = hash_blake3(&content);
        let hash_hex = hex::encode(hash);

        let mut storage = self.storage.write().await;
        // Store by domain/path for lookup
        storage.store(key, content.clone(), None).await?;
        // Store by hash for direct fetch
        storage.store(hash_hex.clone(), content, None).await?;

        Ok(hash_hex)
    }

    pub async fn get_network_status(&self) -> Result<DHTNetworkStatus> {
        let storage = self.storage.read().await;
        let stats = storage.get_storage_stats();
        Ok(DHTNetworkStatus {
            total_nodes: stats.total_entries as u32,
            connected_nodes: 1, // Local node
            storage_used_bytes: stats.total_size,
            total_keys: stats.total_entries as u32,
        })
    }
    
    pub async fn clear_cache(&mut self) -> Result<()> {
        // This would clear cached entries but not stored data
        Ok(())
    }
    
    // Additional methods for compatibility with old DHTClient API
    
    pub async fn fetch_content(&mut self, key: &str) -> Result<Option<Vec<u8>>> {
        let mut storage = self.storage.write().await;
        storage.get(key).await
    }
    
    pub async fn discover_peers(&self) -> Result<Vec<String>> {
        // Return list of known DHT nodes
        let storage = self.storage.read().await;
        let nodes = storage.get_known_nodes();
        Ok(nodes
            .iter()
            .map(|n| {
                let addr = n.addresses.first().cloned().unwrap_or_default();
                format!("{}@{}", hex::encode(n.peer.node_id().as_bytes()), addr)
            })
            .collect())
    }
    
    pub async fn connect_to_peer(&mut self, _peer_address: &str) -> Result<()> {
        // Peer connections are handled by lib-storage's DhtNode management
        Ok(())
    }
    
    pub async fn register_peer(&mut self, _peer_info: serde_json::Value) -> Result<()> {
        // Peer registration is handled by lib-storage
        Ok(())
    }
    
    pub async fn send_dht_query(&self, _peer_addr: &str, _query: String) -> Result<Vec<String>> {
        // DHT queries are handled internally by lib-storage
        Ok(vec![])
    }
    
    pub async fn get_dht_statistics(&self) -> Result<std::collections::HashMap<String, f64>> {
        let storage = self.storage.read().await;
        let stats = storage.get_storage_stats();
        let mut map = std::collections::HashMap::new();
        map.insert("queries_sent".to_string(), 0.0);
        map.insert("queries_received".to_string(), 0.0);
        map.insert("storage_used".to_string(), stats.total_size as f64);
        map.insert("total_keys".to_string(), stats.total_entries as f64);
        Ok(map)
    }

    pub fn get_storage_system(&self) -> Arc<RwLock<UnifiedStorageSystem>> {
        self.storage.clone()
    }

    pub async fn get_cache_stats(&self) -> std::collections::HashMap<String, u64> {
        // Placeholder: lib-storage currently has no cache metrics exposed
        std::collections::HashMap::new()
    }
}

/// Backward-compatible DHT client that wraps ZkDHTIntegration.
/// Now uses UnifiedStorageSystem internally.
pub struct DHTClient {
    inner: ZkDHTIntegration,
}

impl DHTClient {
    pub async fn new(_identity: ZhtpIdentity) -> Result<Self> {
        Ok(Self {
            inner: ZkDHTIntegration::new().await?,
        })
    }

    pub fn from_integration(inner: ZkDHTIntegration) -> Self {
        Self { inner }
    }

    pub fn get_storage_system(&self) -> Arc<RwLock<UnifiedStorageSystem>> {
        self.inner.get_storage_system()
    }

    pub async fn store_content(&mut self, domain: &str, path: &str, content: Vec<u8>) -> Result<String> {
        self.inner.store_content(domain, path, content).await
    }

    pub async fn resolve_content(&mut self, domain: &str, path: &str) -> Result<Option<String>> {
        if let Some(bytes) = self.inner.resolve_content(domain, path).await? {
            let hash_hex = hex::encode(hash_blake3(&bytes));
            Ok(Some(hash_hex))
        } else {
            Ok(None)
        }
    }

    pub async fn fetch_content(&mut self, key: &str) -> Result<Option<Vec<u8>>> {
        self.inner.fetch_content(key).await
    }

    pub async fn get_cache_stats(&self) -> std::collections::HashMap<String, u64> {
        self.inner.get_cache_stats().await
    }

    pub async fn get_dht_statistics(&self) -> Result<std::collections::HashMap<String, f64>> {
        self.inner.get_dht_statistics().await
    }

    pub async fn get_network_status(&self) -> Result<DHTNetworkStatus> {
        self.inner.get_network_status().await
    }

    pub async fn discover_peers(&self) -> Result<Vec<String>> {
        self.inner.discover_peers().await
    }
}

/// DHT network status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DHTNetworkStatus {
    pub total_nodes: u32,
    pub connected_nodes: u32,
    pub storage_used_bytes: u64,
    pub total_keys: u32,
}

/// Call DHT client method (legacy compatibility function)
/// This wraps ZkDHTIntegration methods for backward compatibility
pub async fn call_native_dht_client(method: &str, params: &serde_json::Value) -> Result<serde_json::Value> {
    match method {
        "loadPage" => {
            let url = params.get("url")
                .and_then(|u| u.as_str())
                .ok_or_else(|| anyhow::anyhow!("Missing url parameter"))?;
            
            // Parse zhtp:// URL
            let url = url.strip_prefix("zhtp://").unwrap_or(url);
            let parts: Vec<&str> = url.split('/').collect();
            let domain = parts.get(0).ok_or_else(|| anyhow::anyhow!("Invalid URL"))?;
            let path = if parts.len() > 1 { parts[1..].join("/") } else { String::new() };
            
            let content = serve_web4_page(domain, &path).await?;
            Ok(serde_json::json!({
                "content": {
                    "html": content
                }
            }))
        },
        _ => Ok(serde_json::json!({"error": "Unknown method"}))
    }
}

/// Serve a Web4 page from the DHT
/// This is a simplified wrapper around ZkDHTIntegration
pub async fn serve_web4_page(domain: &str, path: &str) -> Result<String> {
    // This function should be called through a ZkDHTIntegration instance
    // For now, return a placeholder that indicates DHT integration is needed
    Ok(format!(
        "<html><body><h1>DHT Web4 Page</h1><p>Domain: {}</p><p>Path: {}</p></body></html>",
        domain, path
    ))
}

/// Initialize DHT client (legacy compatibility function)
pub async fn initialize_dht_client(identity: ZhtpIdentity) -> Result<DHTClient> {
    DHTClient::new(identity).await
}
