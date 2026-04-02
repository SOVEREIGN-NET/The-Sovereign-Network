//! Persistent DHT backend backed by lib-storage's DhtStorage with sled.
//!
//! Implements `lib_network::dht::DhtBackend` so that `ZkDHTIntegration`
//! stores content on disk via sled rather than in-memory HashMaps.

use anyhow::Result;
use async_trait::async_trait;
use lib_network::dht::DhtBackend;
use lib_storage::dht::backend::SledBackend;
use lib_storage::dht::DhtStorage;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Persistent DHT backend using lib-storage's DhtStorage with sled.
pub struct PersistentDhtBackend {
    storage: Arc<Mutex<DhtStorage<SledBackend>>>,
}

impl PersistentDhtBackend {
    /// Create with a persistent sled backend at the given path.
    pub fn open(
        node_id: lib_storage::types::NodeId,
        max_storage_bytes: u64,
        path: impl AsRef<std::path::Path>,
    ) -> Result<Self> {
        let storage = DhtStorage::new_persistent(node_id, max_storage_bytes, path)?;
        Ok(Self {
            storage: Arc::new(Mutex::new(storage)),
        })
    }
}

#[async_trait]
impl DhtBackend for PersistentDhtBackend {
    async fn store(&self, key: &str, value: Vec<u8>, _ttl_secs: u64) -> Result<()> {
        let mut storage = self.storage.lock().await;
        storage.store(key.to_string(), value, None).await
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let mut storage = self.storage.lock().await;
        storage.get(key).await
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let mut storage = self.storage.lock().await;
        storage.remove(key).await?;
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<usize> {
        let mut storage = self.storage.lock().await;
        storage.cleanup_expired().await
    }

    async fn key_count(&self) -> usize {
        let storage = self.storage.lock().await;
        storage.get_storage_stats().total_entries
    }

    async fn storage_bytes(&self) -> u64 {
        let storage = self.storage.lock().await;
        storage.get_storage_stats().total_size
    }
}
