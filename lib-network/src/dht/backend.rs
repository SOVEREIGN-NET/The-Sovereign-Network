//! DHT storage backend trait.
//!
//! Decouples `ZkDHTIntegration` from concrete storage so the application layer
//! can inject a persistent backend (e.g. lib-storage DhtStorage with sled)
//! without lib-network depending on lib-storage.

use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Backend for DHT content storage.
///
/// Implementations must be thread-safe (`Send + Sync`) and support async I/O.
/// The application layer injects a concrete backend at startup; tests use
/// `InMemoryDhtBackend`.
#[async_trait]
pub trait DhtBackend: Send + Sync {
    /// Store a value with a TTL (seconds). Overwrites any existing entry.
    async fn store(&self, key: &str, value: Vec<u8>, ttl_secs: u64) -> Result<()>;

    /// Retrieve a value by key. Returns `None` if missing or expired.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Delete a key.
    async fn delete(&self, key: &str) -> Result<()>;

    /// Remove all expired entries. Returns count of removed entries.
    async fn cleanup_expired(&self) -> Result<usize>;

    /// Total number of stored keys.
    async fn key_count(&self) -> usize;

    /// Total storage bytes used by values.
    async fn storage_bytes(&self) -> u64;
}

/// Entry stored by the in-memory backend.
struct MemEntry {
    value: Vec<u8>,
    expires_at: u64,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// In-memory DHT backend for tests and single-node development.
pub struct InMemoryDhtBackend {
    entries: Arc<RwLock<HashMap<String, MemEntry>>>,
}

impl InMemoryDhtBackend {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryDhtBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DhtBackend for InMemoryDhtBackend {
    async fn store(&self, key: &str, value: Vec<u8>, ttl_secs: u64) -> Result<()> {
        let entry = MemEntry {
            value,
            expires_at: now_secs() + ttl_secs,
        };
        self.entries.write().await.insert(key.to_string(), entry);
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let mut entries = self.entries.write().await;
        if let Some(entry) = entries.get(key) {
            if now_secs() > entry.expires_at {
                entries.remove(key);
                return Ok(None);
            }
            return Ok(Some(entry.value.clone()));
        }
        Ok(None)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.entries.write().await.remove(key);
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<usize> {
        let mut entries = self.entries.write().await;
        let before = entries.len();
        let now = now_secs();
        entries.retain(|_, e| now <= e.expires_at);
        Ok(before - entries.len())
    }

    async fn key_count(&self) -> usize {
        self.entries.read().await.len()
    }

    async fn storage_bytes(&self) -> u64 {
        self.entries
            .read()
            .await
            .values()
            .map(|e| e.value.len() as u64)
            .sum()
    }
}
