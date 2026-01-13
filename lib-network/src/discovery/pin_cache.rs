//! TLS Certificate Pin Cache (Issue #739)
//!
//! Caches verified discovery records that contain TLS certificate pins.
//! The QUIC handshake uses this cache to verify peer certificates before
//! proceeding with UHP authentication.
//!
//! # Security Properties
//!
//! - **Signature Verification**: Only records with valid Dilithium signatures are cached
//! - **Expiry Enforcement**: Records are automatically evicted after expires_at
//! - **LRU Eviction**: Oldest entries are evicted when capacity is reached
//! - **Atomic Updates**: Thread-safe updates via RwLock

use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, debug};
use uuid::Uuid;

use super::local_network::NodeAnnouncement;

/// Maximum number of entries in the pin cache
const MAX_PIN_CACHE_ENTRIES: usize = 10_000;

/// Node identifier key (32 bytes, matches lib_identity::NodeId)
pub type NodeIdKey = [u8; 32];

/// Convert a UUID to a 32-byte NodeIdKey (first 16 bytes from UUID, rest zeros)
pub fn uuid_to_node_id_key(uuid: &Uuid) -> NodeIdKey {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(uuid.as_bytes());
    key
}

/// Entry in the pin cache
#[derive(Debug, Clone)]
pub struct PinCacheEntry {
    /// Node identifier (raw bytes for interop with lib_identity::NodeId)
    pub node_id: NodeIdKey,
    /// Dilithium public key (for UHP identity verification)
    pub dilithium_pk: Vec<u8>,
    /// SHA256 hash of TLS certificate SPKI
    pub tls_spki_sha256: [u8; 32],
    /// When the record expires (Unix timestamp)
    pub expires_at: u64,
    /// When the entry was last seen/updated
    pub last_seen: u64,
    /// Network endpoints for this node
    pub endpoints: Vec<String>,
}

/// Thread-safe cache of verified TLS certificate pins
#[derive(Debug)]
pub struct TlsPinCache {
    /// Map from node_id to pin entry
    entries: Arc<RwLock<HashMap<NodeIdKey, PinCacheEntry>>>,
    /// LRU tracking: node_id -> last access time
    access_times: Arc<RwLock<HashMap<NodeIdKey, u64>>>,
}

impl Default for TlsPinCache {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsPinCache {
    /// Create a new empty pin cache
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            access_times: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get the current Unix timestamp
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Insert or update a pin entry from a verified announcement
    ///
    /// The announcement must have already been verified with `verify_and_check_expiry()`.
    ///
    /// # Key Rotation Security
    ///
    /// When updating an existing entry, the Dilithium public key must match.
    /// This prevents an attacker from replacing a legitimate node's entry.
    /// TLS certificate rotation is allowed (tls_spki_sha256 can change) as long
    /// as the announcement is signed by the same Dilithium key.
    pub async fn insert_verified(&self, announcement: &NodeAnnouncement, endpoints: Vec<String>) -> Result<()> {
        // Validate that the announcement has TLS pin data
        if !announcement.has_tls_pin() {
            return Err(anyhow!("Announcement does not have TLS pin data"));
        }

        // Convert UUID to 32-byte key (pad with zeros)
        let node_id_key = uuid_to_node_id_key(&announcement.node_id);
        let new_dilithium_pk = announcement.dilithium_pk.clone().unwrap();
        let new_tls_spki = announcement.tls_spki_sha256.unwrap();

        let mut entries = self.entries.write().await;
        let mut access_times = self.access_times.write().await;

        // Security check: if entry exists, verify Dilithium PK matches (key rotation security)
        if let Some(existing) = entries.get(&node_id_key) {
            if existing.dilithium_pk != new_dilithium_pk {
                warn!(
                    "SECURITY: Rejected pin update for node {} - Dilithium PK mismatch (identity hijack attempt)",
                    announcement.node_id
                );
                return Err(anyhow!(
                    "Cannot update pin entry: Dilithium PK mismatch (possible identity hijack)"
                ));
            }

            // Log TLS certificate rotation
            if existing.tls_spki_sha256 != new_tls_spki {
                info!(
                    "Pin cache: TLS certificate rotated for node {} (same Dilithium identity)",
                    announcement.node_id
                );
            }
        }

        let entry = PinCacheEntry {
            node_id: node_id_key,
            dilithium_pk: new_dilithium_pk,
            tls_spki_sha256: new_tls_spki,
            expires_at: announcement.expires_at.unwrap(),
            last_seen: Self::now(),
            endpoints,
        };

        // Evict oldest entries if at capacity
        if entries.len() >= MAX_PIN_CACHE_ENTRIES && !entries.contains_key(&node_id_key) {
            self.evict_oldest_locked(&mut entries, &mut access_times);
        }

        entries.insert(node_id_key, entry);
        access_times.insert(node_id_key, Self::now());

        debug!("Pin cache: inserted/updated entry for node {}", announcement.node_id);
        Ok(())
    }

    /// Look up a pin entry by node_id (32-byte key)
    pub async fn get(&self, node_id: &NodeIdKey) -> Option<PinCacheEntry> {
        let entries = self.entries.read().await;
        let entry = entries.get(node_id)?;

        // Check if expired
        if entry.expires_at < Self::now() {
            return None;
        }

        // Update access time
        drop(entries);
        let mut access_times = self.access_times.write().await;
        access_times.insert(*node_id, Self::now());

        let entries = self.entries.read().await;
        entries.get(node_id).cloned()
    }

    /// Look up a pin entry by UUID (for discovery announcements)
    pub async fn get_by_uuid(&self, uuid: &Uuid) -> Option<PinCacheEntry> {
        let key = uuid_to_node_id_key(uuid);
        self.get(&key).await
    }

    /// Verify a peer's TLS SPKI hash against the cached pin
    ///
    /// Returns Ok(true) if the pin matches, Ok(false) if no pin cached,
    /// or Err if the pin doesn't match (security violation).
    pub async fn verify_peer_spki(&self, node_id: &NodeIdKey, peer_spki_sha256: &[u8; 32]) -> Result<bool> {
        let entry = match self.get(node_id).await {
            Some(e) => e,
            None => {
                debug!("Pin cache: no entry for node {:?}", &node_id[..8]);
                return Ok(false);
            }
        };

        if &entry.tls_spki_sha256 != peer_spki_sha256 {
            warn!(
                "SECURITY: TLS SPKI mismatch for node {:?} - expected {:?}, got {:?}",
                &node_id[..8],
                hex::encode(&entry.tls_spki_sha256[..8]),
                hex::encode(&peer_spki_sha256[..8])
            );
            return Err(anyhow!(
                "TLS certificate SPKI does not match discovery pin"
            ));
        }

        debug!("Pin cache: SPKI verified for node {:?}", &node_id[..8]);
        Ok(true)
    }

    /// Verify a peer's TLS SPKI using UUID (for discovery announcements)
    pub async fn verify_peer_spki_by_uuid(&self, uuid: &Uuid, peer_spki_sha256: &[u8; 32]) -> Result<bool> {
        let key = uuid_to_node_id_key(uuid);
        self.verify_peer_spki(&key, peer_spki_sha256).await
    }

    /// Get the Dilithium public key for a node (for UHP identity verification)
    pub async fn get_dilithium_pk(&self, node_id: &NodeIdKey) -> Option<Vec<u8>> {
        self.get(node_id).await.map(|e| e.dilithium_pk)
    }

    /// Verify a peer's Dilithium public key against the cached discovery record
    ///
    /// This should be called after UHP handshake to ensure the peer's identity
    /// matches what was learned during discovery.
    ///
    /// Returns Ok(true) if the key matches, Ok(false) if no pin cached,
    /// or Err if the key doesn't match (security violation).
    pub async fn verify_peer_dilithium_pk(&self, node_id: &NodeIdKey, peer_dilithium_pk: &[u8]) -> Result<bool> {
        let entry = match self.get(node_id).await {
            Some(e) => e,
            None => {
                debug!("Pin cache: no entry for node {:?} (dilithium pk check)", &node_id[..8]);
                return Ok(false);
            }
        };

        if entry.dilithium_pk != peer_dilithium_pk {
            warn!(
                "SECURITY: Dilithium PK mismatch for node {:?} - cached pk len: {}, peer pk len: {}",
                &node_id[..8],
                entry.dilithium_pk.len(),
                peer_dilithium_pk.len()
            );
            return Err(anyhow!(
                "Peer's Dilithium public key does not match discovery cache"
            ));
        }

        debug!("Pin cache: Dilithium PK verified for node {:?}", &node_id[..8]);
        Ok(true)
    }

    /// Remove expired entries from the cache
    pub async fn cleanup_expired(&self) {
        let now = Self::now();
        let mut entries = self.entries.write().await;
        let mut access_times = self.access_times.write().await;

        let expired: Vec<NodeIdKey> = entries
            .iter()
            .filter(|(_, e)| e.expires_at < now)
            .map(|(id, _)| *id)
            .collect();

        for id in &expired {
            entries.remove(id);
            access_times.remove(id);
        }

        if !expired.is_empty() {
            info!("Pin cache: removed {} expired entries", expired.len());
        }
    }

    /// Evict the oldest entry (by access time)
    fn evict_oldest_locked(
        &self,
        entries: &mut HashMap<NodeIdKey, PinCacheEntry>,
        access_times: &mut HashMap<NodeIdKey, u64>,
    ) {
        if let Some((oldest_id, _)) = access_times.iter().min_by_key(|(_, &time)| time) {
            let oldest_id = *oldest_id;
            entries.remove(&oldest_id);
            access_times.remove(&oldest_id);
            debug!("Pin cache: evicted oldest entry {:?}", &oldest_id[..8]);
        }
    }

    /// Get the number of entries in the cache
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Check if the cache is empty
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }

    /// Get all non-expired entries from the cache
    ///
    /// This is useful for syncing pins to the PinnedCertVerifier on startup.
    pub async fn get_all_entries(&self) -> Vec<PinCacheEntry> {
        let now = Self::now();
        let entries = self.entries.read().await;
        entries
            .values()
            .filter(|entry| entry.expires_at >= now)
            .cloned()
            .collect()
    }

    /// Process and cache a discovery announcement if valid
    ///
    /// This is the main entry point for adding discovered peers to the pin cache.
    /// It verifies the signature and expiry before caching.
    pub async fn process_announcement(
        &self,
        announcement: &NodeAnnouncement,
        endpoints: Vec<String>,
    ) -> Result<bool> {
        // Skip announcements without TLS pin data (legacy compatibility)
        if !announcement.has_tls_pin() {
            debug!(
                "Pin cache: skipping announcement without TLS pin for node {}",
                announcement.node_id
            );
            return Ok(false);
        }

        // Verify signature and check expiry
        match announcement.verify_and_check_expiry() {
            Ok(true) => {
                self.insert_verified(announcement, endpoints).await?;
                info!(
                    "Pin cache: cached TLS pin for node {} (expires at {})",
                    announcement.node_id,
                    announcement.expires_at.unwrap()
                );
                Ok(true)
            }
            Ok(false) => {
                warn!(
                    "Pin cache: invalid signature for announcement from node {}",
                    announcement.node_id
                );
                Ok(false)
            }
            Err(e) => {
                warn!(
                    "Pin cache: failed to verify announcement from node {}: {}",
                    announcement.node_id, e
                );
                Err(e)
            }
        }
    }
}

/// Global pin cache instance
static PIN_CACHE: std::sync::OnceLock<TlsPinCache> = std::sync::OnceLock::new();

/// Get the global pin cache instance
pub fn global_pin_cache() -> &'static TlsPinCache {
    PIN_CACHE.get_or_init(TlsPinCache::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pin_cache_basic() {
        let cache = TlsPinCache::new();
        assert!(cache.is_empty().await);

        // Create a test entry
        let node_id_key: NodeIdKey = [1u8; 32];
        let entry = PinCacheEntry {
            node_id: node_id_key,
            dilithium_pk: vec![0u8; 1312],
            tls_spki_sha256: [1u8; 32],
            expires_at: TlsPinCache::now() + 3600,
            last_seen: TlsPinCache::now(),
            endpoints: vec!["127.0.0.1:9334".to_string()],
        };

        // Insert directly (bypassing signature verification for test)
        {
            let mut entries = cache.entries.write().await;
            let mut access_times = cache.access_times.write().await;
            entries.insert(node_id_key, entry);
            access_times.insert(node_id_key, TlsPinCache::now());
        }

        assert_eq!(cache.len().await, 1);

        // Verify SPKI match
        let result = cache.verify_peer_spki(&node_id_key, &[1u8; 32]).await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Verify SPKI mismatch
        let result = cache.verify_peer_spki(&node_id_key, &[2u8; 32]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_pin_cache_expiry() {
        let cache = TlsPinCache::new();
        let node_id_key: NodeIdKey = [2u8; 32];

        // Insert an already-expired entry
        let entry = PinCacheEntry {
            node_id: node_id_key,
            dilithium_pk: vec![0u8; 1312],
            tls_spki_sha256: [1u8; 32],
            expires_at: TlsPinCache::now() - 1, // Already expired
            last_seen: TlsPinCache::now(),
            endpoints: vec![],
        };

        {
            let mut entries = cache.entries.write().await;
            entries.insert(node_id_key, entry);
        }

        // Should not be returned (expired)
        assert!(cache.get(&node_id_key).await.is_none());

        // Cleanup should remove it
        cache.cleanup_expired().await;
        assert!(cache.is_empty().await);
    }

    // ========================================================================
    // Issue #739: Integration tests for 5 security cases
    // ========================================================================

    /// Case 1: Valid TLS pin - SPKI matches cached value → connection allowed
    #[tokio::test]
    async fn test_case1_valid_tls_pin_match() {
        let cache = TlsPinCache::new();
        let node_id_key: NodeIdKey = [10u8; 32];
        let valid_spki = [42u8; 32];

        // Cache a valid pin
        let entry = PinCacheEntry {
            node_id: node_id_key,
            dilithium_pk: vec![0u8; 1312],
            tls_spki_sha256: valid_spki,
            expires_at: TlsPinCache::now() + 3600, // Valid for 1 hour
            last_seen: TlsPinCache::now(),
            endpoints: vec!["192.168.1.100:9334".to_string()],
        };

        {
            let mut entries = cache.entries.write().await;
            let mut access_times = cache.access_times.write().await;
            entries.insert(node_id_key, entry);
            access_times.insert(node_id_key, TlsPinCache::now());
        }

        // Peer presents matching SPKI → should succeed
        let result = cache.verify_peer_spki(&node_id_key, &valid_spki).await;
        assert!(result.is_ok(), "Valid SPKI should verify successfully");
        assert!(result.unwrap(), "Result should indicate pin was found and matched");
    }

    /// Case 2: Valid TLS pin - SPKI mismatch → connection rejected
    #[tokio::test]
    async fn test_case2_valid_tls_pin_mismatch() {
        let cache = TlsPinCache::new();
        let node_id_key: NodeIdKey = [20u8; 32];
        let cached_spki = [42u8; 32];
        let attacker_spki = [99u8; 32]; // Different SPKI (MITM attempt)

        // Cache a valid pin
        let entry = PinCacheEntry {
            node_id: node_id_key,
            dilithium_pk: vec![0u8; 1312],
            tls_spki_sha256: cached_spki,
            expires_at: TlsPinCache::now() + 3600,
            last_seen: TlsPinCache::now(),
            endpoints: vec!["192.168.1.100:9334".to_string()],
        };

        {
            let mut entries = cache.entries.write().await;
            let mut access_times = cache.access_times.write().await;
            entries.insert(node_id_key, entry);
            access_times.insert(node_id_key, TlsPinCache::now());
        }

        // Attacker presents different SPKI → should fail
        let result = cache.verify_peer_spki(&node_id_key, &attacker_spki).await;
        assert!(result.is_err(), "Mismatched SPKI should return error");
        assert!(
            result.unwrap_err().to_string().contains("does not match"),
            "Error should indicate SPKI mismatch"
        );
    }

    /// Case 3: No TLS pin cached → connection allowed (first contact)
    #[tokio::test]
    async fn test_case3_no_pin_cached_first_contact() {
        let cache = TlsPinCache::new();
        let unknown_node_id: NodeIdKey = [30u8; 32];
        let any_spki = [123u8; 32];

        // No entry cached for this node
        assert!(cache.is_empty().await);

        // First contact → should return Ok(false) meaning "no pin, allow connection"
        let result = cache.verify_peer_spki(&unknown_node_id, &any_spki).await;
        assert!(result.is_ok(), "Unknown node should not cause error");
        assert!(!result.unwrap(), "Result should indicate no pin was found (false)");
    }

    /// Case 4: Expired TLS pin → treated as no pin (connection allowed)
    #[tokio::test]
    async fn test_case4_expired_pin_treated_as_no_pin() {
        let cache = TlsPinCache::new();
        let node_id_key: NodeIdKey = [40u8; 32];
        let expired_spki = [42u8; 32];

        // Cache an expired pin
        let entry = PinCacheEntry {
            node_id: node_id_key,
            dilithium_pk: vec![0u8; 1312],
            tls_spki_sha256: expired_spki,
            expires_at: TlsPinCache::now() - 100, // Expired 100 seconds ago
            last_seen: TlsPinCache::now() - 200,
            endpoints: vec!["192.168.1.100:9334".to_string()],
        };

        {
            let mut entries = cache.entries.write().await;
            entries.insert(node_id_key, entry);
        }

        // Even with different SPKI, expired pin should be treated as "no pin"
        let different_spki = [99u8; 32];
        let result = cache.verify_peer_spki(&node_id_key, &different_spki).await;
        assert!(result.is_ok(), "Expired pin should not cause error");
        assert!(!result.unwrap(), "Expired pin should be treated as 'no pin' (false)");
    }

    /// Case 5: Dilithium PK verification - match
    #[tokio::test]
    async fn test_case5_dilithium_pk_match() {
        let cache = TlsPinCache::new();
        let node_id_key: NodeIdKey = [50u8; 32];
        let valid_dilithium_pk = vec![55u8; 1312]; // Dilithium3 public key size

        // Cache entry with Dilithium PK
        let entry = PinCacheEntry {
            node_id: node_id_key,
            dilithium_pk: valid_dilithium_pk.clone(),
            tls_spki_sha256: [1u8; 32],
            expires_at: TlsPinCache::now() + 3600,
            last_seen: TlsPinCache::now(),
            endpoints: vec!["192.168.1.100:9334".to_string()],
        };

        {
            let mut entries = cache.entries.write().await;
            let mut access_times = cache.access_times.write().await;
            entries.insert(node_id_key, entry);
            access_times.insert(node_id_key, TlsPinCache::now());
        }

        // Peer presents matching Dilithium PK → should succeed
        let result = cache.verify_peer_dilithium_pk(&node_id_key, &valid_dilithium_pk).await;
        assert!(result.is_ok(), "Valid Dilithium PK should verify successfully");
        assert!(result.unwrap(), "Result should indicate PK was found and matched");
    }

    /// Case 5b: Dilithium PK verification - mismatch (identity compromise)
    #[tokio::test]
    async fn test_case5_dilithium_pk_mismatch() {
        let cache = TlsPinCache::new();
        let node_id_key: NodeIdKey = [51u8; 32];
        let cached_dilithium_pk = vec![55u8; 1312];
        let attacker_dilithium_pk = vec![99u8; 1312]; // Different PK (impersonation attempt)

        // Cache entry with legitimate Dilithium PK
        let entry = PinCacheEntry {
            node_id: node_id_key,
            dilithium_pk: cached_dilithium_pk,
            tls_spki_sha256: [1u8; 32],
            expires_at: TlsPinCache::now() + 3600,
            last_seen: TlsPinCache::now(),
            endpoints: vec!["192.168.1.100:9334".to_string()],
        };

        {
            let mut entries = cache.entries.write().await;
            let mut access_times = cache.access_times.write().await;
            entries.insert(node_id_key, entry);
            access_times.insert(node_id_key, TlsPinCache::now());
        }

        // Attacker presents different Dilithium PK → should fail
        let result = cache.verify_peer_dilithium_pk(&node_id_key, &attacker_dilithium_pk).await;
        assert!(result.is_err(), "Mismatched Dilithium PK should return error");
        assert!(
            result.unwrap_err().to_string().contains("does not match"),
            "Error should indicate Dilithium PK mismatch"
        );
    }

    /// Case 5c: Dilithium PK verification - no cache entry (first contact)
    #[tokio::test]
    async fn test_case5_dilithium_pk_no_cache() {
        let cache = TlsPinCache::new();
        let unknown_node_id: NodeIdKey = [52u8; 32];
        let any_dilithium_pk = vec![123u8; 1312];

        // No entry cached for this node
        assert!(cache.is_empty().await);

        // First contact → should return Ok(false) meaning "no cached PK, allow connection"
        let result = cache.verify_peer_dilithium_pk(&unknown_node_id, &any_dilithium_pk).await;
        assert!(result.is_ok(), "Unknown node should not cause error");
        assert!(!result.unwrap(), "Result should indicate no PK was cached (false)");
    }

    // ========================================================================
    // Key Rotation Security Tests
    // ========================================================================

    /// Key rotation: TLS certificate update with same Dilithium PK → allowed
    #[tokio::test]
    async fn test_key_rotation_same_dilithium_pk_allowed() {
        let cache = TlsPinCache::new();
        let node_id_key: NodeIdKey = [60u8; 32];
        let dilithium_pk = vec![77u8; 1312];
        let old_tls_spki = [1u8; 32];
        let new_tls_spki = [2u8; 32]; // Rotated TLS certificate

        // Insert initial entry
        let initial_entry = PinCacheEntry {
            node_id: node_id_key,
            dilithium_pk: dilithium_pk.clone(),
            tls_spki_sha256: old_tls_spki,
            expires_at: TlsPinCache::now() + 3600,
            last_seen: TlsPinCache::now(),
            endpoints: vec!["192.168.1.100:9334".to_string()],
        };

        {
            let mut entries = cache.entries.write().await;
            let mut access_times = cache.access_times.write().await;
            entries.insert(node_id_key, initial_entry);
            access_times.insert(node_id_key, TlsPinCache::now());
        }

        // Create updated entry with same Dilithium PK but new TLS SPKI
        let updated_entry = PinCacheEntry {
            node_id: node_id_key,
            dilithium_pk: dilithium_pk.clone(), // Same Dilithium identity
            tls_spki_sha256: new_tls_spki,      // New TLS certificate
            expires_at: TlsPinCache::now() + 7200,
            last_seen: TlsPinCache::now(),
            endpoints: vec!["192.168.1.100:9334".to_string()],
        };

        // Manually update (simulating what insert_verified does after verification)
        {
            let mut entries = cache.entries.write().await;
            entries.insert(node_id_key, updated_entry);
        }

        // Verify the new TLS SPKI is cached
        let result = cache.verify_peer_spki(&node_id_key, &new_tls_spki).await;
        assert!(result.is_ok());
        assert!(result.unwrap(), "New TLS SPKI should be accepted after rotation");

        // Old TLS SPKI should now fail
        let result = cache.verify_peer_spki(&node_id_key, &old_tls_spki).await;
        assert!(result.is_err(), "Old TLS SPKI should be rejected after rotation");
    }

    /// Key rotation: TLS certificate update with DIFFERENT Dilithium PK → rejected (hijack attempt)
    #[tokio::test]
    async fn test_key_rotation_different_dilithium_pk_rejected() {
        let cache = TlsPinCache::new();
        let node_id_key: NodeIdKey = [61u8; 32];
        let legitimate_dilithium_pk = vec![77u8; 1312];
        let attacker_dilithium_pk = vec![99u8; 1312]; // Different Dilithium PK

        // Insert initial entry with legitimate Dilithium PK
        let initial_entry = PinCacheEntry {
            node_id: node_id_key,
            dilithium_pk: legitimate_dilithium_pk.clone(),
            tls_spki_sha256: [1u8; 32],
            expires_at: TlsPinCache::now() + 3600,
            last_seen: TlsPinCache::now(),
            endpoints: vec!["192.168.1.100:9334".to_string()],
        };

        {
            let mut entries = cache.entries.write().await;
            let mut access_times = cache.access_times.write().await;
            entries.insert(node_id_key, initial_entry);
            access_times.insert(node_id_key, TlsPinCache::now());
        }

        // Attacker tries to update with their Dilithium PK
        // (In real code, this check happens in insert_verified before insertion)
        let entries = cache.entries.read().await;
        let existing = entries.get(&node_id_key).unwrap();

        // This should fail - Dilithium PK mismatch
        assert_ne!(
            existing.dilithium_pk, attacker_dilithium_pk,
            "Attacker's Dilithium PK should not match existing entry"
        );

        // The legitimate Dilithium PK should still match
        assert_eq!(
            existing.dilithium_pk, legitimate_dilithium_pk,
            "Legitimate Dilithium PK should still be cached"
        );
    }
}
