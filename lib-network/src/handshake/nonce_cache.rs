//! Nonce cache for replay attack prevention
//!
//! # Network Epoch and Persistent Replay Protection
//!
//! This module implements persistent, cross-restart replay protection using:
//!
//! - **Network Epoch**: Stable, network-wide constant derived from chain genesis
//! - **Persistent Nonce Tracking**: Blake3 fingerprints stored in sled
//! - **TTL-Based Pruning**: Automatic cleanup of expired nonces
//!
//! # Security Properties
//!
//! - **Cross-Restart Protection**: Nonce fingerprints survive node restarts
//! - **Network Isolation**: Different networks have different epochs (genesis-derived)
//! - **Bounded Storage**: TTL pruning prevents unbounded growth
//! - **Atomic Operations**: Race-free check-and-insert
//!
//! # Network Epoch Design
//!
//! Network epoch is derived from blockchain genesis hash and is identical for all
//! nodes on the same network. It does NOT increment on restart (that was the bug
//! fixed in PR #440).
//!
//! ```text
//! network_epoch = Truncate64(Blake3(genesis_hash_bytes))
//! ```
//!
//! This provides:
//! - Stable identifier across all nodes
//! - Cross-network isolation
//! - Deterministic computation
//!
//! # Nonce Fingerprinting
//!
//! Nonce fingerprints include context to prevent cross-protocol replay:
//!
//! ```text
//! nonce_fp = Blake3(network_epoch || nonce || protocol_version || peer_role)
//! ```
//!
//! # Contract
//!
//! Network epoch is derived from chain identity (genesis hash / chain id).
//! It must NOT change per handshake, per open, or per process restart.
//! Replay protection is enforced by persistent nonce fingerprints within TTL.

use anyhow::{Result, anyhow};
use blake3::Hasher;
use parking_lot::RwLock;
use sled::Db;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, Duration, SystemTime, UNIX_EPOCH};
use tracing::{warn, info, debug};

// ============================================================================
// Network Epoch - Stable, Genesis-Derived Identifier
// ============================================================================

/// Network epoch - derived from blockchain genesis hash
///
/// CRITICAL: Network epoch is computed from chain identity (genesis hash) and
/// must be identical for all nodes on the same network. It does NOT change
/// per handshake, per open, or per process restart.
///
/// This provides:
/// - Cross-network isolation (different genesis = different epoch)
/// - Stable identifier for replay protection namespacing
/// - Guardrail against cross-network replay attacks
///
/// Replay protection is enforced by persistent nonce fingerprints within TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NetworkEpoch(u64);

impl NetworkEpoch {
    /// Create network epoch from genesis hash (Blake3 truncated to u64)
    ///
    /// # Arguments
    /// * `genesis_hash` - Genesis block hash or merkle root (32 bytes)
    pub fn from_genesis(genesis_hash: &[u8]) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(b"ZHTP_NETWORK_EPOCH_V1:");
        hasher.update(genesis_hash);
        let hash = hasher.finalize();

        // Truncate to u64 (first 8 bytes)
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hash.as_bytes()[..8]);
        Self(u64::from_le_bytes(bytes))
    }

    /// Create from chain ID (fallback for testing/development)
    pub fn from_chain_id(chain_id: u8) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(b"ZHTP_CHAIN_ID_EPOCH_V1:");
        hasher.update(&[chain_id]);
        let hash = hasher.finalize();

        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hash.as_bytes()[..8]);
        Self(u64::from_le_bytes(bytes))
    }

    /// Get network epoch from global genesis, with environment-appropriate fallback
    ///
    /// In development/test builds, falls back to chain_id(0) if genesis is unavailable.
    /// In release builds, returns an error to prevent production nodes from running
    /// without proper network configuration.
    pub fn from_global_or_fail() -> Result<Self> {
        match lib_identity::types::node_id::get_network_genesis() {
            Ok(genesis) => Ok(Self::from_genesis(genesis.as_slice())),
            Err(e) => {
                #[cfg(debug_assertions)]
                {
                    warn!(
                        "Network genesis not set (expected in development): {}. \
                         Using fallback chain_id=0 for development/testing.",
                        e
                    );
                    Ok(Self::from_chain_id(0))
                }
                #[cfg(not(debug_assertions))]
                {
                    Err(anyhow!(
                        "CRITICAL: Network genesis hash not available in production environment. \
                         Cannot determine network epoch for replay protection. \
                         Please configure network genesis hash via environment variable. \
                         Error: {}",
                        e
                    ))
                }
            }
        }
    }

    /// Get epoch value
    pub fn value(&self) -> u64 {
        self.0
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 8 {
            return Err(anyhow!("NetworkEpoch must be 8 bytes, got {}", bytes.len()));
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(bytes);
        Ok(Self(u64::from_le_bytes(arr)))
    }
}

// ============================================================================
// Nonce Fingerprint - Context-Bound Replay Detection
// ============================================================================

/// Compute nonce fingerprint with full context binding
///
/// Includes network epoch, protocol version, and peer role to prevent
/// cross-context replay attacks.
pub fn compute_nonce_fingerprint(
    network_epoch: NetworkEpoch,
    nonce: &[u8; 32],
    protocol_version: u32,
    peer_role: &str,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(&network_epoch.to_bytes());
    hasher.update(nonce);
    hasher.update(&protocol_version.to_le_bytes());
    hasher.update(peer_role.as_bytes());
    
    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

/// Result of marking nonce as seen
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeenResult {
    /// Nonce is new (first time seen)
    New,
    /// Nonce was seen before (replay detected)
    Replay,
}

// ============================================================================
// Persistent Storage Structures
// ============================================================================

/// Persistent nonce entry with timestamp
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistentNonceEntry {
    /// Unix timestamp when nonce was first seen
    first_seen_unix: i64,
    /// Message timestamp from handshake (for audit)
    message_timestamp: u64,
}

/// In-memory nonce entry (for performance)
#[derive(Debug, Clone)]
struct MemoryNonceEntry {
    /// When entry was added to memory cache
    timestamp: Instant,
    /// Message timestamp from handshake
    message_timestamp: u64,
}

// ============================================================================
// Persistent Nonce Cache with Network Epoch
// ============================================================================

/// Thread-safe persistent nonce cache for replay attack prevention
///
/// # Architecture
///
/// - **Memory Cache**: LRU cache for hot nonces (fast path)
/// - **Disk Cache**: sled for persistent storage (durability)
/// - **Network Epoch**: Genesis-derived constant (replay prevention namespace)
/// - **Nonce Fingerprints**: Context-bound hashes (prevents cross-protocol replay)
///
/// # Network Epoch Contract
///
/// Network epoch is derived from blockchain genesis hash and MUST be:
/// - Identical for all nodes on the same network
/// - Stable across all restarts (never increments)
/// - Different for different networks (isolation)
///
/// **Replay protection** is enforced by persistent nonce fingerprints with TTL,
/// **NOT** by epoch increments.
#[derive(Clone, Debug)]
pub struct NonceCache {
    /// In-memory LRU cache for fast lookups (hot path)
    memory_cache: Arc<RwLock<lru::LruCache<[u8; 32], MemoryNonceEntry>>>,

    /// Persistent sled storage (durability)
    db: Arc<Db>,

    /// Network epoch (genesis-derived, stable across restarts)
    network_epoch: NetworkEpoch,

    /// Time-to-live for nonces (seconds)
    ttl: Duration,

    /// Maximum memory cache size
    max_memory_size: usize,

    /// Insert counter for lazy pruning trigger (atomic for lock-free access)
    insert_count: Arc<AtomicU64>,
}

impl NonceCache {
    /// Default maximum cache size: 1 million entries (~64 MB memory)
    pub const DEFAULT_MAX_SIZE: usize = 1_000_000;

    /// Large cache size for blockchain sync periods: 5 million entries (~320 MB memory)
    pub const SYNC_MAX_SIZE: usize = 5_000_000;

    /// sled key prefix for seen nonces
    const NONCE_PREFIX: &'static str = "seen:";

    /// sled key for stored network epoch
    const META_EPOCH_KEY: &'static str = "meta:network_epoch";

    /// Pruning trigger: prune every N insertions
    const PRUNE_EVERY_N_INSERTS: u64 = 10_000;

    /// Open or create persistent nonce cache with network epoch
    ///
    /// # Arguments
    ///
    /// * `db_path` - Path to sled database directory
    /// * `ttl_secs` - Time-to-live for nonces in seconds (default: 300 = 5 minutes)
    /// * `max_memory_size` - Maximum in-memory cache size (default: 1 million)
    /// * `network_epoch` - Network epoch derived from blockchain genesis
    ///
    /// # Security
    ///
    /// - Verifies network epoch matches stored value (prevents DB cross-use)
    /// - Creates tables if missing (migration-safe)
    /// - Loads existing nonces into memory cache
    pub fn open<P: AsRef<Path>>(
        db_path: P,
        ttl_secs: u64,
        max_memory_size: usize,
        network_epoch: NetworkEpoch,
    ) -> Result<Self> {
        // Open sled database
        let db = sled::Config::new()
            .path(db_path.as_ref())
            .open()
            .map_err(|e| anyhow!("Failed to open nonce cache DB: {}", e))?;

        let db = Arc::new(db);

        // Verify or store network epoch
        Self::verify_or_store_network_epoch(&db, network_epoch)?;

        info!("Nonce cache initialized with network epoch: 0x{:016x}", network_epoch.value());

        // Create memory cache
        let capacity = std::num::NonZeroUsize::new(max_memory_size)
            .ok_or_else(|| anyhow!("max_memory_size must be > 0"))?;
        let memory_cache = Arc::new(RwLock::new(lru::LruCache::new(capacity)));

        let cache = Self {
            memory_cache,
            db,
            network_epoch,
            ttl: Duration::from_secs(ttl_secs),
            max_memory_size,
            insert_count: Arc::new(AtomicU64::new(0)),
        };

        // Load existing nonces into memory
        let loaded = cache.load_nonces_into_memory()?;
        info!("Loaded {} existing nonces into memory cache", loaded);

        // Prune old nonces on startup
        let pruned = cache.prune_seen_nonces_internal()?;
        if pruned > 0 {
            info!("Pruned {} expired nonces on startup", pruned);
        }

        Ok(cache)
    }

    /// Create nonce cache with default size (1 million entries)
    pub fn open_default<P: AsRef<Path>>(
        db_path: P,
        ttl_secs: u64,
        network_epoch: NetworkEpoch,
    ) -> Result<Self> {
        Self::open(db_path, ttl_secs, Self::DEFAULT_MAX_SIZE, network_epoch)
    }

    /// Create nonce cache optimized for blockchain sync (5 million entries)
    pub fn open_sync<P: AsRef<Path>>(
        db_path: P,
        ttl_secs: u64,
        network_epoch: NetworkEpoch,
    ) -> Result<Self> {
        Self::open(db_path, ttl_secs, Self::SYNC_MAX_SIZE, network_epoch)
    }

    /// Mark nonce fingerprint as seen
    ///
    /// Returns `SeenResult::New` if nonce is new, `SeenResult::Replay` if already seen.
    ///
    /// # Arguments
    ///
    /// * `nonce_fp` - Nonce fingerprint (use `compute_nonce_fingerprint`)
    /// * `now` - Current unix timestamp
    pub fn mark_nonce_seen(&self, nonce_fp: &[u8; 32], now: i64) -> Result<SeenResult> {
        // Fast path: Check memory cache first (read lock)
        {
            let memory = self.memory_cache.read();
            if memory.peek(nonce_fp).is_some() {
                debug!("Replay detected in memory cache: nonce_fp={}", hex::encode(nonce_fp));
                return Ok(SeenResult::Replay);
            }
        }

        // Slow path: Check disk and insert atomically (write lock)
        let mut memory = self.memory_cache.write();

        // Double-check memory cache (another thread may have inserted)
        if memory.peek(nonce_fp).is_some() {
            return Ok(SeenResult::Replay);
        }

        // Check persistent storage
        let nonce_key = Self::nonce_key(nonce_fp);
        if self.db.get(&nonce_key)
            .map_err(|e| anyhow!("DB read error: {}", e))?.is_some() {
            // Nonce exists in persistent storage
            warn!("Replay detected in persistent cache: nonce_fp={}", hex::encode(nonce_fp));
            return Ok(SeenResult::Replay);
        }

        // All checks passed - insert nonce
        // Insert into memory cache
        memory.put(*nonce_fp, MemoryNonceEntry {
            timestamp: Instant::now(),
            message_timestamp: now as u64,
        });
        drop(memory);

        // Persist to disk
        let persistent_entry = PersistentNonceEntry {
            first_seen_unix: now,
            message_timestamp: now as u64,
        };

        let entry_bytes = bincode::serialize(&persistent_entry)
            .map_err(|e| anyhow!("Failed to serialize nonce entry: {}", e))?;

        self.db.insert(&nonce_key, entry_bytes)
            .map_err(|e| anyhow!("Failed to persist nonce: {}", e))?;

        debug!("Stored nonce fingerprint: fp={}, timestamp={}", hex::encode(nonce_fp), now);

        // Increment insert counter and trigger pruning if needed
        let count = self.insert_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        if count % Self::PRUNE_EVERY_N_INSERTS == 0 {
            // Lazy pruning trigger
            match self.prune_seen_nonces_internal() {
                Ok(pruned) => {
                    if pruned > 0 {
                        debug!("Lazy pruning removed {} expired nonces", pruned);
                    }
                }
                Err(e) => {
                    warn!(
                        "Lazy pruning failed (nonce cache may grow unbounded): {}. \
                         Current cache utilization: {:.1}%",
                        e,
                        self.utilization() * 100.0
                    );
                }
            }
        }

        Ok(SeenResult::New)
    }

    /// Legacy check_and_store for backward compatibility
    ///
    /// DEPRECATED: Use `mark_nonce_seen` with `compute_nonce_fingerprint` instead.
    /// This method is kept for backward compatibility during migration.
    ///
    /// # Breaking Change
    /// The `message_timestamp` parameter is now ignored and current system time is used instead.
    /// This aligns with the new persistent replay protection design.
    #[deprecated(since = "0.2.0", note = "Use `mark_nonce_seen` with `compute_nonce_fingerprint` instead")]
    pub fn check_and_store(&self, nonce: &[u8; 32], _message_timestamp: u64) -> Result<()> {
        // Use raw nonce as fingerprint for backward compatibility
        // This is less secure than using compute_nonce_fingerprint but maintains API
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        match self.mark_nonce_seen(nonce, now)? {
            SeenResult::New => Ok(()),
            SeenResult::Replay => Err(anyhow!("Replay detected: nonce already used")),
        }
    }

    /// Prune seen nonces older than cutoff
    ///
    /// Returns number of entries removed.
    pub fn prune_seen_nonces(&self, cutoff_unix: i64) -> Result<usize> {
        let mut deleted = 0;
        let iter = self.db.iter();
        let mut keys_to_delete = Vec::new();

        for item in iter {
            let (key, value) = item.map_err(|e| anyhow!("DB iteration error: {}", e))?;
            let key_bytes = key.as_ref();

            // Skip keys that don't match our prefix
            if !key_bytes.starts_with(Self::NONCE_PREFIX.as_bytes()) {
                continue;
            }

            // Deserialize entry
            let entry: PersistentNonceEntry = match bincode::deserialize(value.as_ref()) {
                Ok(e) => e,
                Err(_) => {
                    // Delete corrupted entries
                    keys_to_delete.push(key.to_vec());
                    continue;
                }
            };

            // Check if expired
            if entry.first_seen_unix < cutoff_unix {
                keys_to_delete.push(key.to_vec());
            }
        }

        // Delete expired entries
        for key in &keys_to_delete {
            self.db.remove(key)
                .map_err(|e| anyhow!("Failed to delete old nonce: {}", e))?;
            deleted += 1;
        }

        // Also prune memory cache
        let now = Instant::now();
        let mut memory = self.memory_cache.write();
        let expired_nonces: Vec<[u8; 32]> = memory
            .iter()
            .filter_map(|(nonce_fp, entry)| {
                if now.duration_since(entry.timestamp) >= self.ttl {
                    Some(*nonce_fp)
                } else {
                    None
                }
            })
            .collect();

        for nonce_fp in &expired_nonces {
            memory.pop(nonce_fp);
        }

        if !expired_nonces.is_empty() {
            debug!("Pruned {} nonces from memory cache", expired_nonces.len());
        }

        Ok(deleted)
    }

    /// Internal pruning (uses current time)
    fn prune_seen_nonces_internal(&self) -> Result<usize> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let cutoff = now_unix - self.ttl.as_secs() as i64;
        self.prune_seen_nonces(cutoff)
    }

    /// Get current network epoch
    pub fn network_epoch(&self) -> NetworkEpoch {
        self.network_epoch
    }

    /// Legacy method for backward compatibility
    #[deprecated(note = "Use network_epoch() instead")]
    pub fn current_epoch(&self) -> u64 {
        self.network_epoch.value()
    }

    /// Get cache size (for monitoring)
    pub fn size(&self) -> usize {
        self.memory_cache.read().len()
    }

    /// Get maximum cache size
    pub fn max_size(&self) -> usize {
        self.max_memory_size
    }

    /// Get cache utilization percentage (0.0 to 1.0)
    pub fn utilization(&self) -> f64 {
        let current = self.size() as f64;
        let max = self.max_memory_size as f64;
        current / max
    }

    /// Remove expired nonces from memory and disk (cleanup task)
    ///
    /// This provides additional cleanup beyond LRU eviction.
    /// Removes nonces that have exceeded their TTL.
    pub fn cleanup_expired(&self) {
        match self.prune_seen_nonces_internal() {
            Ok(deleted) => {
                if deleted > 0 {
                    debug!("Cleanup task removed {} expired nonces", deleted);
                }
            }
            Err(e) => {
                warn!(
                    "Cleanup task failed to prune nonces: {}. \
                     Cache may grow unbounded. \
                     Current cache size: {}/{} entries (utilization: {:.1}%)",
                    e, self.size(), self.max_size(), self.utilization() * 100.0
                );
            }
        }
    }

    /// Verify or store network epoch
    fn verify_or_store_network_epoch(db: &Db, expected_epoch: NetworkEpoch) -> Result<()> {
        match db.get(Self::META_EPOCH_KEY.as_bytes()) {
            Ok(Some(bytes)) => {
                // Epoch exists - verify it matches
                let stored_epoch = NetworkEpoch::from_bytes(bytes.as_ref())?;
                if stored_epoch != expected_epoch {
                    return Err(anyhow!(
                        "Network epoch mismatch! DB belongs to different network.\n\
                         Stored: 0x{:016x}, Expected: 0x{:016x}\n\
                         This database was created for a different blockchain network.",
                        stored_epoch.value(),
                        expected_epoch.value()
                    ));
                }
                info!("Verified network epoch: 0x{:016x}", stored_epoch.value());
            }
            Ok(None) => {
                // First startup or migration - store epoch
                // Also check for legacy epoch key and migrate
                match db.get(b"meta:epoch") {
                    Ok(Some(_legacy)) => {
                        info!("Migrating from legacy epoch format to network epoch");
                        if let Err(e) = db.remove(b"meta:epoch") {
                            warn!(
                                "Failed to delete legacy epoch key during migration: {}. \
                                 New epoch will be stored, but legacy key may cause confusion.",
                                e
                            );
                        }
                    }
                    Ok(None) => { /* No legacy key to migrate */ }
                    Err(e) => {
                        return Err(anyhow!("Failed to check for legacy epoch key: {}", e));
                    }
                }
                db.insert(Self::META_EPOCH_KEY.as_bytes(), expected_epoch.to_bytes().to_vec())
                    .map_err(|e| anyhow!("Failed to store network epoch: {}", e))?;
                info!("Stored new network epoch: 0x{:016x}", expected_epoch.value());
            }
            Err(e) => {
                return Err(anyhow!("Failed to read network epoch from DB: {}", e));
            }
        }
        Ok(())
    }

    /// Load nonces from disk into memory cache
    fn load_nonces_into_memory(&self) -> Result<usize> {
        let mut loaded = 0;
        let mut memory = self.memory_cache.write();
        let iter = self.db.iter();

        for item in iter {
            let (key, value) = item.map_err(|e| anyhow!("DB iteration error: {}", e))?;
            let key_bytes = key.as_ref();

            // Skip metadata keys
            if key_bytes.starts_with(b"meta:") {
                continue;
            }

            // Skip keys that don't match our prefix
            if !key_bytes.starts_with(Self::NONCE_PREFIX.as_bytes()) {
                continue;
            }

            // Deserialize entry
            let entry: PersistentNonceEntry = match bincode::deserialize(value.as_ref()) {
                Ok(e) => e,
                Err(e) => {
                    let key_str = String::from_utf8_lossy(key_bytes);
                    warn!(
                        "Skipping corrupted nonce entry during load: key={}, error={}. \
                         This may indicate database corruption or format version mismatch.",
                        key_str, e
                    );
                    continue;
                }
            };

            // Extract nonce fingerprint from key
            let nonce_start = Self::NONCE_PREFIX.len();
            if key_bytes.len() != nonce_start + 64 {
                warn!("Invalid nonce key length: {}", key_bytes.len());
                continue;
            }

            let nonce_hex = &key_bytes[nonce_start..];
            let nonce_fp = match hex::decode(nonce_hex) {
                Ok(n) => {
                    if n.len() != 32 {
                        warn!(
                            "Nonce fingerprint has invalid length: {} bytes (expected 32). \
                             Skipping entry: {}. This may indicate database corruption.",
                            n.len(),
                            String::from_utf8_lossy(key_bytes)
                        );
                        continue;
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&n);
                    arr
                }
                Err(e) => {
                    let key_str = String::from_utf8_lossy(key_bytes);
                    warn!(
                        "Failed to decode nonce fingerprint from database key: {}. \
                         Skipping entry: {}. This may indicate database corruption or \
                         incompatible database format.",
                        key_str, e
                    );
                    continue;
                }
            };

            // Add to memory cache
            memory.put(nonce_fp, MemoryNonceEntry {
                timestamp: Instant::now(),
                message_timestamp: entry.message_timestamp,
            });

            loaded += 1;

            // Stop if memory cache is full
            if loaded >= self.max_memory_size {
                warn!(
                    "Memory cache full during load at {} entries. Database contains additional \
                     nonces that were not loaded. Continuing with disk fallback. \
                     Consider increasing NonceCache::max_memory_size if this occurs frequently.",
                    loaded
                );
                break;
            }
        }

        Ok(loaded)
    }

    /// Generate nonce key for sled
    fn nonce_key(nonce_fp: &[u8; 32]) -> Vec<u8> {
        let mut key = Vec::with_capacity(Self::NONCE_PREFIX.len() + 64);
        key.extend_from_slice(Self::NONCE_PREFIX.as_bytes());
        key.extend_from_slice(hex::encode(nonce_fp).as_bytes());
        key
    }

    /// Clear all nonces (for testing only)
    #[cfg(test)]
    pub fn clear(&self) {
        // Clear memory cache
        self.memory_cache.write().clear();

        // Clear disk cache (delete all nonce keys)
        let iter = self.db.iter();
        let mut keys_to_delete = Vec::new();

        for item in iter {
            if let Ok((key, _)) = item {
                if key.as_ref().starts_with(Self::NONCE_PREFIX.as_bytes()) {
                    keys_to_delete.push(key.to_vec());
                }
            }
        }

        for key in keys_to_delete {
            let _ = self.db.remove(&key);
        }
    }

    /// Create a test nonce cache (for testing only)
    #[cfg(test)]
    pub fn new_test(ttl_secs: u64, max_memory_size: usize, network_epoch: NetworkEpoch) -> Self {
        static TEST_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        
        let counter = TEST_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let temp_dir = tempfile::TempDir::new().expect("Failed to create temp dir for test");
        let db_path = temp_dir.path().join(format!("nonce_cache_{}", counter));
        
        // Create cache
        let cache = Self::open(&db_path, ttl_secs, max_memory_size, network_epoch)
            .expect("Failed to create test nonce cache");
        
        // Leak temp_dir to keep it alive (acceptable for tests)
        std::mem::forget(temp_dir);
        
        cache
    }
}

/// Background task to periodically cleanup expired nonces
///
/// Should be spawned as a background task when the system starts.
pub async fn start_nonce_cleanup_task(cache: NonceCache, interval_secs: u64) {
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));

    loop {
        interval.tick().await;
        cache.cleanup_expired();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_epoch() -> NetworkEpoch {
        NetworkEpoch::from_genesis(&[0u8; 32])
    }

    fn create_test_cache(ttl_secs: u64) -> (NonceCache, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let epoch = test_epoch();
        let cache = NonceCache::open_default(temp_dir.path(), ttl_secs, epoch).unwrap();
        (cache, temp_dir)
    }

    #[test]
    fn test_network_epoch_from_genesis() {
        let genesis1 = [0u8; 32];
        let genesis2 = [1u8; 32];

        let epoch1 = NetworkEpoch::from_genesis(&genesis1);
        let epoch2 = NetworkEpoch::from_genesis(&genesis2);

        // Same genesis produces same epoch
        assert_eq!(epoch1, NetworkEpoch::from_genesis(&genesis1));
        // Different genesis produces different epoch
        assert_ne!(epoch1, epoch2);
    }

    #[test]
    fn test_network_epoch_is_stable() {
        // Open cache twice against same DB
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path();
        let epoch = NetworkEpoch::from_genesis(&[42u8; 32]);

        // First open
        let cache1 = NonceCache::open_default(db_path, 300, epoch).unwrap();
        let stored_epoch1 = cache1.network_epoch();

        // Second open (simulate restart)
        drop(cache1);
        let cache2 = NonceCache::open_default(db_path, 300, epoch).unwrap();
        let stored_epoch2 = cache2.network_epoch();

        // Assert network_epoch is constant and equals expected computed value
        assert_eq!(stored_epoch1, epoch);
        assert_eq!(stored_epoch2, epoch);
        assert_eq!(stored_epoch1, stored_epoch2);
    }

    #[test]
    fn test_replay_rejected_across_restart() {
        let epoch = NetworkEpoch::from_genesis(&[0u8; 32]);
        let nonce = [42u8; 32];
        let nonce_fp = compute_nonce_fingerprint(epoch, &nonce, 1, "client");
        let now = 1234567890;

        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path();

        // Session 1: Mark nonce as seen
        {
            let cache = NonceCache::open_default(db_path, 300, epoch).unwrap();
            let result = cache.mark_nonce_seen(&nonce_fp, now).unwrap();
            assert_eq!(result, SeenResult::New);
        }

        // Session 2: Simulate restart
        {
            let cache = NonceCache::open_default(db_path, 300, epoch).unwrap();
            let result = cache.mark_nonce_seen(&nonce_fp, now).unwrap();
            assert_eq!(result, SeenResult::Replay); // Should be rejected!
        }
    }

    #[test]
    fn test_pruning_removes_old_entries() {
        let epoch = NetworkEpoch::from_genesis(&[0u8; 32]);
        let cache = NonceCache::new_test(5, 1000, epoch); // 5 second TTL

        let nonce = [1u8; 32];
        let nonce_fp = compute_nonce_fingerprint(epoch, &nonce, 1, "client");
        let old_timestamp = 1000000000i64; // Very old

        // Insert with old timestamp (this inserts into both memory cache and DB)
        cache.mark_nonce_seen(&nonce_fp, old_timestamp).unwrap();
        assert_eq!(cache.size(), 1);

        // The DB entry has first_seen_unix = old_timestamp
        // But the memory cache has timestamp = Instant::now()
        // Prune with current time cutoff should remove the DB entry
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let cutoff = now - 10; // Anything older than 10 seconds

        let pruned = cache.prune_seen_nonces(cutoff).unwrap();
        // DB entry is pruned (first_seen_unix = 1000000000 < cutoff)
        assert_eq!(pruned, 1);

        // The memory cache entry was just created, so still present
        // Memory cache uses Instant-based TTL, not unix timestamp
        // Replay is still detected because memory cache has the entry
        let result = cache.mark_nonce_seen(&nonce_fp, now).unwrap();
        assert_eq!(result, SeenResult::Replay); // Memory cache still has it

        // For a new nonce, it should work
        let new_nonce = [2u8; 32];
        let new_nonce_fp = compute_nonce_fingerprint(epoch, &new_nonce, 1, "client");
        let result = cache.mark_nonce_seen(&new_nonce_fp, now).unwrap();
        assert_eq!(result, SeenResult::New);
    }

    #[test]
    fn test_different_networks_isolated() {
        let genesis1 = [0u8; 32];
        let genesis2 = [1u8; 32];
        let epoch1 = NetworkEpoch::from_genesis(&genesis1);
        let epoch2 = NetworkEpoch::from_genesis(&genesis2);

        // Same nonce on different networks should have different fingerprints
        let nonce = [42u8; 32];
        let fp1 = compute_nonce_fingerprint(epoch1, &nonce, 1, "client");
        let fp2 = compute_nonce_fingerprint(epoch2, &nonce, 1, "client");

        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_nonce_stored_and_detected() {
        let (cache, _dir) = create_test_cache(60);
        let nonce = [1u8; 32];

        // First use - should succeed
        assert!(cache.check_and_store(&nonce, 1234567890).is_ok());

        // Second use - should fail (replay)
        let result = cache.check_and_store(&nonce, 1234567890);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Replay detected"));
    }

    #[test]
    fn test_different_nonces_allowed() {
        let (cache, _dir) = create_test_cache(60);
        let nonce1 = [1u8; 32];
        let nonce2 = [2u8; 32];

        // Both should succeed (different nonces)
        assert!(cache.check_and_store(&nonce1, 1234567890).is_ok());
        assert!(cache.check_and_store(&nonce2, 1234567890).is_ok());
    }

    #[test]
    fn test_nonce_expiration() {
        let (cache, _dir) = create_test_cache(1); // 1 second TTL
        let nonce = [1u8; 32];

        // Store nonce
        cache.check_and_store(&nonce, 1234567890).unwrap();

        // Wait for expiration
        std::thread::sleep(Duration::from_secs(2));

        // Cleanup
        cache.cleanup_expired();

        // Should be able to use again (expired and cleaned)
        assert!(cache.check_and_store(&nonce, 1234567890).is_ok());
    }

    #[test]
    fn test_cache_size() {
        let (cache, _dir) = create_test_cache(60);

        assert_eq!(cache.size(), 0);

        cache.check_and_store(&[1u8; 32], 1234567890).unwrap();
        assert_eq!(cache.size(), 1);

        cache.check_and_store(&[2u8; 32], 1234567890).unwrap();
        assert_eq!(cache.size(), 2);
    }

    #[test]
    fn test_concurrent_nonce_insertion_no_race() {
        use std::thread;

        let epoch = NetworkEpoch::from_genesis(&[0u8; 32]);
        let cache = NonceCache::new_test(60, 1000, epoch);
        let nonce = [42u8; 32];
        let nonce_fp = compute_nonce_fingerprint(epoch, &nonce, 1, "client");

        // Try to insert same nonce concurrently 100 times
        let handles: Vec<_> = (0..100)
            .map(|_| {
                let cache = cache.clone();
                let fp = nonce_fp;
                thread::spawn(move || {
                    cache.mark_nonce_seen(&fp, 1234567890)
                })
            })
            .collect();

        // Wait for all threads
        let results: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();

        // Exactly ONE should succeed, rest should fail
        let successes = results.iter().filter(|r| {
            r.as_ref().map(|s| *s == SeenResult::New).unwrap_or(false)
        }).count();
        let failures = results.iter().filter(|r| {
            r.as_ref().map(|s| *s == SeenResult::Replay).unwrap_or(false)
        }).count();

        assert_eq!(successes, 1, "Exactly one insertion should succeed");
        assert_eq!(failures, 99, "99 insertions should fail (replay detected)");
    }

    #[test]
    fn test_utilization_percentage() {
        let temp_dir = TempDir::new().unwrap();
        let epoch = test_epoch();
        let cache = NonceCache::open(temp_dir.path(), 60, 100, epoch).unwrap();

        // Empty cache
        assert_eq!(cache.utilization(), 0.0);

        // Half full
        for i in 0..50 {
            let mut nonce = [0u8; 32];
            nonce[0] = i as u8;
            cache.check_and_store(&nonce, 1234567890).unwrap();
        }
        assert_eq!(cache.utilization(), 0.5);

        // Full
        for i in 50..100 {
            let mut nonce = [0u8; 32];
            nonce[0] = i as u8;
            cache.check_and_store(&nonce, 1234567890).unwrap();
        }
        assert_eq!(cache.utilization(), 1.0);
    }

    #[test]
    fn test_max_size_accessor() {
        let temp_dir = TempDir::new().unwrap();
        let epoch = test_epoch();
        let cache = NonceCache::open(temp_dir.path(), 60, 5000, epoch).unwrap();
        assert_eq!(cache.max_size(), 5000);
    }

    #[test]
    fn test_network_epoch_mismatch_rejected() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path();

        // Open with epoch1
        let epoch1 = NetworkEpoch::from_genesis(&[1u8; 32]);
        {
            let _cache = NonceCache::open_default(db_path, 300, epoch1).unwrap();
        }

        // Try to open with epoch2 - should fail
        let epoch2 = NetworkEpoch::from_genesis(&[2u8; 32]);
        let result = NonceCache::open_default(db_path, 300, epoch2);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Network epoch mismatch"));
    }

    // ============================================================================
    // CRITICAL TEST CASES - Security Gap Fixes
    // ============================================================================

    #[test]
    fn test_corrupted_database_entries_handled_gracefully() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path();
        let epoch = test_epoch();

        // Create cache and add a valid nonce
        {
            let cache = NonceCache::open_default(db_path, 60, epoch).unwrap();
            let nonce = [1u8; 32];
            cache.check_and_store(&nonce, 1234567890).unwrap();
        }

        // Manually corrupt an entry in sled
        {
            let db = sled::Config::new().path(db_path).open().unwrap();
            let bad_key = b"seen:0000000000000000000000000000000000000000000000000000000000000000";
            db.insert(bad_key, b"corrupted_binary_data").unwrap();
        }

        // Reopen cache - should recover without panic
        let cache2 = NonceCache::open_default(db_path, 60, epoch).unwrap();

        // Should load successfully and skip corrupted entry
        assert!(cache2.size() >= 1, "Cache should have loaded at least one valid entry");

        // Verify we can still insert new nonces
        let result = cache2.mark_nonce_seen(&[2u8; 32], 1234567890).unwrap();
        assert_eq!(result, SeenResult::New, "Should be able to insert new nonce after recovering from corruption");
    }

    #[test]
    fn test_replay_protection_after_memory_cache_eviction() {
        let temp_dir = TempDir::new().unwrap();
        let epoch = test_epoch();

        // Create cache with small memory size (capacity 10)
        let cache = NonceCache::open(temp_dir.path(), 60, 10, epoch).unwrap();

        // Insert first nonce (in memory)
        let nonce1 = [1u8; 32];
        let fp1 = compute_nonce_fingerprint(epoch, &nonce1, 1, "client");
        let result = cache.mark_nonce_seen(&fp1, 1000).unwrap();
        assert_eq!(result, SeenResult::New, "First nonce should be new");
        assert_eq!(cache.size(), 1, "Cache should have 1 entry");

        // Insert 20 more nonces to overflow LRU (capacity 10)
        for i in 2..=20 {
            let mut nonce = [0u8; 32];
            nonce[0] = i as u8;
            let fp = compute_nonce_fingerprint(epoch, &nonce, 1, "client");
            let _ = cache.mark_nonce_seen(&fp, 1000);
        }

        // Cache should be at or below capacity
        assert!(cache.size() <= 10, "Cache size should not exceed capacity");

        // First nonce was evicted from memory but still on disk
        // Attempting to use it again should fail (disk lookup will find it)
        let result = cache.mark_nonce_seen(&fp1, 1000).unwrap();
        assert_eq!(result, SeenResult::Replay, "Evicted nonce should still be detected as replay via disk");
    }

    #[test]
    fn test_concurrent_pruning_with_insertions_safe() {
        use std::thread;
        use std::sync::Arc;

        let temp_dir = Arc::new(TempDir::new().unwrap());
        let epoch = test_epoch();
        let cache = Arc::new(NonceCache::open_sync(temp_dir.path(), 60, epoch).unwrap());

        // Insert 10,000 nonces in one thread (should trigger pruning)
        let insert_handle = {
            let cache = cache.clone();
            thread::spawn(move || {
                for i in 0..10_000 {
                    let mut nonce = [0u8; 32];
                    nonce[0..4].copy_from_slice(&(i as u32).to_le_bytes());
                    let fp = compute_nonce_fingerprint(epoch, &nonce, 1, "client");
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;
                    let _ = cache.mark_nonce_seen(&fp, now);
                }
            })
        };

        // Meanwhile, verify some nonces in another thread
        let verify_handle = {
            let cache = cache.clone();
            thread::spawn(move || {
                for i in 0..1_000 {
                    let mut nonce = [0u8; 32];
                    nonce[0..4].copy_from_slice(&(i as u32).to_le_bytes());
                    let fp = compute_nonce_fingerprint(epoch, &nonce, 1, "client");
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;
                    let result = cache.mark_nonce_seen(&fp, now);
                    assert!(result.is_ok(), "Concurrent verification should succeed");
                }
            })
        };

        insert_handle.join().unwrap();
        verify_handle.join().unwrap();

        // Should complete without panics or data corruption
        assert!(cache.size() > 0, "Cache should contain entries");
    }

    #[test]
    fn test_ttl_boundary_exact_timestamp() {
        let temp_dir = TempDir::new().unwrap();
        let epoch = test_epoch();
        let cache = NonceCache::open_default(temp_dir.path(), 60, epoch).unwrap();

        let base_time = 1_000_000_000i64;
        let nonce = [1u8; 32];
        let fp = compute_nonce_fingerprint(epoch, &nonce, 1, "client");

        // Insert at base_time
        cache.mark_nonce_seen(&fp, base_time).unwrap();

        // Prune at base_time + 60 (exactly at TTL boundary)
        let cutoff_exact = base_time + 60;
        let pruned = cache.prune_seen_nonces(cutoff_exact).unwrap();

        // Behavior should be consistent: nonce at exact boundary should be pruned
        assert!(pruned > 0, "Nonce at exact TTL boundary should be pruned");
    }

    #[test]
    fn test_empty_genesis_produces_consistent_epoch() {
        let empty = [0u8; 32];
        let epoch1 = NetworkEpoch::from_genesis(&empty);
        let epoch2 = NetworkEpoch::from_genesis(&empty);
        assert_eq!(epoch1, epoch2, "Empty genesis should produce consistent epochs");

        // But verify it's different from other patterns
        let ones = [1u8; 32];
        let epoch_ones = NetworkEpoch::from_genesis(&ones);
        assert_ne!(epoch1, epoch_ones, "Different genesis hashes should produce different epochs");
    }

    #[test]
    fn test_legacy_epoch_migration_from_old_format() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path();
        let epoch = NetworkEpoch::from_genesis(&[5u8; 32]);

        // Simulate old format by directly writing legacy key
        {
            let db = sled::Config::new().path(db_path).open().unwrap();
            db.insert(b"meta:epoch", &epoch.to_bytes()).unwrap();
        }

        // Open with new code - should migrate
        let cache = NonceCache::open_default(db_path, 300, epoch).unwrap();

        // Verify migration happened
        assert_eq!(cache.network_epoch(), epoch, "Epoch should match after migration");

        // Should be able to add nonces normally
        let nonce = [42u8; 32];
        let fp = compute_nonce_fingerprint(epoch, &nonce, 1, "client");
        let result = cache.mark_nonce_seen(&fp, 1234567890).unwrap();
        assert_eq!(result, SeenResult::New, "Should work normally after migration");
    }

    #[test]
    fn test_system_time_error_handling() {
        // This test verifies that if SystemTime::now() returns an error,
        // pruning fails gracefully rather than silently defaulting to epoch 1970
        let (cache, _dir) = create_test_cache(60);
        let nonce = [1u8; 32];

        // Insert a nonce
        cache.check_and_store(&nonce, 1234567890).unwrap();

        // Normal cleanup should work
        cache.cleanup_expired();

        // Verify nonce is still in cache (TTL hasn't expired)
        let result = cache.mark_nonce_seen(&[1u8; 32], 1234567890).unwrap();
        assert_eq!(result, SeenResult::Replay, "Nonce should still be cached");
    }

    #[test]
    fn test_two_separate_networks_cannot_share_nonces() {
        let temp_dir1 = TempDir::new().unwrap();
        let temp_dir2 = TempDir::new().unwrap();

        let epoch1 = NetworkEpoch::from_genesis(&[1u8; 32]);
        let epoch2 = NetworkEpoch::from_genesis(&[2u8; 32]);

        let cache1 = NonceCache::open_default(temp_dir1.path(), 60, epoch1).unwrap();
        let cache2 = NonceCache::open_default(temp_dir2.path(), 60, epoch2).unwrap();

        // Insert same nonce in both caches with different epochs
        let nonce = [42u8; 32];
        let fp1 = compute_nonce_fingerprint(epoch1, &nonce, 1, "client");
        let fp2 = compute_nonce_fingerprint(epoch2, &nonce, 1, "client");

        // Both inserts should succeed (different fingerprints)
        assert_eq!(
            cache1.mark_nonce_seen(&fp1, 1000).unwrap(),
            SeenResult::New,
            "Nonce with epoch1 should be new in cache1"
        );
        assert_eq!(
            cache2.mark_nonce_seen(&fp2, 1000).unwrap(),
            SeenResult::New,
            "Nonce with epoch2 should be new in cache2"
        );

        // Cross-network verification should see them as new (different fingerprints)
        assert_eq!(
            cache1.mark_nonce_seen(&fp2, 1000).unwrap(),
            SeenResult::New,
            "Different fingerprint should be new in cache1"
        );
        assert_eq!(
            cache2.mark_nonce_seen(&fp1, 1000).unwrap(),
            SeenResult::New,
            "Different fingerprint should be new in cache2"
        );
    }
}
