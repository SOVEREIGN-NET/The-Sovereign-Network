//! DHT Internal Peer Registry (Ticket #148)
//!
//! Lightweight peer registry for DHT routing that consolidates K-bucket storage
//! into a unified HashMap instead of 160 separate Vec<KBucket> arrays.
//!
//! ## Design Rationale
//!
//! Previously, KademliaRouter maintained routing_table: Vec<KBucket> with 160 buckets,
//! each containing Vec<RoutingEntry>. This created duplicate peer storage across the codebase.
//!
//! Now, we use a single HashMap<NodeId, DhtPeerEntry> that:
//! - Stores each peer exactly once
//! - Indexes peers by NodeId for O(1) lookup
//! - Maintains K-bucket metadata in each entry
//! - Enables efficient queries by bucket_index via secondary index
//!
//! ## Migration Path
//!
//! This internal registry follows the same pattern as lib-network::peer_registry::PeerRegistry
//! but avoids circular dependency (lib-storage ↔ lib-network ↔ lib-blockchain ↔ lib-storage).
//! When circular deps are resolved, this can merge with the unified PeerRegistry.
//!
//! ## Thread Safety
//!
//! All mutations go through `&mut self`, requiring external synchronization.
//! Use `SharedDhtPeerRegistry` type alias for thread-safe concurrent access.

use crate::types::dht_types::DhtNode;
use crate::types::NodeId;
use anyhow::{Result, anyhow};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

// ========== ERROR TYPES ==========

/// Errors specific to sequence tracking and replay detection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SequenceError {
    /// Replay attack detected: sequence number is not greater than last seen
    ReplayDetected { sequence: u64, last_sequence: u64 },
    /// Peer not found in registry
    PeerNotFound,
}

impl std::fmt::Display for SequenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SequenceError::ReplayDetected { sequence, last_sequence } => {
                write!(f, "Replay detected: sequence {} <= {}", sequence, last_sequence)
            }
            SequenceError::PeerNotFound => write!(f, "Peer not found in registry"),
        }
    }
}

impl std::error::Error for SequenceError {}

// ========== CONFIGURABLE CONSTANTS ==========

/// Number of K-buckets in Kademlia routing table (for 256-bit NodeIds)
/// This is 160 because we use the position of the most significant differing bit
/// as the bucket index, which for 256-bit IDs gives us at most 256 buckets,
/// but we cap at 160 for practical reasons (matches standard Kademlia implementations)
pub const NUM_K_BUCKETS: usize = 160;

/// Maximum bucket index (0-indexed, so NUM_K_BUCKETS - 1)
pub const MAX_BUCKET_INDEX: usize = NUM_K_BUCKETS - 1;

/// Default maximum failed attempts before a peer is considered for eviction
pub const DEFAULT_MAX_FAILED_ATTEMPTS: u32 = 3;

/// Default rate limit: maximum peer additions per minute
pub const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 100;

/// Rate limit window in seconds
pub const RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Allow small wraparound window for u64 sequence counters
const SEQUENCE_WRAPAROUND_WINDOW: u64 = 1024;

// ========== DHT PEER ENTRY ==========

/// DHT peer entry with K-bucket metadata
#[derive(Debug, Clone)]
pub struct DhtPeerEntry {
    /// The DHT node information
    pub node: DhtNode,
    /// Kademlia distance from local node
    pub distance: u32,
    /// K-bucket index (0-159)
    pub bucket_index: usize,
    /// Last contact timestamp (Unix seconds)
    pub last_contact: u64,
    /// Failed ping attempts
    pub failed_attempts: u32,
    /// Last accepted sequence number from this peer (replay protection)
    pub last_sequence: Option<u64>,
}

// ========== RATE LIMITER ==========

/// Simple rate limiter for DHT operations to prevent flooding attacks
#[derive(Debug, Clone)]
pub struct DhtRateLimiter {
    /// Timestamps of recent operations (for sliding window)
    operation_timestamps: Vec<u64>,
    /// Maximum operations per window
    max_operations: u32,
    /// Window size in seconds
    window_secs: u64,
}

impl DhtRateLimiter {
    /// Create a new rate limiter
    pub fn new(max_operations: u32, window_secs: u64) -> Self {
        Self {
            operation_timestamps: Vec::with_capacity(max_operations as usize),
            max_operations,
            window_secs,
        }
    }

    /// Check if an operation is allowed and record it if so
    pub fn check_and_record(&mut self) -> bool {
        let now = Self::current_timestamp();
        let window_start = now.saturating_sub(self.window_secs);

        // Remove old timestamps outside the window
        self.operation_timestamps.retain(|&ts| ts > window_start);

        // Check if we're under the limit
        if self.operation_timestamps.len() < self.max_operations as usize {
            self.operation_timestamps.push(now);
            true
        } else {
            false
        }
    }

    /// Get current rate limiter statistics
    pub fn stats(&self) -> (usize, u32) {
        (self.operation_timestamps.len(), self.max_operations)
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

impl Default for DhtRateLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_RATE_LIMIT_PER_MINUTE, RATE_LIMIT_WINDOW_SECS)
    }
}

// ========== DHT PEER REGISTRY ==========

/// Internal peer registry for DHT routing
///
/// Replaces Vec<KBucket> with HashMap<NodeId, DhtPeerEntry>
/// for unified peer storage and efficient lookups.
///
/// ## Features
///
/// - O(1) peer lookup by NodeId
/// - O(1) bucket lookup via secondary index
/// - Built-in rate limiting for flood protection
/// - Configurable eviction thresholds
#[derive(Debug, Clone)]
pub struct DhtPeerRegistry {
    /// Primary storage: NodeId → DhtPeerEntry
    peers: HashMap<NodeId, DhtPeerEntry>,
    /// Secondary index: bucket_index → Set of NodeIds for O(1) bucket lookups
    bucket_index: [HashSet<NodeId>; NUM_K_BUCKETS],
    /// K-bucket size (standard Kademlia K value, typically 20)
    k: usize,
    /// Rate limiter for peer additions
    rate_limiter: DhtRateLimiter,
    /// Maximum failed attempts before eviction consideration
    max_failed_attempts: u32,
}

impl DhtPeerRegistry {
    /// Create a new empty DHT peer registry with default settings
    pub fn new(k: usize) -> Self {
        Self::with_config(k, DEFAULT_RATE_LIMIT_PER_MINUTE, DEFAULT_MAX_FAILED_ATTEMPTS)
    }

    /// Create a new DHT peer registry with custom configuration
    pub fn with_config(k: usize, rate_limit_per_minute: u32, max_failed_attempts: u32) -> Self {
        // Initialize bucket index with empty HashSets
        // We use std::array::from_fn to create the array at runtime
        let bucket_index: [HashSet<NodeId>; NUM_K_BUCKETS] =
            std::array::from_fn(|_| HashSet::new());

        Self {
            peers: HashMap::new(),
            bucket_index,
            k,
            rate_limiter: DhtRateLimiter::new(rate_limit_per_minute, RATE_LIMIT_WINDOW_SECS),
            max_failed_attempts,
        }
    }

    /// Insert or update a peer with rate limiting
    ///
    /// Returns:
    /// - `Ok(true)` if peer was newly inserted
    /// - `Ok(false)` if existing peer was updated
    /// - `Err(...)` if rate limited or invalid bucket index
    pub fn upsert(&mut self, entry: DhtPeerEntry) -> Result<bool> {
        let mut entry = entry;
        // Validate bucket index
        if entry.bucket_index > MAX_BUCKET_INDEX {
            return Err(anyhow!(
                "Invalid bucket index {}: must be 0-{}",
                entry.bucket_index,
                MAX_BUCKET_INDEX
            ));
        }

        let node_id = entry.node.peer.node_id().clone();
        let is_new = !self.peers.contains_key(&node_id);

        if let Some(existing) = self.peers.get(&node_id) {
            entry.last_sequence = existing.last_sequence;
        }

        // Apply rate limiting only for new peer insertions
        if is_new && !self.rate_limiter.check_and_record() {
            return Err(anyhow!(
                "Rate limit exceeded: too many peer additions (max {} per {} seconds)",
                DEFAULT_RATE_LIMIT_PER_MINUTE,
                RATE_LIMIT_WINDOW_SECS
            ));
        }

        // Update secondary index if bucket changed
        if let Some(existing) = self.peers.get(&node_id) {
            if existing.bucket_index != entry.bucket_index {
                // Remove from old bucket
                if existing.bucket_index < NUM_K_BUCKETS {
                    self.bucket_index[existing.bucket_index].remove(&node_id);
                }
            }
        }

        // Add to bucket index
        self.bucket_index[entry.bucket_index].insert(node_id.clone());

        // Insert into primary storage
        self.peers.insert(node_id, entry);
        Ok(is_new)
    }

    /// Get a peer by NodeId
    pub fn get(&self, node_id: &NodeId) -> Option<&DhtPeerEntry> {
        self.peers.get(node_id)
    }

    /// Get mutable peer by NodeId
    pub fn get_mut(&mut self, node_id: &NodeId) -> Option<&mut DhtPeerEntry> {
        self.peers.get_mut(node_id)
    }

    /// Check if a peer exists
    pub fn contains(&self, node_id: &NodeId) -> bool {
        self.peers.contains_key(node_id)
    }

    /// Get the total number of peers in the registry
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Remove a peer by NodeId
    ///
    /// Returns the removed entry if it existed
    pub fn remove(&mut self, node_id: &NodeId) -> Option<DhtPeerEntry> {
        if let Some(entry) = self.peers.remove(node_id) {
            // Remove from bucket index
            if entry.bucket_index < NUM_K_BUCKETS {
                self.bucket_index[entry.bucket_index].remove(node_id);
            }
            Some(entry)
        } else {
            None
        }
    }

    /// Get all peers in a specific K-bucket (O(bucket_size) using secondary index)
    pub fn peers_in_bucket(&self, bucket_index: usize) -> Vec<&DhtPeerEntry> {
        if bucket_index >= NUM_K_BUCKETS {
            return Vec::new();
        }

        self.bucket_index[bucket_index]
            .iter()
            .filter_map(|node_id| self.peers.get(node_id))
            .collect()
    }

    /// Count peers in a specific K-bucket (O(1) using secondary index)
    pub fn bucket_size(&self, bucket_index: usize) -> usize {
        if bucket_index >= NUM_K_BUCKETS {
            return 0;
        }
        self.bucket_index[bucket_index].len()
    }

    /// Check if a K-bucket is full
    pub fn is_bucket_full(&self, bucket_index: usize) -> bool {
        self.bucket_size(bucket_index) >= self.k
    }

    /// Get K-bucket parameter
    pub fn get_k(&self) -> usize {
        self.k
    }

    /// Get the configured max failed attempts threshold
    pub fn get_max_failed_attempts(&self) -> u32 {
        self.max_failed_attempts
    }

    /// Find K closest peers to a target NodeId
    pub fn find_closest(&self, target: &NodeId, count: usize) -> Vec<DhtNode> {
        let requested_count = std::cmp::min(count, self.k);
        let mut closest: Vec<_> = self.peers.values()
            .map(|entry| {
                let distance = target.kademlia_distance(entry.node.peer.node_id());
                (entry.node.clone(), distance)
            })
            .collect();

        // Sort by distance to target
        closest.sort_by_key(|(_, distance)| *distance);

        // Return k closest
        closest.into_iter()
            .take(requested_count)
            .map(|(node, _)| node)
            .collect()
    }

    /// Mark peer as failed (increment failed_attempts)
    ///
    /// Returns `true` if the peer was found and updated, `false` otherwise
    pub fn mark_failed(&mut self, node_id: &NodeId) -> bool {
        if let Some(entry) = self.peers.get_mut(node_id) {
            entry.failed_attempts += 1;
            true
        } else {
            false
        }
    }

    /// Mark peer as responsive (reset failed_attempts, update last_contact)
    ///
    /// Returns `true` if the peer was found and updated, `false` otherwise
    pub fn mark_responsive(&mut self, node_id: &NodeId) -> bool {
        if let Some(entry) = self.peers.get_mut(node_id) {
            entry.failed_attempts = 0;
            entry.last_contact = Self::current_timestamp();
            true
        } else {
            false
        }
    }

    /// Remove peers with excessive failed attempts
    ///
    /// Uses the configured `max_failed_attempts` threshold.
    /// Returns the number of peers removed.
    pub fn cleanup_failed_peers(&mut self) -> usize {
        self.cleanup_failed_peers_with_threshold(self.max_failed_attempts)
    }

    /// Remove peers with failed attempts exceeding the given threshold
    ///
    /// Returns the number of peers removed
    pub fn cleanup_failed_peers_with_threshold(&mut self, max_failed_attempts: u32) -> usize {
        let failed_nodes: Vec<NodeId> = self.peers.iter()
            .filter(|(_, entry)| entry.failed_attempts > max_failed_attempts)
            .map(|(node_id, _)| node_id.clone())
            .collect();

        let count = failed_nodes.len();
        for node_id in failed_nodes {
            self.remove(&node_id);
        }
        count
    }

    /// Check per-peer sequence number and update last seen sequence
    ///
    /// Rejects messages with sequence numbers less than or equal to the last seen.
    /// Allows a small wraparound window for u64 overflow.
    ///
    /// ## Wraparound Handling
    ///
    /// When a counter wraps from u64::MAX to 0, we accept sequences in a small window (0..1024)
    /// only if the last_sequence is very close to u64::MAX (within 1024 of overflow).
    /// This prevents replay attacks that try to exploit the wraparound window.
    pub fn check_and_update_sequence(&mut self, node_id: &NodeId, sequence: u64) -> Result<(), SequenceError> {
        let entry = self.peers.get_mut(node_id)
            .ok_or(SequenceError::PeerNotFound)?;

        if let Some(last_sequence) = entry.last_sequence {
            if sequence <= last_sequence {
                // Check if this is a legitimate wraparound
                // Only accept low sequences if last_sequence is close to u64::MAX
                let is_wraparound = last_sequence > u64::MAX - SEQUENCE_WRAPAROUND_WINDOW
                    && sequence < SEQUENCE_WRAPAROUND_WINDOW;

                if !is_wraparound {
                    return Err(SequenceError::ReplayDetected { sequence, last_sequence });
                }
            }
        }

        entry.last_sequence = Some(sequence);
        Ok(())
    }

    /// Get registry statistics
    pub fn stats(&self) -> DhtPeerStats {
        let total_peers = self.peers.len();

        // Use pre-sized array for bucket distribution (more efficient than HashMap)
        let mut bucket_counts: [usize; NUM_K_BUCKETS] = [0; NUM_K_BUCKETS];
        let mut non_empty_buckets = 0;
        let mut full_buckets = 0;

        for (idx, bucket) in self.bucket_index.iter().enumerate() {
            let count = bucket.len();
            bucket_counts[idx] = count;
            if count > 0 {
                non_empty_buckets += 1;
            }
            if count >= self.k {
                full_buckets += 1;
            }
        }

        // Convert to HashMap for API compatibility
        let bucket_distribution: HashMap<usize, usize> = bucket_counts
            .iter()
            .enumerate()
            .filter(|(_, &count)| count > 0)
            .map(|(idx, &count)| (idx, count))
            .collect();

        DhtPeerStats {
            total_peers,
            non_empty_buckets,
            full_buckets,
            k_value: self.k,
            bucket_distribution,
        }
    }

    /// Get rate limiter statistics (current_count, max_count)
    pub fn rate_limiter_stats(&self) -> (usize, u32) {
        self.rate_limiter.stats()
    }

    /// Get all peers
    pub fn all_peers(&self) -> impl Iterator<Item = &DhtPeerEntry> {
        self.peers.values()
    }

    /// Clear all peers (for testing/shutdown)
    pub fn clear(&mut self) {
        self.peers.clear();
        for bucket in &mut self.bucket_index {
            bucket.clear();
        }
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

// ========== STATISTICS ==========

/// DHT peer statistics
#[derive(Debug, Clone)]
pub struct DhtPeerStats {
    pub total_peers: usize,
    pub non_empty_buckets: usize,
    pub full_buckets: usize,
    pub k_value: usize,
    /// Distribution of peers across buckets (bucket_index -> count)
    pub bucket_distribution: HashMap<usize, usize>,
}

// ========== THREAD-SAFE WRAPPER ==========

/// Thread-safe DHT peer registry wrapper
///
/// Use this type for concurrent access to the peer registry.
/// Provides atomic updates and prevents race conditions.
///
/// ## Example
///
/// ```ignore
/// let registry = new_shared_dht_registry(20);
///
/// // Read access
/// let peer = registry.read().await.get(&node_id);
///
/// // Write access
/// registry.write().await.upsert(entry)?;
/// ```
pub type SharedDhtPeerRegistry = Arc<RwLock<DhtPeerRegistry>>;

/// Create a new thread-safe shared DHT peer registry
pub fn new_shared_dht_registry(k: usize) -> SharedDhtPeerRegistry {
    Arc::new(RwLock::new(DhtPeerRegistry::new(k)))
}

/// Create a new thread-safe shared DHT peer registry with custom configuration
pub fn new_shared_dht_registry_with_config(
    k: usize,
    rate_limit_per_minute: u32,
    max_failed_attempts: u32,
) -> SharedDhtPeerRegistry {
    Arc::new(RwLock::new(DhtPeerRegistry::with_config(
        k,
        rate_limit_per_minute,
        max_failed_attempts,
    )))
}

// ========== TESTS ==========

#[cfg(test)]
mod tests {
    use super::*;
    use lib_identity::{ZhtpIdentity, IdentityType};
    use crate::types::dht_types::{DhtPeerIdentity, build_peer_identity};

    fn create_test_node(device_name: &str, port: u16) -> DhtNode {
        let identity = ZhtpIdentity::new_unified(
            IdentityType::Device,
            None,
            None,
            device_name,
            None,
        ).expect("Failed to create test identity");

        let peer = build_peer_identity(
            identity.node_id.clone(),
            identity.public_key.clone(),
            identity.did.clone(),
            device_name.to_string(),
        );

        DhtNode {
            peer,
            addresses: vec![format!("127.0.0.1:{}", port)],
            public_key: lib_crypto::PostQuantumSignature {
                algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
                signature: vec![],
                public_key: lib_crypto::PublicKey {
                    dilithium_pk: vec![1, 2, 3],
                    kyber_pk: vec![],
                    key_id: [0u8; 32],
                },
                timestamp: 0,
            },
            last_seen: 0,
            reputation: 1000,
            storage_info: None,
        }
    }

    #[test]
    fn test_registry_creation() {
        let registry = DhtPeerRegistry::new(20);
        assert_eq!(registry.get_k(), 20);
        assert_eq!(registry.stats().total_peers, 0);
        assert_eq!(registry.get_max_failed_attempts(), DEFAULT_MAX_FAILED_ATTEMPTS);
    }

    #[test]
    fn test_registry_with_custom_config() {
        let registry = DhtPeerRegistry::with_config(15, 50, 5);
        assert_eq!(registry.get_k(), 15);
        assert_eq!(registry.get_max_failed_attempts(), 5);
    }

    #[test]
    fn test_upsert_and_get() {
        let mut registry = DhtPeerRegistry::new(20);
        let node = create_test_node("test-device", 8000);
        let node_id = node.peer.node_id().clone();

        let entry = DhtPeerEntry {
            node: node.clone(),
            distance: 100,
            bucket_index: 5,
            last_contact: 12345,
            failed_attempts: 0,
            last_sequence: None,
        };

        let is_new = registry.upsert(entry).unwrap();
        assert!(is_new);

        let retrieved = registry.get(&node_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().bucket_index, 5);

        // Update should return false
        let entry2 = DhtPeerEntry {
            node: node.clone(),
            distance: 100,
            bucket_index: 6,
            last_contact: 12346,
            failed_attempts: 0,
            last_sequence: None,
        };
        let is_new2 = registry.upsert(entry2).unwrap();
        assert!(!is_new2);

        // Verify update
        assert_eq!(registry.get(&node_id).unwrap().bucket_index, 6);
    }

    #[test]
    fn test_invalid_bucket_index() {
        let mut registry = DhtPeerRegistry::new(20);
        let node = create_test_node("test-device", 8000);

        let entry = DhtPeerEntry {
            node,
            distance: 100,
            bucket_index: 200, // Invalid: > MAX_BUCKET_INDEX
            last_contact: 12345,
            failed_attempts: 0,
            last_sequence: None,
        };

        let result = registry.upsert(entry);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid bucket index"));
    }

    #[test]
    fn test_bucket_operations() {
        let mut registry = DhtPeerRegistry::new(3); // Small k for testing

        // Add 3 peers to bucket 0
        for i in 0..3 {
            let node = create_test_node(&format!("device-{}", i), 8000 + i);
            let entry = DhtPeerEntry {
                node,
                distance: 10 + i as u32,
                bucket_index: 0,
                last_contact: 12345,
                failed_attempts: 0,
                last_sequence: None,
            };
            registry.upsert(entry).unwrap();
        }

        assert_eq!(registry.bucket_size(0), 3);
        assert!(registry.is_bucket_full(0));
        assert!(!registry.is_bucket_full(1));

        let bucket_peers = registry.peers_in_bucket(0);
        assert_eq!(bucket_peers.len(), 3);
    }

    #[test]
    fn test_secondary_bucket_index() {
        let mut registry = DhtPeerRegistry::new(20);

        // Add peers to different buckets
        for bucket_idx in 0..5 {
            let node = create_test_node(&format!("device-{}", bucket_idx), 8000 + bucket_idx);
            let entry = DhtPeerEntry {
                node,
                distance: bucket_idx as u32,
                bucket_index: bucket_idx as usize,
                last_contact: 12345,
                failed_attempts: 0,
                last_sequence: None,
            };
            registry.upsert(entry).unwrap();
        }

        // Verify O(1) bucket size lookups via secondary index
        for bucket_idx in 0..5 {
            assert_eq!(registry.bucket_size(bucket_idx), 1);
        }
        assert_eq!(registry.bucket_size(5), 0);
    }

    #[test]
    fn test_mark_failed_returns_bool() {
        let mut registry = DhtPeerRegistry::new(20);
        let node = create_test_node("test-device", 8000);
        let node_id = node.peer.node_id().clone();

        // Mark non-existent peer
        assert!(!registry.mark_failed(&node_id));

        // Add peer and mark as failed
        let entry = DhtPeerEntry {
            node,
            distance: 100,
            bucket_index: 5,
            last_contact: 12345,
            failed_attempts: 0,
            last_sequence: None,
        };
        registry.upsert(entry).unwrap();

        assert!(registry.mark_failed(&node_id));
        assert_eq!(registry.get(&node_id).unwrap().failed_attempts, 1);
    }

    #[test]
    fn test_mark_responsive_returns_bool() {
        let mut registry = DhtPeerRegistry::new(20);
        let node = create_test_node("test-device", 8000);
        let node_id = node.peer.node_id().clone();

        // Mark non-existent peer
        assert!(!registry.mark_responsive(&node_id));

        // Add peer with failures and mark responsive
        let entry = DhtPeerEntry {
            node,
            distance: 100,
            bucket_index: 5,
            last_contact: 12345,
            failed_attempts: 5,
            last_sequence: None,
        };
        registry.upsert(entry).unwrap();

        assert!(registry.mark_responsive(&node_id));
        assert_eq!(registry.get(&node_id).unwrap().failed_attempts, 0);
    }

    #[test]
    fn test_cleanup_failed_peers() {
        let mut registry = DhtPeerRegistry::new(20);

        // Add peers with varying failed attempts
        for i in 0..5 {
            let node = create_test_node(&format!("device-{}", i), 8000 + i);
            let entry = DhtPeerEntry {
                node,
                distance: 10 + i as u32,
                bucket_index: 0,
                last_contact: 12345,
                failed_attempts: i as u32,
                last_sequence: None,
            };
            registry.upsert(entry).unwrap();
        }

        assert_eq!(registry.stats().total_peers, 5);

        // Remove peers with > 2 failed attempts (default is 3)
        let removed = registry.cleanup_failed_peers_with_threshold(2);
        assert_eq!(removed, 2); // Peers with 3 and 4 failed attempts

        assert_eq!(registry.stats().total_peers, 3);
    }

    #[test]
    fn test_cleanup_uses_configured_threshold() {
        let mut registry = DhtPeerRegistry::with_config(20, 100, 1); // max_failed = 1

        // Add peer with 2 failed attempts
        let node = create_test_node("test-device", 8000);
        let entry = DhtPeerEntry {
            node,
            distance: 100,
            bucket_index: 0,
            last_contact: 12345,
            failed_attempts: 2,
            last_sequence: None,
        };
        registry.upsert(entry).unwrap();

        // Should be cleaned up with configured threshold of 1
        let removed = registry.cleanup_failed_peers();
        assert_eq!(removed, 1);
    }

    #[test]
    fn test_sequence_tracking_rejects_replay() {
        let mut registry = DhtPeerRegistry::new(20);
        let node = create_test_node("seq-peer", 4100);
        let node_id = node.peer.node_id().clone();

        let entry = DhtPeerEntry {
            node,
            distance: 1,
            bucket_index: 0,
            last_contact: 0,
            failed_attempts: 0,
            last_sequence: None,
        };

        registry.upsert(entry).unwrap();

        registry.check_and_update_sequence(&node_id, 1).unwrap();
        registry.check_and_update_sequence(&node_id, 2).unwrap();

        let err = registry.check_and_update_sequence(&node_id, 2).unwrap_err();
        assert!(err.to_string().contains("Replay detected"));
    }

    #[test]
    fn test_sequence_wraparound_window() {
        let mut registry = DhtPeerRegistry::new(20);
        let node = create_test_node("seq-wrap", 4101);
        let node_id = node.peer.node_id().clone();

        let entry = DhtPeerEntry {
            node,
            distance: 1,
            bucket_index: 0,
            last_contact: 0,
            failed_attempts: 0,
            last_sequence: Some(u64::MAX - 1),
        };

        registry.upsert(entry).unwrap();

        assert!(registry.check_and_update_sequence(&node_id, 0).is_ok());
    }

    #[test]
    fn test_sequence_wraparound_exact_max() {
        let mut registry = DhtPeerRegistry::new(20);
        let node = create_test_node("seq-wrap-max", 4102);
        let node_id = node.peer.node_id().clone();

        let entry = DhtPeerEntry {
            node,
            distance: 1,
            bucket_index: 0,
            last_contact: 0,
            failed_attempts: 0,
            last_sequence: Some(u64::MAX),
        };

        registry.upsert(entry).unwrap();

        // Should allow wraparound from u64::MAX to 0
        assert!(registry.check_and_update_sequence(&node_id, 0).is_ok());
        // Should allow sequential increases after wraparound
        assert!(registry.check_and_update_sequence(&node_id, 1).is_ok());
    }

    #[test]
    fn test_sequence_wraparound_prevents_replay_attack() {
        let mut registry = DhtPeerRegistry::new(20);
        let node = create_test_node("seq-replay", 4103);
        let node_id = node.peer.node_id().clone();

        // Set last_sequence to a value far from u64::MAX
        let entry = DhtPeerEntry {
            node,
            distance: 1,
            bucket_index: 0,
            last_contact: 0,
            failed_attempts: 0,
            last_sequence: Some(1000),
        };

        registry.upsert(entry).unwrap();

        // Should reject sequence 0 because it's not actually a wraparound
        let err = registry.check_and_update_sequence(&node_id, 0).unwrap_err();
        assert_eq!(err, SequenceError::ReplayDetected { sequence: 0, last_sequence: 1000 });
    }

    #[test]
    fn test_sequence_custom_error_type() {
        let mut registry = DhtPeerRegistry::new(20);
        let node = create_test_node("seq-error", 4104);
        let node_id = node.peer.node_id().clone();

        let entry = DhtPeerEntry {
            node,
            distance: 1,
            bucket_index: 0,
            last_contact: 0,
            failed_attempts: 0,
            last_sequence: Some(100),
        };

        registry.upsert(entry).unwrap();

        // Test that we get the correct custom error type
        let err = registry.check_and_update_sequence(&node_id, 50).unwrap_err();
        match err {
            SequenceError::ReplayDetected { sequence, last_sequence } => {
                assert_eq!(sequence, 50);
                assert_eq!(last_sequence, 100);
            }
            _ => panic!("Expected ReplayDetected error"),
        }

        // Test PeerNotFound error
        let unknown_node = create_test_node("unknown", 4105);
        let unknown_id = unknown_node.peer.node_id().clone();
        let err = registry.check_and_update_sequence(&unknown_id, 1).unwrap_err();
        assert_eq!(err, SequenceError::PeerNotFound);
    }

    #[test]
    fn test_find_closest() {
        let mut registry = DhtPeerRegistry::new(20);
        let local_id = NodeId::from_bytes([1u8; 32]);

        // Add several peers
        for i in 0..10 {
            let node = create_test_node(&format!("device-{}", i), 8000 + i);
            let distance = local_id.kademlia_distance(node.peer.node_id());
            let entry = DhtPeerEntry {
                node,
                distance,
                bucket_index: (distance as usize).min(MAX_BUCKET_INDEX),
                last_contact: 12345,
                failed_attempts: 0,
                last_sequence: None,
            };
            registry.upsert(entry).unwrap();
        }

        let target = NodeId::from_bytes([2u8; 32]);
        let closest = registry.find_closest(&target, 5);

        assert_eq!(closest.len(), 5);

        // Verify they're actually sorted by distance
        for i in 0..closest.len() - 1 {
            let dist1 = target.kademlia_distance(closest[i].peer.node_id());
            let dist2 = target.kademlia_distance(closest[i + 1].peer.node_id());
            assert!(dist1 <= dist2, "Peers not sorted by distance");
        }
    }

    #[test]
    fn test_stats() {
        let mut registry = DhtPeerRegistry::new(3);

        // Add peers to different buckets
        for bucket_idx in 0..5 {
            for i in 0..2 {
                let node = create_test_node(&format!("device-{}-{}", bucket_idx, i), 8000 + bucket_idx * 10 + i);
                let entry = DhtPeerEntry {
                    node,
                    distance: (bucket_idx * 10 + i) as u32,
                    bucket_index: bucket_idx as usize,
                    last_contact: 12345,
                    failed_attempts: 0,
                    last_sequence: None,
                };
                registry.upsert(entry).unwrap();
            }
        }

        let stats = registry.stats();
        assert_eq!(stats.total_peers, 10);
        assert_eq!(stats.non_empty_buckets, 5);
        assert_eq!(stats.k_value, 3);
        assert_eq!(stats.full_buckets, 0); // Each bucket has 2, k=3
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = DhtRateLimiter::new(3, 60);

        // First 3 should succeed
        assert!(limiter.check_and_record());
        assert!(limiter.check_and_record());
        assert!(limiter.check_and_record());

        // 4th should fail
        assert!(!limiter.check_and_record());

        let (current, max) = limiter.stats();
        assert_eq!(current, 3);
        assert_eq!(max, 3);
    }

    #[test]
    fn test_rate_limiting_on_upsert() {
        // Create registry with very low rate limit
        let mut registry = DhtPeerRegistry::with_config(20, 2, 3);

        // First 2 insertions should succeed
        for i in 0..2 {
            let node = create_test_node(&format!("device-{}", i), 8000 + i);
            let entry = DhtPeerEntry {
                node,
                distance: i as u32,
                bucket_index: 0,
                last_contact: 12345,
                failed_attempts: 0,
                last_sequence: None,
            };
            assert!(registry.upsert(entry).is_ok());
        }

        // 3rd insertion should fail due to rate limiting
        let node = create_test_node("device-2", 8002);
        let entry = DhtPeerEntry {
            node,
            distance: 2,
            bucket_index: 0,
            last_contact: 12345,
            failed_attempts: 0,
            last_sequence: None,
        };
        let result = registry.upsert(entry);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Rate limit exceeded"));
    }

    #[test]
    fn test_shared_registry() {
        let registry = new_shared_dht_registry(20);

        // Just verify it compiles and can be cloned
        let _cloned = registry.clone();
    }

    #[test]
    fn test_constants() {
        assert_eq!(NUM_K_BUCKETS, 160);
        assert_eq!(MAX_BUCKET_INDEX, 159);
        assert_eq!(DEFAULT_MAX_FAILED_ATTEMPTS, 3);
        assert_eq!(DEFAULT_RATE_LIMIT_PER_MINUTE, 100);
    }
}

// ========== TRAIT IMPLEMENTATION (Ticket #1.14) ==========

use crate::dht::DhtPeerRegistryTrait;
use async_trait::async_trait;

#[async_trait]
impl DhtPeerRegistryTrait for DhtPeerRegistry {
    async fn add_dht_peer(&mut self, node: &DhtNode, bucket_index: usize, distance: u32) -> Result<()> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        let entry = DhtPeerEntry {
            node: node.clone(),
            distance,
            bucket_index,
            last_contact: current_time,
            failed_attempts: 0,
            last_sequence: None,
        };
        
        self.upsert(entry)?;
        Ok(())
    }
    
    async fn find_closest_dht_peers(&self, target: &NodeId, count: usize) -> Result<Vec<DhtNode>> {
        Ok(self.find_closest(target, count))
    }
    
    async fn get_dht_bucket_peers(&self, bucket_index: usize) -> Result<Vec<DhtNode>> {
        Ok(self.peers_in_bucket(bucket_index)
            .into_iter()
            .map(|entry| entry.node.clone())
            .collect())
    }
    
    async fn mark_dht_peer_failed(&mut self, node_id: &NodeId) -> Result<()> {
        self.mark_failed(node_id);
        Ok(())
    }
    
    async fn mark_dht_peer_responsive(&mut self, node_id: &NodeId) -> Result<()> {
        self.mark_responsive(node_id);
        Ok(())
    }
    
    async fn is_dht_bucket_full(&self, bucket_index: usize, k: usize) -> Result<bool> {
        if bucket_index >= NUM_K_BUCKETS {
            return Err(anyhow!("Invalid bucket index {}: must be 0-{}", bucket_index, MAX_BUCKET_INDEX));
        }
        Ok(self.bucket_index[bucket_index].len() >= k)
    }
    
    async fn remove_dht_peer(&mut self, node_id: &NodeId) -> Result<()> {
        self.remove(node_id);
        Ok(())
    }
}
