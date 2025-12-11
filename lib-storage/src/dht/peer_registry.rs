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
//! - Enables efficient queries by bucket_index
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
//! Callers should wrap in Arc<RwLock<DhtPeerRegistry>> for concurrent access.

use crate::types::dht_types::DhtNode;
use crate::types::NodeId;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

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
}

/// Internal peer registry for DHT routing
///
/// Replaces Vec<KBucket> with HashMap<NodeId, DhtPeerEntry>
/// for unified peer storage and efficient lookups.
#[derive(Debug, Clone)]
pub struct DhtPeerRegistry {
    /// Primary storage: NodeId → DhtPeerEntry
    peers: HashMap<NodeId, DhtPeerEntry>,
    /// K-bucket size (standard Kademlia K value, typically 20)
    k: usize,
}

impl DhtPeerRegistry {
    /// Create a new empty DHT peer registry
    pub fn new(k: usize) -> Self {
        Self {
            peers: HashMap::new(),
            k,
        }
    }

    /// Insert or update a peer
    ///
    /// Returns Ok(true) if peer was inserted, Ok(false) if updated
    pub fn upsert(&mut self, entry: DhtPeerEntry) -> Result<bool> {
        let node_id = entry.node.peer.node_id().clone();
        let is_new = !self.peers.contains_key(&node_id);
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
    
    /// Get the total number of peers in the registry
    pub fn len(&self) -> usize {
        self.peers.len()
    }
    
    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Remove a peer by NodeId
    pub fn remove(&mut self, node_id: &NodeId) -> Option<DhtPeerEntry> {
        self.peers.remove(node_id)
    }

    /// Get all peers in a specific K-bucket
    pub fn peers_in_bucket(&self, bucket_index: usize) -> Vec<&DhtPeerEntry> {
        self.peers.values()
            .filter(|entry| entry.bucket_index == bucket_index)
            .collect()
    }

    /// Count peers in a specific K-bucket
    pub fn bucket_size(&self, bucket_index: usize) -> usize {
        self.peers_in_bucket(bucket_index).len()
    }

    /// Check if a K-bucket is full
    pub fn is_bucket_full(&self, bucket_index: usize) -> bool {
        self.bucket_size(bucket_index) >= self.k
    }

    /// Get K-bucket parameter
    pub fn get_k(&self) -> usize {
        self.k
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
    pub fn mark_failed(&mut self, node_id: &NodeId) {
        if let Some(entry) = self.peers.get_mut(node_id) {
            entry.failed_attempts += 1;
        }
    }

    /// Mark peer as responsive (reset failed_attempts, update last_contact)
    pub fn mark_responsive(&mut self, node_id: &NodeId) -> Result<()> {
        if let Some(entry) = self.peers.get_mut(node_id) {
            entry.failed_attempts = 0;
            entry.last_contact = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        }
        Ok(())
    }

    /// Remove peers with excessive failed attempts
    ///
    /// Returns the number of peers removed
    pub fn cleanup_failed_peers(&mut self, max_failed_attempts: u32) -> usize {
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

    /// Get registry statistics
    pub fn stats(&self) -> DhtPeerStats {
        let total_peers = self.peers.len();
        
        // Count peers per bucket
        let mut bucket_distribution = HashMap::new();
        for entry in self.peers.values() {
            *bucket_distribution.entry(entry.bucket_index).or_insert(0) += 1;
        }

        let non_empty_buckets = bucket_distribution.len();
        let full_buckets = bucket_distribution.iter()
            .filter(|(_, &count)| count >= self.k)
            .count();

        DhtPeerStats {
            total_peers,
            non_empty_buckets,
            full_buckets,
            k_value: self.k,
        }
    }

    /// Get all peers
    pub fn all_peers(&self) -> impl Iterator<Item = &DhtPeerEntry> {
        self.peers.values()
    }

    /// Clear all peers (for testing/shutdown)
    pub fn clear(&mut self) {
        self.peers.clear();
    }
}

/// DHT peer statistics
#[derive(Debug, Clone)]
pub struct DhtPeerStats {
    pub total_peers: usize,
    pub non_empty_buckets: usize,
    pub full_buckets: usize,
    pub k_value: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_identity::{ZhtpIdentity, IdentityType};
    use crate::types::dht_types::DhtPeerIdentity;

    fn create_test_node(device_name: &str, port: u16) -> DhtNode {
        let identity = ZhtpIdentity::new_unified(
            IdentityType::Device,
            None,
            None,
            device_name,
            None,
        ).expect("Failed to create test identity");

        let peer = DhtPeerIdentity {
            node_id: identity.node_id.clone(),
            public_key: identity.public_key.clone(),
            did: identity.did.clone(),
            device_id: device_name.to_string(),
        };

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
        };
        let is_new2 = registry.upsert(entry2).unwrap();
        assert!(!is_new2);

        // Verify update
        assert_eq!(registry.get(&node_id).unwrap().bucket_index, 6);
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
    fn test_mark_failed_and_responsive() {
        let mut registry = DhtPeerRegistry::new(20);
        let node = create_test_node("test-device", 8000);
        let node_id = node.peer.node_id().clone();

        let entry = DhtPeerEntry {
            node,
            distance: 100,
            bucket_index: 5,
            last_contact: 12345,
            failed_attempts: 0,
        };
        registry.upsert(entry).unwrap();

        // Mark as failed multiple times
        registry.mark_failed(&node_id);
        registry.mark_failed(&node_id);
        registry.mark_failed(&node_id);

        assert_eq!(registry.get(&node_id).unwrap().failed_attempts, 3);

        // Mark as responsive
        registry.mark_responsive(&node_id).unwrap();
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
            };
            registry.upsert(entry).unwrap();
        }

        assert_eq!(registry.stats().total_peers, 5);

        // Remove peers with > 2 failed attempts
        let removed = registry.cleanup_failed_peers(2);
        assert_eq!(removed, 2); // Peers with 3 and 4 failed attempts

        assert_eq!(registry.stats().total_peers, 3);
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
                bucket_index: (distance as usize).min(159),
                last_contact: 12345,
                failed_attempts: 0,
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
}
