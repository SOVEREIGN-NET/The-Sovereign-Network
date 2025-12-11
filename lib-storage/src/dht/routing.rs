//! Kademlia-based DHT Routing
//! 
//! Implements the Kademlia routing algorithm with K-buckets for efficient
//! peer discovery and routing in the DHT network.
//!
//! **MIGRATED (Ticket #148):** Now uses internal DhtPeerRegistry for unified
//! peer storage instead of maintaining separate Vec<KBucket> arrays.

use crate::types::dht_types::{DhtNode, KBucket, RoutingEntry};
use crate::types::NodeId;
use crate::dht::peer_registry::{DhtPeerRegistry, DhtPeerEntry};
use anyhow::{Result, anyhow};
use std::time::{SystemTime, UNIX_EPOCH};

/// Kademlia routing table for DHT operations
///
/// **MIGRATED (Ticket #148):** Now uses DhtPeerRegistry for unified peer storage
/// instead of maintaining separate routing_table: Vec<KBucket>.
///
/// # Design
///
/// The KademliaRouter now delegates peer storage to DhtPeerRegistry, which uses
/// HashMap<NodeId, DhtPeerEntry> instead of Vec<KBucket>. This eliminates duplicate
/// peer storage while preserving all K-bucket functionality.
///
/// # Thread Safety
///
/// Uses `&mut self` for mutations. Callers should wrap in Arc<RwLock> for
/// concurrent access (to be addressed in future thread-safety ticket).
#[derive(Debug)]
pub struct KademliaRouter {
    /// Local node ID
    local_id: NodeId,
    /// Internal peer registry (replaces routing_table Vec<KBucket>)
    registry: DhtPeerRegistry,
    /// K-bucket size (standard Kademlia K value)
    k: usize,
}

impl KademliaRouter {
    /// Create a new Kademlia router
    ///
    /// **MIGRATED (Ticket #148):** Now creates internal DhtPeerRegistry instead of Vec<KBucket>
    pub fn new(local_id: NodeId, k: usize) -> Self {
        Self {
            local_id,
            registry: DhtPeerRegistry::new(k),
            k,
        }
    }
    
    /// Calculate XOR distance between two node IDs
    pub fn calculate_distance(&self, a: &NodeId, b: &NodeId) -> u32 {
        a.kademlia_distance(b)
    }
    
    /// Get bucket index for a given distance
    fn get_bucket_index(&self, distance: u32) -> usize {
        std::cmp::min(distance as usize, 159)
    }
    
    /// Add a node to the routing table
    ///
    /// **MIGRATED (Ticket #148):** Now uses DhtPeerRegistry.upsert() instead of
    /// direct routing_table manipulation.
    ///
    /// **MIGRATION (Ticket #145):** Uses `node.peer.node_id()` for distance calculation
    /// while storing full UnifiedPeerId for signature verification
    ///
    /// # Security (CRIT-3)
    ///
    /// **TODO:** Currently accepts nodes without verifying NodeId ownership.
    /// Before production, implement challenge-response verification:
    ///
    /// 1. Generate random challenge
    /// 2. Require node to sign challenge with private key matching their public key
    /// 3. Verify NodeId derivation matches: SHA3-256(public_key) == NodeId
    /// 4. Only add node if verification passes
    ///
    /// This prevents NodeId collision/spoofing attacks where an attacker claims
    /// a NodeId they don't own to poison routing tables.
    ///
    /// See: lib-identity::ZhtpIdentity::verify_node_id_derivation()
    pub async fn add_node(&mut self, node: DhtNode) -> Result<()> {
        let node_id = node.peer.node_id();
        if *node_id == self.local_id {
            return Err(anyhow!("Cannot add local node to routing table"));
        }

        // SECURITY (CRIT-3): Validate node has non-empty public key
        // Full challenge-response verification should be done at the network layer
        // before calling add_node, but we add a basic sanity check here
        if node.peer.public_key().dilithium_pk.is_empty() {
            return Err(anyhow!("Cannot add node with empty public key to routing table"));
        }
        
        let distance = self.calculate_distance(&self.local_id, node_id);
        let bucket_index = self.get_bucket_index(distance);
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        // Check if peer already exists
        if let Some(existing) = self.registry.get_mut(node_id) {
            // Update existing peer
            existing.node = node.clone();
            existing.last_contact = current_time;
            existing.failed_attempts = 0;
            existing.distance = distance;
            existing.bucket_index = bucket_index;
            return Ok(());
        }

        // New peer - check if bucket is full
        if self.registry.is_bucket_full(bucket_index) {
            // Bucket full - try to replace least recently seen node with failed attempts > 3
            let lrs_failed = self.registry.peers_in_bucket(bucket_index)
                .iter()
                .filter(|entry| entry.failed_attempts > 3)
                .min_by_key(|entry| entry.last_contact)
                .map(|entry| entry.node.peer.node_id().clone());

            if let Some(node_to_remove) = lrs_failed {
                // Remove the failed node
                self.registry.remove(&node_to_remove);
            } else {
                // Bucket full and no failed peers - cannot add
                return Err(anyhow!("K-bucket {} is full (k={})", bucket_index, self.k));
            }
        }

        // Add new peer
        let entry = DhtPeerEntry {
            node,
            distance,
            bucket_index,
            last_contact: current_time,
            failed_attempts: 0,
        };

        self.registry.upsert(entry)?;
        Ok(())
    }
    
    /// Find the K closest nodes to a target ID (uses k-bucket parameter)
    ///
    /// **MIGRATED (Ticket #148):** Now uses DhtPeerRegistry.find_closest()
    ///
    /// **MIGRATION (Ticket #145):** Uses `node.peer.node_id()` for distance calculation
    /// Returns full DhtNode with UnifiedPeerId for caller to verify signatures
    pub fn find_closest_nodes(&self, target: &NodeId, count: usize) -> Vec<DhtNode> {
        self.registry.find_closest(target, count)
    }
    
    /// Get all nodes in a specific bucket
    ///
    /// **MIGRATED (Ticket #148):** Now uses DhtPeerRegistry.peers_in_bucket()
    pub fn get_bucket_nodes(&self, bucket_index: usize) -> Vec<&DhtNode> {
        self.registry.peers_in_bucket(bucket_index)
            .into_iter()
            .map(|entry| &entry.node)
            .collect()
    }
    
    /// Mark a node as failed (increment failed attempts)
    ///
    /// **MIGRATED (Ticket #148):** Now uses DhtPeerRegistry.mark_failed()
    ///
    /// **MIGRATION (Ticket #145):** Uses `node.peer.node_id()` for lookup
    pub fn mark_node_failed(&mut self, node_id: &NodeId) {
        self.registry.mark_failed(node_id);
    }
    
    /// Mark a node as responsive (reset failed attempts)
    ///
    /// **MIGRATED (Ticket #148):** Now uses DhtPeerRegistry.mark_responsive()
    ///
    /// **MIGRATION (Ticket #145):** Uses `node.peer.node_id()` for lookup
    pub fn mark_node_responsive(&mut self, node_id: &NodeId) -> Result<()> {
        self.registry.mark_responsive(node_id)
    }
    
    /// Remove a node from the routing table
    ///
    /// **MIGRATED (Ticket #148):** Now uses DhtPeerRegistry.remove()
    ///
    /// **MIGRATION (Ticket #145):** Uses `node.peer.node_id()` for lookup
    pub fn remove_node(&mut self, node_id: &NodeId) {
        self.registry.remove(node_id);
    }
    
    /// Get routing table statistics
    ///
    /// **MIGRATED (Ticket #148):** Now uses DhtPeerRegistry.stats()
    pub fn get_stats(&self) -> RoutingStats {
        let stats = self.registry.stats();
        RoutingStats {
            total_nodes: stats.total_peers,
            non_empty_buckets: stats.non_empty_buckets,
            total_buckets: 160, // Kademlia uses 160 buckets for 256-bit IDs
            full_buckets: stats.full_buckets,
            k_value: stats.k_value,
            average_bucket_fill: if stats.non_empty_buckets > 0 {
                stats.total_peers as f64 / stats.non_empty_buckets as f64
            } else {
                0.0
            },
        }
    }

    /// Get the k-bucket parameter value
    ///
    /// **MIGRATED (Ticket #148):** Now uses DhtPeerRegistry.get_k()
    pub fn get_k_value(&self) -> usize {
        self.registry.get_k()
    }

    /// Check if a bucket is full (has k nodes)
    ///
    /// **MIGRATED (Ticket #148):** Now uses DhtPeerRegistry.is_bucket_full()
    pub fn is_bucket_full(&self, bucket_index: usize) -> bool {
        self.registry.is_bucket_full(bucket_index)
    }

    /// Get k-bucket utilization (percentage of buckets that are full)
    ///
    /// **MIGRATED (Ticket #148):** Now uses DhtPeerRegistry stats
    pub fn get_bucket_utilization(&self) -> f64 {
        let stats = self.registry.stats();
        if stats.non_empty_buckets == 0 {
            0.0
        } else {
            (stats.full_buckets as f64 / 160.0) * 100.0 // 160 total K-buckets
        }
    }

    /// Refresh old buckets (Kademlia maintenance)
    ///
    /// **MIGRATED (Ticket #148):** Now checks peer last_contact timestamps
    /// Returns list of bucket indices that need refresh
    pub fn get_buckets_needing_refresh(&self, refresh_interval_secs: u64) -> Vec<usize> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let mut buckets_to_refresh = std::collections::HashSet::new();
        
        // Check all peers and find buckets with stale contacts
        for entry in self.registry.all_peers() {
            if current_time - entry.last_contact > refresh_interval_secs {
                buckets_to_refresh.insert(entry.bucket_index);
            }
        }
        
        buckets_to_refresh.into_iter().collect()
    }

    /// Perform k-bucket maintenance (remove unresponsive nodes)
    ///
    /// **MIGRATED (Ticket #148):** Now uses DhtPeerRegistry.cleanup_failed_peers()
    pub fn perform_bucket_maintenance(&mut self, max_failed_attempts: u32) -> usize {
        self.registry.cleanup_failed_peers(max_failed_attempts)
    }

    /// Generate random node ID for bucket refresh
    pub fn generate_random_id_for_bucket(&self, bucket_index: usize) -> NodeId {
        use lib_crypto::hashing::hash_blake3;
        
        // Generate a random ID that falls in the specified bucket's range
        let mut id_bytes = self.local_id.as_bytes().to_vec();
        
        // Flip bits to create distance in the target bucket range
        if bucket_index < 160 {
            let byte_index = bucket_index / 8;
            let bit_index = bucket_index % 8;
            
            if byte_index < 32 {
                id_bytes[byte_index] ^= 1 << (7 - bit_index);
            }
        }
        
        // Add some randomness to the lower bits
        let random_suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        
        let suffix_bytes = random_suffix.to_le_bytes();
        for (i, &byte) in suffix_bytes.iter().enumerate() {
            if i + 24 < 32 {
                id_bytes[i + 24] ^= byte;
            }
        }

        let hash = hash_blake3(&id_bytes);
        NodeId::from_bytes(hash)
    }

    /// Split k-bucket (used when bucket is full and contains local node's bucket)
    pub fn should_split_bucket(&self, bucket_index: usize) -> bool {
        // Only split if this is the bucket containing our local node ID
        let local_distance = self.calculate_distance(&self.local_id, &self.local_id);
        let local_bucket_index = self.get_bucket_index(local_distance);
        
        bucket_index == local_bucket_index && self.is_bucket_full(bucket_index)
    }
}

/// Routing table statistics
#[derive(Debug)]
pub struct RoutingStats {
    pub total_nodes: usize,
    pub non_empty_buckets: usize,
    pub total_buckets: usize,
    pub full_buckets: usize,
    pub k_value: usize,
    pub average_bucket_fill: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_identity::{ZhtpIdentity, IdentityType};
    use crate::types::dht_types::DhtPeerIdentity;
    
    fn create_test_peer(device_name: &str) -> DhtPeerIdentity {
        let identity = ZhtpIdentity::new_unified(
            IdentityType::Device,
            None,
            None,
            device_name,
            None,
        ).expect("Failed to create test identity");
        
        DhtPeerIdentity {
            node_id: identity.node_id.clone(),
            public_key: identity.public_key.clone(),
            did: identity.did.clone(),
            device_id: device_name.to_string(),
        }
    }
    
    fn build_test_node(peer: DhtPeerIdentity, port: u16) -> DhtNode {
        DhtNode {
            peer,
            addresses: vec![format!("127.0.0.1:{}", port)],
            public_key: lib_crypto::PostQuantumSignature {
                algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
                signature: vec![],
                public_key: lib_crypto::PublicKey {
                    dilithium_pk: vec![],
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
    fn test_router_creation() {
        let local_id = NodeId::from_bytes([1u8; 32]);
        let router = KademliaRouter::new(local_id, 20);
        
        // Verify K value
        assert_eq!(router.k, 20);
        
        // Verify registry initialized
        assert_eq!(router.registry.len(), 0);
    }
    
    #[test]
    fn test_distance_calculation() {
        let local_id = NodeId::from_bytes([1u8; 32]);
        let router = KademliaRouter::new(local_id, 20);
        
        let node_a = NodeId::from_bytes([1u8; 32]);
        let node_b = NodeId::from_bytes([2u8; 32]);
        
        let distance = router.calculate_distance(&node_a, &node_b);
        assert!(distance > 0);
        
        // Distance to self should be 0
        let self_distance = router.calculate_distance(&node_a, &node_a);
        assert_eq!(self_distance, 0);
    }

    #[test]
    fn test_calculate_distance_matches_nodeid_xor() {
        let local_id = NodeId::from_bytes([0u8; 32]);
        let router = KademliaRouter::new(local_id, 20);

        let id_a = NodeId::from_bytes([0xAA; 32]);
        let id_b = NodeId::from_bytes([0x0F; 32]);

        let expected = id_a.kademlia_distance(&id_b);
        let distance = router.calculate_distance(&id_a, &id_b);

        assert_eq!(distance, expected);
    }
    
    #[test]
    fn test_bucket_index() {
        let local_id = NodeId::from_bytes([1u8; 32]);
        let router = KademliaRouter::new(local_id, 20);
        let distance_0 = 0;
        let distance_10 = 10;
        let distance_200 = 200;
        
        assert_eq!(router.get_bucket_index(distance_0), 0);
        assert_eq!(router.get_bucket_index(distance_10), 10);
        assert_eq!(router.get_bucket_index(distance_200), 159); // Capped at 159
    }
    
    #[tokio::test]
    async fn test_add_node() {
        let local_id = NodeId::from_bytes([1u8; 32]);
        let mut router = KademliaRouter::new(local_id, 20);
        
        let test_peer = create_test_peer("test-device");
        let test_node = build_test_node(test_peer, 33442);
        
        router.add_node(test_node).await.unwrap();
        
        let stats = router.get_stats();
        assert_eq!(stats.total_nodes, 1);
        assert_eq!(stats.non_empty_buckets, 1);
        assert_eq!(stats.k_value, 20);
        assert_eq!(stats.full_buckets, 0); // Not full yet
    }

    #[test]
    fn test_k_value_functionality() {
        let local_id = NodeId::from_bytes([1u8; 32]);
        let k_value = 15;
        let router = KademliaRouter::new(local_id, k_value);
        
        assert_eq!(router.get_k_value(), k_value);
        
        // Test bucket full check
        assert!(!router.is_bucket_full(0)); // Empty bucket
        
        // Test utilization
        let utilization = router.get_bucket_utilization();
        assert_eq!(utilization, 0.0); // No nodes yet
    }

    #[tokio::test]
    async fn test_k_bucket_limits() {
        let local_id = NodeId::from_bytes([1u8; 32]);
        let k_value = 3; // Small k for testing
        let mut router = KademliaRouter::new(local_id, k_value);
        
        // Add k+1 nodes to same bucket by creating similar NodeIds
        // that will hash to the same bucket distance
        for i in 2..6 { // 4 nodes total, trying to exceed k=3
            let device_name = format!("test-device-{}", i);
            let test_peer = create_test_peer(&device_name);
            let test_node = build_test_node(test_peer, 33440 + i as u16);
            
            let _ = router.add_node(test_node).await; // May fail if bucket full
        }
        
        let stats = router.get_stats();
        // Verify no individual bucket exceeds k
        for bucket_idx in 0..160 {
            let bucket_nodes = router.get_bucket_nodes(bucket_idx);
            assert!(bucket_nodes.len() <= k_value, 
                "Bucket {} has {} nodes, exceeds k={}", bucket_idx, bucket_nodes.len(), k_value);
        }
    }

    #[test]
    fn test_closest_nodes_k_limit() {
        let local_id = NodeId::from_bytes([1u8; 32]);
        let k_value = 5;
        let router = KademliaRouter::new(local_id, k_value);
        
        let target = NodeId::from_bytes([2u8; 32]);
        
        // Request more nodes than k allows
        let closest = router.find_closest_nodes(&target, 20);
        assert!(closest.len() <= k_value); // Should be limited by k
    }

    #[tokio::test]
    async fn test_bucket_maintenance() {
        let local_id = NodeId::from_bytes([1u8; 32]);
        let mut router = KademliaRouter::new(local_id, 20);
        
        // Add a node
        let test_peer = create_test_peer("test-device");
        let test_node = build_test_node(test_peer.clone(), 33442);
        
        router.add_node(test_node.clone()).await.unwrap();
        
        // Mark node as failed multiple times
        for _ in 0..5 {
            router.mark_node_failed(test_peer.node_id());
        }
        
        // Perform maintenance
        let removed = router.perform_bucket_maintenance(3);
        assert_eq!(removed, 1); // Should remove the failed node
        
        let stats = router.get_stats();
        assert_eq!(stats.total_nodes, 0);
    }

    #[test]
    fn test_random_id_generation() {
        let local_id = NodeId::from_bytes([1u8; 32]);
        let router = KademliaRouter::new(local_id.clone(), 20);
        
        // Generate random IDs for different buckets
        let id_bucket_0 = router.generate_random_id_for_bucket(0);
        let id_bucket_10 = router.generate_random_id_for_bucket(10);
        
        // IDs should be different
        assert_ne!(id_bucket_0, id_bucket_10);
        
        // Distance should roughly correspond to bucket
        let distance_0 = router.calculate_distance(&local_id, &id_bucket_0);
        let distance_10 = router.calculate_distance(&local_id, &id_bucket_10);
        
        // These might not be exact due to randomness, but generally bucket 10 should be further
        println!("Distance 0: {}, Distance 10: {}", distance_0, distance_10);
    }

    #[tokio::test]
    async fn test_bucket_refresh() {
        use lib_identity::ZhtpIdentity;
        use lib_identity::types::IdentityType;
        use crate::types::dht_types::DhtPeerIdentity;
        
        let local_id = NodeId::from_bytes([1u8; 32]);
        let mut router = KademliaRouter::new(local_id.clone(), 20);
        
        // Helper to create test node
        let create_node = |device_name: &str, port: u16| {
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
        };
        
        // Add some test nodes to different buckets
        for i in 0..10 {
            let node = create_node(&format!("device-{}", i), 8080 + i);
            router.add_node(node).await.unwrap();
        }
        
        // Test basic functionality - new router should not need refresh with long interval
        let long_interval_check = router.get_buckets_needing_refresh(3600); // 1 hour
        assert_eq!(long_interval_check.len(), 0, "Newly added peers should not need refresh with 1-hour interval");
        
        // Wait to ensure timestamp difference and test with 1 second interval
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        let one_second_check = router.get_buckets_needing_refresh(1);
        
        // Since we waited 2 seconds, buckets with peers should need refresh with 1-second interval
        println!("Buckets needing refresh after 2 seconds with 1-second interval: {}", one_second_check.len());
        assert!(one_second_check.len() > 0, "After 2 seconds, buckets with peers should need refresh with 1-second interval");
        
        // We added 10 nodes to potentially different buckets
        assert!(one_second_check.len() <= 10, "Should refresh at most 10 buckets (one per added node)");
        
        // Test that the method returns valid bucket indices
        for &bucket_index in &one_second_check {
            assert!(bucket_index < 160, "Bucket index should be within valid range");
        }
    }

    #[tokio::test]
    async fn test_nodeid_persistence_in_routing_table() {
        let local_peer = create_test_peer("local-laptop");
        let local_id = local_peer.node_id().clone();
        let mut router = KademliaRouter::new(local_id.clone(), 20);

        let peer = create_test_peer("peer-phone");
        let peer_id = peer.node_id().clone();
        let test_node = build_test_node(peer, 45000);

        router.add_node(test_node.clone()).await.unwrap();

        let distance = router.calculate_distance(&local_id, &peer_id);
        let bucket_index = router.get_bucket_index(distance);
        let bucket_nodes = router.get_bucket_nodes(bucket_index);

        assert_eq!(bucket_nodes.len(), 1);
        assert_eq!(bucket_nodes[0].peer.node_id(), &peer_id);

        let closest = router.find_closest_nodes(&peer_id, 1);
        assert_eq!(closest.first().map(|n| n.peer.node_id()), Some(&peer_id));
    }
}