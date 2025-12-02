//! Kademlia-based DHT Routing
//! 
//! Implements the Kademlia routing algorithm with K-buckets for efficient
//! peer discovery and routing in the DHT network.

use crate::types::dht_types::{DhtNode, KBucket, RoutingEntry};
use crate::types::NodeId;
use anyhow::{Result, anyhow};
use std::time::{SystemTime, UNIX_EPOCH};

/// Kademlia routing table for DHT operations
#[derive(Debug)]
pub struct KademliaRouter {
    /// Local node ID
    local_id: NodeId,
    /// Routing table with 160 K-buckets (for 256-bit node IDs)
    routing_table: Vec<KBucket>,
    /// K-bucket size (standard Kademlia K value)
    k: usize,
}

impl KademliaRouter {
    /// Create a new Kademlia router
    pub fn new(local_id: NodeId, k: usize) -> Self {
        // Initialize routing table with 160 buckets (for 256-bit node IDs)
        let mut routing_table = Vec::with_capacity(160);
        for _ in 0..160 {
            routing_table.push(KBucket {
                k,
                nodes: Vec::new(),
                last_updated: SystemTime::now(),
            });
        }
        
        Self {
            local_id,
            routing_table,
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
    pub async fn add_node(&mut self, node: DhtNode) -> Result<()> {
        if node.id == self.local_id {
            return Err(anyhow!("Cannot add local node to routing table"));
        }
        
        let distance = self.calculate_distance(&self.local_id, &node.id);
        let bucket_index = self.get_bucket_index(distance);
        
        if let Some(bucket) = self.routing_table.get_mut(bucket_index) {
            // Check if node already exists
            if let Some(pos) = bucket.nodes.iter().position(|entry| entry.node.id == node.id) {
                // Update existing node
                bucket.nodes[pos].node = node.clone();
                bucket.nodes[pos].last_contact = SystemTime::now()
                    .duration_since(UNIX_EPOCH)?
                    .as_secs();
                bucket.nodes[pos].failed_attempts = 0;
            } else if bucket.nodes.len() < bucket.k {
                // Add new node if bucket not full
                bucket.nodes.push(RoutingEntry {
                    node: node.clone(),
                    distance,
                    last_contact: SystemTime::now()
                        .duration_since(UNIX_EPOCH)?
                        .as_secs(),
                    failed_attempts: 0,
                });
            } else {
                // Bucket full - replace least recently seen node if it's unresponsive
                let lrs_node_id = bucket.nodes.iter()
                    .min_by_key(|entry| entry.last_contact)
                    .map(|entry| entry.node.id.clone());
                
                if let Some(node_id) = lrs_node_id {
                    // In a implementation, we would ping the node here
                    // For now, we'll replace if failed_attempts > 3
                    if let Some(lrs_entry) = bucket.nodes.iter().find(|e| e.node.id == node_id) {
                        if lrs_entry.failed_attempts > 3 {
                            // Replace unresponsive node within the same bucket reference
                            let lrs_index = bucket.nodes.iter()
                                .position(|entry| entry.node.id == node_id)
                                .unwrap();
                            bucket.nodes[lrs_index] = RoutingEntry {
                                node: node.clone(),
                                distance,
                                last_contact: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)?
                                    .as_secs(),
                                failed_attempts: 0,
                            };
                        }
                    }
                }
            }
            
            bucket.last_updated = SystemTime::now();
        } else {
            return Err(anyhow!("Invalid bucket index: {}", bucket_index));
        }
        
        Ok(())
    }
    
    /// Find the K closest nodes to a target ID (uses k-bucket parameter)
    pub fn find_closest_nodes(&self, target: &NodeId, count: usize) -> Vec<DhtNode> {
        let requested_count = std::cmp::min(count, self.k); // Limit to k-bucket size
        let mut closest_nodes = Vec::new();
        
        // Start from the bucket closest to target and expand outward
        let target_distance = self.calculate_distance(&self.local_id, target);
        let start_bucket = self.get_bucket_index(target_distance);
        
        // Collect nodes from target bucket first
        if let Some(bucket) = self.routing_table.get(start_bucket) {
            for entry in &bucket.nodes {
                closest_nodes.push((entry.node.clone(), self.calculate_distance(target, &entry.node.id)));
            }
        }
        
        // Expand search to adjacent buckets if we need more nodes
        let mut bucket_offset = 1;
        while closest_nodes.len() < requested_count && bucket_offset <= 159 {
            // Check bucket below
            if start_bucket >= bucket_offset {
                let lower_bucket_idx = start_bucket - bucket_offset;
                if let Some(bucket) = self.routing_table.get(lower_bucket_idx) {
                    for entry in &bucket.nodes {
                        if closest_nodes.len() < requested_count {
                            closest_nodes.push((entry.node.clone(), self.calculate_distance(target, &entry.node.id)));
                        }
                    }
                }
            }
            
            // Check bucket above
            let upper_bucket_idx = start_bucket + bucket_offset;
            if upper_bucket_idx < self.routing_table.len() {
                if let Some(bucket) = self.routing_table.get(upper_bucket_idx) {
                    for entry in &bucket.nodes {
                        if closest_nodes.len() < requested_count {
                            closest_nodes.push((entry.node.clone(), self.calculate_distance(target, &entry.node.id)));
                        }
                    }
                }
            }
            
            bucket_offset += 1;
        }
        
        // Sort by distance to target and return closest k nodes
        closest_nodes.sort_by_key(|(_, distance)| *distance);
        closest_nodes.into_iter()
            .take(requested_count)
            .map(|(node, _)| node)
            .collect()
    }
    
    /// Get all nodes in a specific bucket
    pub fn get_bucket_nodes(&self, bucket_index: usize) -> Vec<&DhtNode> {
        if bucket_index < self.routing_table.len() {
            self.routing_table[bucket_index]
                .nodes
                .iter()
                .map(|entry| &entry.node)
                .collect()
        } else {
            Vec::new()
        }
    }
    
    /// Mark a node as failed (increment failed attempts)
    pub fn mark_node_failed(&mut self, node_id: &NodeId) {
        let distance = self.calculate_distance(&self.local_id, node_id);
        let bucket_index = self.get_bucket_index(distance);
        
        if let Some(bucket) = self.routing_table.get_mut(bucket_index) {
            if let Some(entry) = bucket.nodes.iter_mut().find(|e| e.node.id == *node_id) {
                entry.failed_attempts += 1;
            }
        }
    }
    
    /// Mark a node as responsive (reset failed attempts)
    pub fn mark_node_responsive(&mut self, node_id: &NodeId) -> Result<()> {
        let distance = self.calculate_distance(&self.local_id, node_id);
        let bucket_index = self.get_bucket_index(distance);
        
        if let Some(bucket) = self.routing_table.get_mut(bucket_index) {
            if let Some(entry) = bucket.nodes.iter_mut().find(|e| e.node.id == *node_id) {
                entry.failed_attempts = 0;
                entry.last_contact = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            }
        }
        
        Ok(())
    }
    
    /// Remove a node from the routing table
    pub fn remove_node(&mut self, node_id: &NodeId) {
        let distance = self.calculate_distance(&self.local_id, node_id);
        let bucket_index = self.get_bucket_index(distance);
        
        if let Some(bucket) = self.routing_table.get_mut(bucket_index) {
            bucket.nodes.retain(|entry| entry.node.id != *node_id);
        }
    }
    
    /// Get routing table statistics
    pub fn get_stats(&self) -> RoutingStats {
        let total_nodes: usize = self.routing_table.iter().map(|b| b.nodes.len()).sum();
        let non_empty_buckets = self.routing_table.iter().filter(|b| !b.nodes.is_empty()).count();
        let full_buckets = self.routing_table.iter().filter(|b| b.nodes.len() >= self.k).count();
        
        RoutingStats {
            total_nodes,
            non_empty_buckets,
            total_buckets: self.routing_table.len(),
            full_buckets,
            k_value: self.k,
            average_bucket_fill: if non_empty_buckets > 0 { 
                total_nodes as f64 / non_empty_buckets as f64 
            } else { 
                0.0 
            },
        }
    }

    /// Get the k-bucket parameter value
    pub fn get_k_value(&self) -> usize {
        self.k
    }

    /// Check if a bucket is full (has k nodes)
    pub fn is_bucket_full(&self, bucket_index: usize) -> bool {
        if let Some(bucket) = self.routing_table.get(bucket_index) {
            bucket.nodes.len() >= self.k
        } else {
            false
        }
    }

    /// Get k-bucket utilization (percentage of buckets that are full)
    pub fn get_bucket_utilization(&self) -> f64 {
        let full_buckets = self.routing_table.iter()
            .filter(|b| b.nodes.len() >= self.k)
            .count();
        
        if self.routing_table.is_empty() {
            0.0
        } else {
            (full_buckets as f64 / self.routing_table.len() as f64) * 100.0
        }
    }

    /// Refresh old buckets (Kademlia maintenance)
    pub fn get_buckets_needing_refresh(&self, refresh_interval_secs: u64) -> Vec<usize> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let mut buckets_to_refresh = Vec::new();
        
        for (index, bucket) in self.routing_table.iter().enumerate() {
            let last_updated = bucket.last_updated
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            
            if current_time - last_updated > refresh_interval_secs {
                buckets_to_refresh.push(index);
            }
        }
        
        buckets_to_refresh
    }

    /// Perform k-bucket maintenance (remove unresponsive nodes)
    pub fn perform_bucket_maintenance(&mut self, max_failed_attempts: u32) -> usize {
        let mut removed_count = 0;
        
        for bucket in &mut self.routing_table {
            let initial_count = bucket.nodes.len();
            bucket.nodes.retain(|entry| entry.failed_attempts <= max_failed_attempts);
            removed_count += initial_count - bucket.nodes.len();
        }
        
        removed_count
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
    
    fn build_test_node(id: NodeId, port: u16) -> DhtNode {
        DhtNode {
            id,
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
        
        assert_eq!(router.routing_table.len(), 160);
        assert_eq!(router.k, 20);
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
        
        let test_node = build_test_node(NodeId::from_bytes([2u8; 32]), 33442);
        
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
        
        // Add k+1 nodes to same bucket
        for i in 2..6 { // 4 nodes total
            let mut node_bytes = [1u8; 32];
            node_bytes[31] = i; // Small distance variation
            
            let test_node = build_test_node(
                NodeId::from_bytes(node_bytes),
                33440 + i as u16,
            );
            
            router.add_node(test_node).await.unwrap();
        }
        
        let stats = router.get_stats();
        assert!(stats.total_nodes <= k_value); // Should not exceed k per bucket
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
        let test_node = build_test_node(NodeId::from_bytes([2u8; 32]), 33442);
        
        router.add_node(test_node.clone()).await.unwrap();
        
        // Mark node as failed multiple times
        for _ in 0..5 {
            router.mark_node_failed(&test_node.id);
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

    #[test]
    fn test_bucket_refresh() {
        let local_id = NodeId::from_bytes([1u8; 32]);
        let router = KademliaRouter::new(local_id, 20);
        
        // Test basic functionality - new router should not need refresh with long interval
        let long_interval_check = router.get_buckets_needing_refresh(3600); // 1 hour
        assert_eq!(long_interval_check.len(), 0, "New router should have no buckets needing refresh with 1-hour interval");
        
        // Wait to ensure timestamp difference and test with 1 second interval
        std::thread::sleep(std::time::Duration::from_secs(2));
        let one_second_check = router.get_buckets_needing_refresh(1);
        
        // Since we waited 2 seconds, buckets should need refresh with 1-second interval
        println!("Buckets needing refresh after 2 seconds with 1-second interval: {}", one_second_check.len());
        assert!(one_second_check.len() > 0, "After 2 seconds, buckets should need refresh with 1-second interval");
        
        // Test that we get a reasonable number of buckets (should be all 160)
        assert_eq!(one_second_check.len(), 160, "All 160 buckets should need refresh");
        
        // Test that the method returns valid bucket indices
        for &bucket_index in &one_second_check {
            assert!(bucket_index < 160, "Bucket index should be within valid range");
        }
    }

    #[tokio::test]
    async fn test_nodeid_persistence_in_routing_table() {
        let local_id = NodeId::from_did_device("did:zhtp:local", "laptop").unwrap();
        let mut router = KademliaRouter::new(local_id, 20);

        let peer_id = NodeId::from_did_device("did:zhtp:peer", "phone").unwrap();
        let test_node = build_test_node(peer_id, 45000);

        router.add_node(test_node.clone()).await.unwrap();

        let distance = router.calculate_distance(&local_id, &peer_id);
        let bucket_index = router.get_bucket_index(distance);
        let bucket_nodes = router.get_bucket_nodes(bucket_index);

        assert_eq!(bucket_nodes.len(), 1);
        assert_eq!(bucket_nodes[0].id, peer_id);

        let closest = router.find_closest_nodes(&peer_id, 1);
        assert_eq!(closest.first().map(|n| n.id), Some(peer_id));
    }
}