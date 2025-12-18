//! DHT Trait Implementation for Unified PeerRegistry (Ticket #1.14)
//!
//! This module implements the `DhtPeerRegistryTrait` from lib-storage for the
//! unified `PeerRegistry`, enabling the DHT layer to use the same peer storage
//! as the mesh layer.

use crate::peer_registry::{PeerRegistry, PeerEntry, DhtPeerInfo, UnifiedPeerId};
use crate::peer_registry::types::*;
use lib_storage::dht::DhtPeerRegistryTrait;
use lib_storage::types::dht_types::DhtNode;
use lib_storage::types::NodeId;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use std::time::{SystemTime, UNIX_EPOCH};

#[async_trait]
impl DhtPeerRegistryTrait for PeerRegistry {
    /// Add or update a DHT peer
    async fn add_dht_peer(&mut self, node: &DhtNode, bucket_index: usize, distance: u32) -> Result<()> {
        // Convert DhtNode to UnifiedPeerId
        let peer_id = UnifiedPeerId {
            node_id: node.peer.node_id().clone(),
            public_key: node.peer.public_key().clone(),
            did: node.peer.did().to_string(),
            device_id: node.peer.device_id().to_string(),
        };

        // Check if peer already exists
        if let Some(existing) = self.find_by_node_id(&peer_id.node_id) {
            // Update existing peer's DHT info
            let dht_info = DhtPeerInfo {
                kademlia_distance: distance,
                bucket_index,
                last_contact: Self::current_timestamp(),
                failed_attempts: 0,
            };
            self.update_dht_info(existing, dht_info)?;
            return Ok(());
        }

        // Create new peer entry
        let dht_info = DhtPeerInfo {
            kademlia_distance: distance,
            bucket_index,
            last_contact: Self::current_timestamp(),
            failed_attempts: 0,
        };

        // Convert DhtNode addresses to PeerEndpoints
        let endpoints: Vec<PeerEndpoint> = node.addresses.iter()
            .filter_map(|addr| {
                // Parse address string (assumes format like "udp://127.0.0.1:8080")
                if let Some(socket_addr) = addr.strip_prefix("udp://") {
                    socket_addr.parse().ok().map(|sa| PeerEndpoint {
                        protocol: NetworkProtocol::Udp,
                        address: sa,
                        last_seen: Self::current_timestamp(),
                        failures: 0,
                    })
                } else {
                    None
                }
            })
            .collect();

        let entry = PeerEntry::new(
            peer_id.clone(),
            endpoints,
            vec![NetworkProtocol::Udp],
            ConnectionMetrics::default(),
            false, // authenticated
            false, // quantum_secure
            None,  // next_hop
            0,     // hop_count
            0.5,   // route_quality
            NodeCapabilities::default(),
            None,  // location
            0.5,   // reliability_score
            Some(dht_info),
            DiscoveryMethod::Dht,
            Self::current_timestamp(),
            Self::current_timestamp(),
            PeerTier::Tier3,
            0.5,   // trust_score
        );

        self.upsert(entry).await
    }

    /// Find closest peers to a target NodeId
    async fn find_closest_dht_peers(&self, target: &NodeId, count: usize) -> Result<Vec<DhtNode>> {
        let mut peers_with_distance: Vec<(u32, &PeerEntry)> = self.dht_peers()
            .map(|entry| {
                let distance = entry.peer_id.node_id.kademlia_distance(target);
                (distance, entry)
            })
            .collect();

        // Sort by distance (closest first)
        peers_with_distance.sort_by_key(|(distance, _)| *distance);

        // Take top N and convert to DhtNode
        let dht_nodes: Vec<DhtNode> = peers_with_distance
            .into_iter()
            .take(count)
            .filter_map(|(_, entry)| peer_entry_to_dht_node(entry).ok())
            .collect();

        Ok(dht_nodes)
    }

    /// Get peers in a specific K-bucket
    async fn get_dht_bucket_peers(&self, bucket_index: usize) -> Result<Vec<DhtNode>> {
        let dht_nodes: Vec<DhtNode> = self.dht_peers()
            .filter(|entry| {
                entry.dht_info.as_ref()
                    .map(|info| info.bucket_index == bucket_index)
                    .unwrap_or(false)
            })
            .filter_map(|entry| peer_entry_to_dht_node(entry).ok())
            .collect();

        Ok(dht_nodes)
    }

    /// Mark a peer as failed
    async fn mark_dht_peer_failed(&mut self, node_id: &NodeId) -> Result<()> {
        self.mark_dht_peer_failed(node_id)
    }

    /// Mark a peer as responsive
    async fn mark_dht_peer_responsive(&mut self, node_id: &NodeId) -> Result<()> {
        self.mark_dht_peer_responsive(node_id)
    }

    /// Check if a K-bucket is full
    async fn is_dht_bucket_full(&self, bucket_index: usize, k: usize) -> Result<bool> {
        let bucket_size = self.dht_peers()
            .filter(|entry| {
                entry.dht_info.as_ref()
                    .map(|info| info.bucket_index == bucket_index)
                    .unwrap_or(false)
            })
            .count();

        Ok(bucket_size >= k)
    }

    /// Remove a peer from the registry
    async fn remove_dht_peer(&mut self, node_id: &NodeId) -> Result<()> {
        if let Some(peer_id) = self.find_by_node_id(node_id) {
            self.remove(peer_id).await;
            Ok(())
        } else {
            Err(anyhow!("Peer with NodeId not found"))
        }
    }
}

/// Convert PeerEntry to DhtNode
fn peer_entry_to_dht_node(entry: &PeerEntry) -> Result<DhtNode> {
    use lib_storage::types::dht_types::DhtPeerIdentity;
    use lib_crypto::PostQuantumSignature;

    // Convert addresses
    let addresses: Vec<String> = entry.endpoints.iter()
        .map(|ep| format!("{}://{}", 
            match ep.protocol {
                NetworkProtocol::Udp => "udp",
                NetworkProtocol::Tcp => "tcp",
                NetworkProtocol::Quic => "quic",
                _ => "unknown",
            },
            ep.address
        ))
        .collect();

    let peer_identity = DhtPeerIdentity {
        node_id: entry.peer_id.node_id.clone(),
        public_key: entry.peer_id.public_key.clone(),
        did: entry.peer_id.did.clone(),
        device_id: entry.peer_id.device_id.clone(),
    };

    Ok(DhtNode {
        peer: peer_identity,
        addresses,
        public_key: PostQuantumSignature {
            algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
            signature: vec![],
            public_key: entry.peer_id.public_key.clone(),
        },
        last_seen: entry.last_seen,
        reputation: (entry.trust_score * 100.0) as u32,
        storage_info: None, // TODO: Map from capabilities if available
    })
}
