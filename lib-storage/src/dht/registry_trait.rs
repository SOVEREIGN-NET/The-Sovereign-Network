//! DHT Registry Trait (Ticket #1.14)
//!
//! Defines the minimal interface needed by KademliaRouter to interact with
//! a peer registry. This avoids circular dependency with lib-network while
//! enabling DHT to use the unified PeerRegistry.
//!
//! lib-network::PeerRegistry implements this trait, and zhtp injects it into
//! the DHT layer at runtime.

use crate::types::dht_types::DhtNode;
use crate::types::NodeId;
use anyhow::Result;
use async_trait::async_trait;

/// Minimal DHT peer registry interface
///
/// This trait defines only the operations that KademliaRouter needs from a
/// peer registry. lib-network::PeerRegistry implements this trait.
///
/// # Design Rationale
///
/// We cannot have lib-storage depend on lib-network (circular dependency).
/// By defining this trait in lib-storage, we enable dependency injection:
/// - lib-storage defines the interface it needs
/// - lib-network implements the interface
/// - zhtp wires them together at runtime
#[async_trait]
pub trait DhtPeerRegistryTrait: Send + Sync {
    /// Add or update a DHT peer
    ///
    /// Maps to lib-network::PeerRegistry::upsert() with DHT-specific metadata
    async fn add_dht_peer(&mut self, node: &DhtNode, bucket_index: usize, distance: u32) -> Result<()>;
    
    /// Find closest peers to a target NodeId
    ///
    /// Maps to lib-network::PeerRegistry::find_peers_for_dht()
    async fn find_closest_dht_peers(&self, target: &NodeId, count: usize) -> Result<Vec<DhtNode>>;
    
    /// Get peers in a specific K-bucket
    ///
    /// Maps to lib-network::PeerRegistry::get_dht_bucket()
    async fn get_dht_bucket_peers(&self, bucket_index: usize) -> Result<Vec<DhtNode>>;
    
    /// Mark a peer as failed (increment failed attempts)
    ///
    /// Maps to lib-network::PeerRegistry::record_dht_failure()
    async fn mark_dht_peer_failed(&mut self, node_id: &NodeId) -> Result<()>;
    
    /// Mark a peer as responsive (reset failed attempts, update last_contact)
    ///
    /// Maps to lib-network::PeerRegistry::record_dht_success()
    async fn mark_dht_peer_responsive(&mut self, node_id: &NodeId) -> Result<()>;
    
    /// Check if a K-bucket is full
    ///
    /// Maps to lib-network::PeerRegistry::is_dht_bucket_full()
    async fn is_dht_bucket_full(&self, bucket_index: usize, k: usize) -> Result<bool>;
    
    /// Remove a peer from the registry
    ///
    /// Maps to lib-network::PeerRegistry::remove()
    async fn remove_dht_peer(&mut self, node_id: &NodeId) -> Result<()>;
}
