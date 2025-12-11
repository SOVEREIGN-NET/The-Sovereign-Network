//! DHT Router Adapter for MeshMessageRouter
//!
//! **Ticket #154:** Implements lib-storage's DhtMessageRouter trait for MeshMessageRouter.
//! This adapter breaks the circular dependency between lib-storage and lib-network.

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use lib_crypto::PublicKey;
use crate::routing::message_routing::MeshMessageRouter;
use crate::types::mesh_message::ZhtpMeshMessage;

/// Adapter that implements DhtMessageRouter for MeshMessageRouter
/// 
/// # Architecture
/// 
/// lib-storage defines the DhtMessageRouter trait without depending on lib-network.
/// This adapter implements that trait, allowing mesh routing for DHT traffic.
pub struct MeshDhtRouterAdapter {
    mesh_router: Arc<RwLock<MeshMessageRouter>>,
}

impl MeshDhtRouterAdapter {
    /// Create a new adapter wrapping a MeshMessageRouter
    pub fn new(mesh_router: Arc<RwLock<MeshMessageRouter>>) -> Self {
        Self { mesh_router }
    }
    
    /// Convert serialized DHT message to ZhtpMeshMessage envelope
    /// 
    /// DHT messages are sent as raw payloads wrapped in generic mesh envelopes.
    /// The mesh layer handles routing, relay, and transport selection.
    fn wrap_dht_payload(payload: Vec<u8>, requester: PublicKey) -> ZhtpMeshMessage {
        // Use generic payload wrapper for DHT messages
        // The receiving node will deserialize based on context
        ZhtpMeshMessage::DhtGenericPayload {
            requester,
            payload,
        }
    }
}

#[async_trait::async_trait]
impl lib_storage::dht::network::DhtMessageRouter for MeshDhtRouterAdapter {
    async fn route_dht_message(
        &self,
        message: Vec<u8>,
        destination: &PublicKey,
        sender: &PublicKey,
    ) -> Result<u64> {
        // Wrap the serialized DHT message
        let mesh_message = Self::wrap_dht_payload(message, sender.clone());
        
        // Route through mesh network
        let router = self.mesh_router.read().await;
        router.route_message(mesh_message, destination.clone(), sender.clone()).await
    }
}
