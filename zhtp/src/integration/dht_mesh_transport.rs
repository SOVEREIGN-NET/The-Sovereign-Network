//! Mesh-based DHT network transport.
//!
//! Implements `DhtNetworkTransport` using the QUIC mesh to send DHT store
//! requests to peers. Remote content queries are not yet supported (requires
//! a request/response channel wired through DhtFindValueResponse).

use anyhow::Result;
use async_trait::async_trait;
use lib_network::dht::integration::{DhtNetworkTransport, DhtPeerInfo};
use lib_network::types::mesh_message::ZhtpMeshMessage;
use std::sync::Arc;
use tracing::debug;

use crate::unified_server::MeshRouter;

/// DHT network transport over QUIC mesh.
pub struct MeshDhtNetworkTransport {
    mesh_router: Arc<MeshRouter>,
    /// Local node's public key for populating DhtStore requester field.
    local_node_key_id: [u8; 32],
}

impl MeshDhtNetworkTransport {
    pub fn new(mesh_router: Arc<MeshRouter>, local_node_key_id: [u8; 32]) -> Self {
        Self {
            mesh_router,
            local_node_key_id,
        }
    }
}

#[async_trait]
impl DhtNetworkTransport for MeshDhtNetworkTransport {
    async fn send_store(
        &self,
        peer: &DhtPeerInfo,
        key: &str,
        value: &[u8],
        ttl_secs: u64,
    ) -> Result<()> {
        let quic_guard = self.mesh_router.quic_protocol.read().await;
        let quic = match quic_guard.as_ref() {
            Some(q) => q,
            None => return Err(anyhow::anyhow!("QUIC protocol not available for DHT store")),
        };

        // Use local node's key_id as requester so the receiver can route ACKs
        // and verify the signature. QUIC+UHP provides transport-layer auth.
        let msg = ZhtpMeshMessage::DhtStore {
            requester: lib_crypto::PublicKey {
                dilithium_pk: Vec::new(),
                kyber_pk: Vec::new(),
                key_id: self.local_node_key_id,
            },
            request_id: rand::random(),
            key: key.as_bytes().to_vec(),
            value: value.to_vec(),
            ttl: ttl_secs,
            signature: Vec::new(), // Transport-layer auth via QUIC+UHP
        };

        quic.send_to_peer(&peer.node_id, msg).await?;
        debug!("DHT store sent to peer {:?}", &peer.node_id[..4]);
        Ok(())
    }

    async fn query_content(&self, _peer: &DhtPeerInfo, _key: &str) -> Result<Option<Vec<u8>>> {
        // Remote content queries require a request/response channel wired through
        // DhtFindValueResponse in the message handler. Until that's implemented,
        // return None so fetch_content only checks local storage + replication.
        Ok(None)
    }
}
