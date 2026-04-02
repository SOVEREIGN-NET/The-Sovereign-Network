//! Mesh-based DHT network transport.
//!
//! Implements `DhtNetworkTransport` using the QUIC mesh to send DHT store
//! requests and content queries to peers.

use anyhow::Result;
use async_trait::async_trait;
use lib_network::dht::integration::{DhtNetworkTransport, DhtPeerInfo};
use lib_network::types::mesh_message::ZhtpMeshMessage;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::unified_server::MeshRouter;

/// DHT network transport over QUIC mesh.
pub struct MeshDhtNetworkTransport {
    mesh_router: Arc<MeshRouter>,
}

impl MeshDhtNetworkTransport {
    pub fn new(mesh_router: Arc<MeshRouter>) -> Self {
        Self { mesh_router }
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

        let msg = ZhtpMeshMessage::DhtStore {
            requester: lib_crypto::PublicKey {
                dilithium_pk: Vec::new(),
                kyber_pk: Vec::new(),
                key_id: peer.node_id,
            },
            request_id: rand::random(),
            key: key.as_bytes().to_vec(),
            value: value.to_vec(),
            ttl: ttl_secs,
            signature: Vec::new(), // Signed at transport layer by QUIC+UHP
        };

        quic.send_to_peer(&peer.node_id, msg).await?;
        debug!("DHT store sent to peer {:?}", &peer.node_id[..4]);
        Ok(())
    }

    async fn query_content(&self, peer: &DhtPeerInfo, key: &str) -> Result<Option<Vec<u8>>> {
        let quic_guard = self.mesh_router.quic_protocol.read().await;
        let quic = match quic_guard.as_ref() {
            Some(q) => q,
            None => return Err(anyhow::anyhow!("QUIC protocol not available for DHT query")),
        };

        let msg = ZhtpMeshMessage::DhtFindValue {
            requester: lib_crypto::PublicKey {
                dilithium_pk: Vec::new(),
                kyber_pk: Vec::new(),
                key_id: peer.node_id,
            },
            request_id: rand::random(),
            key: key.as_bytes().to_vec(),
            max_hops: 3,
        };

        // Send the query — response will come back asynchronously via message handler.
        // For now this is fire-and-forget; a full implementation would use a response
        // channel with timeout. The content will be cached when the DhtFindValueResponse
        // arrives via the message handler.
        match quic.send_to_peer(&peer.node_id, msg).await {
            Ok(()) => {
                debug!("DHT query sent to peer {:?} for key {}", &peer.node_id[..4], key);
            }
            Err(e) => {
                warn!("DHT query to peer {:?} failed: {}", &peer.node_id[..4], e);
            }
        }

        // Async response not yet wired — returns None.
        // Content arrives via DhtFindValueResponse in the message handler.
        Ok(None)
    }
}
