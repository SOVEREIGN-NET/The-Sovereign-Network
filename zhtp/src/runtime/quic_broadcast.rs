//! Global QUIC broadcast for peer endpoint gossip.
//!
//! Provides a way for peer_endpoints to broadcast PeerEndpointAnnounce
//! messages to all connected mesh peers via the QuicMeshProtocol.

use lib_network::protocols::quic_mesh::QuicMeshProtocol;
use lib_network::types::mesh_message::ZhtpMeshMessage;
use std::sync::Arc;
use tokio::sync::RwLock;

static QUIC_PROTOCOL: std::sync::OnceLock<Arc<QuicMeshProtocol>> = std::sync::OnceLock::new();

/// Set the global QUIC protocol reference (called during unified server init).
pub fn set_global_quic_protocol(quic: Arc<QuicMeshProtocol>) {
    let _ = QUIC_PROTOCOL.set(quic);
}

/// Broadcast a PeerEndpointAnnounce to all connected mesh peers.
pub async fn broadcast_peer_endpoint(did: &str, addr: &str) {
    let quic = match QUIC_PROTOCOL.get() {
        Some(q) => q,
        None => return,
    };

    let msg = ZhtpMeshMessage::PeerEndpointAnnounce {
        did: did.to_string(),
        addr: addr.to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    let mut sent = 0;
    for peer_id in quic.connected_peer_ids() {
        if quic.send_to_peer(&peer_id, msg.clone()).await.is_ok() {
            sent += 1;
        }
    }
    if sent > 0 {
        tracing::info!(
            "📡 Gossiped peer endpoint to {} peers: {} @ {}",
            sent, &did[..20.min(did.len())], addr
        );
    }
}
