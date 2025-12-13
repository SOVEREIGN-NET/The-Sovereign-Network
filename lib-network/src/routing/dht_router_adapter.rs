//! DHT Mesh Transport Adapter
//!
//! **Ticket #154:** Implements DhtTransport trait for mesh network routing.
//! This adapter enables DHT traffic to be routed through the mesh network
//! using public key addressing instead of raw socket addresses.

use anyhow::{Result, anyhow};
use std::sync::Arc;
use tokio::sync::RwLock;
use lib_crypto::PublicKey;
use lib_storage::dht::transport::{DhtTransport, PeerId};
use crate::routing::message_routing::MeshMessageRouter;
use crate::types::mesh_message::ZhtpMeshMessage;

/// Mesh-based DHT transport implementation
///
/// # Architecture (Ticket #154)
///
/// This transport implements `DhtTransport` (defined in lib-storage) using the
/// mesh network for message delivery. This allows DHT operations to benefit from:
/// - Multi-protocol transport selection (BLE, QUIC, WiFi, UDP)
/// - Automatic relay through intermediate nodes
/// - Public key-based addressing
///
/// Messages are wrapped in `ZhtpMeshMessage::DhtGenericPayload` and routed
/// through the mesh network.
pub struct MeshDhtTransport {
    mesh_router: Arc<RwLock<MeshMessageRouter>>,
    local_pubkey: PublicKey,
    /// Channel for receiving DHT messages from mesh
    receiver: Arc<RwLock<tokio::sync::mpsc::UnboundedReceiver<(Vec<u8>, PeerId)>>>,
}

impl MeshDhtTransport {
    /// Create a new mesh DHT transport
    ///
    /// # Arguments
    /// * `mesh_router` - The mesh message router for sending messages
    /// * `local_pubkey` - This node's public key
    ///
    /// # Returns
    /// Tuple of (transport, sender) - sender is used to inject received DHT messages
    pub fn new(
        mesh_router: Arc<RwLock<MeshMessageRouter>>,
        local_pubkey: PublicKey,
    ) -> (Self, tokio::sync::mpsc::UnboundedSender<(Vec<u8>, PeerId)>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let transport = Self {
            mesh_router,
            local_pubkey,
            receiver: Arc::new(RwLock::new(rx)),
        };
        (transport, tx)
    }

    /// Convert serialized DHT message to ZhtpMeshMessage envelope
    fn wrap_dht_payload(payload: Vec<u8>, requester: PublicKey) -> ZhtpMeshMessage {
        ZhtpMeshMessage::DhtGenericPayload {
            requester,
            payload,
        }
    }

    /// Extract PublicKey from mesh PeerId
    /// 
    /// # Security
    /// - Validates public key length (must be 32 bytes for ED25519)
    /// - Prevents malformed public keys from being used
    fn peer_id_to_pubkey(peer_id: &PeerId) -> Result<PublicKey> {
        match peer_id {
            PeerId::Mesh(key_bytes) => {
                // SECURITY FIX #2: Validate public key format
                // ED25519 public keys must be exactly 32 bytes
                if key_bytes.len() != 32 {
                    return Err(anyhow!(
                        "Invalid ED25519 public key length: {} bytes (expected 32)",
                        key_bytes.len()
                    ));
                }
                
                // Additional validation: Check for null bytes (should not be present in valid keys)
                if key_bytes.iter().any(|&byte| byte == 0) {
                    return Err(anyhow!(
                        "Invalid public key: contains null bytes"
                    ));
                }
                
                Ok(PublicKey::new(key_bytes.clone()))
            }
            _ => Err(anyhow!("MeshDhtTransport only accepts Mesh peer IDs, got: {:?}", peer_id)),
        }
    }
}

#[async_trait::async_trait]
impl DhtTransport for MeshDhtTransport {
    async fn send(&self, data: &[u8], peer: &PeerId) -> Result<()> {
        let destination = Self::peer_id_to_pubkey(peer)?;

        // Wrap the DHT message
        let mesh_message = Self::wrap_dht_payload(data.to_vec(), self.local_pubkey.clone());

        // Route through mesh network
        let router = self.mesh_router.read().await;
        router.route_message(mesh_message, destination, self.local_pubkey.clone()).await?;

        Ok(())
    }

    async fn receive(&self) -> Result<(Vec<u8>, PeerId)> {
        let mut receiver = self.receiver.write().await;
        if let Some((data, peer_id)) = receiver.recv().await {
            Ok((data, peer_id))
        } else {
            Err(anyhow!("Mesh DHT transport receiver closed"))
        }
    }

    fn local_peer_id(&self) -> PeerId {
        PeerId::Mesh(self.local_pubkey.key_id.to_vec())
    }

    async fn can_reach(&self, peer: &PeerId) -> bool {
        // Mesh transport can reach any mesh peer
        matches!(peer, PeerId::Mesh(_))
    }

    fn mtu(&self) -> usize {
        // Mesh network handles fragmentation, so we can accept large messages
        65536
    }

    fn typical_latency_ms(&self) -> u32 {
        // Variable based on route and underlying transport
        50
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_id_conversion() {
        let pubkey = PublicKey::new(vec![1, 2, 3, 4]);
        let peer_id = PeerId::Mesh(pubkey.key_id.clone());

        let result = MeshDhtTransport::peer_id_to_pubkey(&peer_id);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().key_id, pubkey.key_id);
    }

    #[test]
    fn test_invalid_peer_id_conversion() {
        let peer_id = PeerId::Udp("127.0.0.1:8080".parse().unwrap());
        let result = MeshDhtTransport::peer_id_to_pubkey(&peer_id);
        assert!(result.is_err());
    }
    
    /// Test public key validation - correct length
    #[test]
    fn test_valid_public_key() {
        let valid_key = vec![1u8; 32]; // 32 bytes = valid ED25519 key length
        let peer_id = PeerId::Mesh(valid_key.clone());
        let result = MeshDhtTransport::peer_id_to_pubkey(&peer_id);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().key_id, valid_key);
    }
    
    /// Test public key validation - wrong length (too short)
    #[test]
    fn test_invalid_public_key_too_short() {
        let short_key = vec![1u8; 16]; // Too short
        let peer_id = PeerId::Mesh(short_key);
        let result = MeshDhtTransport::peer_id_to_pubkey(&peer_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid ED25519 public key length"));
    }
    
    /// Test public key validation - wrong length (too long)
    #[test]
    fn test_invalid_public_key_too_long() {
        let long_key = vec![1u8; 64]; // Too long
        let peer_id = PeerId::Mesh(long_key);
        let result = MeshDhtTransport::peer_id_to_pubkey(&peer_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid ED25519 public key length"));
    }
    
    /// Test public key validation - contains null bytes
    #[test]
    fn test_invalid_public_key_with_null_bytes() {
        let mut key_with_nulls = vec![1u8; 32];
        key_with_nulls[15] = 0; // Add null byte
        let peer_id = PeerId::Mesh(key_with_nulls);
        let result = MeshDhtTransport::peer_id_to_pubkey(&peer_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("contains null bytes"));
    }
}
