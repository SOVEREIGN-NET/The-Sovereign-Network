use anyhow::{anyhow, Result};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::identity::unified_peer::UnifiedPeerId;
use crate::peer_registry::PeerEndpoint;
use crate::protocols::NetworkProtocol;
use crate::protocols::bluetooth::classic::BluetoothClassicProtocol;
use crate::protocols::lorawan::LoRaWANMeshProtocol;
use crate::protocols::quic_mesh::QuicMeshProtocol;
use crate::protocols::wifi_direct::WiFiDirectMeshProtocol;
use crate::types::mesh_message::ZhtpMeshMessage;

/// Capabilities for a transport link
#[derive(Debug, Clone)]
pub struct LinkCaps {
    pub secure: bool,
    pub mtu: u32,
    pub max_frame: u32,
    pub latency_ms: u32,
}

/// Minimal link state for a peer
#[derive(Debug, Clone)]
pub struct LinkState {
    pub peer: UnifiedPeerId,
    pub available: Vec<(NetworkProtocol, LinkCaps)>,
}

/// Thin TransportManager that validates handler availability and enforces no-downgrade
#[derive(Clone, Default)]
pub struct TransportManager {
    bluetooth: Option<Arc<RwLock<BluetoothClassicProtocol>>>,
    wifi: Option<Arc<RwLock<WiFiDirectMeshProtocol>>>,
    lora: Option<Arc<RwLock<LoRaWANMeshProtocol>>>,
    quic: Option<Arc<RwLock<QuicMeshProtocol>>>,
}

impl TransportManager {
    pub fn with_bluetooth(mut self, handler: Arc<RwLock<BluetoothClassicProtocol>>) -> Self {
        self.bluetooth = Some(handler);
        self
    }

    pub fn with_wifi(mut self, handler: Arc<RwLock<WiFiDirectMeshProtocol>>) -> Self {
        self.wifi = Some(handler);
        self
    }

    pub fn with_lora(mut self, handler: Arc<RwLock<LoRaWANMeshProtocol>>) -> Self {
        self.lora = Some(handler);
        self
    }

    pub fn with_quic(mut self, handler: Arc<RwLock<QuicMeshProtocol>>) -> Self {
        self.quic = Some(handler);
        self
    }

    /// Send a message over a chosen transport, enforcing secure/handler availability
    pub async fn send(
        &self,
        protocol: &NetworkProtocol,
        endpoint: &PeerEndpoint,
        peer: &UnifiedPeerId,
        message: &ZhtpMeshMessage,
        serialized: &[u8],
    ) -> Result<()> {
        match protocol {
            NetworkProtocol::BluetoothClassic | NetworkProtocol::BluetoothLE => {
                let handler = self
                    .bluetooth
                    .as_ref()
                    .ok_or_else(|| anyhow!("Bluetooth handler not available"))?;
                handler
                    .read()
                    .await
                    .send_mesh_message(&endpoint.address, serialized)
                    .await
            }
            NetworkProtocol::WiFiDirect => {
                let handler = self
                    .wifi
                    .as_ref()
                    .ok_or_else(|| anyhow!("WiFi Direct handler not available"))?;
                handler
                    .read()
                    .await
                    .send_mesh_message(&endpoint.address, serialized)
                    .await
            }
            NetworkProtocol::LoRaWAN => {
                let handler = self
                    .lora
                    .as_ref()
                    .ok_or_else(|| anyhow!("LoRaWAN handler not available"))?;
                handler
                    .read()
                    .await
                    .send_mesh_message(&endpoint.address, serialized)
                    .await
            }
            NetworkProtocol::QUIC => {
                let handler = self
                    .quic
                    .as_ref()
                    .ok_or_else(|| anyhow!("QUIC handler not available"))?;
                handler
                    .read()
                    .await
                    .send_to_peer(peer.node_id().as_bytes(), message.clone())
                    .await
            }
            NetworkProtocol::TCP | NetworkProtocol::UDP => Err(anyhow!(
                "Transport downgrade blocked for peer {}",
                peer.to_compact_string()
            )),
            NetworkProtocol::Satellite => Err(anyhow!(
                "Satellite transport not handled by TransportManager"
            )),
        }
    }
}
