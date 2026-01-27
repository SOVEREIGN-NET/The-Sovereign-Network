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
use crate::types::node_address::NodeAddress;

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
    /// QUIC handler is stored directly as Arc (Issue #167)
    /// QuicMeshProtocol doesn't implement Clone, so we can't wrap it in RwLock.
    /// It's safe to store as Arc<QuicMeshProtocol> because it's shared globally (Issue #907).
    quic: Option<Arc<QuicMeshProtocol>>,
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

    /// Set QUIC handler (stored as Arc<QuicMeshProtocol> - see struct comment)
    pub fn with_quic(mut self, handler: Arc<QuicMeshProtocol>) -> Self {
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
                
                // Extract Bluetooth address string from NodeAddress
                let addr_str = match &endpoint.address {
                    NodeAddress::BluetoothClassic(addr) | NodeAddress::BluetoothLE(addr) => addr.as_str(),
                    _ => return Err(anyhow!("Invalid address type for Bluetooth protocol")),
                };
                
                handler
                    .read()
                    .await
                    .send_mesh_message(addr_str, serialized)
                    .await
            }
            NetworkProtocol::WiFiDirect => {
                let handler = self
                    .wifi
                    .as_ref()
                    .ok_or_else(|| anyhow!("WiFi Direct handler not available"))?;
                
                // Extract WiFi Direct address string from NodeAddress
                let addr_str = match &endpoint.address {
                    NodeAddress::WiFiDirect { addr, .. } => addr.to_string(),
                    _ => return Err(anyhow!("Invalid address type for WiFi Direct protocol")),
                };
                
                handler
                    .read()
                    .await
                    .send_mesh_message(&addr_str, serialized)
                    .await
            }
            NetworkProtocol::LoRaWAN => {
                let handler = self
                    .lora
                    .as_ref()
                    .ok_or_else(|| anyhow!("LoRaWAN handler not available"))?;
                
                // Extract LoRaWAN address string from NodeAddress
                let addr_str = match &endpoint.address {
                    NodeAddress::LoRaWAN { dev_addr, .. } => dev_addr.as_str(),
                    _ => return Err(anyhow!("Invalid address type for LoRaWAN protocol")),
                };
                
                handler
                    .read()
                    .await
                    .send_mesh_message(addr_str, serialized)
                    .await
            }
            NetworkProtocol::QUIC => {
                let handler = self
                    .quic
                    .as_ref()
                    .ok_or_else(|| anyhow!("QUIC handler not available"))?;
                // QUIC handler is Arc<QuicMeshProtocol> directly (not wrapped in RwLock)
                // because QuicMeshProtocol doesn't implement Clone - it's stored globally (Issue #907)
                handler
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
