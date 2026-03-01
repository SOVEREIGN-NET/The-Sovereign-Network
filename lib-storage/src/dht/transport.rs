//! DHT Transport Abstraction Layer
//!
//! **TICKET #152:** Multi-protocol DHT transport abstraction
//!
//! This module defines the `DhtTransport` trait that enables Kademlia DHT to work
//! over multiple protocols (UDP, BLE, WiFi Direct, LoRaWAN, QUIC).
//!
//! **Architecture Note:** The trait is defined here in lib-storage to avoid
//! circular dependencies. Implementations live in lib-network which depends
//! on lib-storage (not the other way around).
//!
//! **PeerId Note:** PeerId is now defined in lib-types and re-exported here
//! for backward compatibility.

use anyhow::Result;
use async_trait::async_trait;
use std::net::SocketAddr;

// Re-export PeerId from lib-types (canonical location)
pub use lib_types::PeerId;

/// Transport abstraction for DHT operations
///
/// This trait allows Kademlia DHT to work over any protocol by abstracting
/// the send/receive operations. Implementations exist in lib-network for:
/// - `UdpDhtTransport` - Original UDP transport
/// - `BleDhtTransport` - Bluetooth Low Energy via GATT
/// - `QuicDhtTransport` - QUIC with reliability and PQC
/// - `WiFiDirectDhtTransport` - WiFi Direct P2P
/// - `MultiDhtTransport` - Protocol selection with fallback
#[async_trait]
pub trait DhtTransport: Send + Sync {
    /// Send DHT message to peer
    async fn send(&self, data: &[u8], peer: &PeerId) -> Result<()>;

    /// Receive DHT message (returns data and sender peer ID)
    async fn receive(&self) -> Result<(Vec<u8>, PeerId)>;

    /// Get local peer ID for this transport
    fn local_peer_id(&self) -> PeerId;

    /// Check if peer is reachable via this transport
    async fn can_reach(&self, peer: &PeerId) -> bool;

    /// Get maximum transmission unit for this transport
    fn mtu(&self) -> usize {
        match self.local_peer_id() {
            PeerId::Udp(_) => 1400,        // UDP mesh default
            PeerId::Bluetooth(_) => 512,   // BLE MTU minus overhead
            PeerId::WiFiDirect(_) => 1400, // Similar to UDP
            PeerId::LoRaWAN(_) => 242,     // LoRaWAN SF7 max payload
            PeerId::Quic(_) => 1200,       // QUIC recommended MTU
            PeerId::Mesh(_) => 65536,      // Mesh handles fragmentation
        }
    }

    /// Get typical latency for this transport (milliseconds)
    fn typical_latency_ms(&self) -> u32 {
        match self.local_peer_id() {
            PeerId::Udp(_) => 10,
            PeerId::Bluetooth(_) => 100,
            PeerId::WiFiDirect(_) => 20,
            PeerId::LoRaWAN(_) => 1000,
            PeerId::Quic(_) => 15, // Slightly higher than UDP due to QUIC overhead
            PeerId::Mesh(_) => 50, // Variable based on underlying transport
        }
    }
}

/// UDP-based DHT transport (basic implementation in lib-storage)
///
/// This is a simple UDP transport for lib-storage's internal use.
/// More advanced transports (BLE, QUIC, WiFi Direct) are implemented in lib-network.
pub struct UdpDhtTransport {
    socket: std::sync::Arc<tokio::net::UdpSocket>,
    local_addr: SocketAddr,
}

impl UdpDhtTransport {
    /// Create a new UDP transport with an existing socket
    pub fn new(socket: std::sync::Arc<tokio::net::UdpSocket>, local_addr: SocketAddr) -> Self {
        Self { socket, local_addr }
    }

    /// Create a new UDP transport by binding to an address
    pub async fn bind(addr: SocketAddr) -> Result<Self> {
        let socket = tokio::net::UdpSocket::bind(addr).await?;
        let local_addr = socket.local_addr()?;
        Ok(Self {
            socket: std::sync::Arc::new(socket),
            local_addr,
        })
    }
}

#[async_trait]
impl DhtTransport for UdpDhtTransport {
    async fn send(&self, data: &[u8], peer: &PeerId) -> Result<()> {
        match peer {
            PeerId::Udp(addr) => {
                self.socket.send_to(data, addr).await?;
                Ok(())
            }
            _ => Err(anyhow::anyhow!("UDP transport can only send to UDP peers")),
        }
    }

    async fn receive(&self) -> Result<(Vec<u8>, PeerId)> {
        let mut buf = vec![0u8; 65536];
        let (len, addr) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(len);
        Ok((buf, PeerId::Udp(addr)))
    }

    fn local_peer_id(&self) -> PeerId {
        PeerId::Udp(self.local_addr)
    }

    async fn can_reach(&self, peer: &PeerId) -> bool {
        matches!(peer, PeerId::Udp(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_id_display() {
        let udp = PeerId::Udp("127.0.0.1:8080".parse().unwrap());
        assert_eq!(udp.to_string(), "127.0.0.1:8080");

        let ble = PeerId::Bluetooth("AA:BB:CC:DD:EE:FF".to_string());
        assert_eq!(ble.to_string(), "gatt://AA:BB:CC:DD:EE:FF");

        let quic = PeerId::Quic("10.0.0.1:443".parse().unwrap());
        assert_eq!(quic.to_string(), "quic://10.0.0.1:443");
    }

    #[test]
    fn test_peer_id_protocol() {
        let udp = PeerId::Udp("127.0.0.1:8080".parse().unwrap());
        assert_eq!(udp.protocol(), "udp");

        let ble = PeerId::Bluetooth("test".to_string());
        assert_eq!(ble.protocol(), "bluetooth");
    }

    #[test]
    fn test_socket_addr_extraction() {
        let udp = PeerId::Udp("127.0.0.1:8080".parse().unwrap());
        assert!(udp.socket_addr().is_some());

        let ble = PeerId::Bluetooth("test".to_string());
        assert!(ble.socket_addr().is_none());
    }
}
