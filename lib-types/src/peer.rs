//! Peer Identifier Types
//!
//! Core networking identifiers for P2P communication.

use std::net::SocketAddr;

/// Peer identifier for protocol-agnostic addressing
///
/// Each variant represents a different transport protocol with its
/// native addressing scheme.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum PeerId {
    /// UDP peer identified by socket address
    Udp(SocketAddr),
    /// Bluetooth peer identified by address (MAC or UUID)
    Bluetooth(String),
    /// WiFi Direct peer identified by IP address
    WiFiDirect(SocketAddr),
    /// LoRaWAN peer identified by device EUI
    LoRaWAN(String),
    /// QUIC peer identified by socket address (uses same addressing as UDP)
    Quic(SocketAddr),
    /// Mesh peer identified by public key
    /// Routes DHT traffic through mesh network using public key addressing
    Mesh(Vec<u8>),
}

impl PeerId {
    /// Convert to string representation for routing
    pub fn to_address_string(&self) -> String {
        match self {
            PeerId::Udp(addr) => addr.to_string(),
            PeerId::Bluetooth(addr) => format!("gatt://{}", addr),
            PeerId::WiFiDirect(addr) => format!("wifid://{}", addr),
            PeerId::LoRaWAN(eui) => format!("lora://{}", eui),
            PeerId::Quic(addr) => format!("quic://{}", addr),
            PeerId::Mesh(pubkey) => format!("mesh://{}", hex::encode(pubkey)),
        }
    }

    /// Get protocol type
    pub fn protocol(&self) -> &str {
        match self {
            PeerId::Udp(_) => "udp",
            PeerId::Bluetooth(_) => "bluetooth",
            PeerId::WiFiDirect(_) => "wifidirect",
            PeerId::LoRaWAN(_) => "lorawan",
            PeerId::Quic(_) => "quic",
            PeerId::Mesh(_) => "mesh",
        }
    }

    /// Create from socket address (defaults to UDP)
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        PeerId::Udp(addr)
    }

    /// Get socket address if this is a UDP, WiFiDirect, or QUIC peer
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            PeerId::Udp(addr) | PeerId::WiFiDirect(addr) | PeerId::Quic(addr) => Some(*addr),
            _ => None,
        }
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_address_string())
    }
}
