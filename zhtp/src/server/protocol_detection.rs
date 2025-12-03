//! Protocol Detection Module
//!
//! Automatic protocol detection for incoming connections:
//! - HTTP/1.1 REST API (over QUIC)
//! - QUIC ZHTP Mesh (native protocol)
//! - WiFi Direct P2P
//! - Bluetooth (BLE/Classic)
//! - Bootstrap discovery
//!
//! NOTE: TCP/UDP mesh protocols removed - using QUIC only


/// Protocol detection for incoming connections
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncomingProtocol {
    /// HTTP/1.1 REST API requests (tunneled over QUIC)
    HTTP,
    /// QUIC-native ZHTP mesh protocol
    QuicMesh,
    /// WiFi Direct device connections
    WiFiDirect,
    /// Bluetooth device connections
    Bluetooth,
    /// Network bootstrap connections
    Bootstrap,
    /// Unknown protocol
    Unknown,
}

impl IncomingProtocol {
    /// Detect protocol type from QUIC stream or connection data
    pub fn detect_quic(buffer: &[u8]) -> Self {
        let data = String::from_utf8_lossy(buffer);
        
        // HTTP detection (HTTP/1.1 or HTTP/3 over QUIC)
        if data.starts_with("GET ") || data.starts_with("POST ") || 
           data.starts_with("PUT ") || data.starts_with("DELETE ") ||
           data.starts_with("OPTIONS ") || data.starts_with("HEAD ") {
            return IncomingProtocol::HTTP;
        }
        
        // QUIC-native ZHTP mesh detection
        if data.starts_with("ZHTP/1.0 MESH") || data.starts_with("ZHTP/2.0") {
            return IncomingProtocol::QuicMesh;
        }
        
        // Try to deserialize as QUIC mesh message
        if buffer.len() >= 20 && buffer.len() < 4096 {
            use lib_network::types::mesh_message::ZhtpMeshMessage;
            if let Ok(_) = bincode::deserialize::<ZhtpMeshMessage>(buffer) {
                return IncomingProtocol::QuicMesh;
            }
        }
        
        // WiFi Direct detection (for WiFi Direct over QUIC)
        if data.contains("WIFI-DIRECT") || data.contains("P2P-DEVICE") {
            return IncomingProtocol::WiFiDirect;
        }
        
        // Bluetooth detection (for BLE/Classic bridge over QUIC)
        if data.contains("BLUETOOTH") || data.contains("BT-") || 
           data.contains("ZHTP-PHONE") || data.contains("RFCOMM") {
            return IncomingProtocol::Bluetooth;
        }
        
        // Default to bootstrap for unknown connections
        IncomingProtocol::Bootstrap
    }
    
    /// Check if protocol is mesh-related
    pub fn is_mesh(&self) -> bool {
        matches!(self, IncomingProtocol::QuicMesh)
    }
    
    /// Check if protocol is wireless
    pub fn is_wireless(&self) -> bool {
        matches!(self, IncomingProtocol::WiFiDirect | IncomingProtocol::Bluetooth)
    }
    
    /// Get protocol name for logging
    pub fn name(&self) -> &'static str {
        match self {
            IncomingProtocol::HTTP => "HTTP (over QUIC)",
            IncomingProtocol::QuicMesh => "ZHTP Mesh (QUIC)",
            IncomingProtocol::WiFiDirect => "WiFi Direct",
            IncomingProtocol::Bluetooth => "Bluetooth",
            IncomingProtocol::Bootstrap => "Bootstrap",
            IncomingProtocol::Unknown => "Unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_detection() {
        let buffer = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(IncomingProtocol::detect_quic(buffer), IncomingProtocol::HTTP);
        
        let buffer = b"POST /api HTTP/1.1\r\n";
        assert_eq!(IncomingProtocol::detect_quic(buffer), IncomingProtocol::HTTP);
    }
    
    #[test]
    fn test_mesh_detection() {
        let buffer = b"ZHTP/1.0 MESH ANNOUNCE";
        assert_eq!(IncomingProtocol::detect_quic(buffer), IncomingProtocol::QuicMesh);
        
        let buffer = b"ZHTP/2.0 HANDSHAKE";
        assert_eq!(IncomingProtocol::detect_quic(buffer), IncomingProtocol::QuicMesh);
    }
    
    #[test]
    fn test_protocol_helpers() {
        assert!(IncomingProtocol::QuicMesh.is_mesh());
        assert!(!IncomingProtocol::HTTP.is_mesh());
        
        assert!(IncomingProtocol::WiFiDirect.is_wireless());
        assert!(IncomingProtocol::Bluetooth.is_wireless());
        assert!(!IncomingProtocol::HTTP.is_wireless());
    }
}
