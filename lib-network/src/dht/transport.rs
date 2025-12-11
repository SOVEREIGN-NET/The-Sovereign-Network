// DHT Transport Abstraction Layer
// Enables Kademlia DHT to work over multiple protocols (UDP, BLE, WiFi Direct, LoRaWAN, QUIC)
//
// **TICKET #152:** Implement DHT transport layer for multi-protocol support

use anyhow::Result;
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Peer identifier for protocol-agnostic addressing
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PeerId {
    /// UDP peer identified by socket address
    Udp(SocketAddr),
    /// Bluetooth peer identified by address (MAC or UUID)
    Bluetooth(String),
    /// WiFi Direct peer identified by IP address
    WiFiDirect(SocketAddr),
    /// LoRaWAN peer identified by device EUI
    LoRaWAN(String),
}

impl PeerId {
    /// Convert to string representation for routing
    pub fn to_address_string(&self) -> String {
        match self {
            PeerId::Udp(addr) => addr.to_string(),
            PeerId::Bluetooth(addr) => format!("gatt://{}", addr),
            PeerId::WiFiDirect(addr) => format!("wifid://{}", addr),
            PeerId::LoRaWAN(eui) => format!("lora://{}", eui),
        }
    }
    
    /// Get protocol type
    pub fn protocol(&self) -> &str {
        match self {
            PeerId::Udp(_) => "udp",
            PeerId::Bluetooth(_) => "bluetooth",
            PeerId::WiFiDirect(_) => "wifidirect",
            PeerId::LoRaWAN(_) => "lorawan",
        }
    }
}

/// Transport abstraction for DHT operations
/// Allows Kademlia to work over any protocol
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
            PeerId::Udp(_) => 1400,           // UDP mesh default
            PeerId::Bluetooth(_) => 512,      // BLE MTU minus overhead
            PeerId::WiFiDirect(_) => 1400,    // Similar to UDP
            PeerId::LoRaWAN(_) => 242,        // LoRaWAN SF7 max payload
        }
    }
    
    /// Get typical latency for this transport (milliseconds)
    fn typical_latency_ms(&self) -> u32 {
        match self.local_peer_id() {
            PeerId::Udp(_) => 10,
            PeerId::Bluetooth(_) => 100,
            PeerId::WiFiDirect(_) => 20,
            PeerId::LoRaWAN(_) => 1000,
        }
    }
}

/// UDP-based DHT transport (original implementation)
pub struct UdpDhtTransport {
    socket: Arc<tokio::net::UdpSocket>,
    local_addr: SocketAddr,
}

impl UdpDhtTransport {
    pub fn new(socket: Arc<tokio::net::UdpSocket>, local_addr: SocketAddr) -> Self {
        Self { socket, local_addr }
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

/// Bluetooth-based DHT transport (routes through mesh)
pub struct BleDhtTransport {
    bluetooth_protocol: Arc<RwLock<crate::protocols::bluetooth::BluetoothMeshProtocol>>,
    local_id: String,
    // Channel for receiving DHT messages from GATT
    receiver: Arc<RwLock<tokio::sync::mpsc::UnboundedReceiver<(Vec<u8>, String)>>>,
}

impl BleDhtTransport {
    pub fn new(
        bluetooth_protocol: Arc<RwLock<crate::protocols::bluetooth::BluetoothMeshProtocol>>,
        local_id: String,
    ) -> (Self, tokio::sync::mpsc::UnboundedSender<(Vec<u8>, String)>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let transport = Self {
            bluetooth_protocol,
            local_id,
            receiver: Arc::new(RwLock::new(rx)),
        };
        (transport, tx)
    }
}

#[async_trait]
impl DhtTransport for BleDhtTransport {
    async fn send(&self, data: &[u8], peer: &PeerId) -> Result<()> {
        match peer {
            PeerId::Bluetooth(addr) => {
                let protocol = self.bluetooth_protocol.read().await;
                protocol.send_mesh_message(addr, data).await?;
                Ok(())
            }
            _ => Err(anyhow::anyhow!("BLE transport can only send to Bluetooth peers")),
        }
    }
    
    async fn receive(&self) -> Result<(Vec<u8>, PeerId)> {
        let mut receiver = self.receiver.write().await;
        if let Some((data, sender)) = receiver.recv().await {
            Ok((data, PeerId::Bluetooth(sender)))
        } else {
            Err(anyhow::anyhow!("BLE transport receiver closed"))
        }
    }
    
    fn local_peer_id(&self) -> PeerId {
        PeerId::Bluetooth(self.local_id.clone())
    }
    
    async fn can_reach(&self, peer: &PeerId) -> bool {
        if let PeerId::Bluetooth(addr) = peer {
            let protocol = self.bluetooth_protocol.read().await;
            let connections = protocol.current_connections.read().await;
            let result = connections.contains_key(addr);
            drop(connections);
            drop(protocol);
            result
        } else {
            false
        }
    }
}

/// QUIC-based DHT transport (**TICKET #152**)
/// Provides reliable, multiplexed transport with built-in TLS 1.3 and post-quantum security
pub struct QuicDhtTransport {
    endpoint: Arc<quinn::Endpoint>,
    local_addr: SocketAddr,
    // Active QUIC connections to peers
    connections: Arc<RwLock<std::collections::HashMap<SocketAddr, quinn::Connection>>>,
    // Channel for receiving DHT messages
    receiver: Arc<RwLock<tokio::sync::mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>>>,
}

impl QuicDhtTransport {
    pub fn new(
        endpoint: Arc<quinn::Endpoint>,
        local_addr: SocketAddr,
    ) -> (Self, tokio::sync::mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let transport = Self {
            endpoint,
            local_addr,
            connections: Arc::new(RwLock::new(std::collections::HashMap::new())),
            receiver: Arc::new(RwLock::new(rx)),
        };
        (transport, tx)
    }
    
    /// Get or establish QUIC connection to peer
    async fn get_connection(&self, addr: &SocketAddr) -> Result<quinn::Connection> {
        // Check if we already have a connection
        {
            let connections = self.connections.read().await;
            if let Some(conn) = connections.get(addr) {
                if !conn.close_reason().is_some() {
                    return Ok(conn.clone());
                }
            }
        }
        
        // Establish new connection
        let conn = self.endpoint.connect(*addr, "dht")?.await?;
        
        // Store connection
        let mut connections = self.connections.write().await;
        connections.insert(*addr, conn.clone());
        
        Ok(conn)
    }
}

#[async_trait]
impl DhtTransport for QuicDhtTransport {
    async fn send(&self, data: &[u8], peer: &PeerId) -> Result<()> {
        match peer {
            PeerId::Udp(addr) => {
                // Get or establish QUIC connection
                let conn = self.get_connection(addr).await?;
                
                // Open unidirectional stream and send data
                let mut send_stream = conn.open_uni().await?;
                send_stream.write_all(data).await?;
                send_stream.finish()?;
                
                Ok(())
            }
            _ => Err(anyhow::anyhow!("QUIC transport can only send to UDP-addressed peers")),
        }
    }
    
    async fn receive(&self) -> Result<(Vec<u8>, PeerId)> {
        let mut receiver = self.receiver.write().await;
        if let Some((data, addr)) = receiver.recv().await {
            Ok((data, PeerId::Udp(addr)))
        } else {
            Err(anyhow::anyhow!("QUIC transport receiver closed"))
        }
    }
    
    fn local_peer_id(&self) -> PeerId {
        PeerId::Udp(self.local_addr)
    }
    
    async fn can_reach(&self, peer: &PeerId) -> bool {
        matches!(peer, PeerId::Udp(_))
    }
    
    fn mtu(&self) -> usize {
        1200 // QUIC recommended MTU for reliable delivery
    }
    
    fn typical_latency_ms(&self) -> u32 {
        15 // Slightly higher than UDP due to QUIC overhead, but with reliability
    }
}

/// WiFi Direct DHT transport (**TICKET #152**)
/// Provides peer-to-peer transport over WiFi Direct connections
pub struct WiFiDirectDhtTransport {
    wifi_direct_protocol: Arc<RwLock<crate::protocols::wifi_direct::WiFiDirectMeshProtocol>>,
    local_addr: SocketAddr,
    // Channel for receiving DHT messages from WiFi Direct
    receiver: Arc<RwLock<tokio::sync::mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>>>,
}

impl WiFiDirectDhtTransport {
    pub fn new(
        wifi_direct_protocol: Arc<RwLock<crate::protocols::wifi_direct::WiFiDirectMeshProtocol>>,
        local_addr: SocketAddr,
    ) -> (Self, tokio::sync::mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let transport = Self {
            wifi_direct_protocol,
            local_addr,
            receiver: Arc::new(RwLock::new(rx)),
        };
        (transport, tx)
    }
}

#[async_trait]
impl DhtTransport for WiFiDirectDhtTransport {
    async fn send(&self, data: &[u8], peer: &PeerId) -> Result<()> {
        match peer {
            PeerId::WiFiDirect(addr) => {
                let protocol = self.wifi_direct_protocol.read().await;
                // Send via WiFi Direct mesh protocol
                protocol.send_mesh_message(&addr.to_string(), data).await?;
                Ok(())
            }
            _ => Err(anyhow::anyhow!("WiFi Direct transport can only send to WiFi Direct peers")),
        }
    }
    
    async fn receive(&self) -> Result<(Vec<u8>, PeerId)> {
        let mut receiver = self.receiver.write().await;
        if let Some((data, addr)) = receiver.recv().await {
            Ok((data, PeerId::WiFiDirect(addr)))
        } else {
            Err(anyhow::anyhow!("WiFi Direct transport receiver closed"))
        }
    }
    
    fn local_peer_id(&self) -> PeerId {
        PeerId::WiFiDirect(self.local_addr)
    }
    
    async fn can_reach(&self, peer: &PeerId) -> bool {
        if let PeerId::WiFiDirect(addr) = peer {
            let protocol = self.wifi_direct_protocol.read().await;
            // Check if peer is in connected devices
            let connected = protocol.connected_devices.read().await;
            connected.contains_key(&addr.to_string())
        } else {
            false
        }
    }
    
    fn mtu(&self) -> usize {
        1400 // Similar to UDP, WiFi Direct has good MTU
    }
    
    fn typical_latency_ms(&self) -> u32 {
        20 // Low latency for local P2P connections
    }
}

/// Multi-protocol DHT transport (tries multiple protocols)
/// Optimizes by using fastest/closest transport available
pub struct MultiDhtTransport {
    transports: Vec<Arc<dyn DhtTransport>>,
    primary: PeerId,
}

impl MultiDhtTransport {
    pub fn new(transports: Vec<Arc<dyn DhtTransport>>, primary: PeerId) -> Self {
        Self { transports, primary }
    }
    
    /// Find best transport for reaching a peer
    async fn best_transport_for(&self, peer: &PeerId) -> Option<Arc<dyn DhtTransport>> {
        // Try exact protocol match first
        for transport in &self.transports {
            if transport.local_peer_id().protocol() == peer.protocol() {
                if transport.can_reach(peer).await {
                    return Some(transport.clone());
                }
            }
        }
        
        // Try any transport that can reach the peer
        for transport in &self.transports {
            if transport.can_reach(peer).await {
                return Some(transport.clone());
            }
        }
        
        None
    }
}

#[async_trait]
impl DhtTransport for MultiDhtTransport {
    async fn send(&self, data: &[u8], peer: &PeerId) -> Result<()> {
        if let Some(transport) = self.best_transport_for(peer).await {
            transport.send(data, peer).await
        } else {
            Err(anyhow::anyhow!("No transport available for peer: {:?}", peer))
        }
    }
    
    async fn receive(&self) -> Result<(Vec<u8>, PeerId)> {
        // Use tokio::select! to receive from any transport
        // For now, just receive from first available transport
        if let Some(transport) = self.transports.first() {
            transport.receive().await
        } else {
            Err(anyhow::anyhow!("No transports available"))
        }
    }
    
    fn local_peer_id(&self) -> PeerId {
        self.primary.clone()
    }
    
    async fn can_reach(&self, peer: &PeerId) -> bool {
        for transport in &self.transports {
            if transport.can_reach(peer).await {
                return true;
            }
        }
        false
    }
}

/// Peer address resolver - maps between protocol-specific addresses and PeerIds
pub struct PeerAddressResolver {
    /// Map from public key to available peer IDs
    peer_map: Arc<RwLock<std::collections::HashMap<String, Vec<PeerId>>>>,
}

impl PeerAddressResolver {
    pub fn new() -> Self {
        Self {
            peer_map: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }
    
    /// Register a peer's available addresses
    pub async fn register_peer(&self, pubkey: &str, peer_id: PeerId) {
        let mut map = self.peer_map.write().await;
        map.entry(pubkey.to_string())
            .or_insert_with(Vec::new)
            .push(peer_id);
    }
    
    /// Get all peer IDs for a given public key
    pub async fn get_peer_ids(&self, pubkey: &str) -> Vec<PeerId> {
        self.peer_map.read().await
            .get(pubkey)
            .cloned()
            .unwrap_or_default()
    }
    
    /// Convert PeerId to DHT node address (for Kademlia compatibility)
    pub fn peer_id_to_dht_address(&self, peer_id: &PeerId) -> Vec<u8> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        // Hash the peer ID to create a stable 20-byte Kademlia address
        let mut hasher = DefaultHasher::new();
        peer_id.to_address_string().hash(&mut hasher);
        let hash = hasher.finish();
        
        // Extend to 20 bytes (Kademlia standard)
        let mut addr = vec![0u8; 20];
        addr[0..8].copy_from_slice(&hash.to_be_bytes());
        addr
    }
}

impl Default for PeerAddressResolver {
    fn default() -> Self {
        Self::new()
    }
}
