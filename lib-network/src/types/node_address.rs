use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Unified network address type that consolidates all protocol-specific addressing
/// This replaces the scattered PeerId, PeerEndpoint, SocketAddr, and string-based
/// address representations throughout the codebase.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeAddress {
    /// UDP transport with IP:port
    Udp(SocketAddr),
    /// TCP transport with IP:port
    Tcp(SocketAddr),
    /// QUIC transport with IP:port
    Quic(SocketAddr),
    /// Bluetooth Classic with MAC address
    BluetoothClassic(String),
    /// Bluetooth Low Energy with MAC address or UUID
    BluetoothLE(String),
    /// WiFi Direct with IP address and optional MAC
    WiFiDirect { addr: SocketAddr, mac: Option<String> },
    /// LoRaWAN with DevAddr (device address)
    LoRaWAN { dev_addr: String, dev_eui: Option<String> },
    /// Mesh network with public key routing
    Mesh(Vec<u8>),
    /// Domain name (for ZDNS resolution)
    Domain(String),
}

impl NodeAddress {
    /// Convert address to canonical string representation
    pub fn to_address_string(&self) -> String {
        match self {
            NodeAddress::Udp(addr) => format!("udp://{}", addr),
            NodeAddress::Tcp(addr) => format!("tcp://{}", addr),
            NodeAddress::Quic(addr) => format!("quic://{}", addr),
            NodeAddress::BluetoothClassic(mac) => format!("bt://{}", mac),
            NodeAddress::BluetoothLE(addr) => format!("ble://{}", addr),
            NodeAddress::WiFiDirect { addr, mac } => {
                if let Some(m) = mac {
                    format!("wifid://{}?mac={}", addr, m)
                } else {
                    format!("wifid://{}", addr)
                }
            }
            NodeAddress::LoRaWAN { dev_addr, dev_eui } => {
                if let Some(eui) = dev_eui {
                    format!("lora://{}?eui={}", dev_addr, eui)
                } else {
                    format!("lora://{}", dev_addr)
                }
            }
            NodeAddress::Mesh(pubkey) => format!("mesh://{}", hex::encode(pubkey)),
            NodeAddress::Domain(domain) => format!("zdns://{}", domain),
        }
    }

    /// Get the protocol identifier
    pub fn protocol(&self) -> &'static str {
        match self {
            NodeAddress::Udp(_) => "udp",
            NodeAddress::Tcp(_) => "tcp",
            NodeAddress::Quic(_) => "quic",
            NodeAddress::BluetoothClassic(_) => "bluetooth",
            NodeAddress::BluetoothLE(_) => "ble",
            NodeAddress::WiFiDirect { .. } => "wifi_direct",
            NodeAddress::LoRaWAN { .. } => "lorawan",
            NodeAddress::Mesh(_) => "mesh",
            NodeAddress::Domain(_) => "domain",
        }
    }

    /// Check if this is an IP-based address
    pub fn is_ip_based(&self) -> bool {
        matches!(
            self,
            NodeAddress::Udp(_) | NodeAddress::Tcp(_) | NodeAddress::Quic(_) | NodeAddress::WiFiDirect { .. }
        )
    }

    /// Get the socket address if this is an IP-based protocol
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            NodeAddress::Udp(addr) | NodeAddress::Tcp(addr) | NodeAddress::Quic(addr) => Some(*addr),
            NodeAddress::WiFiDirect { addr, .. } => Some(*addr),
            _ => None,
        }
    }

    /// Generate DHT node address (20-byte Kademlia-compatible)
    pub fn to_dht_address(&self) -> Vec<u8> {
        let digest = blake3::hash(self.to_address_string().as_bytes());
        digest.as_bytes()[0..20].to_vec()
    }

    /// Parse from string representation
    pub fn from_string(s: &str) -> Result<Self, AddressParseError> {
        if let Some(rest) = s.strip_prefix("udp://") {
            let addr = rest.parse().map_err(|_| AddressParseError::InvalidFormat)?;
            Ok(NodeAddress::Udp(addr))
        } else if let Some(rest) = s.strip_prefix("tcp://") {
            let addr = rest.parse().map_err(|_| AddressParseError::InvalidFormat)?;
            Ok(NodeAddress::Tcp(addr))
        } else if let Some(rest) = s.strip_prefix("quic://") {
            let addr = rest.parse().map_err(|_| AddressParseError::InvalidFormat)?;
            Ok(NodeAddress::Quic(addr))
        } else if let Some(rest) = s.strip_prefix("bt://") {
            Ok(NodeAddress::BluetoothClassic(rest.to_string()))
        } else if let Some(rest) = s.strip_prefix("ble://") {
            Ok(NodeAddress::BluetoothLE(rest.to_string()))
        } else if let Some(rest) = s.strip_prefix("wifid://") {
            let parts: Vec<&str> = rest.split('?').collect();
            let addr = parts[0].parse().map_err(|_| AddressParseError::InvalidFormat)?;
            let mac = if parts.len() > 1 {
                parts[1].strip_prefix("mac=").map(String::from)
            } else {
                None
            };
            Ok(NodeAddress::WiFiDirect { addr, mac })
        } else if let Some(rest) = s.strip_prefix("lora://") {
            let parts: Vec<&str> = rest.split('?').collect();
            let dev_addr = parts[0].to_string();
            let dev_eui = if parts.len() > 1 {
                parts[1].strip_prefix("eui=").map(String::from)
            } else {
                None
            };
            Ok(NodeAddress::LoRaWAN { dev_addr, dev_eui })
        } else if let Some(rest) = s.strip_prefix("mesh://") {
            let pubkey = hex::decode(rest).map_err(|_| AddressParseError::InvalidFormat)?;
            Ok(NodeAddress::Mesh(pubkey))
        } else if let Some(rest) = s.strip_prefix("zdns://") {
            Ok(NodeAddress::Domain(rest.to_string()))
        } else {
            Err(AddressParseError::UnknownProtocol)
        }
    }
}

impl fmt::Display for NodeAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_address_string())
    }
}

/// Address parsing error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressParseError {
    InvalidFormat,
    UnknownProtocol,
}

impl fmt::Display for AddressParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressParseError::InvalidFormat => write!(f, "Invalid address format"),
            AddressParseError::UnknownProtocol => write!(f, "Unknown protocol"),
        }
    }
}

impl std::error::Error for AddressParseError {}

/// Endpoint with address and connection metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressEndpoint {
    /// Network address
    pub address: NodeAddress,
    /// Signal strength/quality (0.0 - 1.0)
    pub signal_strength: f64,
    /// Latency in milliseconds
    pub latency_ms: u32,
    /// Last successful connection timestamp
    pub last_seen: Option<u64>,
}

impl AddressEndpoint {
    pub fn new(address: NodeAddress) -> Self {
        Self {
            address,
            signal_strength: 1.0,
            latency_ms: 0,
            last_seen: None,
        }
    }

    pub fn with_metrics(address: NodeAddress, signal_strength: f64, latency_ms: u32) -> Self {
        Self {
            address,
            signal_strength,
            latency_ms,
            last_seen: None,
        }
    }
}

/// Unified address resolver - consolidates all address resolution logic
/// Replaces PeerAddressResolver, get_address_for_peer methods, and ZDNS resolver
#[derive(Debug)]
pub struct AddressResolver {
    /// Map from public key to available addresses
    peer_addresses: Arc<RwLock<HashMap<String, Vec<AddressEndpoint>>>>,
    /// Map from domain name to resolved addresses (ZDNS cache)
    domain_cache: Arc<RwLock<HashMap<String, Vec<NodeAddress>>>>,
}

impl AddressResolver {
    pub fn new() -> Self {
        Self {
            peer_addresses: Arc::new(RwLock::new(HashMap::new())),
            domain_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register an address for a peer
    pub async fn register_address(&self, pubkey: &str, endpoint: AddressEndpoint) {
        let mut map = self.peer_addresses.write().await;
        map.entry(pubkey.to_string())
            .or_insert_with(Vec::new)
            .push(endpoint);
    }

    /// Register multiple addresses for a peer
    pub async fn register_addresses(&self, pubkey: &str, endpoints: Vec<AddressEndpoint>) {
        let mut map = self.peer_addresses.write().await;
        map.entry(pubkey.to_string())
            .or_insert_with(Vec::new)
            .extend(endpoints);
    }

    /// Get all addresses for a peer
    pub async fn get_addresses(&self, pubkey: &str) -> Vec<AddressEndpoint> {
        self.peer_addresses
            .read()
            .await
            .get(pubkey)
            .cloned()
            .unwrap_or_default()
    }

    /// Get addresses filtered by protocol
    pub async fn get_addresses_by_protocol(&self, pubkey: &str, protocol: &str) -> Vec<AddressEndpoint> {
        self.peer_addresses
            .read()
            .await
            .get(pubkey)
            .map(|endpoints| {
                endpoints
                    .iter()
                    .filter(|ep| ep.address.protocol() == protocol)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get the best address for a peer (highest signal strength, lowest latency)
    pub async fn get_best_address(&self, pubkey: &str) -> Option<AddressEndpoint> {
        let endpoints = self.get_addresses(pubkey).await;
        endpoints.into_iter().max_by(|a, b| {
            // Sort by signal strength first, then by inverse latency
            a.signal_strength
                .partial_cmp(&b.signal_strength)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.latency_ms.cmp(&a.latency_ms))
        })
    }

    /// Remove all addresses for a peer
    pub async fn remove_peer(&self, pubkey: &str) {
        self.peer_addresses.write().await.remove(pubkey);
    }

    /// Update metrics for a specific address
    pub async fn update_metrics(&self, pubkey: &str, address: &NodeAddress, signal_strength: f64, latency_ms: u32) {
        let mut map = self.peer_addresses.write().await;
        if let Some(endpoints) = map.get_mut(pubkey) {
            if let Some(endpoint) = endpoints.iter_mut().find(|ep| &ep.address == address) {
                endpoint.signal_strength = signal_strength;
                endpoint.latency_ms = latency_ms;
                endpoint.last_seen = Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                );
            }
        }
    }

    /// Cache domain resolution result
    pub async fn cache_domain(&self, domain: &str, addresses: Vec<NodeAddress>) {
        self.domain_cache
            .write()
            .await
            .insert(domain.to_string(), addresses);
    }

    /// Get cached domain resolution
    pub async fn get_cached_domain(&self, domain: &str) -> Option<Vec<NodeAddress>> {
        self.domain_cache.read().await.get(domain).cloned()
    }

    /// Clear domain cache
    pub async fn clear_domain_cache(&self) {
        self.domain_cache.write().await.clear();
    }
}

impl Default for AddressResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_address_string_conversion() {
        let addr = NodeAddress::Udp("127.0.0.1:8080".parse().unwrap());
        assert_eq!(addr.to_address_string(), "udp://127.0.0.1:8080");
        assert_eq!(addr.protocol(), "udp");

        let addr = NodeAddress::BluetoothClassic("AA:BB:CC:DD:EE:FF".to_string());
        assert_eq!(addr.to_address_string(), "bt://AA:BB:CC:DD:EE:FF");
        assert_eq!(addr.protocol(), "bluetooth");
    }

    #[test]
    fn test_address_parsing() {
        let addr = NodeAddress::from_string("udp://192.168.1.1:5000").unwrap();
        assert_eq!(addr, NodeAddress::Udp("192.168.1.1:5000".parse().unwrap()));

        let addr = NodeAddress::from_string("bt://AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(addr, NodeAddress::BluetoothClassic("AA:BB:CC:DD:EE:FF".to_string()));

        let addr = NodeAddress::from_string("zdns://example.sov").unwrap();
        assert_eq!(addr, NodeAddress::Domain("example.sov".to_string()));
    }

    #[test]
    fn test_socket_addr_extraction() {
        let addr = NodeAddress::Udp("10.0.0.1:9000".parse().unwrap());
        assert!(addr.socket_addr().is_some());

        let addr = NodeAddress::BluetoothClassic("AA:BB:CC:DD:EE:FF".to_string());
        assert!(addr.socket_addr().is_none());
    }

    #[tokio::test]
    async fn test_address_resolver() {
        let resolver = AddressResolver::new();
        let pubkey = "test_pubkey";

        let endpoint = AddressEndpoint::new(NodeAddress::Udp("127.0.0.1:8080".parse().unwrap()));
        resolver.register_address(pubkey, endpoint).await;

        let addresses = resolver.get_addresses(pubkey).await;
        assert_eq!(addresses.len(), 1);

        let best = resolver.get_best_address(pubkey).await;
        assert!(best.is_some());
    }
}
