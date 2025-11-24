# ZHTP lib-network API Reference

This document provides comprehensive API documentation for the lib-network module.

## Core Components

###  ZhtpMeshServer

The main mesh networking server that coordinates all networking protocols and provides the internet replacement functionality.

#### Constructor

```rust
pub async fn new(
    node_id: [u8; 32], 
    owner_key: PublicKey,
    storage: UnifiedStorageSystem, 
    protocols: Vec<NetworkProtocol>
) -> Result<Self>
```

**Parameters:**
- `node_id`: Unique 32-byte identifier for this mesh node
- `owner_key`: Cryptographic public key for node ownership and control
- `storage`: Unified storage system from lib-storage for DHT backend
- `protocols`: List of networking protocols to enable (auto-filtered by hardware)

**Returns:** Configured ZhtpMeshServer instance ready to start

#### Core Methods

##### Server Lifecycle

```rust
// Start the mesh server with all configured protocols
pub async fn start(&mut self) -> Result<()>

// Stop the mesh server gracefully
pub async fn stop(&self) -> Result<()>

// Emergency stop with immediate shutdown (owner only)
pub async fn emergency_stop(&self, caller_wallet_key: &PublicKey) -> Result<()>
```

##### Network Operations

```rust
// Handle incoming mesh message
pub async fn handle_mesh_message(&self, message: ZhtpMeshMessage, sender: PublicKey) -> Result<()>

// Process native ZHTP request from browser/API clients
pub async fn process_lib_request(
    &self,
    method: String,
    uri: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
) -> Result<ZhtpApiResponse>
```

##### Statistics & Monitoring

```rust
// Get current network statistics
pub async fn get_network_stats(&self) -> MeshProtocolStats

// Get revenue pools for UBI distribution
pub async fn get_revenue_pools(&self) -> HashMap<String, u64>

// Check if emergency stop has been triggered
pub async fn is_emergency_stopped(&self) -> bool
```

##### Web4 Content Serving

```rust
// Serve Web4 content via zkDHT
pub async fn serve_web4_content(&self, domain: &str, path: &str) -> Result<Vec<u8>>

// Get DHT network status
pub async fn get_dht_status(&self) -> DHTNetworkStatus

// Clear DHT cache
pub async fn clear_dht_cache(&self)
```

##### Economic Functions

```rust
// Record routing proof for earning tokens
pub async fn record_routing_proof(
    &self,
    message_hash: [u8; 32],
    source: PublicKey,
    destination: PublicKey,
    data_size: usize,
    hop_count: u8,
) -> Result<()>

// Get routing rewards balance
pub async fn get_routing_rewards_balance(&self) -> Result<u64>

// Transfer routing rewards to another wallet
pub async fn transfer_routing_rewards(&self, recipient_wallet_key: PublicKey, amount: u64) -> Result<()>
```

##### Security & Access Control

```rust
// Verify node ownership using wallet public key
pub async fn verify_node_ownership(&self, wallet_key: &PublicKey) -> bool

// Get permission level for a wallet
pub async fn get_permission_level(&self, wallet_key: &PublicKey) -> PermissionLevel

// Add admin wallet (owner only)
pub async fn add_admin_wallet(&self, caller_wallet_key: &PublicKey, admin_wallet_key: PublicKey) -> Result<()>

// Set maximum connection limit for safety
pub async fn set_max_connections(&self, max: usize) -> Result<()>

// Get current connection count and limit status
pub async fn get_connection_status(&self) -> (usize, usize, bool)
```

###  Permission Levels

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionLevel {
    /// Node owner - full control including emergency stop
    Owner,
    /// Network admin - can disconnect peers and manage connections
    Admin, 
    /// Regular user - can only disconnect own connections
    User,
    /// No permissions
    None,
}
```

###  Network Statistics

```rust
#[derive(Debug, Clone, Default)]
pub struct MeshProtocolStats {
    pub active_connections: u32,
    pub total_connections: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub connection_errors: u64,
    pub last_activity: u64,
    pub average_latency_ms: f64,
    pub throughput_mbps: f64,
    pub total_data_routed: u64,
    pub routing_rewards_earned: u64,
    pub network_health: f64,
}
```

###  Network Protocols

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NetworkProtocol {
    /// Bluetooth Low Energy for device-to-device communication
    BluetoothLE,
    /// Bluetooth Classic (BR/EDR) for high-throughput mesh
    BluetoothClassic,
    /// WiFi Direct for medium-range peer connections
    WiFiDirect,
    /// LoRaWAN for long-range low-power communication
    LoRaWAN,
    /// Satellite for global coverage
    Satellite,
    /// TCP for internet bridging
    TCP,
    /// UDP for mesh networking
    UDP,
}
```

##  Hardware Discovery API

### HardwareCapabilities

```rust
#[derive(Debug, Clone, Default)]
pub struct HardwareCapabilities {
    pub lorawan_available: bool,
    pub bluetooth_available: bool,
    pub wifi_direct_available: bool,
    pub hardware_details: HashMap<String, HardwareDevice>,
}

impl HardwareCapabilities {
    /// Detect all available hardware capabilities
    pub async fn detect() -> Result<Self>
    
    /// Get enabled protocols based on hardware availability
    pub fn get_enabled_protocols(&self) -> Vec<String>
    
    /// Check if any mesh protocols are available
    pub fn has_mesh_capabilities(&self) -> bool
}
```

### HardwareDevice

```rust
#[derive(Debug, Clone)]
pub struct HardwareDevice {
    pub name: String,
    pub device_type: String,
    pub vendor_info: Option<String>,
    pub device_path: Option<String>,
    pub properties: HashMap<String, String>,
}
```

##  DHT Protocol API

### DhtProtocolHandler

Native binary DHT protocol handler for efficient content distribution.

#### Constructor

```rust
pub fn new(identity: ZhtpIdentity) -> Self
```

#### Initialization

```rust
/// Initialize DHT protocol handler with UDP socket
pub async fn initialize(&mut self, bind_addr: SocketAddr) -> Result<()>
```

#### Content Operations

```rust
/// Query DHT for content
pub async fn query_content(&self, domain: &str, path: &str, peer_addr: SocketAddr) -> Result<Option<Hash>>

/// Store content in DHT
pub async fn store_content(
    &self, 
    domain: &str, 
    path: &str, 
    content: Vec<u8>,
    peer_addr: SocketAddr
) -> Result<bool>
```

#### Peer Operations

```rust
/// Discover DHT peers
pub async fn discover_peers(&self, max_peers: u16, peer_addr: SocketAddr) -> Result<Vec<DhtPeerInfo>>

/// Ping a peer to check availability
pub async fn ping_peer(&self, peer_addr: SocketAddr) -> Result<()>

/// Get the listening port of this DHT node
pub async fn get_listening_port(&self) -> Option<u16>
```

### DHT Message Types

#### Query Operations

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtQueryPayload {
    pub domain: String,
    pub path: String,
    pub flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtQueryResponsePayload {
    pub content_hash: Option<Hash>,
    pub error: Option<String>,
    pub peer_suggestions: Vec<[u8; 32]>,
    pub ttl: u32,
}
```

#### Store Operations

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtStorePayload {
    pub domain: String,
    pub path: String,
    pub content_hash: Hash,
    pub content: Vec<u8>,
    pub duration: u32,
    pub replication: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtStoreAckPayload {
    pub content_hash: Hash,
    pub success: bool,
    pub error: Option<String>,
    pub expires_at: u64,
}
```

## 🛰️ ZHTP Relay Protocol

Secure DHT relay through mesh peers with post-quantum encryption.

### ZhtpRelayQuery

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpRelayQuery {
    pub request_id: String,
    pub domain: String,
    pub path: String,
    pub requester_pubkey: Vec<u8>,
    pub encrypted_payload: ZhtpEncryptedMessage,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}
```

### ZhtpRelayResponse

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpRelayResponse {
    pub request_id: String,
    pub found: bool,
    pub content_hash: Option<Hash>,
    pub content_type: Option<String>,
    pub responder_pubkey: Vec<u8>,
    pub encrypted_content: ZhtpEncryptedMessage,
    pub signature: Vec<u8>,
    pub timestamp: u64,
    pub relay_capabilities: NodeCapabilities,
}
```

##  Security API

### SecurityCredentials

```rust
#[derive(Debug, Clone)]
pub struct SecurityCredentials {
    pub wallet_key: PublicKey,
    pub signature: Vec<u8>,
    pub timestamp: u64,
    pub nonce: String,
}
```

### SecurityAuditLog

```rust
#[derive(Debug, Clone)]
pub struct SecurityAuditLog {
    pub timestamp: u64,
    pub operation: String,
    pub caller_key: String,
    pub target: Option<String>,
    pub permission_level: String,
    pub success: bool,
    pub reason: String,
}
```

##  Discovery Statistics

```rust
#[derive(Debug, Clone, Default)]
pub struct DiscoveryStatistics {
    pub local_peers: u32,
    pub regional_peers: u32,
    pub global_peers: u32,
    pub relay_peers: u32,
}

/// Get discovery statistics for peer distribution
pub async fn get_discovery_statistics() -> Result<DiscoveryStatistics>
```

##  Platform-Specific APIs

### Windows

```rust
/// Initialize Windows networking
pub async fn init_windows_networking() -> Result<()>

/// Scan for Windows Bluetooth devices
pub async fn scan_windows_bluetooth() -> Result<Vec<String>>

/// Get Windows network interfaces
pub async fn get_windows_interfaces() -> Result<Vec<String>>
```

### Linux

```rust
/// Initialize Linux networking with BlueZ
pub async fn init_linux_networking() -> Result<()>

/// Scan for Linux Bluetooth devices via BlueZ
pub async fn scan_linux_bluetooth() -> Result<Vec<String>>

/// Get Linux network interfaces via NetworkManager
pub async fn get_linux_interfaces() -> Result<Vec<String>>
```

### macOS

```rust
/// Initialize macOS networking with Core Bluetooth
pub async fn init_macos_networking() -> Result<()>

/// Scan for macOS Bluetooth devices
pub async fn scan_macos_bluetooth() -> Result<Vec<String>>

/// Get macOS network interfaces
pub async fn get_macos_interfaces() -> Result<Vec<String>>
```

##  Message Types

### ZhtpMeshMessage

Core message type for mesh communication:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZhtpMeshMessage {
    /// Peer discovery with capabilities
    PeerDiscovery {
        capabilities: Vec<MeshCapability>,
        location: Option<GeographicLocation>,
        shared_resources: SharedResources,
    },
    /// Content request message
    ContentRequest {
        domain: String,
        path: String,
        request_id: String,
    },
    /// Content response message
    ContentResponse {
        request_id: String,
        content: Option<Vec<u8>>,
        content_hash: Option<Hash>,
        error: Option<String>,
    },
    /// Routing message for mesh forwarding
    RouteMessage {
        destination: PublicKey,
        payload: Vec<u8>,
        ttl: u8,
        route_history: Vec<PublicKey>,
    },
}
```

### ZhtpApiResponse

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpApiResponse {
    pub status: u16,
    pub status_message: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}
```

##  Error Handling

All API functions return `Result<T>` types using `anyhow::Error` for comprehensive error information:

```rust
use anyhow::{Result, anyhow};

// Common error patterns:
match server.start().await {
    Ok(_) => println!(" Success"),
    Err(e) => {
        // Check specific error conditions
        let error_msg = e.to_string();
        
        if error_msg.contains("hardware") {
            eprintln!("Hardware detection failed");
        } else if error_msg.contains("permission") {
            eprintln!("Insufficient permissions");
        } else if error_msg.contains("emergency") {
            eprintln!("Emergency stop active");
        }
        
        // Full error chain
        eprintln!("Error: {:?}", e);
    }
}
```

##  Testing Utilities

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hardware_detection() {
        let capabilities = HardwareCapabilities::detect().await.unwrap();
        assert!(capabilities.has_mesh_capabilities());
    }

    #[tokio::test]
    async fn test_dht_operations() {
        // Test DHT packet serialization/deserialization
        let packet = create_test_dht_packet();
        let serialized = bincode::serialize(&packet).unwrap();
        let deserialized: DhtPacket = bincode::deserialize(&serialized).unwrap();
        
        assert_eq!(packet.header.version, deserialized.header.version);
    }
}
```

##  Configuration

### Environment Variables

- `ZHTP_DHT_PORT`: DHT listening port (default: 33444)
- `ZHTP_MAX_CONNECTIONS`: Maximum peer connections (default: 100)
- `ZHTP_LOG_LEVEL`: Logging level (trace/debug/info/warn/error)
- `ZHTP_HARDWARE_DETECT`: Enable hardware detection (true/false)

### Feature Flags

```toml
[features]
default = ["enhanced-bluetooth", "enhanced-wifi-direct", "hardware-detection"]
enhanced-bluetooth = []
enhanced-wifi-direct = []
hardware-detection = []
security-enhancements = []
```

---

This API documentation covers the complete lib-network interface for building mesh networking applications with ZHTP. 