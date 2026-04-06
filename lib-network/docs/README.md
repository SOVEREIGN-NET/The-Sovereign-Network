# ZHTP lib-network: Mesh Networking for ISP Replacement

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![ZHTP](https://img.shields.io/badge/ZHTP-v1.0-green.svg)](https://zhtp.network)

**lib-network** is the core networking library of the ZHTP (Zero-Hash Transport Protocol) ecosystem, designed to create a mesh networking system that can **replace traditional ISPs** with a decentralized, community-owned internet infrastructure.

##  Vision: The New Internet

ZHTP lib-network enables:
- ** ISP Replacement**: Direct peer-to-peer mesh networking without ISP dependency
- ** Earn While You Connect**: Users get paid tokens for participating in the mesh network
- ** Post-Quantum Security**: Cryptographically secure with Dilithium5 and Kyber encryption
- **📱 Universal Access**: Works on phones, laptops, IoT devices via Bluetooth, WiFi, LoRaWAN, Satellite
- **🏠 Local-First**: Local mesh networking with global reach through relays

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    ZHTP Mesh Server                         │
├─────────────────────────────────────────────────────────────┤
│   Wallet-Based Security     Economic Incentives        │
│  ⚡ Hardware Detection        Emergency Controls         │
├─────────────────────────────────────────────────────────────┤
│                  Multi-Protocol Stack                       │
├─────────────────┬───────────────┬───────────────────────────┤
│  📱 Bluetooth   │  📶 WiFi      │   LoRaWAN/Satellite     │
│  LE + Classic   │  Direct P2P   │  Long-Range Global        │
├─────────────────┼───────────────┼───────────────────────────┤
│               Discovery & Routing System                     │
├─────────────────────────────────────────────────────────────┤
│   Hardware Detection   Geographic Location              │
│  🕸️ Smart Routing        Network Monitoring              │
├─────────────────────────────────────────────────────────────┤
│            Native Binary DHT (lib-storage backend)          │
├─────────────────────────────────────────────────────────────┤
│  🗃️ Content Distribution   Zero-Knowledge Proofs         │
│   Web4 Integration     ⚡ High-Performance Binary         │
└─────────────────────────────────────────────────────────────┘
```

##  Key Features

###  Multi-Protocol Mesh Networking
- **Bluetooth LE**: Device-to-device communication (phones, laptops, IoT)
- **Bluetooth Classic**: High-throughput mesh connections
- **WiFi Direct**: Medium-range peer-to-peer connections
- **LoRaWAN**: Long-range (15km+) low-power communication
- **Satellite**: Global coverage for remote areas
- **TCP/UDP**: Internet bridging for hybrid connectivity

###  Advanced Security
- **Post-Quantum Cryptography**: Dilithium5 signatures, Kyber encryption
- **Wallet-Based Authentication**: No centralized identity required
- **Zero-Knowledge Proofs**: Privacy-preserving verification
- **Emergency Controls**: Owner/admin access controls with audit logs

###  Economic Incentives
- **Routing Rewards**: Earn tokens for forwarding mesh traffic
- **Storage Rewards**: Get paid for providing DHT storage
- **Relay Rewards**: Compensation for internet bridge services
- **UBI Distribution**: Universal Basic Income through network participation

###  Intelligent Discovery
- **Cross-Platform Hardware Detection**: Automatic protocol enablement
- **Geographic Routing**: Location-aware mesh optimization
- **Network Health Monitoring**: Real-time statistics and diagnostics
- **Smart Peer Selection**: Reputation-based routing decisions

##  Module Structure

```
lib-network/
├── src/
│   ├── lib.rs                    # Main API and exports
│   ├── types/                    # Core data structures
│   │   ├── network_statistics.rs # Network monitoring
│   │   ├── mesh_message.rs      # Mesh communication
│   │   └── api_response.rs      # API responses
│   ├── mesh/
│   │   └── server.rs            # ZHTP Mesh Server (main component)
│   ├── dht/                     # Distributed Hash Table
│   │   ├── protocol.rs          # Native binary DHT protocol
│   │   ├── cache.rs             # Content caching
│   │   └── monitoring.rs        # DHT health monitoring
│   ├── protocols/               # Network protocols
│   │   ├── bluetooth.rs         # Bluetooth LE mesh
│   │   ├── wifi_direct.rs       # WiFi Direct P2P
│   │   ├── lorawan.rs           # LoRaWAN long-range
│   │   └── satellite.rs         # Satellite connectivity
│   ├── discovery/               # Peer and hardware discovery
│   │   ├── hardware.rs          # Cross-platform detection
│   │   ├── network_scanner.rs   # Network topology scanning
│   │   └── smart_routing.rs     # Intelligent routing
│   └── platform/                # Platform-specific implementations
│       ├── windows.rs           # Windows WinRT APIs
│       ├── linux.rs             # Linux BlueZ/NetworkManager
│       └── macos.rs             # macOS Core Bluetooth
└── docs/                        # This documentation
```

## 🛠️ Quick Start

### Basic Mesh Node Setup

```rust
use lib_network::{ZhtpMeshServer, NetworkProtocol};
use lib_crypto::PublicKey;
use lib_storage::UnifiedStorageSystem;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize storage system
    let storage = UnifiedStorageSystem::new().await?;
    
    // Create owner wallet key for node control
    let owner_key = PublicKey::new(vec![/* your public key */]);
    
    // Configure protocols (auto-detected based on hardware)
    let protocols = vec![
        NetworkProtocol::BluetoothLE,
        NetworkProtocol::WiFiDirect,
        NetworkProtocol::LoRaWAN,      // If hardware available
        NetworkProtocol::Satellite,    // Software-based
    ];
    
    // Create and start mesh server
    let mut server = ZhtpMeshServer::new(
        [1u8; 32],  // Node ID
        owner_key,
        storage,
        protocols
    ).await?;
    
    // Start the mesh internet
    server.start().await?;
    
    println!(" ZHTP Mesh Network ONLINE!");
    println!(" Earning tokens for network participation!");
    
    // Keep the server running
    tokio::signal::ctrl_c().await?;
    server.stop().await?;
    
    Ok(())
}
```

### DHT Content Operations

```rust
use lib_network::dht::DhtProtocolHandler;

// Query content from the mesh DHT
let content_hash = dht.query_content(
    "example.zhtp",     // Domain
    "/index.html",      // Path
    peer_addr           // Peer to query
).await?;

// Store content in the distributed network
let success = dht.store_content(
    "mysite.zhtp",      // Domain
    "/page.html",       // Path
    content_data,       // Content bytes
    peer_addr           // Storage peer
).await?;
```

### Network Discovery

```rust
use lib_network::discovery::HardwareCapabilities;

// Detect available networking hardware
let capabilities = HardwareCapabilities::detect().await?;

println!("Available protocols:");
for protocol in capabilities.get_enabled_protocols() {
    println!("   {}", protocol);
}

// Discover mesh peers
let peers = dht.discover_peers(10, bootstrap_peer).await?;
println!("Found {} mesh peers", peers.len());
```

### ZHTP Client Configuration (v1.1.0+)

The ZHTP client requires explicit configuration for secure operation:

```rust
use lib_network::client::{ZhtpClient, ZhtpClientConfig};
use lib_network::web4::client::{Web4Client, Web4ClientConfig};
use lib_identity::ZhtpIdentity;

// Configure ZHTP client with bootstrap mode (development only)
let config = ZhtpClientConfig {
    allow_bootstrap: true,  // Accept any TLS certificate (INSECURE - dev only)
};
let mut client = ZhtpClient::new_bootstrap_with_config(identity, config).await?;
client.connect("127.0.0.1:443").await?;

// Configure Web4 client with custom cache directory
let web4_config = Web4ClientConfig {
    allow_bootstrap: true,
    cache_dir: Some(PathBuf::from("/custom/cache")),
    session_id: None,  // Uses UUID if None
};
let mut web4 = Web4Client::new_bootstrap_with_config(identity, web4_config).await?;
web4.connect("127.0.0.1:443").await?;
```

**Why Configuration Injection?**
- ✅ No environment variable dependencies
- ✅ Works in containerized environments
- ✅ WASM compatible
- ✅ Explicit and type-safe
- ✅ Testable without OS-level setup

**For Tests:**
Enable network integration tests with the feature flag:
```bash
cargo test --features allow-net-tests
```

##  Security Model

### Wallet-Based Authentication
- **Owner Wallet**: Full node control, emergency stop, admin management
- **Admin Wallets**: Can disconnect peers, view audit logs
- **User Wallets**: Can disconnect own connections
- **Routing Wallet**: Receives automatic routing rewards

### Cryptographic Protection
- **Dilithium5 Signatures**: Post-quantum digital signatures for all operations
- **Kyber Encryption**: Post-quantum key exchange for secure communication

## Handshake

UHP/2.0 defines the trust boundary between transport and verified identity.
See `lib-network/docs/handshake/README.md`.

## Option B Plan (QUIC-Only Payloads)

We are actively executing the QUIC-only transport plan.
See `docs/option-b/README.md`.
- **Blake3 Hashing**: High-performance content addressing
- **Replay Protection**: Timestamp and nonce validation

### Emergency Controls
```rust
// Emergency stop (owner only)
server.emergency_stop(&owner_credentials).await?;

// Connection limits for safety
server.set_max_connections(100).await?;

// Audit log for security operations
let audit_log = server.get_security_audit_log(&admin_credentials).await?;
```

##  Economic Integration

### Routing Rewards
- **10 tokens** base reward per message routed
- **1 token per KB** data size bonus
- **5 tokens per hop** multi-hop routing bonus

### Automatic Payments
```rust
// Check routing earnings
let balance = server.get_routing_rewards_balance().await?;
println!("Earned {} tokens from routing", balance);

// Transfer rewards to external wallet
server.transfer_routing_rewards(recipient_key, amount).await?;
```

##  Global Coverage Strategy

### Local Mesh (0-1 km)
- **Bluetooth LE**: Phone-to-phone mesh networking
- **WiFi Direct**: High-speed local connections

### Regional Mesh (1-15 km)  
- **LoRaWAN**: Long-range radio with gateway infrastructure
- **WiFi Relay**: Internet bridge points

### Global Mesh (Worldwide)
- **Satellite**: Starlink, Iridium, and other satellite networks
- **Internet Bridges**: Hybrid connectivity for global reach

##  Performance Characteristics

| Protocol | Range | Bandwidth | Latency | Power |
|----------|-------|-----------|---------|-------|
| Bluetooth LE | 100m | 1 Mbps | 50ms | Low |
| WiFi Direct | 200m | 250 Mbps | 10ms | Medium |
| LoRaWAN | 15km | 50 kbps | 1s | Ultra-Low |
| Satellite | Global | 100 Mbps | 500ms | High |

##  Platform Support

### Windows
- **WinRT Bluetooth APIs**: Native Windows 10/11 Bluetooth LE
- **WiFi Direct APIs**: Windows WiFi Direct framework
- **Device Manager Integration**: Automatic hardware detection

### Linux
- **BlueZ**: Linux Bluetooth stack integration
- **NetworkManager**: WiFi Direct and interface management
- **GPIO/SPI**: Direct LoRaWAN hardware support (Raspberry Pi)

### macOS
- **Core Bluetooth**: Native macOS Bluetooth framework
- **System Profiler**: Hardware capability detection
- **Network Framework**: Modern networking APIs

##  Network Statistics

```rust
// Get comprehensive network statistics
let stats = server.get_network_stats().await;

println!("Network Status:");
println!("  Active Connections: {}", stats.active_connections);
println!("  Total Data Routed: {} MB", stats.total_data_routed / 1_000_000);
println!("  Routing Rewards: {} tokens", stats.routing_rewards_earned);
println!("  Network Health: {:.1}%", stats.network_health * 100.0);
```

##  Error Handling

lib-network uses `anyhow::Result` for comprehensive error handling:

```rust
use anyhow::Result;

match server.start().await {
    Ok(_) => println!(" Mesh server started successfully"),
    Err(e) => {
        eprintln!(" Failed to start mesh server: {}", e);
        
        // Check for specific error conditions
        if e.to_string().contains("hardware") {
            eprintln!("💡 Try: Install LoRaWAN hardware or enable Bluetooth");
        }
    }
}
```

## 🔬 Testing

```bash
# Run all tests
cargo test

# Test with hardware detection
cargo test --features "hardware-test"

# Network integration tests
cargo test integration -- --nocapture
```

## 🤝 Contributing

lib-network is part of the ZHTP ecosystem. Contributions welcome!

1. **Protocol Implementation**: Add support for new mesh protocols
2. **Platform Support**: Improve cross-platform hardware detection  
3. **Performance**: Optimize routing and DHT operations
4. **Security**: Enhance cryptographic protections

## 📚 Related Documentation

- [**ZHTP Protocol Specification**](../zhtp/docs/protocol.md)
- [**lib-storage Integration**](../lib-storage/docs/README.md)
- [**lib-crypto Security**](../lib-crypto/docs/README.md)
- [**Economic Model**](../lib-economy/docs/README.md)

##  Roadmap

### Phase 1: Foundation 
- [x] Multi-protocol mesh networking
- [x] Native binary DHT protocol
- [x] Cross-platform hardware detection
- [x] Wallet-based security model

### Phase 2: Scale (In Progress)
- [ ] Global satellite integration
- [ ] Advanced routing algorithms
- [ ] Mobile app integration
- [ ] Industrial IoT support

### Phase 3: Adoption
- [ ] ISP partnership program
- [ ] Community governance
- [ ] Regulatory compliance
- [ ] Mass deployment tools

---

**lib-network**: Powering the decentralized internet revolution, one mesh connection at a time. ✨
