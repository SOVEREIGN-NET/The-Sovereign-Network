# ZHTP lib-network Configuration Guide

This guide covers all configuration options for the lib-network mesh networking system.

## 🏗️ Basic Configuration

### Creating a Mesh Node

```rust
use lib_network::{ZhtpMeshServer, NetworkProtocol, NetworkConfig};
use lib_crypto::PublicKey;
use lib_storage::UnifiedStorageSystem;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Initialize storage backend
    let storage = UnifiedStorageSystem::new().await?;
    
    // 2. Create owner wallet for node control
    let owner_key = PublicKey::new(your_public_key_bytes);
    
    // 3. Configure networking protocols
    let protocols = vec![
        NetworkProtocol::BluetoothLE,     // Always available
        NetworkProtocol::WiFiDirect,      // High bandwidth local
        NetworkProtocol::LoRaWAN,         // Long range (if hardware available)
        NetworkProtocol::Satellite,       // Global coverage
    ];
    
    // 4. Create mesh server
    let mut server = ZhtpMeshServer::new(
        generate_node_id(),  // Unique node identifier
        owner_key,           // Node ownership key
        storage,             // DHT storage backend
        protocols            // Enabled protocols (filtered by hardware)
    ).await?;
    
    // 5. Start the mesh network
    server.start().await?;
    
    Ok(())
}

fn generate_node_id() -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"my-unique-node-identifier");
    hasher.update(&std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_le_bytes());
    
    let result = hasher.finalize();
    let mut node_id = [0u8; 32];
    node_id.copy_from_slice(&result);
    node_id
}
```

##  Advanced Configuration

### Network Configuration Structure

```rust
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub node_id: [u8; 32],           // Unique node identifier
    pub listen_port: u16,            // DHT listening port
    pub max_peers: usize,            // Maximum peer connections
    pub protocols: Vec<NetworkProtocol>, // Enabled protocols
    pub listen_addresses: Vec<String>,   // Binding addresses
    pub bootstrap_peers: Vec<String>,    // Initial peer discovery
}

impl NetworkConfig {
    pub fn new() -> Self {
        Self {
            node_id: [0u8; 32],      // Set unique ID
            listen_port: 33444,       // Standard ZHTP DHT port
            max_peers: 100,          // Safe default
            protocols: vec![
                NetworkProtocol::BluetoothLE,
                NetworkProtocol::WiFiDirect,
            ],
            listen_addresses: vec!["0.0.0.0:33444".to_string()],
            bootstrap_peers: vec![
                "100.94.204.6:9333".to_string(),  // ZHTP bootstrap
            ],
        }
    }
}
```

### Protocol-Specific Configuration

#### Bluetooth LE Configuration

```rust
use lib_network::protocols::bluetooth::BluetoothConfig;

let bluetooth_config = BluetoothConfig {
    device_name: "ZHTP-Mesh-Node".to_string(),
    advertise_interval_ms: 1000,     // Advertisement frequency
    scan_window_ms: 100,             // Scan window duration
    connection_timeout_ms: 5000,     // Connection timeout
    max_connections: 8,              // BLE connection limit
    tx_power: -12,                   // dBm (adjust for range vs power)
};
```

#### WiFi Direct Configuration

```rust
use lib_network::protocols::wifi_direct::WiFiDirectConfig;

let wifi_config = WiFiDirectConfig {
    group_name: "ZHTP-Mesh".to_string(),
    passphrase: "zhtp-secure-2024".to_string(),
    channel: 6,                      // WiFi channel (1-11)
    max_clients: 16,                 // P2P group size limit
    beacon_interval_ms: 100,         // Beacon frequency
    discovery_timeout_s: 30,         // Peer discovery timeout
};
```

#### LoRaWAN Configuration

```rust
use lib_network::protocols::lorawan::LoRaWANConfig;

let lora_config = LoRaWANConfig {
    frequency: 915_000_000,          // 915MHz (US) or 868MHz (EU)
    spreading_factor: 7,             // SF7-SF12 (range vs data rate)
    bandwidth: 125_000,              // 125kHz bandwidth
    coding_rate: 5,                  // 4/5 coding rate
    tx_power: 14,                    // dBm transmit power
    sync_word: 0x34,                 // Network sync word
    preamble_length: 8,              // Preamble symbols
};
```

#### Satellite Configuration

```rust
use lib_network::protocols::satellite::SatelliteConfig;

let satellite_config = SatelliteConfig {
    provider: SatelliteProvider::Starlink,  // Starlink, Iridium, etc.
    terminal_id: "ZHTP-SAT-001".to_string(),
    uplink_frequency: 14_000_000_000,       // 14GHz uplink
    downlink_frequency: 12_000_000_000,     // 12GHz downlink
    max_throughput_mbps: 100,               // Link capacity
    latency_budget_ms: 500,                 // Acceptable latency
};
```

##  Security Configuration

### Wallet-Based Authentication

```rust
use lib_network::security::{SecurityConfig, PermissionLevel};
use lib_crypto::PublicKey;

// Configure node security
let mut security_config = SecurityConfig::new();

// Set node owner (full control)
security_config.owner_key = owner_public_key;

// Add admin wallets (can disconnect peers)
security_config.add_admin_key(admin_public_key_1);
security_config.add_admin_key(admin_public_key_2);

// Configure connection limits
security_config.max_connections = 50;
security_config.rate_limit_per_ip = 10;  // Connections per IP per minute

// Enable audit logging
security_config.audit_log_enabled = true;
security_config.audit_log_retention_days = 30;
```

### Cryptographic Settings

```rust
use lib_network::crypto::CryptoConfig;

let crypto_config = CryptoConfig {
    signature_algorithm: SignatureAlgorithm::Dilithium2,  // Post-quantum
    encryption_algorithm: EncryptionAlgorithm::Kyber512,  // Post-quantum KEM
    hash_algorithm: HashAlgorithm::Blake3,                // High-performance
    key_rotation_interval_hours: 24,                      // Rotate keys daily
    require_perfect_forward_secrecy: true,                // PFS for all sessions
};
```

##  Economic Configuration

### Routing Rewards

```rust
use lib_network::economics::EconomicConfig;

let economic_config = EconomicConfig {
    // Base routing rewards
    base_routing_reward: 10,          // 10 tokens per message
    data_size_multiplier: 1,          // 1 token per KB
    hop_count_multiplier: 5,          // 5 tokens per hop
    
    // Storage rewards
    storage_reward_per_gb_day: 100,   // 100 tokens per GB-day
    
    // Quality multipliers
    latency_bonus_threshold_ms: 100,  // Bonus for low latency
    reliability_bonus_threshold: 0.99, // Bonus for high reliability
    
    // UBI distribution
    ubi_pool_percentage: 20.0,        // 20% of rewards go to UBI
    ubi_distribution_interval_s: 3600, // Hourly UBI distribution
};
```

### Payment Configuration

```rust
// Configure automatic payments
server.configure_payments(PaymentConfig {
    auto_withdraw_threshold: 1000,     // Auto-withdraw at 1000 tokens
    withdrawal_address: my_wallet_address,
    gas_price_multiplier: 1.1,         // 10% gas buffer
    confirmation_blocks: 3,            // Wait 3 blocks for confirmation
}).await?;
```

##  Discovery Configuration

### Hardware Detection

```rust
use lib_network::discovery::HardwareConfig;

let hardware_config = HardwareConfig {
    // Enable/disable hardware detection
    bluetooth_detection: true,
    wifi_detection: true,
    lorawan_detection: true,
    
    // Detection timeouts
    bluetooth_scan_timeout_s: 10,
    wifi_scan_timeout_s: 5,
    lorawan_detection_timeout_s: 30,
    
    // Platform-specific options
    linux_use_bluez: true,
    windows_use_winrt: true,
    macos_use_core_bluetooth: true,
};
```

### Network Discovery

```rust
use lib_network::discovery::DiscoveryConfig;

let discovery_config = DiscoveryConfig {
    // Peer discovery intervals
    local_discovery_interval_s: 30,    // Local subnet scan
    regional_discovery_interval_s: 300, // LoRaWAN discovery
    global_discovery_interval_s: 600,   // Satellite peer discovery
    
    // Discovery parameters
    max_peers_per_protocol: 10,        // Limit peers per protocol
    peer_timeout_s: 300,               // Peer expiry timeout
    reputation_threshold: 0.5,         // Minimum peer reputation
    
    // Geographic preferences
    prefer_local_peers: true,          // Prioritize local mesh
    max_hop_count: 5,                  // Limit routing hops
};
```

##  Monitoring Configuration

### Network Statistics

```rust
use lib_network::monitoring::MonitoringConfig;

let monitoring_config = MonitoringConfig {
    // Statistics collection
    stats_collection_interval_s: 60,   // Collect stats every minute
    stats_retention_hours: 24,         // Keep 24 hours of stats
    
    // Health monitoring
    health_check_interval_s: 10,       // Check health every 10s
    connection_health_threshold: 0.8,  // 80% connection success rate
    latency_health_threshold_ms: 1000, // Max 1s acceptable latency
    
    // Alerts
    enable_health_alerts: true,
    alert_email: "admin@example.com".to_string(),
    alert_webhook: Some("https://hooks.slack.com/...".to_string()),
};
```

### Logging Configuration

```rust
use tracing::{info, warn, error};
use tracing_subscriber::{EnvFilter, fmt::layer};

// Configure comprehensive logging
tracing_subscriber::registry()
    .with(EnvFilter::new("lib_network=debug,info"))
    .with(layer().with_target(false))
    .init();

// Log levels by component:
// TRACE: Detailed protocol packet information
// DEBUG: Connection establishment, peer discovery
// INFO:  Server lifecycle, major operations
// WARN:  Recoverable errors, degraded performance
// ERROR: Critical failures requiring attention
```

##  Platform-Specific Configuration

### Windows Configuration

```rust
#[cfg(target_os = "windows")]
use lib_network::platform::windows::WindowsConfig;

#[cfg(target_os = "windows")]
let windows_config = WindowsConfig {
    // Bluetooth configuration
    use_winrt_bluetooth: true,          // Use modern WinRT APIs
    bluetooth_device_watcher: true,     // Background device scanning
    
    // WiFi Direct configuration
    use_wifi_direct_api: true,          // Use Windows WiFi Direct
    wifi_direct_role: WiFiDirectRole::GroupOwner,
    
    // Firewall configuration
    auto_configure_firewall: true,      // Auto-add firewall rules
    firewall_rule_name: "ZHTP-Mesh".to_string(),
};
```

### Linux Configuration

```rust
#[cfg(target_os = "linux")]
use lib_network::platform::linux::LinuxConfig;

#[cfg(target_os = "linux")]
let linux_config = LinuxConfig {
    // Bluetooth configuration (BlueZ)
    use_bluez_dbus: true,               // Use D-Bus interface
    bluez_adapter_path: "/org/bluez/hci0".to_string(),
    
    // Network configuration
    use_network_manager: true,          // Use NetworkManager
    create_mesh_interface: true,        // Create dedicated mesh interface
    
    // GPIO configuration (Raspberry Pi)
    enable_gpio: true,                  // Enable GPIO for LoRaWAN
    spi_device_path: "/dev/spidev0.0".to_string(),
    reset_gpio_pin: 22,                 // LoRaWAN module reset pin
};
```

### macOS Configuration

```rust
#[cfg(target_os = "macos")]
use lib_network::platform::macos::MacOSConfig;

#[cfg(target_os = "macos")]
let macos_config = MacOSConfig {
    // Core Bluetooth configuration
    use_core_bluetooth: true,           // Use Core Bluetooth framework
    bluetooth_restore_identifier: "ZHTPMesh".to_string(),
    
    // Network framework configuration
    use_network_framework: true,        // Use Network.framework
    bonjour_service_type: "_zhtp._tcp".to_string(),
    
    // Permissions
    request_bluetooth_permission: true, // Request permission on startup
    request_location_permission: false, // Location not required
};
```

##  Dynamic Configuration

### Runtime Configuration Updates

```rust
// Update configuration while running
server.update_max_connections(200).await?;
server.update_security_config(new_security_config).await?;
server.add_bootstrap_peer("192.168.1.100:33444".to_string()).await?;

// Protocol management
server.enable_protocol(NetworkProtocol::LoRaWAN).await?;
server.disable_protocol(NetworkProtocol::Satellite).await?;

// Economic configuration updates
server.update_routing_rewards(15, 2, 8).await?;  // base, size, hop multipliers
```

### Configuration Persistence

```rust
use serde::{Serialize, Deserialize};
use std::fs;

#[derive(Serialize, Deserialize)]
struct MeshNodeConfig {
    network: NetworkConfig,
    security: SecurityConfig,
    economic: EconomicConfig,
    monitoring: MonitoringConfig,
}

impl MeshNodeConfig {
    // Save configuration to file
    pub fn save(&self, path: &str) -> Result<()> {
        let config_toml = toml::to_string(self)?;
        fs::write(path, config_toml)?;
        Ok(())
    }
    
    // Load configuration from file
    pub fn load(path: &str) -> Result<Self> {
        let config_str = fs::read_to_string(path)?;
        let config: MeshNodeConfig = toml::from_str(&config_str)?;
        Ok(config)
    }
}

// Usage
let config = MeshNodeConfig::load("mesh-config.toml")?;
let server = ZhtpMeshServer::with_config(config).await?;
```

##  Testing Configuration

### Development Configuration

```rust
#[cfg(debug_assertions)]
fn create_dev_config() -> NetworkConfig {
    NetworkConfig {
        node_id: [42u8; 32],  // Fixed ID for testing
        listen_port: 33445,   // Non-standard port
        max_peers: 10,        // Limited for testing
        protocols: vec![
            NetworkProtocol::BluetoothLE,  // Always testable
        ],
        listen_addresses: vec!["127.0.0.1:33445".to_string()],
        bootstrap_peers: vec![], // No external dependencies
    }
}
```

### Performance Testing Configuration

```rust
fn create_performance_config() -> NetworkConfig {
    NetworkConfig {
        max_peers: 1000,                // High connection count
        protocols: vec![
            NetworkProtocol::WiFiDirect, // High bandwidth protocol only
        ],
        // Optimized for throughput testing
        ..NetworkConfig::default()
    }
}
```

## 📚 Configuration Examples

### Home Mesh Node

```rust
// Optimal configuration for home mesh networking
fn home_mesh_config() -> NetworkConfig {
    NetworkConfig {
        max_peers: 50,
        protocols: vec![
            NetworkProtocol::BluetoothLE,  // Phone connectivity
            NetworkProtocol::WiFiDirect,   // High bandwidth local
        ],
        // Focus on local mesh with internet bridge capability
        ..NetworkConfig::default()
    }
}
```

### IoT Sensor Node

```rust
// Low-power configuration for IoT devices
fn iot_sensor_config() -> NetworkConfig {
    NetworkConfig {
        max_peers: 5,                   // Limited connections
        protocols: vec![
            NetworkProtocol::LoRaWAN,   // Long range, low power
        ],
        // Optimized for battery life
        ..NetworkConfig::default()
    }
}
```

### Relay/Gateway Node

```rust
// High-capacity relay node configuration
fn relay_node_config() -> NetworkConfig {
    NetworkConfig {
        max_peers: 500,                 // High capacity
        protocols: vec![
            NetworkProtocol::BluetoothLE,
            NetworkProtocol::WiFiDirect,
            NetworkProtocol::LoRaWAN,
            NetworkProtocol::Satellite,
        ],
        // All protocols enabled for maximum reach
        ..NetworkConfig::default()
    }
}
```

---

This configuration guide covers all aspects of setting up and tuning ZHTP lib-network for various use cases. Adjust settings based on your specific hardware, network conditions, and performance requirements. 