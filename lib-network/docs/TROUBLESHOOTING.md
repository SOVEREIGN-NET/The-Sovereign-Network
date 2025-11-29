# ZHTP lib-network Troubleshooting Guide

This guide helps diagnose and resolve common issues with the ZHTP mesh networking system.

##  Quick Diagnostics

### Check System Status

```rust
use lib_network::{ZhtpMeshServer, HardwareCapabilities};

// Basic health check
async fn diagnose_mesh_health(server: &ZhtpMeshServer) -> Result<()> {
    // 1. Check if server is running
    if server.is_emergency_stopped().await {
        println!(" Server is in emergency stop mode");
        return Ok(());
    }
    
    // 2. Check network statistics
    let stats = server.get_network_stats().await;
    println!(" Network Status:");
    println!("   Active Connections: {}", stats.active_connections);
    println!("   Network Health: {:.1}%", stats.network_health * 100.0);
    println!("   Total Data Routed: {} MB", stats.total_data_routed / 1_000_000);
    
    // 3. Check DHT status
    let dht_status = server.get_dht_status().await;
    println!("🗃️  DHT Status:");
    println!("   Connected: {}", dht_status.connected);
    println!("   Peer Count: {}", dht_status.peer_count);
    println!("   Cache Size: {} items", dht_status.cache_size);
    
    // 4. Check hardware capabilities
    let capabilities = HardwareCapabilities::detect().await?;
    println!(" Hardware Status:");
    for protocol in capabilities.get_enabled_protocols() {
        println!("    {}", protocol);
    }
    
    Ok(())
}
```

### Connection Status Check

```bash
# Check network connectivity
ping 8.8.8.8

# Check ZHTP DHT port
netstat -an | grep 33444

# Check for ZHTP processes
ps aux | grep zhtp
```

##  Common Issues and Solutions

### 1. Server Won't Start

#### Symptoms
- Server startup fails with errors
- No mesh connections established
- Hardware detection failures

#### Diagnostic Steps

```rust
// Enable verbose logging
use tracing_subscriber::{EnvFilter, fmt::layer};

tracing_subscriber::registry()
    .with(EnvFilter::new("lib_network=trace,debug"))
    .with(layer().with_target(false))
    .init();

// Check startup sequence
match server.start().await {
    Err(e) => {
        println!("Startup failed: {}", e);
        
        // Check specific error conditions
        let error_msg = e.to_string();
        
        if error_msg.contains("hardware") {
            println!("💡 Hardware detection issue - check device drivers");
        } else if error_msg.contains("permission") {
            println!("💡 Permission denied - run as administrator/root");
        } else if error_msg.contains("port") {
            println!("💡 Port conflict - another process using DHT port");
        }
    }
    Ok(_) => println!(" Server started successfully")
}
```

#### Common Causes and Fixes

**Hardware Detection Failures:**
```bash
# Linux - Check Bluetooth
sudo systemctl status bluetooth
sudo hciconfig  # Should show hci0

# Linux - Check WiFi
iwconfig
sudo iw dev  # Should show wireless interfaces

# Windows - Check Device Manager
# Look for Bluetooth and WiFi devices
devmgmt.msc

# macOS - Check Bluetooth
system_profiler SPBluetoothDataType
```

**Port Conflicts:**
```bash
# Check what's using the DHT port (33444)
sudo netstat -tulpn | grep 33444
sudo lsof -i :33444

# Kill conflicting process
sudo kill <PID>
```

**Permission Issues:**
```bash
# Linux - Add user to bluetooth group
sudo usermod -a -G bluetooth $USER

# Linux - Grant CAP_NET_RAW for BLE (without sudo)
sudo setcap cap_net_raw+ep /usr/bin/your-zhtp-binary

# Windows - Run as Administrator
# Right-click executable → "Run as administrator"
```

### 2. No Peers Discovered

#### Symptoms
- Mesh server starts but finds no peers
- Discovery protocols active but no connections
- Isolated node with no mesh connectivity

#### Diagnostic Steps

```rust
// Test peer discovery
async fn test_discovery(server: &ZhtpMeshServer) -> Result<()> {
    use lib_network::discovery::{get_discovery_statistics};
    
    let stats = get_discovery_statistics().await?;
    println!(" Discovery Statistics:");
    println!("   Local peers: {}", stats.local_peers);
    println!("   Regional peers: {}", stats.regional_peers);
    println!("   Global peers: {}", stats.global_peers);
    println!("   Relay peers: {}", stats.relay_peers);
    
    if stats.local_peers == 0 {
        println!("  No local peers found - check Bluetooth/WiFi");
    }
    
    if stats.regional_peers == 0 {
        println!("  No regional peers found - check LoRaWAN hardware");
    }
    
    Ok(())
}
```

#### Solutions

**Enable Bluetooth Discoverability:**
```bash
# Linux
sudo bluetoothctl
[bluetooth]# power on
[bluetooth]# discoverable on
[bluetooth]# pairable on

# Windows
# Settings → Bluetooth & devices → Make your device discoverable

# macOS  
# System Preferences → Bluetooth → Advanced → Make discoverable
```

**WiFi Direct Setup:**
```bash
# Linux - Check WiFi Direct support
sudo iw list | grep -A 10 "Supported interface modes" | grep P2P

# Create WiFi Direct interface
sudo iw dev wlan0 interface add p2p0 type __p2pdev
```

**Network Firewall Configuration:**
```bash
# Linux - Allow ZHTP DHT port
sudo ufw allow 33444/udp
sudo iptables -A INPUT -p udp --dport 33444 -j ACCEPT

# Windows - Add firewall rule
netsh advfirewall firewall add rule name="ZHTP DHT" dir=in action=allow protocol=UDP localport=33444

# macOS - Allow incoming connections
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /path/to/zhtp-binary
```

### 3. Poor Network Performance

#### Symptoms
- High latency between mesh peers
- Low throughput despite good connections
- Frequent connection drops

#### Performance Diagnostics

```rust
// Monitor network performance
async fn monitor_performance(server: &ZhtpMeshServer) {
    loop {
        let stats = server.get_network_stats().await;
        
        println!(" Performance Metrics:");
        println!("   Average Latency: {:.1}ms", stats.average_latency_ms);
        println!("   Throughput: {:.2} Mbps", stats.throughput_mbps);
        println!("   Error Rate: {:.2}%", 
            stats.connection_errors as f64 / stats.total_connections as f64 * 100.0);
        
        // Alert on performance issues
        if stats.average_latency_ms > 1000.0 {
            println!("  High latency detected!");
        }
        
        if stats.throughput_mbps < 1.0 {
            println!("  Low throughput detected!");
        }
        
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
    }
}
```

#### Performance Optimization

**Protocol Selection:**
```rust
// Prioritize high-performance protocols
let optimized_protocols = vec![
    NetworkProtocol::WiFiDirect,    // Highest throughput
    NetworkProtocol::BluetoothLE,   // Most compatible
    NetworkProtocol::LoRaWAN,       // Long range backup
];
```

**Connection Limits:**
```rust
// Optimize connection count
server.set_max_connections(50).await?;  // Reduce if performance issues

// Monitor connection status
let (current, max, at_limit) = server.get_connection_status().await;
if at_limit {
    println!("  Connection limit reached - may affect performance");
}
```

**Hardware Optimization:**
```bash
# Linux - Optimize Bluetooth
echo 'options bluetooth disable_ertm=1' | sudo tee -a /etc/modprobe.d/bluetooth.conf
sudo systemctl restart bluetooth

# Increase UDP buffer sizes
echo 'net.core.rmem_max = 16777216' | sudo tee -a /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### 4. DHT Content Issues

#### Symptoms
- Content not found in DHT
- Slow content retrieval
- Content storage failures

#### DHT Diagnostics

```rust
// Test DHT operations
async fn test_dht(server: &ZhtpMeshServer) -> Result<()> {
    // Test content storage
    let test_content = b"Hello ZHTP Mesh!";
    let success = server.dht.read().await
        .store_content("test.zhtp", "/hello", test_content.to_vec(), 
                      "127.0.0.1:33444".parse().unwrap())
        .await?;
    
    if !success {
        println!(" DHT storage test failed");
        return Ok(());
    }
    
    // Test content retrieval
    let retrieved = server.dht.read().await
        .query_content("test.zhtp", "/hello", 
                      "127.0.0.1:33444".parse().unwrap())
        .await?;
    
    match retrieved {
        Some(hash) => println!(" DHT retrieval successful: {:?}", hash),
        None => println!(" DHT retrieval failed"),
    }
    
    Ok(())
}
```

#### DHT Fixes

**Clear Corrupted Cache:**
```rust
// Clear DHT cache if corrupted
server.clear_dht_cache().await;
println!("🗑️  DHT cache cleared");
```

**Check Storage Backend:**
```rust
// Verify lib-storage integration
let storage_status = server.storage.read().await.get_status().await?;
println!(" Storage Status: {:?}", storage_status);
```

### 5. Economic/Reward Issues

#### Symptoms
- No routing rewards earned
- Wallet balance not updating
- Payment transfers failing

#### Economic Diagnostics

```rust
// Check economic status
async fn check_economics(server: &ZhtpMeshServer) -> Result<()> {
    // Check routing rewards
    let balance = server.get_routing_rewards_balance().await?;
    println!(" Routing Rewards Balance: {} tokens", balance);
    
    // Check revenue pools
    let pools = server.get_revenue_pools().await;
    println!("🏦 Revenue Pools:");
    for (pool, amount) in pools {
        println!("   {}: {} tokens", pool, amount);
    }
    
    // Verify node ownership
    let is_owner = server.verify_node_ownership(&owner_key).await;
    println!(" Node Ownership Verified: {}", is_owner);
    
    Ok(())
}
```

#### Economic Fixes

**Verify Wallet Configuration:**
```rust
// Check wallet setup
let owner_wallet = server.owner_wallet.read().await;
let routing_wallet = server.routing_rewards_wallet.read().await;

println!("👛 Owner Wallet: {}", owner_wallet.id);
println!("💳 Routing Wallet: {}", routing_wallet.id);
println!(" Balance: {} tokens", routing_wallet.balance);
```

**Test Routing Proof Recording:**
```rust
// Manually test routing rewards
let test_hash = [42u8; 32];
let result = server.record_routing_proof(
    test_hash,
    source_key,
    dest_key,
    1024,  // 1KB message
    2      // 2 hops
).await;

match result {
    Ok(_) => println!(" Routing proof recorded successfully"),
    Err(e) => println!(" Routing proof failed: {}", e),
}
```

##  Advanced Debugging

### Enable Detailed Logging

```rust
// Maximum logging detail
use tracing_subscriber::{EnvFilter, fmt::layer};

tracing_subscriber::registry()
    .with(EnvFilter::new("lib_network=trace,lib_crypto=debug,lib_storage=debug"))
    .with(layer()
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true))
    .init();
```

### Network Packet Analysis

```bash
# Capture ZHTP DHT packets
sudo tcpdump -i any port 33444 -w zhtp-traffic.pcap

# Analyze with Wireshark
wireshark zhtp-traffic.pcap
```

### System Resource Monitoring

```bash
# Monitor CPU and memory usage
top -p $(pgrep zhtp)

# Monitor network interfaces
watch -n 1 'cat /proc/net/dev'

# Monitor Bluetooth connections
watch -n 1 'bluetoothctl info'
```

### Hardware Testing

```rust
// Test individual protocol functionality
async fn test_protocols() -> Result<()> {
    use lib_network::protocols::{bluetooth::*, wifi_direct::*};
    
    // Test Bluetooth LE
    let mut bt_protocol = BluetoothMeshProtocol::new([1u8; 32])?;
    match bt_protocol.start_discovery().await {
        Ok(_) => println!(" Bluetooth LE working"),
        Err(e) => println!(" Bluetooth LE failed: {}", e),
    }
    
    // Test WiFi Direct
    let mut wifi_protocol = WiFiDirectMeshProtocol::new([2u8; 32])?;
    match wifi_protocol.start_discovery().await {
        Ok(_) => println!(" WiFi Direct working"),
        Err(e) => println!(" WiFi Direct failed: {}", e),
    }
    
    Ok(())
}
```

##  Diagnostic Checklist

### Pre-Startup Checklist

- [ ] Hardware drivers installed and updated
- [ ] Required permissions granted (admin/root if needed)
- [ ] Firewall ports opened (33444/UDP)
- [ ] Bluetooth enabled and discoverable
- [ ] WiFi adapter supports Direct/P2P mode
- [ ] LoRaWAN hardware connected (if applicable)
- [ ] Sufficient disk space for DHT cache
- [ ] System time synchronized (for crypto operations)

### Runtime Health Checks

- [ ] Server starts without errors
- [ ] At least one protocol successfully initialized
- [ ] Hardware capabilities detected correctly
- [ ] DHT listening on correct port
- [ ] Peer discovery finding other nodes
- [ ] Routing rewards being earned
- [ ] Network statistics updating
- [ ] No emergency stop triggered

### Performance Monitoring

- [ ] Average latency < 500ms for local peers
- [ ] Throughput > 1 Mbps for WiFi Direct
- [ ] Connection success rate > 90%
- [ ] DHT cache hit ratio > 80%
- [ ] Economic rewards accumulating
- [ ] No frequent disconnections
- [ ] Memory usage stable over time

## 🆘 Getting Help

### Collecting Debug Information

```rust
// Generate comprehensive debug report
async fn generate_debug_report(server: &ZhtpMeshServer) -> Result<String> {
    let mut report = String::new();
    
    // System info
    report.push_str(&format!("ZHTP Debug Report - {}\n", chrono::Utc::now()));
    report.push_str(&format!("OS: {}\n", std::env::consts::OS));
    report.push_str(&format!("Arch: {}\n", std::env::consts::ARCH));
    
    // Hardware capabilities
    let capabilities = HardwareCapabilities::detect().await?;
    report.push_str(&format!("Hardware: {:?}\n", capabilities));
    
    // Network statistics
    let stats = server.get_network_stats().await;
    report.push_str(&format!("Network Stats: {:?}\n", stats));
    
    // DHT status
    let dht_status = server.get_dht_status().await;
    report.push_str(&format!("DHT Status: {:?}\n", dht_status));
    
    // Connection status
    let (current, max, at_limit) = server.get_connection_status().await;
    report.push_str(&format!("Connections: {}/{} (limited: {})\n", 
                            current, max, at_limit));
    
    Ok(report)
}
```

### Community Resources

- **GitHub Issues**: Report bugs and feature requests
- **Discord Community**: Real-time help and discussion
- **Documentation**: Comprehensive guides and API reference
- **Stack Overflow**: Technical Q&A with `zhtp` tag

### Professional Support

For enterprise deployments and critical issues:
- **Priority Support**: Dedicated technical assistance
- **Custom Integration**: Professional services for specialized deployments
- **Training Programs**: Team training for ZHTP mesh networking

---

This troubleshooting guide covers the most common issues encountered when deploying ZHTP mesh networking. For additional help, consult the community resources or professional support options. 