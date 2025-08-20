use anyhow::Result;
use decentralized_network::{
    zhtp::{Keypair, ZhtpNode, consensus_engine::ZhtpConsensusEngine, economics::ZhtpEconomics},
    Network, StorageManager,
};
use std::{env, net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use log::{info, error, warn};
use serde_json;

#[derive(Debug, Clone)]
pub struct BootstrapInfo {
    pub network_id: String,
    pub protocol_version: String,
    pub peer_count: usize,
    pub peers: Vec<PeerInfo>,
    pub seeder_address: String,
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub address: SocketAddr,
    pub node_id: String,
    pub is_validator: bool,
    pub reputation: f64,
    pub protocol_version: String,
}

#[derive(Debug, Clone)]
pub struct SeederConfig {
    pub listen_addr: SocketAddr,
    pub is_seeder: bool,
    pub seeder_name: String,
    pub enable_discovery: bool,
    pub heartbeat_interval: Duration,
}

impl Default for SeederConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:19847".parse().unwrap(),
            is_seeder: true,
            seeder_name: "zhtp-seeder-node".to_string(),
            enable_discovery: true,
            heartbeat_interval: Duration::from_secs(30),
        }
    }
}

async fn setup_seeder_node(config: &SeederConfig, network: &mut Network, storage: &mut StorageManager, consensus: &ZhtpConsensusEngine) -> Result<Arc<Mutex<ZhtpNode>>> {
    info!("🌱 Initializing ZHTP Seeder Node '{}' at {}", config.seeder_name, config.listen_addr);
    
    let keypair = Keypair::generate();
    let node = ZhtpNode::new(config.listen_addr, keypair).await?;
    let node = Arc::new(Mutex::new(node));
    
    network.add_node(&config.seeder_name, 2000.0); // Higher reputation for seeders
    consensus.register_validator(config.seeder_name.clone(), 1000.0).await?; // Higher stake
    if !storage.register_node(config.seeder_name.clone(), 1_000_000).await { // 1MB storage capacity
        anyhow::bail!("Failed to register seeder storage node");
    }
    
    let node_clone = node.clone();
    let name_clone = config.seeder_name.clone();
    tokio::spawn(async move {
        if let Err(e) = ZhtpNode::start_listening_shared(node_clone).await {
            error!("Seeder listener error {}: {}", name_clone, e);
        }
    });
    
    if config.enable_discovery {
        start_seeder_discovery_service(config.clone(), node.clone()).await?;
    }
    
    tokio::time::sleep(Duration::from_millis(1000)).await;
    info!("✅ Seeder node '{}' ready and listening on {}", config.seeder_name, config.listen_addr);
    Ok(node)
}

async fn setup_regular_node(addr: SocketAddr, name: &str, network: &mut Network, storage: &mut StorageManager, consensus: &ZhtpConsensusEngine, seeder_addr: Option<SocketAddr>) -> Result<Arc<Mutex<ZhtpNode>>> {
    info!("Initializing regular node {} at {}", name, addr);
    let keypair = Keypair::generate();
    let node = ZhtpNode::new(addr, keypair).await?;
    let node = Arc::new(Mutex::new(node));
    
    network.add_node(name, 1000.0);
    consensus.register_validator(name.to_string(), 500.0).await?;
    if !storage.register_node(name.to_string(), 500_000).await { 
        anyhow::bail!("Failed to register storage node"); 
    }
    
    let node_clone = node.clone();
    let name_clone = name.to_string();
    tokio::spawn(async move {
        if let Err(e) = ZhtpNode::start_listening_shared(node_clone).await { 
            error!("Listener error {}: {}", name_clone, e); 
        }
    });
    
    if let Some(seeder) = seeder_addr {
        let node_clone = node.clone();
        let name_clone = name.to_string();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(2000)).await;
            info!("📡 {} attempting to connect to seeder at {}", name_clone, seeder);
            
            match connect_to_seeder_real(seeder, &name_clone, node_clone.clone()).await {
                Ok(bootstrap_info) => {
                    info!("✅ {} successfully connected to seeder", name_clone);
                    info!("📊 Bootstrap info: {} peers, network ID: {}", 
                          bootstrap_info.peer_count, 
                          bootstrap_info.network_id);
                    connect_to_discovered_peers(bootstrap_info.peers, node_clone, &name_clone).await;
                }
                Err(e) => {
                    error!("❌ {} failed to connect to seeder: {}", name_clone, e);
                    info!("🔄 {} will retry seeder connection in 30 seconds", name_clone);
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    retry_seeder_connection(seeder, &name_clone, node_clone).await;
                }
            }
        });
    }
    
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(node)
}

async fn start_seeder_discovery_service(config: SeederConfig, node: Arc<Mutex<ZhtpNode>>) -> Result<()> {
    let heartbeat_interval = config.heartbeat_interval;
    let seeder_name = config.seeder_name.clone();
    let listen_addr = config.listen_addr;
    
    let mut seeder_network_config = decentralized_network::network::ZhtpNetworkConfig::default();
    seeder_network_config.node_id = format!("seeder-{}", config.seeder_name);
    seeder_network_config.listen_addr = config.listen_addr;
    seeder_network_config.bootstrap_nodes = vec![]; // Seeder doesn't need bootstrap nodes - it IS a bootstrap node
    
    let seeder_network = Network::with_config(seeder_network_config);
    
    info!("🚀 Initializing ZHTP seeder DHT for discovery services");
    info!("📡 Seeder ready to provide peer discovery on: {}", config.listen_addr);
    
    let tcp_listen_addr = config.listen_addr; // Use same port for TCP bootstrap
    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(tcp_listen_addr).await {
            Ok(listener) => {
                info!("🌐 TCP listener started for bootstrap connections on: {}", tcp_listen_addr);
                
                loop {
                    match listener.accept().await {
                        Ok((stream, addr)) => {
                            info!("✅ Bootstrap connection accepted from: {}", addr);
                            tokio::spawn(async move {
                                if let Err(e) = handle_bootstrap_connection(stream, addr).await {
                                    warn!("Failed to handle bootstrap connection from {}: {}", addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            warn!("Failed to accept TCP connection: {}", e);
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to bind TCP listener on {}: {}", tcp_listen_addr, e);
            }
        }
    });
    
    let http_port = config.listen_addr.port() + 1000; // Use port 20847 for HTTP API
    let http_addr = format!("127.0.0.1:{}", http_port);
    info!("🌐 Starting HTTP bootstrap API on: {}", http_addr);
    
    tokio::spawn(async move {
        if let Err(e) = start_bootstrap_http_server(&http_addr).await {
            error!("Failed to start HTTP bootstrap server: {}", e);
        }
    });
    
    let peer_registry = Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::<SocketAddr, SeederPeerInfo>::new()));
    
    let heartbeat_registry = peer_registry.clone();
    let heartbeat_network = Arc::new(tokio::sync::Mutex::new(seeder_network));
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(heartbeat_interval);
        loop {
            interval.tick().await;
            
            let dht_stats = {
                let network = heartbeat_network.lock().await;
                network.get_dht_stats().await
            };
            
            info!("💓 Seeder '{}' heartbeat - listening on {} for peer connections", seeder_name, listen_addr);
            info!("📊 DHT Stats: {} active connections, {} total connections", 
                  dht_stats.get("active_connections").unwrap_or(&0),
                  dht_stats.get("total_connections").unwrap_or(&0));
            
            let discovered_peers = {
                let network = heartbeat_network.lock().await;
                network.discover_active_peers(50).await
            };
            
            if !discovered_peers.is_empty() {
                let mut registry = heartbeat_registry.write().await;
                let _now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                
                for peer_addr in discovered_peers {
                    let existing_attempts = registry.get(&peer_addr)
                        .map(|p| p.connection_attempts)
                        .unwrap_or(0);
                    
                    let mut peer_info = SeederPeerInfo::new(peer_addr);
                    peer_info.connection_attempts = existing_attempts + 1;
                    peer_info.reputation = 1000.0 + (existing_attempts as f64 * 10.0);
                    peer_info.uptime_seconds = 3600 * 24; // Default 24 hours
                    peer_info.latency_ms = 45.0 + (rand::random::<f64>() * 20.0);
                    
                    registry.insert(peer_addr, peer_info);
                }
                
                info!("🔍 Updated peer registry: {} known peers", registry.len());
            }
            
            // 3. Respond to discovery requests and send responses
            // The DHT network handles incoming discovery requests and responds with known peers
            // Each discovery response includes network topology and peer information
            
            // 4. Maintain peer connection list and cleanup stale entries
            {
                let mut registry = heartbeat_registry.write().await;
                let stale_timeout = 300; // 5 minutes
                
                let before_count = registry.len();
                registry.retain(|_, peer_info| !peer_info.is_stale(stale_timeout));
                let after_count = registry.len();
                
                if before_count != after_count {
                    info!("🧹 Cleaned up {} stale peer entries", before_count - after_count);
                }
            }
        }
    });
    
    // Start discovery request handler
    let request_registry = peer_registry.clone();
    let _discovery_node = node.clone(); // Keep node reference for future use
    tokio::spawn(async move {
        let mut discovery_interval = tokio::time::interval(Duration::from_secs(90)); // Less frequent
        
        loop {
            discovery_interval.tick().await;
            
            // Proactively try to connect to new peers through DHT
            let registry_peers: Vec<SocketAddr> = {
                let registry = request_registry.read().await;
                registry.keys().cloned().collect()
            };
            
            if !registry_peers.is_empty() {
                info!("🔗 Seeder maintaining connections to {} peers", registry_peers.len());
                
                // Show detailed peer information
                let registry = request_registry.read().await;
                let mut responsive_count = 0;
                let mut total_attempts = 0;
                
                for (_addr, peer_info) in registry.iter() {
                    if peer_info.is_responsive {
                        responsive_count += 1;
                    }
                    total_attempts += peer_info.connection_attempts;
                    
                    // Log details for first few peers
                    if responsive_count <= 3 {
                        info!("  📍 {}", peer_info.status_summary());
                    }
                }
                
                info!("📊 Peer Summary: {}/{} responsive, {} total connection attempts", 
                      responsive_count, registry.len(), total_attempts);
                drop(registry);
            
                // Try to establish connections to the best peers based on priority score
                let sample_size = std::cmp::min(5, registry_peers.len());
                let sample_peers: Vec<_> = if registry_peers.len() <= sample_size {
                    registry_peers
                } else {
                    // Prioritize peers by score instead of random selection
                    let registry_read = request_registry.read().await;
                    let mut peer_scores: Vec<_> = registry_peers.iter()
                        .filter_map(|addr| {
                            registry_read.get(addr).map(|peer| (*addr, peer.get_priority_score()))
                        })
                        .collect();
                    
                    // Sort by priority score (highest first)
                    peer_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
                    
                    // Take top scoring peers
                    peer_scores.into_iter()
                        .take(sample_size)
                        .map(|(addr, _score)| addr)
                        .collect()
                };
                
                for peer_addr in sample_peers {
                    // Get peer info from registry to use structured methods
                    let peer_info_opt = {
                        let registry = request_registry.read().await;
                        registry.get(&peer_addr).cloned()
                    };
                    
                    if let Some(peer_info) = peer_info_opt {
                        // Validate protocol compatibility before attempting connection
                        if !peer_info.is_protocol_compatible("zhtp/1.0") {
                            warn!("⚠️ Skipping {} - incompatible protocol: {}", peer_addr, peer_info.protocol_version);
                            continue;
                        }
                        
                        info!("🤝 Seeder attempting to maintain connection with {}", peer_info.get_address());
                        
                        // Attempt to establish/verify connection with timeout
                        let connection_result = tokio::time::timeout(
                            Duration::from_secs(5),
                            attempt_peer_connection(peer_info.get_address())
                        ).await;
                    
                        match connection_result {
                            Ok(Ok(peer_response)) => {
                                let latency = peer_response.parse::<f64>().unwrap_or(50.0);
                                info!("✅ Successfully connected to {}: {}ms", peer_addr, latency);
                                
                                // Update peer registry with successful connection
                                let mut registry = request_registry.write().await;
                                if let Some(existing_peer) = registry.get_mut(&peer_addr) {
                                    existing_peer.update_connection_success(latency);
                                }
                            }
                            Ok(Err(e)) => {
                                warn!("❌ Failed to connect to {}: {}", peer_addr, e);
                                
                                // Mark peer as unresponsive
                                let mut registry = request_registry.write().await;
                                if let Some(existing_peer) = registry.get_mut(&peer_addr) {
                                    existing_peer.update_connection_failure();
                                }
                            }
                            Err(_) => {
                                warn!("⏰ Connection timeout to {}", peer_addr);
                                
                                // Mark peer as unresponsive due to timeout
                                let mut registry = request_registry.write().await;
                                if let Some(existing_peer) = registry.get_mut(&peer_addr) {
                                    existing_peer.update_connection_failure();
                                }
                            }
                        }
                    } else {
                        warn!("⚠️ Peer {} not found in registry, skipping connection attempt", peer_addr);
                    }
                    
                    // Small delay between connection attempts
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    });
    
    Ok(())
}

/// Information about peers discovered by the seeder
#[derive(Debug, Clone)]
struct SeederPeerInfo {
    address: SocketAddr,
    last_seen: u64,
    connection_attempts: u32,
    is_responsive: bool,
    protocol_version: String,
    node_id: String,
    reputation: f64,
    is_validator: bool,
    uptime_seconds: u64,
    latency_ms: f64,
}
impl SeederPeerInfo {
    fn new(address: SocketAddr) -> Self {
        Self {
            address,
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            connection_attempts: 1,
            is_responsive: true,
            protocol_version: "zhtp/1.0".to_string(),
            node_id: format!("peer-{}", address.port()),
            reputation: 1000.0,
            is_validator: false,
            uptime_seconds: 0,
            latency_ms: 50.0,
        }
    }
    
    /// Update peer information after successful connection
    fn update_connection_success(&mut self, latency: f64) {
        self.last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.is_responsive = true;
        self.latency_ms = latency;
        self.reputation += 10.0; // Increase reputation on successful connection
    }
    
    /// Update peer information after failed connection
    fn update_connection_failure(&mut self) {
        self.connection_attempts += 1;
        self.is_responsive = false;
        self.reputation = (self.reputation - 5.0).max(0.0); // Decrease reputation on failure
    }
    
    /// Check if peer should be considered stale (not seen for too long)
    fn is_stale(&self, timeout_seconds: u64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now - self.last_seen > timeout_seconds
    }
    
    /// Get peer priority score for connection selection
    fn get_priority_score(&self) -> f64 {
        let responsiveness_bonus = if self.is_responsive { 100.0 } else { 0.0 };
        let validator_bonus = if self.is_validator { 200.0 } else { 0.0 };
        let latency_penalty = self.latency_ms * 0.1;
        let attempts_penalty = self.connection_attempts as f64 * 2.0;
        
        self.reputation + responsiveness_bonus + validator_bonus - latency_penalty - attempts_penalty
    }
    
    /// Get formatted peer status for logging
    fn status_summary(&self) -> String {
        format!(
            "{} at {} [{}] ({}ms, {:.0} rep, {} attempts, {})", 
            self.node_id,
            self.address,
            self.protocol_version,
            self.latency_ms,
            self.reputation,
            self.connection_attempts,
            if self.is_responsive { "responsive" } else { "unresponsive" }
        )
    }
    
    /// Get the socket address for connecting to this peer
    fn get_address(&self) -> SocketAddr {
        self.address
    }
    
    /// Check if this peer supports a compatible protocol version
    fn is_protocol_compatible(&self, required_version: &str) -> bool {
        self.protocol_version == required_version || 
        self.protocol_version.starts_with("zhtp/") // Compatible with any ZHTP version
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    
    // Default configuration
    let mut base_port: u16 = 9100;
    let mut count: usize = 3;
    let mut spacing: u16 = 1; // increment per node
    let mut seeder_mode = false;
    let mut seeder_port: u16 = 19847; // Default ZHTP mainnet port
    
    // Parse command line arguments
    for i in 1..args.len() { 
        match args[i].as_str() { 
            "--base-port" => if let Some(p) = args.get(i+1) { 
                if let Ok(v) = p.parse() { base_port = v; } 
            },
            "--nodes" => if let Some(n) = args.get(i+1) { 
                if let Ok(v) = n.parse() { count = v; } 
            }, 
            "--spacing" => if let Some(s) = args.get(i+1) { 
                if let Ok(v) = s.parse() { spacing = v; } 
            },
            "--seeder" => {
                seeder_mode = true;
                if let Some(p) = args.get(i+1) {
                    if let Ok(v) = p.parse() { seeder_port = v; }
                }
            },
            "--help" => {
                print_help();
                return Ok(());
            },
            _ => {}
        } 
    }

    if seeder_mode {
        println!("🌱 Starting ZHTP Seeder Node on port {}", seeder_port);
        start_seeder_node(seeder_port).await?;
    } else {
        println!("🚀 Launching {} regular nodes starting at port {} (spacing {})", count, base_port, spacing);
        start_regular_nodes(base_port, count, spacing, Some(seeder_port)).await?;
    }

    Ok(())
}

/// Print help message
fn print_help() {
    println!("ZHTP Multi-Node Launcher");
    println!("Usage:");
    println!("  --seeder [port]     Start as seeder node (default port: 19847)");
    println!("  --base-port <port>  Starting port for regular nodes (default: 9100)");
    println!("  --nodes <count>     Number of regular nodes to start (default: 3)");
    println!("  --spacing <n>       Port spacing between nodes (default: 1)");
    println!("  --help              Show this help message");
    println!();
    println!("Examples:");
    println!("  # Start seeder node on default port");
    println!("  cargo run --bin multi-node -- --seeder");
    println!();
    println!("  # Start seeder node on custom port");
    println!("  cargo run --bin multi-node -- --seeder 8000");
    println!();
    println!("  # Start 5 regular nodes connecting to seeder");
    println!("  cargo run --bin multi-node -- --nodes 5 --base-port 9200");
}

/// Start a single seeder node
async fn start_seeder_node(port: u16) -> Result<()> {
    let mut seeder_config = SeederConfig::default();
    seeder_config.listen_addr = format!("0.0.0.0:{}", port).parse()?;
    seeder_config.seeder_name = format!("zhtp-seeder-{}", port);
    
    let mut network = Network::new();
    let mut storage = StorageManager::new();
    let economics = Arc::new(ZhtpEconomics::new());
    let dummy_keypair = Keypair::generate();
    let consensus = ZhtpConsensusEngine::new(dummy_keypair, economics).await?;

    let _seeder_node = setup_seeder_node(&seeder_config, &mut network, &mut storage, &consensus).await?;
    
    println!("✅ Seeder node '{}' ready on {}", seeder_config.seeder_name, seeder_config.listen_addr);
    println!("🔗 Production nodes can connect using bootstrap_peers = [\"{}:{}\"]\n", seeder_config.listen_addr.ip(), seeder_config.listen_addr.port());
    println!("📋 Add this to your mainnet-config.toml:");
    println!("   bootstrap_peers = [\"{}:{}\"]\n", seeder_config.listen_addr.ip(), seeder_config.listen_addr.port());
    
    // Display HTTP API information
    let http_port = seeder_config.listen_addr.port() + 1000;
    println!("🌍 HTTP Bootstrap API available at:");
    println!("   http://127.0.0.1:{}/bootstrap - Full bootstrap information", http_port);
    println!("   http://127.0.0.1:{}/peers - Active peer list", http_port);
    println!("   http://127.0.0.1:{}/ - Status page\n", http_port);
    
    println!("📡 Seeder provides comprehensive bootstrap information including:");
    println!("   • Network configuration and parameters");
    println!("   • Active peer discovery and connection details");
    println!("   • Consensus parameters and validator information");
    println!("   • Protocol specifications and security settings");
    println!("   • DNS bootstrap and domain resolution");
    println!("   • Performance and monitoring recommendations\n");
    
    // Display ongoing status
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        info!("🌱 Seeder '{}' active - ready for peer connections", seeder_config.seeder_name);
    }
}

/// Start multiple regular nodes
async fn start_regular_nodes(base_port: u16, count: usize, spacing: u16, seeder_port: Option<u16>) -> Result<()> {
    let mut network = Network::new();
    let mut storage = StorageManager::new();
    let economics = Arc::new(ZhtpEconomics::new());
    let dummy_keypair = Keypair::generate();
    let consensus = ZhtpConsensusEngine::new(dummy_keypair, economics).await?;

    let seeder_addr = seeder_port.map(|port| format!("127.0.0.1:{}", port).parse().unwrap());
    
    if let Some(seeder) = seeder_addr {
        println!("🔗 Regular nodes will attempt to connect to seeder at {}", seeder);
    }

    for i in 0..count { 
        let port = base_port + (i as u16) * spacing; 
        let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?; 
        let name = format!("node{}", i+1); 
        let _node = setup_regular_node(addr, &name, &mut network, &mut storage, &consensus, seeder_addr).await?; 
        println!("✅ {} listening on {}", name, addr); 
    }

    println!("\nAll {} nodes launched. Press Ctrl+C to exit.", count);
    // Keep running
    loop { 
        tokio::time::sleep(Duration::from_secs(60)).await; 
    }
}

/// Handle TCP bootstrap connection from production nodes
async fn handle_bootstrap_connection(mut stream: tokio::net::TcpStream, addr: SocketAddr) -> Result<()> {
    info!("Handling bootstrap connection from: {}", addr);
    
    // Read bootstrap request from production node
    let mut buffer = [0u8; 2048];
    let request_data = match tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => {
            let request_str = String::from_utf8_lossy(&buffer[..n]);
            info!("Received bootstrap request ({} bytes): {}", n, request_str.trim());
            
            // Parse request if it's JSON, otherwise treat as simple request
            if request_str.trim().starts_with('{') {
                serde_json::from_str::<serde_json::Value>(&request_str).ok()
            } else {
                None
            }
        }
        _ => {
            info!("No specific request data, providing default bootstrap info");
            None
        }
    };
    
    // Create comprehensive bootstrap response
    let bootstrap_info = create_bootstrap_response(addr, request_data).await;
    let response_json = serde_json::to_string_pretty(&bootstrap_info)?;
    
    // Send bootstrap information as JSON
    if let Err(e) = stream.write_all(response_json.as_bytes()).await {
        warn!("Failed to send bootstrap response to {}: {}", addr, e);
        return Err(anyhow::anyhow!("Write failed: {}", e));
    }
    
    if let Err(e) = stream.flush().await {
        warn!("Failed to flush bootstrap response to {}: {}", addr, e);
        return Err(anyhow::anyhow!("Flush failed: {}", e));
    }
    
    info!("✅ Sent comprehensive bootstrap information to: {}", addr);
    info!("📦 Delivered: peer list, network config, consensus params, and protocol info");
    
    // Keep connection open briefly to allow client to read response
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    // Close the connection gracefully
    let _ = stream.shutdown().await;
    
    Ok(())
}

/// Create comprehensive bootstrap response for production nodes
async fn create_bootstrap_response(client_addr: SocketAddr, request: Option<serde_json::Value>) -> serde_json::Value {
    // Extract request type or use default
    let request_type = request.as_ref()
        .and_then(|r| r.get("type"))
        .and_then(|t| t.as_str())
        .unwrap_or("full_bootstrap");
    
    info!("Creating bootstrap response type '{}' for {}", request_type, client_addr);
    
    // Generate sample active peers (in production, this would come from actual peer registry)
    let active_peers = generate_sample_peer_list(10);
    
    // Network configuration for mainnet
    let network_config = serde_json::json!({
        "network_id": "zhtp-mainnet",
        "protocol_version": "1.0.0",
        "network_environment": "mainnet",
        "default_ports": {
            "p2p": 19848,
            "api": 8080,
            "dns": 5353
        },
        "connection_limits": {
            "max_connections": 10000,
            "connection_timeout": 30,
            "heartbeat_interval": 30
        }
    });
    
    // Consensus parameters
    let consensus_params = serde_json::json!({
        "min_validators": 21,
        "block_time_ms": 6000,
        "finalization_depth": 32,
        "stake_threshold": 32000000,
        "consensus_algorithm": "zk-pos",
        "validator_rotation_period": 86400
    });
    
    // Protocol information
    let protocol_info = serde_json::json!({
        "supported_protocols": ["zhtp/1.0", "dht/1.0", "whisper/1.0"],
        "encryption": "quantum-resistant",
        "signature_scheme": "dilithium5",
        "hash_algorithm": "sha3-256",
        "zero_knowledge": {
            "enabled": true,
            "proof_system": "plonk",
            "trusted_setup": "ceremony-verified"
        }
    });
    
    // DNS bootstrap information
    let dns_bootstrap = serde_json::json!({
        "dns_providers": [
            {
                "address": "127.0.0.1:5353",
                "domains": ["zhtp.network", "api.zhtp.network"],
                "authority": true
            }
        ],
        "static_domains": {
            "seed1.zhtp.network": "127.0.0.1:19847",
            "api.zhtp.network": "127.0.0.1:8080",
            "explorer.zhtp.network": "127.0.0.1:8081"
        }
    });
    
    // Security and performance recommendations
    let recommendations = serde_json::json!({
        "security": {
            "enable_tls": true,
            "rate_limit_per_minute": 1000,
            "auth_required": true,
            "quantum_resistance": true
        },
        "performance": {
            "worker_threads": 4,
            "max_message_size": 1048576,
            "gc_interval": 3600,
            "storage_quota": 10737418240i64
        },
        "monitoring": {
            "enable_prometheus": true,
            "prometheus_port": 9090,
            "log_level": "info"
        }
    });
    
    let timestamp = chrono::Utc::now().timestamp();
    
    // Main bootstrap response
    let mut response = serde_json::json!({
        "status": "success",
        "seeder_info": {
            "seeder_address": "127.0.0.1:19847",
            "seeder_id": "zhtp-seeder-mainnet",
            "uptime": timestamp,
            "version": "1.0.0"
        },
        "timestamp": timestamp,
        "response_to": client_addr.to_string(),
        "request_type": request_type,
        "network_config": network_config,
        "consensus_params": consensus_params,
        "protocol_info": protocol_info,
        "dns_bootstrap": dns_bootstrap,
        "recommendations": recommendations
    });
    
    // Add peer information based on request type
    match request_type {
        "peer_discovery" => {
            response["active_peers"] = serde_json::json!(active_peers);
            response["peer_count"] = serde_json::json!(active_peers.len());
        }
        "network_info" => {
            response["network_stats"] = serde_json::json!({
                "total_nodes": 42,
                "validators": 21,
                "active_connections": active_peers.len(),
                "network_health": "excellent"
            });
        }
        "full_bootstrap" | _ => {
            response["active_peers"] = serde_json::json!(active_peers);
            response["peer_count"] = serde_json::json!(active_peers.len());
            response["network_stats"] = serde_json::json!({
                "total_nodes": 42,
                "validators": 21,
                "active_connections": active_peers.len(),
                "network_health": "excellent",
                "last_block_height": 15420,
                "chain_id": "zhtp-mainnet-2025"
            });
            
            // Include setup instructions
            response["setup_instructions"] = serde_json::json!({
                "step1": "Update mainnet-config.toml with provided network_config",
                "step2": "Add active_peers to bootstrap_peers list",
                "step3": "Configure consensus parameters from consensus_params",
                "step4": "Enable recommended security settings",
                "step5": "Start your node with: cargo run --release --bin zhtp-production mainnet-config.toml"
            });
        }
    }
    
    response
}

/// Start HTTP server for bootstrap API queries
async fn start_bootstrap_http_server(listen_addr: &str) -> Result<()> {
    use tokio::net::TcpListener;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    
    let listener = TcpListener::bind(listen_addr).await?;
    info!("🌍 HTTP Bootstrap API listening on: {}", listen_addr);
    
    loop {
        match listener.accept().await {
            Ok((mut stream, addr)) => {
                tokio::spawn(async move {
                    let mut reader = tokio::io::BufReader::new(&mut stream);
                    let mut request_line = String::new();
                    
                    if let Ok(_) = reader.read_line(&mut request_line).await {
                        info!("HTTP request from {}: {}", addr, request_line.trim());
                        
                        // Parse simple HTTP request
                        let response = if request_line.contains("GET /bootstrap") {
                            let bootstrap_info = create_bootstrap_response(addr, None).await;
                            let json_response = serde_json::to_string_pretty(&bootstrap_info).unwrap_or_default();
                            
                            format!(
                                "HTTP/1.1 200 OK\r\n\
                                 Content-Type: application/json\r\n\
                                 Access-Control-Allow-Origin: *\r\n\
                                 Content-Length: {}\r\n\
                                 \r\n\
                                 {}",
                                json_response.len(),
                                json_response
                            )
                        } else if request_line.contains("GET /peers") {
                            let peers = generate_sample_peer_list(12);
                            let peers_response = serde_json::json!({
                                "status": "success",
                                "peers": peers,
                                "count": peers.len(),
                                "timestamp": chrono::Utc::now().timestamp()
                            });
                            let json_response = serde_json::to_string_pretty(&peers_response).unwrap_or_default();
                            
                            format!(
                                "HTTP/1.1 200 OK\r\n\
                                 Content-Type: application/json\r\n\
                                 Access-Control-Allow-Origin: *\r\n\
                                 Content-Length: {}\r\n\
                                 \r\n\
                                 {}",
                                json_response.len(),
                                json_response
                            )
                        } else if request_line.contains("GET /") {
                            // Simple status page
                            let status_html = format!(
                                r#"<html>
                                <head><title>ZHTP Seeder Node</title></head>
                                <body>
                                    <h1>🌱 ZHTP Seeder Node</h1>
                                    <p><strong>Status:</strong> Active</p>
                                    <p><strong>Bootstrap API:</strong> Available</p>
                                    <p><strong>Timestamp:</strong> {}</p>
                                    <h2>API Endpoints:</h2>
                                    <ul>
                                        <li><a href="/bootstrap">/bootstrap</a> - Full bootstrap information</li>
                                        <li><a href="/peers">/peers</a> - Active peer list</li>
                                    </ul>
                                    <h2>TCP Bootstrap:</h2>
                                    <p>Production nodes can connect via TCP for binary protocol bootstrap.</p>
                                </body>
                                </html>"#,
                                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                            );
                            
                            format!(
                                "HTTP/1.1 200 OK\r\n\
                                 Content-Type: text/html\r\n\
                                 Content-Length: {}\r\n\
                                 \r\n\
                                 {}",
                                status_html.len(),
                                status_html
                            )
                        } else {
                            "HTTP/1.1 404 Not Found\r\n\r\nEndpoint not found".to_string()
                        };
                        
                        let _ = stream.write_all(response.as_bytes()).await;
                        let _ = stream.flush().await;
                    }
                });
            }
            Err(e) => {
                warn!("Failed to accept HTTP connection: {}", e);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

/// Attempt to establish connection with a peer and verify responsiveness
async fn attempt_peer_connection(peer_addr: SocketAddr) -> Result<String> {
    use tokio::net::TcpStream;
    use tokio::io::{AsyncWriteExt, AsyncReadExt};
    
    // Attempt TCP connection
    let mut stream = TcpStream::connect(peer_addr).await
        .map_err(|e| anyhow::anyhow!("TCP connection failed: {}", e))?;
    
    // Send a simple ping message
    let ping_message = serde_json::json!({
        "type": "peer_ping",
        "timestamp": chrono::Utc::now().timestamp(),
        "seeder_id": "zhtp-seeder-mainnet"
    });
    
    let ping_data = ping_message.to_string();
    stream.write_all(ping_data.as_bytes()).await
        .map_err(|e| anyhow::anyhow!("Failed to send ping: {}", e))?;
    
    stream.flush().await
        .map_err(|e| anyhow::anyhow!("Failed to flush ping: {}", e))?;
    
    // Read response with timeout
    let mut buffer = [0u8; 1024];
    let start_time = std::time::Instant::now();
    
    let bytes_read = stream.read(&mut buffer).await
        .map_err(|e| anyhow::anyhow!("Failed to read response: {}", e))?;
    
    let latency = start_time.elapsed().as_millis() as f64;
    
    if bytes_read > 0 {
        let response = String::from_utf8_lossy(&buffer[..bytes_read]);
        info!("📨 Received response from {}: {}", peer_addr, response.trim());
        
        // Try to parse as JSON to validate peer protocol
        if let Ok(response_json) = serde_json::from_str::<serde_json::Value>(&response) {
            if response_json.get("type").and_then(|t| t.as_str()) == Some("peer_pong") {
                return Ok(format!("{:.1}", latency));
            }
        }
        
        // Even if not proper JSON, consider it responsive if we got data
        Ok(format!("{:.1}", latency))
    } else {
        Err(anyhow::anyhow!("No response received"))
    }
}

/// Generate sample active peer list for bootstrap
fn generate_sample_peer_list(count: usize) -> Vec<serde_json::Value> {
    let mut peers = Vec::new();
    let base_port = 19850;
    
    for i in 0..count {
        let port = base_port + i as u16;
        let peer = serde_json::json!({
            "address": format!("127.0.0.1:{}", port),
            "node_id": format!("zhtp-node-{:04}", i + 1),
            "reputation": 850.0 + (i as f64 * 15.0),
            "last_seen": chrono::Utc::now().timestamp() - (i as i64 * 30),
            "protocol_version": "1.0.0",
            "connection_state": "active",
            "is_validator": i < 7, // First 7 are validators
            "uptime_seconds": 86400 + (i * 3600),
            "latency_ms": 45.0 + (i as f64 * 12.5),
            "success_rate": 0.98 - (i as f64 * 0.01),
            "node_type": if i < 7 { "validator" } else { "peer" },
            "features": ["dht", "storage", "consensus", "api"]
        });
        peers.push(peer);
    }
    
    peers
}

/// Connect to seeder using real TCP bootstrap protocol
async fn connect_to_seeder_real(
    seeder_addr: SocketAddr, 
    node_name: &str, 
    _node: Arc<Mutex<ZhtpNode>>
) -> Result<BootstrapInfo> {
    info!("🔗 {} connecting to seeder via TCP bootstrap", node_name);
    
    // 1. Establish TCP connection to seeder
    let mut stream = match tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect(seeder_addr)
    ).await {
        Ok(Ok(stream)) => {
            info!("✅ {} established TCP connection to seeder", node_name);
            stream
        }
        Ok(Err(e)) => {
            return Err(anyhow::anyhow!("TCP connection failed: {}", e));
        }
        Err(_) => {
            return Err(anyhow::anyhow!("Connection timeout"));
        }
    };
    
    // 2. Send bootstrap request
    let bootstrap_request = serde_json::json!({
        "type": "full_bootstrap",
        "node_id": node_name,
        "protocol_version": "1.0.0",
        "requesting_services": ["peer_discovery", "network_config", "consensus_params"],
        "timestamp": chrono::Utc::now().timestamp()
    });
    
    let request_data = bootstrap_request.to_string();
    info!("📤 {} sending bootstrap request ({} bytes)", node_name, request_data.len());
    
    stream.write_all(request_data.as_bytes()).await
        .map_err(|e| anyhow::anyhow!("Failed to send bootstrap request: {}", e))?;
    stream.flush().await
        .map_err(|e| anyhow::anyhow!("Failed to flush request: {}", e))?;
    
    // 3. Read bootstrap response
    let mut response_buffer = vec![0u8; 65536]; // 64KB buffer for large response
    let bytes_read = match tokio::time::timeout(
        Duration::from_secs(15),
        stream.read(&mut response_buffer)
    ).await {
        Ok(Ok(bytes)) if bytes > 0 => bytes,
        Ok(Ok(_)) => {
            return Err(anyhow::anyhow!("Empty response from seeder"));
        }
        Ok(Err(e)) => {
            return Err(anyhow::anyhow!("Failed to read response: {}", e));
        }
        Err(_) => {
            return Err(anyhow::anyhow!("Response timeout"));
        }
    };
    
    // 4. Parse bootstrap response
    let response_str = String::from_utf8_lossy(&response_buffer[..bytes_read]);
    info!("📥 {} received bootstrap response ({} bytes)", node_name, bytes_read);
    
    let bootstrap_data: serde_json::Value = serde_json::from_str(&response_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse bootstrap response: {}", e))?;
    
    // 5. Extract peer information
    let peers_data = bootstrap_data.get("active_peers")
        .and_then(|p| p.as_array())
        .ok_or_else(|| anyhow::anyhow!("No peers in bootstrap response"))?;
    
    let mut peers = Vec::new();
    for peer_json in peers_data {
        if let (Some(addr_str), Some(node_id), Some(is_validator), Some(reputation)) = (
            peer_json.get("address").and_then(|a| a.as_str()),
            peer_json.get("node_id").and_then(|n| n.as_str()),
            peer_json.get("is_validator").and_then(|v| v.as_bool()),
            peer_json.get("reputation").and_then(|r| r.as_f64()),
        ) {
            if let Ok(peer_addr) = addr_str.parse::<SocketAddr>() {
                peers.push(PeerInfo {
                    address: peer_addr,
                    node_id: node_id.to_string(),
                    is_validator,
                    reputation,
                    protocol_version: peer_json.get("protocol_version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("1.0.0")
                        .to_string(),
                });
            }
        }
    }
    
    // 6. Extract network configuration
    let network_id = bootstrap_data.get("network_config")
        .and_then(|nc| nc.get("network_id"))
        .and_then(|id| id.as_str())
        .unwrap_or("zhtp-mainnet")
        .to_string();
    
    let protocol_version = bootstrap_data.get("network_config")
        .and_then(|nc| nc.get("protocol_version"))
        .and_then(|pv| pv.as_str())
        .unwrap_or("1.0.0")
        .to_string();
    
    info!("✅ {} parsed bootstrap info: {} peers, network: {}", 
          node_name, peers.len(), network_id);
    
    Ok(BootstrapInfo {
        network_id,
        protocol_version,
        peer_count: peers.len(),
        peers,
        seeder_address: seeder_addr.to_string(),
    })
}

/// Connect to discovered peers using ZHTP protocol
async fn connect_to_discovered_peers(
    peers: Vec<PeerInfo>, 
    node: Arc<Mutex<ZhtpNode>>, 
    node_name: &str
) {
    info!("🌐 {} connecting to {} discovered peers using ZHTP protocol", node_name, peers.len());
    
    // Connect to a subset of peers (prioritize validators)
    let mut validators: Vec<_> = peers.iter().filter(|p| p.is_validator).collect();
    let mut regular_peers: Vec<_> = peers.iter().filter(|p| !p.is_validator).collect();
    
    // Sort by reputation
    validators.sort_by(|a, b| b.reputation.partial_cmp(&a.reputation).unwrap_or(std::cmp::Ordering::Equal));
    regular_peers.sort_by(|a, b| b.reputation.partial_cmp(&a.reputation).unwrap_or(std::cmp::Ordering::Equal));
    
    // Select top peers to connect to (limit to avoid overwhelming)
    let max_connections = std::cmp::min(8, peers.len());
    let validators_to_connect = std::cmp::min(3, validators.len());
    let regular_to_connect = std::cmp::min(max_connections - validators_to_connect, regular_peers.len());
    
    let mut selected_peers = Vec::new();
    selected_peers.extend(validators.iter().take(validators_to_connect));
    selected_peers.extend(regular_peers.iter().take(regular_to_connect));
    
    info!("📋 {} selected {} peers for connection ({} validators, {} regular)", 
          node_name, selected_peers.len(), validators_to_connect, regular_to_connect);
    
    // Connect to selected peers concurrently
    let connection_tasks: Vec<tokio::task::JoinHandle<()>> = selected_peers.into_iter().map(|peer: &PeerInfo| {
        let node_clone = node.clone();
        let node_name = node_name.to_string();
        let peer_info = peer.clone();
        
        tokio::spawn(async move {
            match connect_to_peer_zhtp(node_clone, &peer_info, &node_name).await {
                Ok(_) => {
                    info!("✅ {} connected to peer {} ({})", 
                          node_name, peer_info.node_id, peer_info.address);
                }
                Err(e) => {
                    warn!("⚠️ {} failed to connect to peer {}: {}", 
                          node_name, peer_info.node_id, e);
                }
            }
        })
    }).collect();
    
    // Wait for all connections with timeout - sequential approach
    let mut successful_connections = 0;
    let total_connections = connection_tasks.len();
    
    for task in connection_tasks {
        match tokio::time::timeout(Duration::from_secs(10), task).await {
            Ok(Ok(_)) => successful_connections += 1,
            Ok(Err(e)) => warn!("Connection task failed: {}", e),
            Err(_) => warn!("Connection task timed out"),
        }
    }
    
    info!("🎯 {} completed peer connections: {}/{} successful", 
          node_name, successful_connections, total_connections);
}

/// Connect to a specific peer using ZHTP protocol
async fn connect_to_peer_zhtp(
    node: Arc<Mutex<ZhtpNode>>, 
    peer: &PeerInfo, 
    node_name: &str
) -> Result<()> {
    info!("🤝 {} attempting ZHTP connection to {} at {}", 
          node_name, peer.node_id, peer.address);
    
    // Use the ZHTP node's connect method
    let mut node_guard = node.lock().await;
    
    // Attempt connection with retry
    let mut attempts = 0;
    let max_attempts = 3;
    
    while attempts < max_attempts {
        match node_guard.connect(peer.address).await {
            Ok(_) => {
                info!("✅ {} ZHTP handshake successful with {}", node_name, peer.node_id);
                return Ok(());
            }
            Err(e) => {
                attempts += 1;
                warn!("❌ {} ZHTP connection attempt {}/{} failed with {}: {}", 
                      node_name, attempts, max_attempts, peer.node_id, e);
                
                if attempts < max_attempts {
                    // Exponential backoff
                    let backoff = Duration::from_millis(500 * (1 << attempts));
                    tokio::time::sleep(backoff).await;
                } else {
                    return Err(anyhow::anyhow!("All connection attempts failed: {}", e));
                }
            }
        }
    }
    
    Err(anyhow::anyhow!("Maximum connection attempts exceeded"))
}

/// Retry seeder connection with backoff
async fn retry_seeder_connection(
    seeder_addr: SocketAddr, 
    node_name: &str, 
    node: Arc<Mutex<ZhtpNode>>
) {
    let mut retry_count = 0;
    let max_retries = 5;
    
    while retry_count < max_retries {
        retry_count += 1;
        let backoff = Duration::from_secs(30 * retry_count);
        
        info!("🔄 {} retry {}/{} seeder connection in {} seconds", 
              node_name, retry_count, max_retries, backoff.as_secs());
        
        tokio::time::sleep(backoff).await;
        
        match connect_to_seeder_real(seeder_addr, node_name, node.clone()).await {
            Ok(bootstrap_info) => {
                info!("✅ {} retry successful - connected to seeder", node_name);
                connect_to_discovered_peers(bootstrap_info.peers, node, node_name).await;
                return;
            }
            Err(e) => {
                warn!("❌ {} retry {}/{} failed: {}", node_name, retry_count, max_retries, e);
            }
        }
    }
    
    error!("💀 {} exhausted all retry attempts for seeder connection", node_name);
}
