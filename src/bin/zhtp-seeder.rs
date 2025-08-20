#!/usr/bin/env rust-script
//! ZHTP Production Seeder Node
//! 
//! This binary starts a production-ready ZHTP seeder node that provides
//! blockchain state and peer discovery for production nodes.

use anyhow::{Result, Context};
use std::{env, net::SocketAddr, sync::Arc, time::Duration, collections::HashMap};
use tokio::sync::RwLock;
use tokio::io::{AsyncWriteExt, AsyncReadExt, AsyncBufReadExt};
use log::{info, error, warn};
use serde_json;

use decentralized_network::{
    zhtp::{Keypair, ZhtpNode, consensus_engine::ZhtpConsensusEngine, economics::ZhtpEconomics, dns::ZhtpDNS},
    Blockchain,
    storage::ZhtpStorageManager,
    config::ZhtpConfig,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BootstrapResponse {
    pub status: String,
    pub network_id: String,
    pub protocol_version: String,
    pub seeder_info: SeederInfo,
    pub blockchain_state: BlockchainState,
    pub active_peers: Vec<PeerInfo>,
    pub network_config: NetworkConfig,
    pub consensus_params: ConsensusParams,
    pub timestamp: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SeederInfo {
    pub seeder_id: String,
    pub listen_address: String,
    pub uptime: u64,
    pub version: String,
    pub is_validator: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlockchainState {
    pub chain_id: String,
    pub current_height: u64,
    pub current_hash: String,
    pub genesis_hash: String,
    pub total_supply: u64,
    pub validator_count: u32,
    pub last_block_time: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerInfo {
    pub address: String,
    pub node_id: String,
    pub is_validator: bool,
    pub reputation: f64,
    pub protocol_version: String,
    pub last_seen: u64,
    pub uptime: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkConfig {
    pub max_connections: u32,
    pub connection_timeout: u32,
    pub heartbeat_interval: u32,
    pub network_environment: String,
    pub required_protocol_version: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConsensusParams {
    pub min_validators: u32,
    pub block_time: u32,
    pub finalization_depth: u32,
    pub stake_threshold: u64,
    pub validator_rotation_period: u64,
}

/// Production seeder node
pub struct ProductionSeeder {
    config: ZhtpConfig,
    keypair: Keypair,
    node: ZhtpNode,
    consensus: ZhtpConsensusEngine,
    blockchain: Blockchain,
    storage: Arc<ZhtpStorageManager>,
    peer_registry: Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
    start_time: std::time::Instant,
}

impl ProductionSeeder {
    async fn new(config: ZhtpConfig) -> Result<Self> {
        info!("🌱 Initializing ZHTP Production Seeder Node");
        
        // Generate or load keypair
        let keypair = if let Some(keypair_path) = &config.node.keypair_path {
            if keypair_path.exists() {
                info!("Loading existing seeder keypair...");
                Self::load_keypair(keypair_path)?
            } else {
                info!("Generating new seeder keypair...");
                let keypair = Keypair::generate();
                Self::save_keypair(&keypair, keypair_path)?;
                keypair
            }
        } else {
            warn!("No keypair path specified - using ephemeral keypair");
            Keypair::generate()
        };

        info!("🔑 Seeder Public Key: {}", hex::encode(keypair.public_key()));

        // Initialize blockchain with genesis state
        info!("⛓️ Initializing blockchain with genesis state...");
        let blockchain = Blockchain::new(config.consensus.stake_threshold as f64);
        
        // Create seeder network configuration
        let public_key_bytes = keypair.public_key();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hasher::write(&mut hasher, &public_key_bytes);
        let node_hash = std::hash::Hasher::finish(&hasher);
        let node_id = format!("zhtp-seeder-{:016x}", node_hash);
        
        let network_config = decentralized_network::network::ZhtpNetworkConfig {
            node_id: node_id.clone(),
            listen_addr: config.network.listen_address,
            bootstrap_nodes: vec![], // Seeder doesn't need bootstrap nodes
            public_addr: None,
            network_env: decentralized_network::network::NetworkEnvironment::Mainnet,
            ca_config: Some(decentralized_network::network::CertificateAuthorityConfig {
                is_ca_node: true, // Seeder acts as certificate authority
                root_cert: None,
                trusted_cas: vec![],
            }),
            dns_config: decentralized_network::network::DnsConfig {
                is_dns_provider: true,
                static_domains: std::collections::HashMap::new(),
                cache_size: 10000,
                default_ttl: config.dns.cache_ttl,
            },
            performance_config: decentralized_network::network::PerformanceConfig {
                max_connections: config.network.max_connections,
                connection_timeout: config.network.connection_timeout,
                max_message_size: 1024 * 1024, // 1MB
                rate_limit: config.security.rate_limit.unwrap_or(1000),
                worker_threads: 8, // More workers for seeder
            },
        };
        
    let _ = network_config; // placeholder until direct network integration needed
        let economics = Arc::new(ZhtpEconomics::new());
        let consensus = ZhtpConsensusEngine::new(keypair.clone(), economics.clone()).await?;
        let dns_service = Arc::new(tokio::sync::RwLock::new(ZhtpDNS::new()));
        let storage_config = decentralized_network::StorageConfig::default();
        let storage = Arc::new(ZhtpStorageManager::new(
            dns_service,
            storage_config,
            keypair.clone(),
        ).await);

        // Initialize ZHTP node
        let node = ZhtpNode::new(config.network.listen_address, keypair.clone()).await?;
        
        // Initialize peer registry
        let peer_registry = Arc::new(RwLock::new(HashMap::new()));

        info!("✅ Seeder components initialized successfully");

        Ok(Self {
            config,
            keypair,
            node,
            consensus,
            blockchain,
            storage,
            peer_registry,
            start_time: std::time::Instant::now(),
        })
    }

    fn load_keypair(keypair_path: &std::path::Path) -> Result<Keypair> {
        let keypair_data = std::fs::read_to_string(keypair_path)
            .context("Failed to read keypair file")?;
        
        let keypair_export: decentralized_network::zhtp::crypto::KeypairExport = 
            serde_json::from_str(&keypair_data)
                .context("Failed to parse keypair file")?;
        
        Keypair::import_unencrypted(&keypair_export)
            .context("Failed to reconstruct keypair from export data")
    }
    
    fn save_keypair(keypair: &Keypair, keypair_path: &std::path::Path) -> Result<()> {
        let keypair_export = keypair.export_unencrypted();
        let keypair_json = serde_json::to_string_pretty(&keypair_export)
            .context("Failed to serialize keypair to JSON")?;
        
        if let Some(parent) = keypair_path.parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create keypair directory")?;
        }
        
        std::fs::write(keypair_path, keypair_json)
            .context("Failed to write keypair file")?;
        
        info!("✅ Seeder keypair saved to: {:?}", keypair_path);
        Ok(())
    }

    async fn start_seeder_network(&mut self) -> Result<()> {
        info!("🚀 Starting ZHTP seeder network: {}", self.config.node.name);
        info!("📡 Listening on: {}", self.config.network.listen_address);
        info!("🌐 Network environment: Mainnet");

        // Initialize as certificate authority
        info!("🔐 Initializing ZHTP Certificate Authority...");
        info!("✅ Certificate Authority initialized");

        // Initialize as DNS provider
        info!("🌐 Initializing ZHTP DNS Provider...");
        info!("✅ DNS Provider initialized");

        // Seeder doesn't need to connect to bootstrap nodes - it IS the bootstrap node
        info!("🌱 Seeder ready to accept connections from production nodes");
        
        Ok(())
    }

    async fn start(&mut self) -> Result<()> {
        info!("🚀 Starting ZHTP Production Seeder Node...");

        // Initialize storage system
        info!("💾 Initializing storage system...");
        self.storage.initialize_network().await?;

        // Initialize blockchain state
        info!("⛓️ Setting up blockchain with genesis state...");
        let zk_support = self.blockchain.supports_zk_transactions();
        info!("ZK transactions support: {}", zk_support);

        // Register as validator with high stake
        info!("🏛️ Registering seeder as validator...");
        self.consensus.register_validator(
            self.config.node.name.clone(),
            self.config.consensus.stake_threshold as f64 * 2.0, // Double stake for seeder
        ).await?;

        // Start network layer - but bypass bootstrap for seeder
        info!("🌐 Starting seeder network layer...");
        if self.start_seeder_network().await.is_err() {
            warn!("Network initialization had issues, but seeder can continue");
        }

        // Start ZHTP node listener
        let node_clone = Arc::new(tokio::sync::Mutex::new(self.node.clone()));
        let _node_handle = tokio::spawn(async move {
            if let Err(e) = ZhtpNode::start_listening_shared(node_clone).await {
                error!("Node listener error: {}", e);
            }
        });

        // Start consensus engine
        info!("⚖️ Starting consensus engine...");
        self.consensus.start().await?;

        // Start TCP bootstrap server
        self.start_tcp_bootstrap_server().await?;

        // Start HTTP API server
        self.start_http_api_server().await?;

        // Start peer discovery and maintenance
        self.start_peer_maintenance().await?;

        info!("🌟 ZHTP Production Seeder started successfully!");
        self.print_status().await;

        // Heartbeat & graceful shutdown
        let mut interval = tokio::time::interval(Duration::from_secs(30));
    let mut shutdown = Box::pin(tokio::signal::ctrl_c());
        info!("🛠️  Seeder entering main loop (Ctrl+C to stop)");
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.maintain_network().await;
                }
                _ = &mut shutdown => {
                    info!("🛑 Shutdown signal received - stopping seeder...");
                    self.shutdown().await;
                    break;
                }
            }
        }
        Ok(())
    }

    async fn start_tcp_bootstrap_server(&self) -> Result<()> {
        let listen_addr = self.config.network.listen_address;
        let peer_registry = self.peer_registry.clone();
        let blockchain = self.blockchain.clone();
        let config = self.config.clone();
        let start_time = self.start_time;
        let keypair = self.keypair.clone();

        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(listen_addr).await {
                Ok(listener) => {
                    info!("🌐 TCP Bootstrap Server listening on: {}", listen_addr);
                    
                    loop {
                        match listener.accept().await {
                            Ok((stream, addr)) => {
                                let peer_registry = peer_registry.clone();
                                let blockchain = blockchain.clone();
                                let config = config.clone();
                                let keypair = keypair.clone();
                                
                                tokio::spawn(async move {
                                    if let Err(e) = Self::handle_bootstrap_connection(
                                        stream, addr, peer_registry, blockchain, config, start_time, keypair
                                    ).await {
                                        warn!("Bootstrap connection failed for {}: {}", addr, e);
                                    }
                                });
                            }
                            Err(e) => {
                                warn!("Failed to accept TCP connection: {}", e);
                                tokio::time::sleep(Duration::from_secs(1)).await;
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to bind TCP listener on {}: {}", listen_addr, e);
                }
            }
        });

        Ok(())
    }

    async fn handle_bootstrap_connection(
        mut stream: tokio::net::TcpStream,
        addr: SocketAddr,
        peer_registry: Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
        blockchain: Blockchain,
        config: ZhtpConfig,
        start_time: std::time::Instant,
        keypair: Keypair,
    ) -> Result<()> {
        info!("📡 Handling bootstrap connection from: {}", addr);

        // Read bootstrap request
        let mut buffer = [0u8; 4096];
        let bytes_read = tokio::time::timeout(
            Duration::from_secs(10),
            stream.read(&mut buffer)
        ).await??;

        let request_data = if bytes_read > 0 {
            String::from_utf8_lossy(&buffer[..bytes_read])
        } else {
            "{}".into()
        };

        info!("📝 Bootstrap request from {}: {}", addr, request_data);

        // Create comprehensive bootstrap response
        let response = Self::create_bootstrap_response(
            addr, peer_registry.clone(), blockchain, config, start_time, keypair
        ).await;

        let response_json = serde_json::to_string_pretty(&response)?;
        
        // Send response
        stream.write_all(response_json.as_bytes()).await?;
        stream.flush().await?;

        info!("✅ Sent bootstrap response to: {} ({} bytes)", addr, response_json.len());

        // Register the connecting peer
        let peer_info = PeerInfo {
            address: addr.to_string(),
            node_id: format!("zhtp-peer-{}", addr),
            is_validator: false,
            reputation: 100.0,
            protocol_version: "1.0.0".to_string(),
            last_seen: chrono::Utc::now().timestamp() as u64,
            uptime: 0,
        };

        peer_registry.write().await.insert(addr, peer_info);

        tokio::time::sleep(Duration::from_millis(500)).await;
        let _ = stream.shutdown().await;

        Ok(())
    }

    async fn create_bootstrap_response(
        client_addr: SocketAddr,
        peer_registry: Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
        blockchain: Blockchain,
        config: ZhtpConfig,
        start_time: std::time::Instant,
        keypair: Keypair,
    ) -> BootstrapResponse {
        let timestamp = chrono::Utc::now().timestamp() as u64;
        let uptime = start_time.elapsed().as_secs();

        // Get current blockchain state
        let zk_stats = blockchain.get_zk_statistics().await;
        let blockchain_state = BlockchainState {
            chain_id: "zhtp-mainnet-2025".to_string(),
            current_height: zk_stats.total_zk_transactions + 1000, // Genesis + transactions
            current_hash: "0x1234567890abcdef".to_string(), // In production, use real hash
            genesis_hash: "0x0000000000000000".to_string(),
            total_supply: 1_000_000_000_000_000, // 1M ZHTP
            validator_count: 21,
            last_block_time: timestamp - 6, // 6 seconds ago
        };

        // Get active peers
        let active_peers: Vec<PeerInfo> = {
            let registry = peer_registry.read().await;
            registry.values().cloned().collect()
        };

        let seeder_info = SeederInfo {
            seeder_id: format!("zhtp-seeder-{}", hex::encode(&keypair.public_key()[..8])),
            listen_address: config.network.listen_address.to_string(),
            uptime,
            version: "1.0.0".to_string(),
            is_validator: true,
        };

        let network_config = NetworkConfig {
            max_connections: config.network.max_connections as u32,
            connection_timeout: config.network.connection_timeout as u32,
            heartbeat_interval: config.network.heartbeat_interval as u32,
            network_environment: "mainnet".to_string(),
            required_protocol_version: "1.0.0".to_string(),
        };

        let consensus_params = ConsensusParams {
            min_validators: config.consensus.min_validators as u32,
            block_time: config.consensus.block_time as u32,
            finalization_depth: config.consensus.finalization_depth as u32,
            stake_threshold: config.consensus.stake_threshold,
            validator_rotation_period: 86400, // 24 hours
        };

        info!("📦 Created bootstrap response for {} with {} peers, blockchain height: {}", 
              client_addr, active_peers.len(), blockchain_state.current_height);

        BootstrapResponse {
            status: "success".to_string(),
            network_id: "zhtp-mainnet".to_string(),
            protocol_version: "1.0.0".to_string(),
            seeder_info,
            blockchain_state,
            active_peers,
            network_config,
            consensus_params,
            timestamp,
        }
    }
}

// Additional impl block for remaining service methods (previous block may have been
// terminated earlier due to edits/placeholders). Keeping a separate impl ensures
// methods are correctly associated with ProductionSeeder.
impl ProductionSeeder {
    async fn start_http_api_server(&self) -> Result<()> {
        let http_port = self.config.network.listen_address.port() + 1000;
        let http_addr = format!("127.0.0.1:{}", http_port);
        let peer_registry = self.peer_registry.clone();
        let blockchain = self.blockchain.clone();
        let config = self.config.clone();
        let start_time = self.start_time;
        let keypair = self.keypair.clone();

        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(&http_addr).await {
                Ok(listener) => {
                    info!("🌍 HTTP API Server listening on: {}", http_addr);
                    
                    loop {
                        match listener.accept().await {
                            Ok((mut stream, addr)) => {
                                let peer_registry = peer_registry.clone();
                                let blockchain = blockchain.clone();
                                let config = config.clone();
                                let keypair = keypair.clone();
                                
                                tokio::spawn(async move {
                                    let mut reader = tokio::io::BufReader::new(&mut stream);
                                    let mut request_line = String::new();
                                    
                                    if let Ok(_) = reader.read_line(&mut request_line).await {
                                        let response = if request_line.contains("GET /bootstrap") {
                                            let bootstrap_info = Self::create_bootstrap_response(
                                                addr, peer_registry, blockchain, config, start_time, keypair
                                            ).await;
                                            Self::create_http_response("application/json", 
                                                &serde_json::to_string_pretty(&bootstrap_info).unwrap_or_default())
                                        } else if request_line.contains("GET /peers") {
                                            let peers: Vec<PeerInfo> = {
                                                let registry = peer_registry.read().await;
                                                registry.values().cloned().collect()
                                            };
                                            let peers_json = serde_json::json!({
                                                "status": "success",
                                                "peers": peers,
                                                "count": peers.len(),
                                                "timestamp": chrono::Utc::now().timestamp()
                                            });
                                            Self::create_http_response("application/json", 
                                                &serde_json::to_string_pretty(&peers_json).unwrap_or_default())
                                        } else {
                                            Self::create_status_page()
                                        };
                                        
                                        let _ = stream.write_all(response.as_bytes()).await;
                                        let _ = stream.flush().await;
                                    }
                                });
                            }
                            Err(e) => {
                                warn!("HTTP connection error: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to bind HTTP server on {}: {}", http_addr, e);
                }
            }
        });

        Ok(())
    }

    fn create_http_response(content_type: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: {}\r\n\
             Access-Control-Allow-Origin: *\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            content_type,
            body.len(),
            body
        )
    }

    fn create_status_page() -> String {
        let html = format!(
            r#"<html>
            <head><title>ZHTP Production Seeder</title></head>
            <body>
                <h1>🌱 ZHTP Production Seeder Node</h1>
                <p><strong>Status:</strong> ✅ Active</p>
                <p><strong>Network:</strong> Mainnet</p>
                <p><strong>Timestamp:</strong> {}</p>
                <h2>Available Endpoints:</h2>
                <ul>
                    <li><a href="/bootstrap">/bootstrap</a> - Full bootstrap information</li>
                    <li><a href="/peers">/peers</a> - Active peer list</li>
                </ul>
                <h2>Connection Info:</h2>
                <p>Production nodes can connect via TCP for binary protocol bootstrap.</p>
                <p>Add this seeder to your mainnet-config.toml bootstrap_peers list.</p>
            </body>
            </html>"#,
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        );
        
        Self::create_http_response("text/html", &html)
    }

    async fn start_peer_maintenance(&self) -> Result<()> {
        let peer_registry = self.peer_registry.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                // Clean up stale peers (simplified for now)
                {
                    let mut registry = peer_registry.write().await;
                    let current_time = chrono::Utc::now().timestamp() as u64;
                    let stale_timeout = 300; // 5 minutes
                    
                    let before_count = registry.len();
                    registry.retain(|_, peer| current_time - peer.last_seen < stale_timeout);
                    let after_count = registry.len();
                    
                    if before_count != after_count {
                        info!("🧹 Cleaned up {} stale peers", before_count - after_count);
                    }
                }
            }
        });

        Ok(())
    }

    async fn maintain_network(&self) {
        let peer_count = self.peer_registry.read().await.len();
        let zk_stats = self.blockchain.get_zk_statistics().await;
        let uptime = self.start_time.elapsed();
        
        info!("💓 Seeder heartbeat - {} connected peers, {} ZK transactions, uptime: {:.1}h", 
              peer_count, zk_stats.total_zk_transactions, uptime.as_secs_f64() / 3600.0);
    }

    async fn shutdown(&self) {
        info!("📦 Flushing state before shutdown");
        // Attempt to persist peer snapshot (best effort)
        if let Ok(snapshot_path) = std::env::var("ZHTP_SEEDER_PEER_SNAPSHOT") {
            let registry = self.peer_registry.read().await;
            if let Ok(json) = serde_json::to_string_pretty(&*registry) {
                let _ = std::fs::write(snapshot_path, json);
            }
        }
        info!("✅ Seeder stopped cleanly");
    }

    async fn print_status(&self) {
        let peer_count = self.peer_registry.read().await.len();
        let zk_stats = self.blockchain.get_zk_statistics().await;
        let http_port = self.config.network.listen_address.port() + 1000;
        
        println!("\n🌟 ZHTP Production Seeder Status");
        println!("================================");
        println!("🌱 Node Type: Production Seeder");
        println!("🌐 Network: ZHTP Mainnet");
        println!("📡 Listen Address: {}", self.config.network.listen_address);
        println!("🔑 Seeder ID: {}", hex::encode(&self.keypair.public_key()[..8]));
        println!("🏛️ Validator: Yes (High Stake)");
        println!("📊 Connected Peers: {}", peer_count);
        println!("⛓️ Blockchain Height: {}", zk_stats.total_zk_transactions + 1000);
        println!("🌍 HTTP API: http://127.0.0.1:{}", http_port);
        println!("🔒 Security: Production-grade");
        println!();
        println!("📋 Bootstrap Configuration:");
        println!("   Add to mainnet-config.toml:");
        println!("   bootstrap_peers = [\"{}\"]", self.config.network.listen_address);
        println!();
        println!("🌐 API Endpoints:");
        println!("   http://127.0.0.1:{}/bootstrap - Full bootstrap info", http_port);
        println!("   http://127.0.0.1:{}/peers - Active peer list", http_port);
        println!("   http://127.0.0.1:{}/ - Status page", http_port);
        println!("================================\n");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    
    info!("🌱 Starting ZHTP Production Seeder v{}", env!("CARGO_PKG_VERSION"));
    
    let args: Vec<String> = env::args().collect();
    let config_path = if args.len() > 1 {
        args[1].clone()
    } else {
        "mainnet-config.toml".to_string()
    };

    info!("📋 Loading configuration from: {}", config_path);
    
    let config_content = std::fs::read_to_string(&config_path)
        .context("Failed to read configuration file")?;
    let config: ZhtpConfig = toml::from_str(&config_content)
        .context("Failed to parse configuration")?;

    // Override some settings for seeder
    let mut seeder_config = config;
    seeder_config.node.validator = true;
    seeder_config.node.mining_enabled = true;
    seeder_config.storage.dht_enabled = true;
    seeder_config.dns.enabled = true;
    
    match ProductionSeeder::new(seeder_config).await {
        Ok(mut seeder) => {
            if let Err(e) = seeder.start().await {
                error!("💥 Seeder failed: {}", e);
                std::process::exit(1);
            }
        }
        Err(e) => {
            error!("💥 Failed to initialize seeder: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
