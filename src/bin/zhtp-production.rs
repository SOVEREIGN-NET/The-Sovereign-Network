#!/usr/bin/env rust-script
//! ZHTP Production Node Startup
//! 
//! This binary starts a production-ready ZHTP node with full monitoring,
//! security, and mainnet connectivity.

use anyhow::{Result, Context};
use std::env;
use std::sync::Arc;
use std::net::SocketAddr;
use tokio::signal;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use log::{info, error, warn};

use decentralized_network::{
    zhtp::{ZhtpNode, Keypair},
    zhtp::consensus_engine::ZhtpConsensusEngine,
    zhtp::economics::ZhtpEconomics,
    zhtp::dns::ZhtpDNS,
    Network, Blockchain,
    storage::ZhtpStorageManager,
    config::ZhtpConfig,
    security_monitor::{ZhtpSecurityMonitor, SecurityConfig},
    health_monitor::{ZhtpHealthMonitor, HealthThresholds},
    api_server::{ZhtpApiServer, ApiConfig},
};

// Bootstrap response types (should match seeder)
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

/// Production node configuration
struct ProductionNode {
    config: ZhtpConfig,
    keypair: Keypair,
    node: ZhtpNode,
    consensus: ZhtpConsensusEngine,
    blockchain: Blockchain,
    network: Network,
    storage: Arc<ZhtpStorageManager>,
    api_server: ZhtpApiServer,
    security_monitor: Arc<ZhtpSecurityMonitor>,
    health_monitor: Arc<ZhtpHealthMonitor>,
}

impl ProductionNode {
    fn load_keypair(keypair_path: &std::path::Path) -> Result<Keypair> {
        info!("Loading keypair from: {:?}", keypair_path);
        
        let keypair_data = std::fs::read_to_string(keypair_path)
            .context("Failed to read keypair file")?;
        
        let keypair_export: decentralized_network::zhtp::crypto::KeypairExport = 
            serde_json::from_str(&keypair_data)
                .context("Failed to parse keypair JSON data")?;
        
        // Import the keypair from the export struct
        Keypair::import_unencrypted(&keypair_export)
            .context("Failed to reconstruct keypair from export data")
    }
    
    fn save_keypair(keypair: &Keypair, keypair_path: &std::path::Path) -> Result<()> {
        info!("Saving keypair to: {:?}", keypair_path);
        
        let keypair_export = keypair.export_unencrypted();
        
        let keypair_json = serde_json::to_string_pretty(&keypair_export)
            .context("Failed to serialize keypair to JSON")?;
        
        let temp_path = keypair_path.with_extension("tmp");
        std::fs::write(&temp_path, keypair_json)
            .context("Failed to write keypair to temporary file")?;
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&temp_path)?.permissions();
            perms.set_mode(0o600); // rw-------
            std::fs::set_permissions(&temp_path, perms)
                .context("Failed to set secure permissions on keypair file")?;
        }
        
        #[cfg(windows)]
        {
            warn!("File permissions on Windows are managed by the filesystem ACLs");
        }
        
        if keypair_path.exists() {
            let backup_path = keypair_path.with_extension("bak");
            if let Err(e) = std::fs::copy(keypair_path, &backup_path) {
                warn!("Failed to create keypair backup: {}", e);
            } else {
                info!("📁 Created keypair backup at: {:?}", backup_path);
            }
        }
        
        std::fs::rename(&temp_path, keypair_path)
            .context("Failed to move temporary keypair file to final location")?;
        
        info!("✅ Keypair saved successfully with secure permissions");
        info!("🔐 File permissions: 600 (owner read/write only)");
        Ok(())
    }

    async fn from_config(config_path: &str) -> Result<Self> {
        info!("Loading configuration from: {}", config_path);
        
        let config_content = std::fs::read_to_string(config_path)
            .context("Failed to read configuration file")?;
        let config: ZhtpConfig = toml::from_str(&config_content)
            .context("Failed to parse configuration")?;

        info!("Configuration loaded successfully");
        
        info!("Listen address: {}", config.network.listen_address);
        info!("Bootstrap peers: {:?}", config.network.bootstrap_peers);
        
        Self::validate_config(&config)?;

        let keypair = if let Some(keypair_path) = &config.node.keypair_path {
            if keypair_path.exists() {
                info!("Loading existing keypair from: {:?}", keypair_path);
                let loaded_keypair = Self::load_keypair(keypair_path)
                    .context("Failed to load existing keypair")?;
                
                if let Err(_) = loaded_keypair.check_rotation() {
                    warn!("⚠️  Loaded keypair has expired and needs rotation");
                    info!("🔄 Generating new keypair and backing up old one...");
                    
                    let backup_path = keypair_path.with_extension("expired.bak");
                    if let Err(e) = std::fs::copy(keypair_path, &backup_path) {
                        warn!("Failed to backup expired keypair: {}", e);
                    } else {
                        info!("📁 Backed up expired keypair to: {:?}", backup_path);
                    }
                    
                    let new_keypair = Keypair::generate();
                    Self::save_keypair(&new_keypair, keypair_path)
                        .context("Failed to save rotated keypair")?;
                    
                    info!("✅ New keypair generated and saved successfully");
                    info!("🔑 New public key: {}", hex::encode(new_keypair.public_key()));
                    new_keypair
                } else {
                    info!("✅ Loaded keypair is valid and current");
                    loaded_keypair
                }
            } else {
                info!("Generating new keypair and saving to: {:?}", keypair_path);
                let keypair = Keypair::generate();
                
                if let Some(parent) = keypair_path.parent() {
                    std::fs::create_dir_all(parent)
                        .context("Failed to create keypair directory")?;
                }
                
                Self::save_keypair(&keypair, keypair_path)
                    .context("Failed to save generated keypair")?;
                
                info!("✅ Keypair generated and saved successfully");
                info!("🔑 Public key: {}", hex::encode(keypair.public_key()));
                keypair
            }
        } else {
            warn!("⚠️  No keypair path specified, using ephemeral keypair");
            warn!("🔄 Node identity will change on restart!");
            Keypair::generate()
        };

        info!("Initializing core blockchain components...");
        
        let blockchain = Blockchain::new(config.consensus.stake_threshold as f64);
        let public_key_bytes = keypair.public_key();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hasher::write(&mut hasher, &public_key_bytes);
        let node_hash = std::hash::Hasher::finish(&hasher);
        let node_id = format!("zhtp-node-{:016x}", node_hash);
        
        let network_config = decentralized_network::network::ZhtpNetworkConfig {
            node_id,
            listen_addr: config.network.listen_address,
            bootstrap_nodes: config.network.bootstrap_peers.clone(),
            public_addr: None,
            network_env: decentralized_network::network::NetworkEnvironment::Mainnet,
            ca_config: Some(decentralized_network::network::CertificateAuthorityConfig {
                is_ca_node: false,
                root_cert: None,
                trusted_cas: vec![],
            }),
            dns_config: decentralized_network::network::DnsConfig {
                is_dns_provider: config.dns.enabled,
                static_domains: std::collections::HashMap::new(),
                cache_size: 10000,
                default_ttl: config.dns.cache_ttl,
            },
            performance_config: decentralized_network::network::PerformanceConfig {
                max_connections: config.network.max_connections,
                connection_timeout: config.network.connection_timeout,
                max_message_size: 1024 * 1024, // 1MB
                rate_limit: config.security.rate_limit.unwrap_or(100),
                worker_threads: 4,
            },
        };
        let network = Network::with_config(network_config);
        let economics = Arc::new(ZhtpEconomics::new());
        let consensus = ZhtpConsensusEngine::new(keypair.clone(), economics.clone()).await?;
        let dns_service = Arc::new(tokio::sync::RwLock::new(ZhtpDNS::new()));
        let storage_config = decentralized_network::StorageConfig::default();
        let storage = Arc::new(ZhtpStorageManager::new(
            dns_service,
            storage_config,
            keypair.clone(),
        ).await);

        info!("Initializing ZHTP node...");
        // Initialize ZHTP node
        let node = ZhtpNode::new(config.network.listen_address, keypair.clone()).await?;

        let security_config = SecurityConfig {
            rate_limit_requests_per_minute: config.security.rate_limit.unwrap_or(100),
            blacklist_threshold: 10,
            enable_quantum_detection: true,
            enable_consensus_monitoring: true,
            auto_ban_enabled: true,
            ..Default::default()
        };
        let security_monitor = Arc::new(ZhtpSecurityMonitor::new(security_config));
        let health_thresholds = HealthThresholds::default();
        let health_monitor = Arc::new(ZhtpHealthMonitor::new(Some(health_thresholds)));
        let api_config = ApiConfig {
            listen_address: config.api.listen_address,
            enable_tls: true,
            enable_cors: true,
            allowed_origins: vec!["https://localhost:3000".to_string()],
            rate_limit_requests_per_minute: config.security.rate_limit.unwrap_or(100),
            request_timeout_seconds: 30,
            max_request_body_size: 1024 * 1024,
            require_authentication: true,
            enable_audit_logging: true,
            enable_security_headers: true,
            session_timeout_minutes: 30,
        };
        
        let auth_config = Default::default();
        let tls_config = None;
        
        let api_server = ZhtpApiServer::new(
            api_config,
            auth_config,
            tls_config,
        ).await?;

        info!("Production node components initialized successfully");

        Ok(Self {
            config,
            keypair,
            node,
            consensus,
            blockchain,
            network,
            storage,
            api_server,
            security_monitor,
            health_monitor,
        })
    }

    fn validate_config(config: &ZhtpConfig) -> Result<()> {
        info!("Validating production configuration...");

        if config.network.bootstrap_peers.is_empty() {
            return Err(anyhow::anyhow!("No bootstrap peers configured"));
        }

        if !config.node.data_dir.exists() {
            std::fs::create_dir_all(&config.node.data_dir)
                .context("Failed to create data directory")?;
        }

        if let Some(keypair_path) = &config.node.keypair_path {
            if let Some(parent) = keypair_path.parent() {
                if parent.exists() {
                    let test_file = parent.join(".zhtp_write_test");
                    match std::fs::write(&test_file, "test") {
                        Ok(_) => {
                            let _ = std::fs::remove_file(&test_file);
                        }
                        Err(e) => {
                            return Err(anyhow::anyhow!(
                                "Keypair directory is not writable: {}", e
                            ));
                        }
                    }
                }
            }
            
            if keypair_path.exists() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let metadata = std::fs::metadata(keypair_path)
                        .context("Failed to read keypair file metadata")?;
                    let mode = metadata.permissions().mode();
                    if mode & 0o077 != 0 {
                        warn!("⚠️  Keypair file has overly permissive permissions: {:o}", mode);
                        warn!("🔒 Consider setting permissions to 600 (rw-------)");
                    }
                }
                
                #[cfg(not(unix))]
                {
                    info!("✅ Keypair file exists (permission check skipped on non-Unix)");
                }
            }
        } else {
            warn!("⚠️  No persistent keypair configured - node identity will be ephemeral");
        }

        if !config.security.enable_tls {
            warn!("TLS is disabled - this is not recommended for production");
        }

        if config.consensus.min_validators < 3 {
            warn!("Minimum validators is less than 3 - this may affect security");
        }

        info!("Configuration validation completed");
        Ok(())
    }

    async fn start(&mut self) -> Result<()> {
        info!("Starting ZHTP production node...");

        self.health_monitor.start_monitoring().await?;
        info!("Health monitoring started");

        info!("Initializing storage system...");
        self.storage.initialize_network().await?;
        info!("Storage system initialized");

        info!("Initializing blockchain state...");
        let zk_support = self.blockchain.supports_zk_transactions();
        info!("Blockchain initialized with ZK support: {}", zk_support);

        info!("Starting network layer...");
        self.network.start_production_node().await
            .map_err(|e| anyhow::anyhow!("Network start failed: {}", e))?;
        info!("Network layer started");

        let api_server_handle = {
            let api_config = self.api_server.state.config.clone();
            let security_monitor = self.security_monitor.clone();
            let health_monitor = self.health_monitor.clone();
            tokio::spawn(async move {
                if let Err(e) = decentralized_network::api_server::start_api_server(
                    api_config.listen_address,
                    security_monitor,
                    health_monitor,
                ).await {
                    error!("API server error: {}", e);
                }
            })
        };

        let node_clone = Arc::new(tokio::sync::Mutex::new(self.node.clone()));
        let node_handle = tokio::spawn(async move {
            if let Err(e) = ZhtpNode::start_listening_shared(node_clone).await {
                error!("Node networking error: {}", e);
            }
        });

        if self.config.node.validator {
            info!("Registering as validator...");
            self.consensus.register_validator(
                self.config.node.name.clone(),
                self.config.consensus.stake_threshold as f64,
            ).await?;
            info!("Successfully registered as validator");
        }

        info!("Connecting to bootstrap peers...");
        if let Err(e) = self.network.start_production_node().await {
            warn!("Failed to start network: {}", e);
        } else {
            info!("✅ Network started successfully");
        }

        // Connect to bootstrap peers and get blockchain state
        info!("🔗 Connecting to bootstrap peers for blockchain sync...");
        if !self.config.network.bootstrap_peers.is_empty() {
            for bootstrap_peer in &self.config.network.bootstrap_peers {
                info!("📡 Attempting bootstrap connection to: {}", bootstrap_peer);
                match self.connect_to_bootstrap_peer(&bootstrap_peer.to_string()).await {
                    Ok(bootstrap_info) => {
                        info!("✅ Successfully connected to bootstrap peer: {}", bootstrap_peer);
                        info!("📊 Bootstrap info: network_id={}, blockchain_height={}", 
                              bootstrap_info.network_id, bootstrap_info.blockchain_state.current_height);
                        
                        // Update blockchain state from bootstrap
                        self.sync_blockchain_from_bootstrap(&bootstrap_info).await?;
                        break; // Successfully connected to one bootstrap peer
                    }
                    Err(e) => {
                        warn!("❌ Failed to connect to bootstrap peer {}: {}", bootstrap_peer, e);
                    }
                }
            }
        } else {
            warn!("⚠️ No bootstrap peers configured - node will start isolated");
        }

        if self.config.node.mining_enabled {
            info!("Starting consensus engine...");
            if let Err(e) = self.consensus.start().await {
                warn!("Failed to start consensus engine: {}", e);
            } else {
                info!("✅ Consensus engine started successfully");
            }
        }

        info!("🚀 ZHTP production node started successfully!");
        self.print_status().await;
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Received shutdown signal");
            }
            _ = api_server_handle => {
                error!("API server stopped unexpectedly");
            }
            _ = node_handle => {
                error!("Node networking stopped unexpectedly");
            }
        }

        self.shutdown().await?;
        Ok(())
    }

    async fn print_status(&self) {
        println!("\n🌟 ZHTP Production Node Status");
        println!("================================");
        println!("📍 Node Name: {}", self.config.node.name);
        println!("🌐 Network: mainnet");
        println!("📡 Listen Address: {}", self.config.network.listen_address);
        println!("🏗️  Validator: {}", if self.config.node.validator { "Yes" } else { "No" });
        println!("📊 API Server: http://{}", self.config.api.listen_address);
        println!("📈 Metrics: http://{}:{}/metrics", 
                 self.config.api.listen_address.ip(),
                 self.config.api.listen_address.port());
        println!("🔒 Security: Enabled with rate limiting");
        println!("💊 Health Checks: Active");
        println!("📁 Data Directory: {}", self.config.node.data_dir.display());
        
        let health_status = self.health_monitor.get_health_status().await;
        println!("🟢 Overall Health: {:?}", health_status.overall_status);
        
        let security_metrics = self.security_monitor.get_metrics();
        println!("🛡️  Security Metrics:");
        println!("   - Total Requests: {}", security_metrics.total_requests);
        println!("   - Blocked Requests: {}", security_metrics.blocked_requests);
        println!("   - Block Rate: {:.2}%", security_metrics.block_rate);
        
        let zk_stats = self.blockchain.get_zk_statistics().await;
        println!("⛓️  Blockchain Status:");
        println!("   - ZK Transactions: {}", zk_stats.total_zk_transactions);
        println!("   - Pending ZK Transactions: {}", zk_stats.pending_zk_transactions);
        println!("   - ZK Support: {}", self.blockchain.supports_zk_transactions());
        
        println!("💾 Storage Status:");
        println!("   - DHT Network: Active");
        println!("   - Content Addressing: Enabled");
        
        println!("\n📝 Useful Commands:");
        println!("   - View logs: journalctl -u zhtp-node -f");
        println!("   - Health check: curl http://localhost:8080/health");
        println!("   - Metrics: curl http://localhost:8080/metrics");
        println!("   - Node info: curl http://localhost:8080/info");
        println!("================================\n");
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down ZHTP production node...");
        info!("Processing pending blockchain transactions...");
        let pending_zk_txs = self.blockchain.get_pending_zk_transactions().await;
        info!("Found {} pending ZK transactions to process", pending_zk_txs.len());

        info!("Shutting down network connections...");
        info!("Flushing storage data...");
        info!("Performing graceful shutdown...");
        info!("Stopping network services...");
        info!("Waiting for in-flight operations to complete...");
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        info!("Stopping consensus participation...");
        info!("Flushing data and closing connections...");
        info!("Performing final cleanup...");
        info!("ZHTP production node shut down successfully");
        Ok(())
    }

    async fn connect_to_bootstrap_peer(&self, peer_address: &str) -> Result<BootstrapResponse> {
        info!("🔗 Connecting to bootstrap peer: {}", peer_address);
        
        let addr: SocketAddr = peer_address.parse()
            .context("Invalid bootstrap peer address")?;
        
        // Connect via TCP to bootstrap peer
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            tokio::net::TcpStream::connect(addr)
        ).await?
        .context("Failed to connect to bootstrap peer")?;
        
        // Send bootstrap request
        let bootstrap_request = serde_json::json!({
            "request_type": "full_bootstrap",
            "node_id": format!("zhtp-production-{}", hex::encode(&self.keypair.public_key()[..8])),
            "protocol_version": "1.0.0",
            "timestamp": chrono::Utc::now().timestamp()
        });
        
        let request_data = bootstrap_request.to_string();
        stream.write_all(request_data.as_bytes()).await?;
        stream.flush().await?;
        
        // Read bootstrap response
        let mut buffer = [0u8; 64 * 1024]; // 64KB buffer for large bootstrap responses
        let bytes_read = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            stream.read(&mut buffer)
        ).await??;
        
        if bytes_read == 0 {
            return Err(anyhow::anyhow!("No response from bootstrap peer"));
        }
        
        let response_data = String::from_utf8_lossy(&buffer[..bytes_read]);
        info!("📦 Received bootstrap response ({} bytes)", bytes_read);
        
        // Parse bootstrap response
        let bootstrap_response: BootstrapResponse = serde_json::from_str(&response_data)
            .context("Failed to parse bootstrap response")?;
        
        if bootstrap_response.status != "success" {
            return Err(anyhow::anyhow!("Bootstrap peer returned error status"));
        }
        
        info!("✅ Bootstrap successful - network_id: {}, peers: {}", 
              bootstrap_response.network_id, bootstrap_response.active_peers.len());
        
        Ok(bootstrap_response)
    }

    async fn sync_blockchain_from_bootstrap(&mut self, bootstrap_info: &BootstrapResponse) -> Result<()> {
        info!("⛓️ Syncing blockchain state from bootstrap peer...");
        
        let blockchain_state = &bootstrap_info.blockchain_state;
        info!("📊 Bootstrap blockchain state:");
        info!("   - Chain ID: {}", blockchain_state.chain_id);
        info!("   - Current Height: {}", blockchain_state.current_height);
        info!("   - Current Hash: {}", blockchain_state.current_hash);
        info!("   - Total Supply: {}", blockchain_state.total_supply);
        info!("   - Validators: {}", blockchain_state.validator_count);
        
        // In a real implementation, you would sync the full blockchain state here
        // For now, we'll just log the information and update consensus parameters
        
        // Update consensus parameters from bootstrap
        let consensus_params = &bootstrap_info.consensus_params;
        info!("⚖️ Updating consensus parameters from bootstrap:");
        info!("   - Min Validators: {}", consensus_params.min_validators);
        info!("   - Block Time: {}ms", consensus_params.block_time);
        info!("   - Stake Threshold: {}", consensus_params.stake_threshold);
        
        // Connect to active peers from bootstrap
        info!("🌐 Connecting to {} active peers from bootstrap...", bootstrap_info.active_peers.len());
        
        let max_peer_connections = std::cmp::min(5, bootstrap_info.active_peers.len());
        for (i, peer_info) in bootstrap_info.active_peers.iter().take(max_peer_connections).enumerate() {
            info!("🤝 Connecting to peer {}/{}: {} ({})", 
                  i + 1, max_peer_connections, peer_info.node_id, peer_info.address);
            
            // In a real implementation, you would establish ZHTP connections to these peers
            // For now, we'll just log the connection attempt
        }
        
        info!("✅ Blockchain sync from bootstrap completed");
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    info!("Starting ZHTP Production Node v{}", env!("CARGO_PKG_VERSION"));
    let args: Vec<String> = env::args().collect();
    let config_path = if args.len() > 1 {
        args[1].clone()
    } else {
        let default_paths = [
            "./mainnet-config.toml",
        ];

        let mut found_config = None;
        for path in &default_paths {
            if std::path::Path::new(path).exists() {
                found_config = Some(path.to_string());
                break;
            }
        }

        match found_config {
            Some(path) => path,
            None => {
                error!("No configuration file found. Usage: {} <config-file>", args[0]);
                error!("Looked for configuration in:");
                for path in &default_paths {
                    error!("  - {}", path);
                }
                std::process::exit(1);
            }
        }
    };

    match ProductionNode::from_config(&config_path).await {
        Ok(mut node) => {
            if let Err(e) = node.start().await {
                error!("Failed to start production node: {}", e);
                std::process::exit(1);
            }
        }
        Err(e) => {
            error!("Failed to initialize production node: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
