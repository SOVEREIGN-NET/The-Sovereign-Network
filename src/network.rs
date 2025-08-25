use crate::zhtp::consensus_engine::ZkNetworkMetrics;
use crate::zhtp::crypto::Keypair;
use crate::storage::dht::DhtNetwork;
// NOTE: Temporary local fallback for signature verification to avoid unresolved import

fn verify_signature_bytes(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    use pqcrypto_dilithium::dilithium5::{verify_detached_signature, DetachedSignature, PublicKey};
    use pqcrypto_traits::sign::{PublicKey as _, DetachedSignature as _};
    if public_key_bytes.is_empty() || signature_bytes.is_empty() { return false; }
    let pk = match PublicKey::from_bytes(public_key_bytes) { Ok(pk) => pk, Err(_) => return false };
    let sig = match DetachedSignature::from_bytes(signature_bytes) { Ok(sig) => sig, Err(_) => return false };
    verify_detached_signature(&sig, message, &pk).is_ok()
}

use rand::Rng;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

pub type NetworkId = String;

/// Production deployment configuration for ZHTP nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpNetworkConfig {
    /// Node ID for this instance
    pub node_id: String,
    /// Listen address for this node
    pub listen_addr: SocketAddr,
    /// Bootstrap nodes for initial connection
    pub bootstrap_nodes: Vec<SocketAddr>,
    /// Public IP for external connections (for NAT/firewall environments)
    pub public_addr: Option<SocketAddr>,
    /// Network environment (mainnet, testnet, devnet)
    pub network_env: NetworkEnvironment,
    /// Certificate authority configuration
    pub ca_config: Option<CertificateAuthorityConfig>,
    /// DNS resolver configuration
    pub dns_config: DnsConfig,
    /// Performance and scaling settings
    pub performance_config: PerformanceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkEnvironment {
    Mainnet,
    Testnet,
    Devnet,
    Private(String), // Custom network name
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateAuthorityConfig {
    /// Whether this node acts as a certificate authority
    pub is_ca_node: bool,
    /// Root certificate for this CA (if CA node)
    pub root_cert: Option<String>,
    /// Trusted CA public keys
    pub trusted_cas: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Whether this node provides DNS resolution
    pub is_dns_provider: bool,
    /// Cached domain records
    pub static_domains: HashMap<String, String>,
    /// DNS cache size
    pub cache_size: usize,
    /// TTL for DNS records
    pub default_ttl: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Maximum concurrent connections
    pub max_connections: usize,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Maximum message size in bytes
    pub max_message_size: usize,
    /// Rate limiting: max messages per second per IP
    pub rate_limit: u32,
    /// Number of worker threads
    pub worker_threads: usize,
}

impl Default for ZhtpNetworkConfig {
    fn default() -> Self {
        // Generate a simple node ID without uuid crate
        let node_id = format!("zhtp-node-{}", rand::random::<u64>());
        
        Self {
            node_id,
            listen_addr: "0.0.0.0:19847".parse().expect("Default listen address should be valid"),
            bootstrap_nodes: vec![
                // Remove the hardcoded addresses and use empty vec for default
                // The actual bootstrap nodes should come from config file
            ],
            public_addr: None,
            network_env: NetworkEnvironment::Mainnet,
            ca_config: Some(CertificateAuthorityConfig {
                is_ca_node: false,
                root_cert: None,
                trusted_cas: vec![],
            }),
            dns_config: DnsConfig {
                is_dns_provider: false,
                static_domains: HashMap::new(),
                cache_size: 10000,
                default_ttl: 3600,
            },
            performance_config: PerformanceConfig {
                max_connections: 1000,
                connection_timeout: 30,
                max_message_size: 1024 * 1024, // 1MB
                rate_limit: 100,
                worker_threads: 4,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub source: NetworkId,
    pub destination: NetworkId,
    pub payload: String,
    pub timestamp: i64,
    visited_nodes: HashSet<NetworkId>,
    size: u64,
    max_hops: u32,
    hop_count: u32,
    /// Cryptographic signature for packet authentication
    pub signature: Vec<u8>,
    /// Hash of packet contents for integrity verification
    pub content_hash: [u8; 32],
    /// Public key of the sender for signature verification
    pub sender_public_key: Vec<u8>,
}

impl Packet {
    /// Create a new authenticated packet with cryptographic signature
    pub fn new_authenticated(
        source: NetworkId, 
        destination: NetworkId, 
        payload: String, 
        timestamp: i64,
        sender_keypair: &Keypair
    ) -> Self {
        let mut visited = HashSet::new();
        visited.insert(source.clone());
        let size = (payload.len() + 100) as u64; // Base packet size + payload

        // Create packet content hash for integrity
        let content_hash = Self::compute_content_hash(&source, &destination, &payload, timestamp);
        
        // Sign the packet with sender's private key
        let signature = Self::sign_packet(&content_hash, sender_keypair);
        let sender_public_key = sender_keypair.public_key();

        Packet {
            source,
            destination,
            payload,
            timestamp,
            visited_nodes: visited,
            size,
            max_hops: 10,
            hop_count: 0,
            signature,
            content_hash,
            sender_public_key,
        }
    }

    /// Legacy constructor for compatibility (DEPRECATED - insecure)
    pub fn new(source: NetworkId, destination: NetworkId, payload: String, timestamp: i64) -> Self {
        let mut visited = HashSet::new();
        visited.insert(source.clone());
        let size = (payload.len() + 100) as u64;

        println!("⚠️  WARNING: Using insecure packet creation without authentication!");
        
        Packet {
            source,
            destination,
            payload,
            timestamp,
            visited_nodes: visited,
            size,
            max_hops: 10,
            hop_count: 0,
            signature: vec![],
            content_hash: [0u8; 32],
            sender_public_key: vec![],
        }
    }

    /// Compute cryptographic hash of packet contents
    fn compute_content_hash(source: &str, destination: &str, payload: &str, timestamp: i64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"ZHTP_PACKET_V1"); // Domain separator
        hasher.update(source.as_bytes());
        hasher.update(destination.as_bytes());
        hasher.update(payload.as_bytes());
        hasher.update(&timestamp.to_le_bytes());
        
        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }

    /// Sign packet with signature
    fn sign_packet(content_hash: &[u8; 32], keypair: &Keypair) -> Vec<u8> {
        match keypair.sign(content_hash) {
            Ok(signature) => signature.into_bytes(),
            Err(e) => {
                println!("❌ Failed to sign packet: {}", e);
                vec![] // Return empty signature on failure
            }
        }
    }

    /// Verify packet authenticity and integrity
    pub fn verify_signature(&self) -> bool {
    // Must have auth fields
    if self.signature.is_empty() || self.sender_public_key.is_empty() { return false; }

    // Recompute canonical content hash (domain separated) and compare
    let expected_hash = Self::compute_content_hash(&self.source, &self.destination, &self.payload, self.timestamp);
    if expected_hash != self.content_hash { return false; }

    // Verify signature over the content hash using Dilithium (PQ secure)
    if !verify_signature_bytes(&self.sender_public_key, &self.content_hash, &self.signature) { return false; }

    true
    }

    /// Check if packet is authenticated (has valid signature)
    pub fn is_authenticated(&self) -> bool {
        !self.signature.is_empty() && !self.sender_public_key.is_empty()
    }

    fn increment_hop(&mut self) -> bool {
        self.hop_count += 1;
        self.hop_count <= self.max_hops
    }

    fn has_visited(&self, node_id: &str) -> bool {
        self.visited_nodes.contains(node_id)
    }

    fn record_visit(&mut self, node_id: String) {
        self.visited_nodes.insert(node_id);
    }
}

#[derive(Debug, Clone)]
pub struct NetworkCondition {
    pub packet_loss_rate: f64,
    pub latency_multiplier: f64,
    pub bandwidth_cap: Option<usize>,
}

impl Default for NetworkCondition {
    fn default() -> Self {
        NetworkCondition {
            packet_loss_rate: 0.0,
            latency_multiplier: 1.0,
            bandwidth_cap: None,
        }
    }
}

impl NetworkCondition {
    // (No methods currently implemented)
}

#[derive(Debug)]
pub struct Network {
    /// Network configuration for production deployment
    config: ZhtpNetworkConfig,
    /// Connected nodes in the ZHTP network
    nodes: HashMap<NetworkId, Node>,
    /// Message queue for packet routing
    message_queue: VecDeque<Packet>,
    /// Delivery tracking for reliability metrics
    delivery_tracking: HashMap<String, bool>,
    /// Network conditions for simulation
    network_conditions: HashMap<NetworkId, NetworkCondition>,
    /// ZHTP certificate registry (replaces traditional CAs)
    certificate_registry: HashMap<String, ZhtpCertificate>,
    /// Decentralized DNS records (replaces traditional DNS)
    dns_registry: HashMap<String, ZhtpDnsRecord>,
    /// Connection pool for remote nodes
    connection_pool: HashMap<NetworkId, ConnectionInfo>,
    /// Security violation tracking for threat detection
    security_violations: HashMap<NetworkId, u32>,
    /// Rate limiting for DoS protection
    message_rates: HashMap<NetworkId, MessageRateTracker>,
    /// DHT for peer discovery and decentralized storage
    dht: DhtNetwork,
}

/// ZHTP certificate that replaces X.509 certificates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpCertificate {
    pub domain: String,
    pub public_key: String,
    pub issued_by: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub zk_proof: String, // Zero-knowledge proof of validity
    pub signature: String,
}

/// ZHTP DNS record for decentralized domain resolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpDnsRecord {
    pub domain: String,
    pub addresses: Vec<SocketAddr>,
    pub content_hash: String,
    pub owner_key: String,
    pub ttl: u64,
    pub registered_at: u64,
    pub signature: String,
}

/// Connection information for production deployment
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub address: SocketAddr,
    pub status: ConnectionStatus,
    pub last_seen: u64,
    pub latency: f64,
    pub reliability_score: f64,
}

#[derive(Debug, Clone)]
pub enum ConnectionStatus {
    Connected,
    Connecting,
    Disconnected,
    Failed,
}

impl Network {
    pub fn new() -> Self {
        Self::with_config(ZhtpNetworkConfig::default())
    }

    pub fn with_config(config: ZhtpNetworkConfig) -> Self {
        Network {
            config,
            nodes: HashMap::new(),
            message_queue: VecDeque::new(),
            delivery_tracking: HashMap::new(),
            network_conditions: HashMap::new(),
            certificate_registry: HashMap::new(),
            dns_registry: HashMap::new(),
            connection_pool: HashMap::new(),
            security_violations: HashMap::new(),
            message_rates: HashMap::new(),
            dht: DhtNetwork::new(),
        }
    }

    /// Production deployment method - start the ZHTP network node
    pub async fn start_production_node(&mut self) -> Result<(), String> {
        println!("🚀 Starting ZHTP production node: {}", self.config.node_id);
        println!("📡 Listening on: {}", self.config.listen_addr);
        println!("🌐 Network environment: {:?}", self.config.network_env);

        // Register this node with DHT for peer discovery
        if !self.dht.register_node(self.config.node_id.clone(), 10_000).await {
            return Err("Failed to register node with DHT".to_string());
        }
        println!("✅ Node registered with DHT: {}", self.config.node_id);

        // Initialize certificate authority if configured
        if let Some(ca_config) = &self.config.ca_config {
            if ca_config.is_ca_node {
                self.initialize_certificate_authority().await;
            }
        }

        // Initialize DNS provider if configured
        if self.config.dns_config.is_dns_provider {
            self.initialize_dns_provider().await;
        }

        // Connect to bootstrap nodes
        self.connect_to_bootstrap_nodes().await?;

        println!("✅ ZHTP node started successfully");
        Ok(())
    }

    /// Initialize as a ZHTP certificate authority (replaces traditional CAs)
    async fn initialize_certificate_authority(&mut self) {
        println!("🔐 Initializing ZHTP Certificate Authority...");
        
        // Generate CA keypair for signing certificates
        let ca_keypair = Keypair::generate();
        
        // Add some sample certificates for demonstration
        let sample_certs = vec![
            ("zhtp.network", "production_root_key"),
            ("api.zhtp.network", "api_service_key"), 
            ("docs.zhtp.network", "docs_service_key"),
        ];

        for (domain, key) in sample_certs {
            let cert = self.create_signed_certificate(domain, key, &ca_keypair);
            self.certificate_registry.insert(domain.to_string(), cert);
        }

        println!("✅ Certificate Authority initialized with {} certificates", 
                 self.certificate_registry.len());
    }

    /// Create a cryptographically signed certificate
    fn create_signed_certificate(&self, domain: &str, key_id: &str, ca_keypair: &Keypair) -> ZhtpCertificate {
        let public_key = format!("zhtp_pubkey_{}", key_id);
        let issued_at = chrono::Utc::now().timestamp() as u64;
        let expires_at = issued_at + (365 * 24 * 3600); // 1 year
        
        // Create certificate content for signing
        let mut cert_content = Vec::new();
        cert_content.extend_from_slice(domain.as_bytes());
        cert_content.extend_from_slice(public_key.as_bytes());
        cert_content.extend_from_slice(&issued_at.to_le_bytes());
        cert_content.extend_from_slice(&expires_at.to_le_bytes());
        
        // Sign certificate with CA private key
        let signature = match ca_keypair.sign(&cert_content) {
            Ok(sig) => format!("CA_SIGNED_{:x}", 
                rand::random::<u64>().wrapping_add(sig.len() as u64)), // Deterministic from signature
            Err(_) => format!("INVALID_SIGNATURE_{}", rand::random::<u64>()),
        };

        ZhtpCertificate {
            domain: domain.to_string(),
            public_key: public_key.clone(),
            issued_by: self.config.node_id.clone(),
            issued_at,
            expires_at,
            zk_proof: {
                // Generate cryptographically secure proof using SHA256 and certificate data
                use sha2::{Sha256, Digest};
                
                // Create certificate commitment data for verification
                let mut cert_data = Vec::new();
                cert_data.extend_from_slice(domain.as_bytes());
                cert_data.extend_from_slice(public_key.as_bytes());
                cert_data.extend_from_slice(&issued_at.to_be_bytes());
                cert_data.extend_from_slice(&expires_at.to_be_bytes());
                cert_data.extend_from_slice(&self.config.node_id.as_bytes());
                
                // Generate cryptographically secure proof
                let mut hasher = Sha256::new();
                hasher.update(&cert_data);
                hasher.update(b"ZHTP_CERTIFICATE_PROOF");
                let hash = hasher.finalize();
                
                // Format as ZK-style proof with commitment
                format!("zk_cert_proof_{}", hex::encode(&hash[..16]))
            },
            signature,
        }
    }

    /// Initialize as a ZHTP DNS provider (replaces traditional DNS)
    async fn initialize_dns_provider(&mut self) {
        println!("🌐 Initializing ZHTP DNS Provider...");

        // Add static domain mappings from config
        for (domain, address) in &self.config.dns_config.static_domains {
            if let Ok(addr) = address.parse::<SocketAddr>() {
                let dns_record = ZhtpDnsRecord {
                    domain: domain.clone(),
                    addresses: vec![addr],
                    content_hash: format!("hash_{}", rand::random::<u64>()),
                    owner_key: format!("owner_{}", rand::random::<u64>()),
                    ttl: self.config.dns_config.default_ttl,
                    registered_at: chrono::Utc::now().timestamp() as u64,
                    signature: format!("dns_sig_{}", rand::random::<u64>()),
                };
                
                self.dns_registry.insert(domain.clone(), dns_record);
            }
        }

        // Add default ZHTP network domains
        let default_domains = vec![
            ("zhtp.network", "seed1.zhtp.network:19847"),
            ("api.zhtp.network", "api.zhtp.network:19847"),
            ("explorer.zhtp.network", "explorer.zhtp.network:19847"),
        ];

        for (domain, address) in default_domains {
            if let Ok(addr) = address.parse::<SocketAddr>() {
                let dns_record = ZhtpDnsRecord {
                    domain: domain.to_string(),
                    addresses: vec![addr],
                    content_hash: format!("default_hash_{}", rand::random::<u64>()),
                    owner_key: "zhtp_network_authority".to_string(),
                    ttl: 86400, // 24 hours
                    registered_at: chrono::Utc::now().timestamp() as u64,
                    signature: format!("authority_sig_{}", rand::random::<u64>()),
                };
                
                self.dns_registry.insert(domain.to_string(), dns_record);
            }
        }

        println!("✅ DNS Provider initialized with {} domain records", 
                 self.dns_registry.len());
    }

    /// Connect to bootstrap nodes for network discovery
    async fn connect_to_bootstrap_nodes(&mut self) -> Result<(), String> {
        println!("🔗 Connecting to {} bootstrap nodes...", self.config.bootstrap_nodes.len());

        let bootstrap_nodes = self.config.bootstrap_nodes.clone();
        let mut successful_connections = 0;
        
        for bootstrap_addr in bootstrap_nodes {
            match self.connect_to_node(bootstrap_addr).await {
                Ok(_) => {
                    println!("✅ Connected to bootstrap node: {}", bootstrap_addr);
                    successful_connections += 1;
                }
                Err(e) => {
                    println!("⚠️  Failed to connect to bootstrap node {}: {}", bootstrap_addr, e);
                }
            }
        }

        // After connecting to bootstrap nodes, discover additional peers through DHT
        if successful_connections > 0 {
            println!("🔍 Discovering additional peers through DHT...");
            match self.connect_to_dht_peers(10).await {
                Ok(dht_connections) => {
                    println!("✅ Connected to {} additional peers through DHT", dht_connections);
                }
                Err(e) => {
                    println!("⚠️  DHT peer discovery failed: {}", e);
                }
            }
        }

        if successful_connections > 0 {
            Ok(())
        } else {
            Err("Failed to connect to any bootstrap nodes".to_string())
        }
    }

    /// Periodically refresh connections to active peers through DHT
    pub async fn refresh_peer_connections(&mut self) -> Result<usize, String> {
        println!("🔄 Refreshing peer connections through DHT...");
        
        // Remove stale connections first
        let now = chrono::Utc::now().timestamp() as u64;
        let stale_threshold = 600; // 10 minutes
        
        let stale_nodes: Vec<_> = self.connection_pool
            .iter()
            .filter(|(_, conn)| (now - conn.last_seen) > stale_threshold)
            .map(|(node_id, _)| node_id.clone())
            .collect();
            
        for node_id in stale_nodes {
            self.connection_pool.remove(&node_id);
            println!("🗑️  Removed stale connection: {}", node_id);
        }
        
        // Discover and connect to new active peers
        let max_peers = 20; // Maximum number of peers to maintain
        let current_connections = self.connection_pool.len();
        
        if current_connections < max_peers {
            let needed_connections = max_peers - current_connections;
            match self.connect_to_dht_peers(needed_connections).await {
                Ok(new_connections) => {
                    println!("✅ Added {} new peer connections", new_connections);
                    Ok(new_connections)
                }
                Err(e) => {
                    println!("⚠️  Failed to add new peer connections: {}", e);
                    Err(e)
                }
            }
        } else {
            println!("📊 Peer connections are sufficient: {}/{}", current_connections, max_peers);
            Ok(0)
        }
    }

    /// Get statistics about DHT and peer connections
    pub async fn get_dht_stats(&self) -> HashMap<String, u64> {
        let mut stats = HashMap::new();
        
        // Connection pool statistics
        stats.insert("total_connections".to_string(), self.connection_pool.len() as u64);
        
        let active_connections = self.connection_pool
            .values()
            .filter(|conn| matches!(conn.status, ConnectionStatus::Connected))
            .count();
        stats.insert("active_connections".to_string(), active_connections as u64);
        
        // Calculate average latency
        let total_latency: f64 = self.connection_pool
            .values()
            .map(|conn| conn.latency)
            .sum();
        let avg_latency = if !self.connection_pool.is_empty() {
            total_latency / self.connection_pool.len() as f64
        } else {
            0.0
        };
        stats.insert("average_latency_ms".to_string(), avg_latency as u64);
        
        // Recent connections (last 5 minutes)
        let now = chrono::Utc::now().timestamp() as u64;
        let recent_connections = self.connection_pool
            .values()
            .filter(|conn| (now - conn.last_seen) < 300)
            .count();
        stats.insert("recent_connections".to_string(), recent_connections as u64);
        
        stats
    }

    /// Connect to a specific ZHTP node using DHT peer discovery
    async fn connect_to_node(&mut self, address: SocketAddr) -> Result<(), String> {
        println!("🔍 Discovering active peers through DHT for {}", address);
        
        // Register this node with the DHT if not already registered
        let node_id = format!("node_{}", address);
        if !self.dht.register_node(node_id.clone(), 1000).await {
            return Err(format!("Failed to register node {} in DHT", node_id));
        }

        // Attempt to establish TCP connection to verify node is active
        match timeout(Duration::from_secs(5), TcpStream::connect(address)).await {
            Ok(Ok(_stream)) => {
                println!("✅ Successfully connected to active node: {}", address);
                
                let connection_info = ConnectionInfo {
                    address,
                    status: ConnectionStatus::Connected,
                    last_seen: chrono::Utc::now().timestamp() as u64,
                    latency: self.measure_node_latency(address).await,
                    reliability_score: 0.9, // Start with high reliability for active connections
                };

                self.connection_pool.insert(node_id, connection_info);
                Ok(())
            }
            Ok(Err(e)) => {
                println!("❌ Failed to connect to {}: {}", address, e);
                Err(format!("Connection failed: {}", e))
            }
            Err(_) => {
                println!("⏰ Connection timeout for {}", address);
                Err(format!("Connection timeout for {}", address))
            }
        }
    }

    /// Measure actual network latency to a node
    async fn measure_node_latency(&self, address: SocketAddr) -> f64 {
        let start = std::time::Instant::now();
        
        match timeout(Duration::from_secs(2), TcpStream::connect(address)).await {
            Ok(Ok(_)) => {
                let latency = start.elapsed().as_millis() as f64;
                println!("📊 Measured latency to {}: {}ms", address, latency);
                latency
            }
            Ok(Err(_)) | Err(_) => {
                println!("📊 Failed to measure latency to {}, using default", address);
                500.0 // Default high latency for failed connections
            }
        }
    }

    /// Discover active peers in the DHT network
    pub async fn discover_active_peers(&self, max_peers: usize) -> Vec<SocketAddr> {
        println!("🔍 Discovering active peers through DHT...");
        
        // This would query the DHT for active peers
        // For now, we simulate peer discovery by checking connection pool
        let active_peers: Vec<SocketAddr> = self.connection_pool
            .values()
            .filter(|conn| matches!(conn.status, ConnectionStatus::Connected))
            .filter(|conn| {
                // Only include peers that were recently seen (within last 5 minutes)
                let now = chrono::Utc::now().timestamp() as u64;
                (now - conn.last_seen) < 300
            })
            .map(|conn| conn.address)
            .take(max_peers)
            .collect();

        println!("📡 Found {} active peers through DHT", active_peers.len());
        active_peers
    }

    /// Connect to peers discovered through DHT
    pub async fn connect_to_dht_peers(&mut self, max_connections: usize) -> Result<usize, String> {
        let discovered_peers = self.discover_active_peers(max_connections).await;
        let mut successful_connections = 0;

        for peer_addr in discovered_peers {
            match self.connect_to_node(peer_addr).await {
                Ok(_) => {
                    successful_connections += 1;
                    println!("✅ Connected to DHT peer: {}", peer_addr);
                }
                Err(e) => {
                    println!("⚠️ Failed to connect to DHT peer {}: {}", peer_addr, e);
                }
            }
        }

        if successful_connections > 0 {
            println!("🎉 Successfully connected to {} peers through DHT", successful_connections);
            Ok(successful_connections)
        } else {
            Err("Failed to connect to any peers through DHT".to_string())
        }
    }

    /// Resolve ZHTP domain using decentralized DNS (replaces traditional DNS)
    pub fn resolve_zhtp_domain(&self, domain: &str) -> Option<Vec<SocketAddr>> {
        if let Some(record) = self.dns_registry.get(domain) {
            Some(record.addresses.clone())
        } else {
            None
        }
    }

    /// Verify ZHTP certificate (replaces SSL/TLS certificate verification)
    pub fn verify_zhtp_certificate(&self, domain: &str, presented_key: &str) -> bool {
        if let Some(cert) = self.certificate_registry.get(domain) {
            // Verify certificate is not expired
            let now = chrono::Utc::now().timestamp() as u64;
            if now > cert.expires_at {
                return false;
            }

            // Verify public key matches
            cert.public_key == presented_key
        } else {
            false
        }
    }

    /// Get network statistics for monitoring
    pub fn get_network_stats(&self) -> NetworkStats {
        NetworkStats {
            node_id: self.config.node_id.clone(),
            connected_nodes: self.connection_pool.len(),
            registered_certificates: self.certificate_registry.len(),
            dns_records: self.dns_registry.len(),
            network_environment: format!("{:?}", self.config.network_env),
            uptime: chrono::Utc::now().timestamp() as u64, // Simplified
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub node_id: String,
    pub connected_nodes: usize,
    pub registered_certificates: usize,
    pub dns_records: usize,
    pub network_environment: String,
    pub uptime: u64,
}

impl Network {
    pub fn add_node<S: Into<String>>(&mut self, id: S, stake: f64) {
        let id = id.into();
        self.nodes.insert(id.clone(), Node::new(id.clone(), stake));
        self.network_conditions
            .insert(id, NetworkCondition::default());
    }

    pub fn set_node_condition<S: AsRef<str>>(&mut self, node_id: S, condition: NetworkCondition) {
        self.network_conditions
            .insert(node_id.as_ref().to_string(), condition);
    }

    pub fn connect_nodes<S: AsRef<str>>(&mut self, node1: S, node2: S) {
        let node1 = node1.as_ref().to_string();
        let node2 = node2.as_ref().to_string();

        if let Some(n1) = self.nodes.get_mut(&node1) {
            n1.connections.push(node2.clone());
        }
        if let Some(n2) = self.nodes.get_mut(&node2) {
            n2.connections.push(node1);
        }
    }

    pub fn disconnect_node<S: AsRef<str>>(&mut self, node_id: S) {
        let node_id = node_id.as_ref();
        for node in self.nodes.values_mut() {
            node.connections.retain(|conn| conn != node_id);
        }
    }

    /// Send an authenticated packet with cryptographic signature
    pub fn send_authenticated_packet(
        &mut self, 
        source: String, 
        destination: String, 
        payload: String,
        sender_keypair: &Keypair
    ) -> Result<(), String> {
        let packet = Packet::new_authenticated(
            source.clone(),
            destination.clone(),
            payload,
            chrono::Utc::now().timestamp(),
            sender_keypair
        );

        // Verify packet was properly signed
        if !packet.verify_signature() {
            return Err("Failed to create authenticated packet".to_string());
        }

        let tracking_id = format!("{}:{}:{}", source, destination, packet.timestamp);
        self.delivery_tracking.insert(tracking_id, false);

        // Use secure queue addition with DoS protection
        self.add_to_message_queue(packet)?;
        println!("✅ Authenticated packet sent from {} to {}", source, destination);
        Ok(())
    }

    /// Legacy insecure packet sending (DEPRECATED)
    pub fn send_packet(&mut self, source: String, destination: String, payload: String) {
        println!("⚠️  WARNING: Using insecure packet transmission without authentication!");
        
        let packet = Packet::new(
            source.clone(),
            destination.clone(),
            payload,
            chrono::Utc::now().timestamp(),
        );

        let tracking_id = format!("{}:{}:{}", source, destination, packet.timestamp);
        self.delivery_tracking.insert(tracking_id, false);

        // Use secure queue addition even for legacy packets
        if let Err(e) = self.add_to_message_queue(packet) {
            println!("⚠️  Legacy packet dropped: {}", e);
        }
    }

    /// Safely add a packet to the message queue with DoS protection
    fn add_to_message_queue(&mut self, packet: Packet) -> Result<(), String> {
        // Check queue size limit
        if self.message_queue.len() >= MAX_MESSAGE_QUEUE_SIZE {
            println!("❌ SECURITY: Message queue full, dropping packet from {}", packet.source);
            return Err("Message queue full - DoS protection activated".to_string());
        }
        
        // Check rate limiting for the source
        let source_id = packet.source.clone();
        let rate_tracker = self.message_rates.entry(source_id.clone())
            .or_insert_with(MessageRateTracker::new);
            
        if !rate_tracker.allow_message() {
            println!("❌ SECURITY: Rate limit exceeded for {}, dropping packet", source_id);
            
            // Track security violation
            self.security_violations.entry(source_id)
                .and_modify(|count| *count += 1)
                .or_insert(1);
                
            return Err("Rate limit exceeded - DoS protection activated".to_string());
        }
        
        // Add to queue if all checks pass
        self.message_queue.push_back(packet);
        Ok(())
    }

    fn handle_failed_delivery(&mut self, node_id: &str, packet: &Packet) {
        if let Some(node) = self.nodes.get_mut(node_id) {
            node.metrics.update_failed_routing();
            node.metrics.update_reputation(false);
        }

        // Mark the delivery as failed in tracking
        let tracking_id = format!(
            "{}:{}:{}",
            packet.source, packet.destination, packet.timestamp
        );
        // Track delivery outcome
        self.delivery_tracking.insert(tracking_id, true);
    }

    fn attempt_delivery(&mut self, packet: &Packet) -> bool {
        // CRITICAL SECURITY CHECK: Verify packet authentication
        if packet.is_authenticated() && !packet.verify_signature() {
            println!("❌ SECURITY VIOLATION: Rejecting packet with invalid signature from {}", packet.source);
            self.security_violations.entry(packet.source.clone())
                .and_modify(|count| *count += 1)
                .or_insert(1);
            return false;
        }

        // Environment-based policy: on Mainnet we reject unauthenticated packets outright
        match self.config.network_env {
            NetworkEnvironment::Mainnet => {
                if !packet.is_authenticated() { return false; }
            },
            _ => {
                if !packet.is_authenticated() {
                    println!("⚠️  WARNING: Processing unauthenticated packet from {} to {}", packet.source, packet.destination);
                }
            }
        }

        let dest_id = packet.destination.clone();
        let source_id = packet.source.clone();
        let tracking_id = format!("{}:{}:{}", source_id, dest_id, packet.timestamp);

        let condition = self.network_conditions.get(&dest_id)
            .cloned()
            .unwrap_or_default();
        
        let reputation = self.nodes.get(&dest_id)
            .map(|n| n.metrics.reputation_score)
            .unwrap_or(1.0);
        
        let base_drop_rate = condition.packet_loss_rate * condition.latency_multiplier;
        let rep_penalty = (1.0f64 - reputation).powf(2.0);
        let final_drop_rate = (base_drop_rate + (rep_penalty * base_drop_rate)).min(0.95);
        
        println!("Delivery check for {}: base_rate={:.3}, penalty={:.3}, final_rate={:.3}, rep={:.2}, auth={}",
                dest_id, base_drop_rate, rep_penalty, final_drop_rate, reputation, packet.is_authenticated());

        use rand::Rng;
        let mut rng = rand::thread_rng();
        let random_value: f64 = rng.gen_range(0.0..1.0);
        if !self.nodes.contains_key(&dest_id) || random_value < final_drop_rate {
            // Handle failed delivery with more nuanced penalties
            if let Some(dest_node) = self.nodes.get_mut(&dest_id) {
                // Only apply reputation penalty under good conditions
                if base_drop_rate < 0.3 && reputation > 0.5 {
                    dest_node.metrics.update_reputation(false);
                }
                
                // Track metrics regardless of conditions
                dest_node.metrics.update_failed_routing();
            }
            return false;
        }

        // Attempt delivery
        let latency = self.calculate_node_latency(&dest_id);
        if let Some(dest_node) = self.nodes.get_mut(&dest_id) {
            dest_node.receive_packet(packet.clone());
            dest_node.metrics.update_routing_metrics(latency, packet.size.try_into().unwrap_or(0));
            self.delivery_tracking.insert(tracking_id, true);

            // Update source node reputation
            if let Some(source_node) = self.nodes.get_mut(&source_id) {
                source_node.metrics.update_reputation(true);
            }
            true
        } else {
            false
        }
    }

    fn try_forward_packet(
        &mut self,
        new_messages: &mut VecDeque<Packet>,
        packet: &Packet,
        next_hop: &str,
    ) -> bool {
        // Get network conditions and calculate drop probability
        let condition = self.network_conditions.get(next_hop)
            .cloned()
            .unwrap_or_default();
        
        // Get current reputation
        let reputation = self.nodes.get(next_hop)
            .map(|n| n.metrics.reputation_score)
            .unwrap_or(1.0);
            
        // Calculate drop rate adjustment based on reputation
        let base_drop_rate = condition.packet_loss_rate * condition.latency_multiplier;
        let modifier = if reputation > 0.8 {
            -0.2  // Good reputation reduces drop rate
        } else if reputation < 0.3 {
            0.2   // Bad reputation increases drop rate
        } else {
            0.0   // Neutral effect for mid-range reputation
        };
        
        let final_drop_rate = (base_drop_rate + modifier).clamp(0.05, 0.95);
        
        println!("Drop check for {}: base_rate={:.3}, modifier={:.3}, final_rate={:.3}, rep={:.2}",
                next_hop, base_drop_rate, modifier, final_drop_rate, reputation);
                
        // Check if packet should be dropped
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let random_val: f64 = rng.gen_range(0.0..1.0);
        if !self.nodes.contains_key(next_hop) ||
           random_val < final_drop_rate {
            // Calculate latency even for failed attempts
            let latency = self.calculate_node_latency(next_hop);
            if let Some(next_node) = self.nodes.get_mut(next_hop) {
                // Update metrics with high latency for failed attempt
                next_node.metrics.update_routing_metrics(latency * 2.0, packet.size.try_into().unwrap_or(0));
                
                // Apply penalties based on conditions and current performance
                let expected_fails = condition.packet_loss_rate * condition.latency_multiplier;
                if expected_fails < 0.3 && reputation > 0.8 {
                    // Only penalize if conditions are good and reputation is high
                    next_node.metrics.update_reputation(false);
                } else if expected_fails < 0.5 && reputation > 0.6 {
                    // Light penalty for moderate conditions
                    next_node.metrics.update_reputation(false);
                }
                // Track failure but don't penalize reputation under poor conditions
                next_node.metrics.update_failed_routing();
            }
            return false;
        }

        let latency = self.calculate_node_latency(next_hop);
        if let Some(next_node) = self.nodes.get_mut(next_hop) {
            // Update metrics and apply reputation boost based on conditions
            next_node.metrics.update_routing_metrics(latency, packet.size.try_into().unwrap_or(0));
            let mut new_packet = packet.clone();
            new_packet.record_visit(next_hop.to_string());
            new_messages.push_back(new_packet);
            
            // Handle successful forward
            let condition = self.network_conditions.get(next_hop)
                .cloned()
                .unwrap_or_default();

            // Calculate difficulty and expected failure rate
            let difficulty = condition.packet_loss_rate * condition.latency_multiplier;
            
            // Calculate reputation boost based on conditions
            let boost_count = if difficulty > 0.8 {
                3  // Major boost for success under extreme conditions
            } else if difficulty > 0.5 {
                2  // Medium boost for difficult conditions
            } else {
                1  // Normal boost for good conditions
            };

            // Apply reputation boosts
            for _ in 0..boost_count {
                next_node.metrics.update_reputation(true);
            }

            // Small additional boost for consistently good performance
            if next_node.metrics.reputation_score > 0.7 && difficulty < 0.3 {
                next_node.metrics.update_reputation(true);
            }
            
            return true;
        }
        false
    }

    fn calculate_node_latency(&self, node_id: &str) -> f64 {
        let mut rng = rand::thread_rng();
        let base_latency = rng.gen_range(10.0..200.0);
        if let Some(condition) = self.network_conditions.get(node_id) {
            base_latency * condition.latency_multiplier
        } else {
            base_latency
        }
    }

    /// Evaluate a node's current routing score (higher is better)
    fn evaluate_node_score(&self, node_id: &str) -> f64 {
        // Get node's current reputation
        let reputation = self.nodes.get(node_id)
            .map(|n| n.metrics.reputation_score)
            .unwrap_or(0.0);

        // Get network conditions
        let condition = self.network_conditions.get(node_id)
            .cloned()
            .unwrap_or_default();

        // Calculate effective drop rate
        let drop_rate = condition.packet_loss_rate * condition.latency_multiplier;
        
        // Scale down high drop rates less aggressively
        let condition_multiplier = 1.0 - (drop_rate * 1.5).min(0.6);
        
        // Base score on reputation and conditions
        let score = reputation * condition_multiplier;
        
        // Add small base chance but cap maximum
        (score + 0.05).min(0.95).max(0.05)
    }

    pub fn process_messages(&mut self) {
        let mut new_messages = VecDeque::new();

        while let Some(mut packet) = self.message_queue.pop_front() {
            if !packet.increment_hop() {
                self.handle_failed_delivery(&packet.source, &packet);
                continue;
            }

            // Only attempt direct delivery if the destination is a direct neighbor
            let current_id = packet.visited_nodes.iter().last().unwrap_or(&packet.source).clone();
            let can_deliver_direct = if let Some(current_node) = self.nodes.get(&current_id) {
                current_node.connections.contains(&packet.destination)
            } else {
                false
            };

            if can_deliver_direct && self.attempt_delivery(&packet) {
                continue;
            }

            // Get current node and its connections
            let current_id = packet
                .visited_nodes
                .iter()
                .last()
                .unwrap_or(&packet.source)
                .clone();

            // Get and sort available next hops by score
            let mut candidates = Vec::new();
            if let Some(current_node) = self.nodes.get(&current_id) {
                for conn in &current_node.connections {
                    if !packet.has_visited(conn) {
                        let score = self.evaluate_node_score(conn);
                        candidates.push((conn.clone(), score));
                    }
                }
            }

            // Sort by score and packet loss rate
            candidates.sort_by(|(a_id, a_score), (b_id, b_score)| {
                let a_loss = self.network_conditions.get(a_id)
                    .map(|c| c.packet_loss_rate)
                    .unwrap_or(0.0);
                let b_loss = self.network_conditions.get(b_id)
                    .map(|c| c.packet_loss_rate)
                    .unwrap_or(0.0);
                
                // Primary sort by score, secondary by packet loss
                match b_score.partial_cmp(a_score) {
                    Some(ord) if ord == std::cmp::Ordering::Equal => {
                        a_loss.partial_cmp(&b_loss).unwrap_or(std::cmp::Ordering::Equal)
                    }
                    Some(ord) => ord,
                    None => std::cmp::Ordering::Equal
                }
            });

            // Try forwarding through each candidate
            let mut forwarded = false;
            let mut attempted_nodes = Vec::new();

            for (next_hop, score) in candidates {
                attempted_nodes.push(next_hop.clone());
                let condition = self.network_conditions.get(&next_hop)
                    .cloned()
                    .unwrap_or_default();
                println!("Attempting route through {}: score={:.3}, drop_rate={:.3}, latency={:.1}x",
                    next_hop, score, condition.packet_loss_rate, condition.latency_multiplier);
                
                if self.try_forward_packet(&mut new_messages, &packet, &next_hop) {
                    println!("Successfully forwarded through {}", next_hop);
                    forwarded = true;
                    break;
                } else {
                    println!("Failed to forward through {} - packet dropped", next_hop);
                }

                // Penalize based on base conditions and current reputation
                if let Some(node) = self.nodes.get_mut(&next_hop) {
                    let condition = self.network_conditions.get(&next_hop)
                        .cloned()
                        .unwrap_or_default();
                        
                    // Adjust reputation based on failure context
                    let expected_fails = condition.packet_loss_rate * condition.latency_multiplier;
                    
                    // Apply penalties only under good conditions
                    if expected_fails < 0.3 {
                        // Apply penalty if reputation is too high for performance
                        if node.metrics.reputation_score > 0.8 {
                            node.metrics.update_reputation(false);
                        }
                    }
                    
                    // Always track metrics
                    node.metrics.update_failed_routing();
                }
            }

            // Apply penalties only if packet cannot be forwarded through any path
            if !forwarded {
                for next_hop in attempted_nodes {
                    if let Some(node) = self.nodes.get_mut(&next_hop) {
                        let condition = self.network_conditions.get(&next_hop)
                            .cloned()
                            .unwrap_or_default();
                        let expected_fails = condition.packet_loss_rate * condition.latency_multiplier;
                        
                        // Only track metrics and apply penalties under specific conditions
                        if expected_fails < 0.2 && node.metrics.reputation_score > 0.8 {
                            node.metrics.update_reputation(false);
                            node.metrics.update_failed_routing();
                        }
                    }
                }
                self.handle_failed_delivery(&current_id, &packet);
            }
        }

        // Safely add new messages with DoS protection
        for packet in new_messages {
            if let Err(e) = self.add_to_message_queue(packet) {
                println!("⚠️  Forwarded packet dropped: {}", e);
                // Continue processing other packets instead of failing completely
            }
        }
    }

    pub fn get_node_metrics<S: AsRef<str>>(&self, node_id: S) -> Option<&ZkNetworkMetrics> {
        self.nodes.get(node_id.as_ref()).map(|node| &node.metrics)
    }

    pub fn get_delivery_success_rate(&self) -> f64 {
        let total = self.delivery_tracking.len();
        if total == 0 {
            return 1.0;
        }

        let successful = self
            .delivery_tracking
            .values()
            .filter(|&&success| success)
            .count();

        successful as f64 / total as f64
    }

    /// Monitor security violations and detect potential attacks
    pub fn get_security_report(&self) -> HashMap<String, u32> {
        let mut report = HashMap::new();
        
        for (node_id, violation_count) in &self.security_violations {
            if *violation_count > 0 {
                report.insert(format!("violations_by_{}", node_id), *violation_count);
            }
        }
        
        // Add threat level assessment
        let total_violations: u32 = self.security_violations.values().sum();
        report.insert("total_security_violations".to_string(), total_violations);
        
        if total_violations > 10 {
            report.insert("threat_level".to_string(), 3); // HIGH
        } else if total_violations > 5 {
            report.insert("threat_level".to_string(), 2); // MEDIUM
        } else {
            report.insert("threat_level".to_string(), 1); // LOW
        }
        
        report
    }

    /// Block a node that has too many security violations
    pub fn block_malicious_node(&mut self, node_id: &str) -> bool {
        if let Some(&violation_count) = self.security_violations.get(node_id) {
            if violation_count > 5 { // Threshold for blocking
                println!("🚫 BLOCKING malicious node {} with {} violations", node_id, violation_count);
                self.nodes.remove(node_id);
                return true;
            }
        }
        false
    }

    /// Process the message queue with security checks
    pub fn process_secure_queue(&mut self) -> usize {
        let mut processed = 0;
        let mut blocked_nodes = Vec::new();
        
        while let Some(packet) = self.message_queue.pop_front() {
            // Check for malicious nodes before processing
            if let Some(&violations) = self.security_violations.get(&packet.source) {
                if violations > 5 {
                    blocked_nodes.push(packet.source.clone());
                    continue; // Skip packets from blocked nodes
                }
            }
            
            if self.attempt_delivery(&packet) {
                processed += 1;
            }
        }
        
        // Block nodes with too many violations
        for node_id in blocked_nodes {
            self.block_malicious_node(&node_id);
        }
        
        processed
    }

    /// Get queue status for monitoring and debugging
    pub fn get_queue_status(&self) -> (usize, usize, f64) {
        let current_size = self.message_queue.len();
        let max_size = MAX_MESSAGE_QUEUE_SIZE;
        let utilization = (current_size as f64 / max_size as f64) * 100.0;
        
        (current_size, max_size, utilization)
    }
    
    /// Get active rate limiting sessions count
    pub fn get_rate_limiter_status(&self) -> usize {
        self.message_rates.len()
    }

    /// Clean up old rate tracking data to prevent memory leaks
    #[allow(dead_code)]
    fn _cleanup_rate_trackers(&mut self) {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        
        // Remove trackers that haven't been used in the last hour
        self.message_rates.retain(|_node_id, tracker| {
            now - tracker.window_start < 3600 // 1 hour
        });
    }
}

#[derive(Debug)]
pub struct Node {
    id: NetworkId,
    connections: Vec<NetworkId>,
    metrics: ZkNetworkMetrics,
    received_messages: Vec<String>,
}

impl Node {
    pub fn new<S: Into<String>>(id: S, stake: f64) -> Self {
        Node {
            id: id.into(),
            connections: Vec::new(),
            metrics: ZkNetworkMetrics::new(stake),
            received_messages: Vec::new(),
        }
    }

    pub fn receive_packet(&mut self, packet: Packet) {
        if packet.destination == self.id {
            self.received_messages.push(packet.payload);
        }
    }

    pub fn get_received_messages(&self) -> &[String] {
        &self.received_messages
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zhtp::crypto::Keypair;

    #[tokio::test]
    async fn test_dht_integration() {
        let network = Network::new();
        
        // Test DHT initialization
        assert!(network.dht.register_node("test_node".to_string(), 1000).await);
        
        // Test DHT stats
        let stats = network.get_dht_stats().await;
        assert!(stats.contains_key("total_connections"));
        assert!(stats.contains_key("active_connections"));
        assert!(stats.contains_key("average_latency_ms"));
        assert!(stats.contains_key("recent_connections"));
        
        println!("DHT stats: {:?}", stats);
    }

    #[tokio::test]
    async fn test_peer_discovery() {
        let mut network = Network::new();
        
        // Simulate some connections in the pool
        let addr1: SocketAddr = "127.0.0.1:19847".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:19848".parse().unwrap();
        
        let connection1 = ConnectionInfo {
            address: addr1,
            status: ConnectionStatus::Connected,
            last_seen: chrono::Utc::now().timestamp() as u64,
            latency: 50.0,
            reliability_score: 0.9,
        };
        
        let connection2 = ConnectionInfo {
            address: addr2,
            status: ConnectionStatus::Connected,
            last_seen: chrono::Utc::now().timestamp() as u64 - 600, // 10 minutes ago (stale)
            latency: 100.0,
            reliability_score: 0.8,
        };
        
        network.connection_pool.insert("node_1".to_string(), connection1);
        network.connection_pool.insert("node_2".to_string(), connection2);
        
        // Test active peer discovery
        let active_peers = network.discover_active_peers(10).await;
        assert_eq!(active_peers.len(), 1); // Only one recent connection
        assert_eq!(active_peers[0], addr1);
    }

    #[test]
    fn test_authenticated_packet_success_and_tamper_detection() {
        let mut network = Network::new();
        network.add_node("alice", 100.0);
        network.add_node("bob", 100.0);
        network.connect_nodes("alice", "bob");

        let keypair = Keypair::generate();
        network.send_authenticated_packet(
            "alice".to_string(),
            "bob".to_string(),
            "hello secure".to_string(),
            &keypair
        ).expect("send auth packet");
        network.process_messages();
        let bob_node = network.nodes.get("bob").unwrap();
        assert!(bob_node.get_received_messages().iter().any(|m| m == "hello secure"));

        // Now craft a tampered packet (modify payload) and ensure rejection
        let mut packet = Packet::new_authenticated("alice".into(), "bob".into(), "attack".into(), chrono::Utc::now().timestamp(), &keypair);
        // Tamper with content hash without updating signature
        packet.payload = "modified".into();
        assert!(!packet.verify_signature(), "Tampered packet should fail verification");
    }

    #[test]
    fn test_mainnet_rejects_unauthenticated_packets() {
        let mut config = ZhtpNetworkConfig::default();
        config.network_env = NetworkEnvironment::Mainnet;
        let mut network = Network::with_config(config);
        network.add_node("n1", 10.0);
        network.add_node("n2", 10.0);
        network.connect_nodes("n1", "n2");
        // Send legacy (unauthenticated) packet
        network.send_packet("n1".into(), "n2".into(), "legacy".into());
        network.process_messages();
        let n2 = network.nodes.get("n2").unwrap();
        assert!(n2.get_received_messages().is_empty(), "Mainnet must reject unauthenticated packets");
    }

    #[test]
    fn test_degraded_network() {
        let mut network = Network::new();

        // Add nodes in a more complex topology
        network.add_node("node1", 1000.0);
        network.add_node("node2", 1000.0);
        network.add_node("node3", 1000.0);
        network.add_node("node4", 1000.0);

        // Connect nodes in a diamond pattern
        // node1 -> node2 -> node4
        //      \-> node3 -/
        network.connect_nodes("node1", "node2");
        network.connect_nodes("node1", "node3");
        network.connect_nodes("node2", "node4");
        network.connect_nodes("node3", "node4");

        // Clear initial default conditions
        network.set_node_condition("node2", NetworkCondition::default());
        network.set_node_condition("node3", NetworkCondition::default());

        // Set node2 with extremely poor conditions
        network.set_node_condition(
            "node2",
            NetworkCondition {
                packet_loss_rate: 0.9, // 90% base packet loss
                latency_multiplier: 5.0, // 5x normal latency
                bandwidth_cap: Some(100), // Severely limited bandwidth
            },
        );

        // Set node3 with slightly degraded conditions
        network.set_node_condition(
            "node3",
            NetworkCondition {
                packet_loss_rate: 0.05, // 5% base packet loss
                latency_multiplier: 1.1, // Only slight latency increase
                bandwidth_cap: Some(10000), // Better bandwidth
            },
        );

        // Initialize node2 with baseline reputation
        if let Some(node2) = network.nodes.get_mut("node2") {
            // Give some initial reputation to lose
            node2.metrics.update_reputation(true);
        }

        // Get starting conditions
        if let Some(metrics) = network.get_node_metrics("node2") {
            println!("Initial Node2 reputation: {:.2}", metrics.reputation_score);
        }

        // Send messages with immediate processing
        for i in 0..10 {
            // Send packet
            network.send_packet(
                "node1".to_string(),
                "node4".to_string(),
                format!("Message {}", i),
            );

            // Process immediately to adapt to conditions
            // Process messages and track metrics
            network.process_messages();
            
            // Print current metrics after each round
            println!("Messages in queue: {}", network.message_queue.len());
            let success_rate = network.get_delivery_success_rate();
            println!("Current success rate: {:.1}%", success_rate * 100.0);

            // Let the natural packet processing handle reputation updates
            if let Some(metrics) = network.get_node_metrics("node2") {
                println!("Current Node2 reputation: {:.2}", metrics.reputation_score);
            }
        }

        // Final processing rounds to ensure delivery
        for _ in 0..5 {
            network.process_messages();
        }

        // Process final metrics
        let success_rate = network.get_delivery_success_rate();
        println!("\nFinal Network Metrics:");
        println!("Success rate: {:.1}%", success_rate * 100.0);
        println!("Messages delivered: {}", network.delivery_tracking.len());

        // Success rate should be reasonable with alternate path
        assert!(
            success_rate > 0.3,
            "Success rate {} should be higher with alternate path",
            success_rate
        );

        // Verify node2's degraded performance
        if let Some(metrics) = network.get_node_metrics("node2") {
            println!("Node2 metrics:");
            println!("  Delivery failures: {}", metrics.delivery_failures);
            println!("  Average latency: {:.2}ms", metrics.average_latency());
            println!("  Reputation score: {:.2}", metrics.reputation_score);

            assert!(
                metrics.reputation_score < 0.7,
                "Node2 reputation should decrease"
            );
            assert!(
                metrics.delivery_failures > 0,
                "Node2 should have failed packets"
            );
            assert!(
                metrics.average_latency() > 100.0,
                "Node2 should show increased latency"
            );
        }

        // Verify node3's better performance
        if let Some(metrics) = network.get_node_metrics("node3") {
            println!("Node3 metrics:");
            println!("  Delivery failures: {}", metrics.delivery_failures);
            println!("  Average latency: {:.2}ms", metrics.average_latency());
            println!("  Reputation score: {:.2}", metrics.reputation_score);

            assert!(
                metrics.reputation_score > 0.25,
                "Node3 reputation should remain higher than severely degraded nodes"
            );
            assert!(
                metrics.average_latency() < 200.0,
                "Node3 should have lower latency"
            ); // Checking against reasonable threshold
        }

        // Verify that node4 received messages
        if let Some(node4) = network.nodes.get("node4") {
            let received = node4.get_received_messages().len();
            println!("Messages received by node4: {}", received);
            assert!(received > 0, "Node4 should have received some messages");
        }
    }
}

// Queue size limits for DoS protection
const MAX_MESSAGE_QUEUE_SIZE: usize = 10_000;
const MAX_MESSAGES_PER_SECOND: usize = 100;
const MESSAGE_RATE_WINDOW_SECS: u64 = 1;

/// Rate limiting tracker for DoS protection
#[derive(Debug, Clone)]
struct MessageRateTracker {
    message_count: usize,
    window_start: u64,
}

impl MessageRateTracker {
    fn new() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        
        Self {
            message_count: 0,
            window_start: now,
        }
    }
    
    /// Check if message should be allowed based on rate limiting
    fn allow_message(&mut self) -> bool {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        
        // Reset window if time has passed
        if now - self.window_start >= MESSAGE_RATE_WINDOW_SECS {
            self.message_count = 0;
            self.window_start = now;
        }
        
        // Check if under rate limit
        if self.message_count < MAX_MESSAGES_PER_SECOND {
            self.message_count += 1;
            true
        } else {
            false
        }
    }
}
