//! ZHTP Server Configuration
//! 
//! Comprehensive configuration system for ZHTP servers with economic,
//! security, networking, and performance settings.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// ZHTP Server Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server host address
    pub host: String,
    /// Server port
    pub port: u16,
    /// Request timeout in seconds
    pub request_timeout_seconds: u64,
    /// Maximum request size in bytes
    pub max_request_size: usize,
    /// Maximum response size in bytes
    pub max_response_size: usize,
    /// Maximum concurrent connections
    pub max_connections: usize,
    /// Keep-alive timeout in seconds
    pub keep_alive_timeout_seconds: u64,
    /// Enable compression
    pub enable_compression: bool,
    /// Compression level (1-9)
    pub compression_level: u32,
    /// Enable TLS/SSL
    pub enable_tls: bool,
    /// TLS certificate path
    pub tls_cert_path: Option<String>,
    /// TLS private key path
    pub tls_key_path: Option<String>,
    /// Economic configuration
    pub economic: EconomicConfig,
    /// Security configuration
    pub security: SecurityConfig,
    /// Networking configuration
    pub networking: NetworkingConfig,
    /// Performance configuration
    pub performance: PerformanceConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Custom configuration values
    pub custom: HashMap<String, String>,
}

/// Economic configuration for ZHTP server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicConfig {
    /// Enable DAO fee processing
    pub enable_dao_fees: bool,
    /// DAO fee percentage (0.0 to 1.0)
    pub dao_fee_percentage: f64,
    /// Minimum DAO fee in wei
    pub min_dao_fee_wei: u64,
    /// Maximum DAO fee in wei
    pub max_dao_fee_wei: u64,
    /// Enable UBI distribution
    pub enable_ubi: bool,
    /// UBI distribution percentage (0.0 to 1.0)
    pub ubi_percentage: f64,
    /// Economic validation timeout in seconds
    pub validation_timeout_seconds: u64,
    /// Enable economic incentives
    pub enable_incentives: bool,
    /// Incentive calculation method
    pub incentive_method: IncentiveMethod,
    /// Payment processor configuration
    pub payment_processor: PaymentProcessorConfig,
}

/// UBI incentive calculation methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IncentiveMethod {
    /// Fixed amount per request
    FixedAmount(u64),
    /// Percentage of transaction value
    Percentage(f64),
    /// Based on request complexity
    Complexity,
    /// Based on server load
    LoadBased,
    /// Dynamic calculation
    Dynamic,
}

/// Payment processor configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentProcessorConfig {
    /// Enable multi-wallet support
    pub enable_multi_wallet: bool,
    /// Supported wallet types
    pub supported_wallets: Vec<WalletType>,
    /// Default wallet type
    pub default_wallet: WalletType,
    /// Payment timeout in seconds
    pub payment_timeout_seconds: u64,
    /// Enable automatic refunds
    pub enable_auto_refunds: bool,
    /// Refund timeout in seconds
    pub refund_timeout_seconds: u64,
}

/// Supported wallet types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalletType {
    /// MetaMask wallet
    MetaMask,
    /// Phantom wallet
    Phantom,
    /// Native ZHTP wallet
    ZhtpNative,
    /// WalletConnect
    WalletConnect,
    /// Hardware wallet (Ledger, Trezor)
    Hardware,
    /// Custom wallet implementation
    Custom(String),
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable zero-knowledge proof verification
    pub enable_zk_proofs: bool,
    /// ZK proof timeout in seconds
    pub zk_proof_timeout_seconds: u64,
    /// Enable post-quantum cryptography
    pub enable_post_quantum: bool,
    /// Post-quantum algorithm preference
    pub post_quantum_algorithm: PostQuantumAlgorithm,
    /// Enable request signing verification
    pub enable_request_signing: bool,
    /// Required signature algorithms
    pub required_signature_algorithms: Vec<SignatureAlgorithm>,
    /// Enable rate limiting
    pub enable_rate_limiting: bool,
    /// Rate limiting configuration
    pub rate_limiting: RateLimitConfig,
    /// Enable DDoS protection
    pub enable_ddos_protection: bool,
    /// DDoS protection configuration
    pub ddos_protection: DDoSProtectionConfig,
    /// Enable access control
    pub enable_access_control: bool,
    /// Access control configuration
    pub access_control: AccessControlConfig,
}

/// Post-quantum cryptography algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PostQuantumAlgorithm {
    /// CRYSTALS-Dilithium for signatures
    Dilithium,
    /// CRYSTALS-Kyber for encryption
    Kyber,
    /// Combined Dilithium + Kyber
    DilithiumKyber,
    /// FALCON signatures
    Falcon,
    /// SPHINCS+ signatures
    Sphincs,
}

/// Signature algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// ECDSA with secp256k1
    EcdsaSecp256k1,
    /// ECDSA with P-256
    EcdsaP256,
    /// Ed25519
    Ed25519,
    /// CRYSTALS-Dilithium
    Dilithium,
    /// RSA with PSS padding
    RsaPss,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Requests per minute
    pub requests_per_minute: u32,
    /// Burst size
    pub burst_size: u32,
    /// Rate limit by IP
    pub limit_by_ip: bool,
    /// Rate limit by user identity
    pub limit_by_identity: bool,
    /// Rate limit by DAO account
    pub limit_by_dao_account: bool,
}

/// DDoS protection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DDoSProtectionConfig {
    /// Connection threshold per IP
    pub connection_threshold_per_ip: u32,
    /// Request threshold per IP per minute
    pub request_threshold_per_ip_per_minute: u32,
    /// Block duration in seconds
    pub block_duration_seconds: u64,
    /// Enable adaptive thresholds
    pub enable_adaptive_thresholds: bool,
    /// Enable geofencing
    pub enable_geofencing: bool,
    /// Allowed countries (ISO 3166-1 alpha-2)
    pub allowed_countries: Vec<String>,
    /// Blocked countries (ISO 3166-1 alpha-2)
    pub blocked_countries: Vec<String>,
}

/// Access control configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlConfig {
    /// Default access policy
    pub default_policy: AccessPolicy,
    /// Require authentication
    pub require_authentication: bool,
    /// Authentication methods
    pub auth_methods: Vec<AuthMethod>,
    /// Enable role-based access control
    pub enable_rbac: bool,
    /// Enable attribute-based access control
    pub enable_abac: bool,
    /// Access control timeout in seconds
    pub access_timeout_seconds: u64,
}

/// Access policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessPolicy {
    /// Allow all requests
    AllowAll,
    /// Deny all requests
    DenyAll,
    /// Require authentication
    RequireAuth,
    /// Require DAO membership
    RequireDaoMembership,
    /// Custom policy
    Custom(String),
}

/// Authentication methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthMethod {
    /// API key authentication
    ApiKey,
    /// JWT token authentication
    Jwt,
    /// OAuth 2.0
    OAuth2,
    /// Zero-knowledge proof authentication
    ZkProof,
    /// Wallet signature authentication
    WalletSignature,
    /// Multi-factor authentication
    Mfa,
}

/// Networking configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkingConfig {
    /// Enable mesh networking
    pub enable_mesh: bool,
    /// Mesh configuration
    pub mesh: MeshConfig,
    /// Enable 
    pub enable_isp_bypass: bool,
    ///  configuration
    pub isp_bypass: IspBypassConfig,
    /// Enable P2P networking
    pub enable_p2p: bool,
    /// P2P configuration
    pub p2p: P2pConfig,
    /// Enable ZDNS
    pub enable_zdns: bool,
    /// ZDNS configuration
    pub zdns: ZdnsConfig,
}

/// Mesh networking configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfig {
    /// Maximum mesh connections
    pub max_connections: u32,
    /// Mesh discovery timeout in seconds
    pub discovery_timeout_seconds: u64,
    /// Enable automatic mesh routing
    pub enable_auto_routing: bool,
    /// Mesh routing algorithm
    pub routing_algorithm: MeshRoutingAlgorithm,
    /// Enable mesh load balancing
    pub enable_load_balancing: bool,
    /// Load balancing strategy
    pub load_balancing_strategy: LoadBalancingStrategy,
}

/// Mesh routing algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MeshRoutingAlgorithm {
    /// Shortest path first
    ShortestPath,
    /// Load-based routing
    LoadBased,
    /// Economic incentive routing
    EconomicIncentive,
    /// Geographic routing
    Geographic,
    /// Hybrid routing
    Hybrid,
}

/// Load balancing strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadBalancingStrategy {
    /// Round robin
    RoundRobin,
    /// Least connections
    LeastConnections,
    /// Weighted round robin
    WeightedRoundRobin,
    /// Economic priority
    EconomicPriority,
    /// Geographic proximity
    GeographicProximity,
}

///  configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IspBypassConfig {
    /// Enable Tor integration
    pub enable_tor: bool,
    /// Enable I2P integration
    pub enable_i2p: bool,
    /// Enable VPN integration
    pub enable_vpn: bool,
    /// VPN providers
    pub vpn_providers: Vec<String>,
    /// Enable DNS over HTTPS
    pub enable_doh: bool,
    /// DoH servers
    pub doh_servers: Vec<String>,
    /// Enable DNS over TLS
    pub enable_dot: bool,
    /// DoT servers
    pub dot_servers: Vec<String>,
}

/// P2P networking configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pConfig {
    /// P2P protocol
    pub protocol: P2pProtocol,
    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<String>,
    /// Maximum P2P connections
    pub max_connections: u32,
    /// P2P discovery interval in seconds
    pub discovery_interval_seconds: u64,
    /// Enable NAT traversal
    pub enable_nat_traversal: bool,
    /// NAT traversal methods
    pub nat_traversal_methods: Vec<NatTraversalMethod>,
}

/// P2P protocols
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2pProtocol {
    /// libp2p
    Libp2p,
    /// Custom ZHTP P2P protocol
    ZhtpP2p,
    /// BitTorrent protocol
    BitTorrent,
    /// Kademlia DHT
    Kademlia,
}

/// NAT traversal methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NatTraversalMethod {
    /// STUN
    Stun,
    /// TURN
    Turn,
    /// ICE
    Ice,
    /// UPnP
    Upnp,
    /// NAT-PMP
    NatPmp,
}

/// ZDNS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZdnsConfig {
    /// ZDNS resolvers
    pub resolvers: Vec<String>,
    /// Enable ZDNS caching
    pub enable_caching: bool,
    /// Cache TTL in seconds
    pub cache_ttl_seconds: u64,
    /// Enable ZDNS validation
    pub enable_validation: bool,
    /// Validation timeout in seconds
    pub validation_timeout_seconds: u64,
    /// Enable ownership proof verification
    pub enable_ownership_verification: bool,
}

/// Performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Worker thread count
    pub worker_threads: Option<usize>,
    /// Enable connection pooling
    pub enable_connection_pooling: bool,
    /// Connection pool size
    pub connection_pool_size: u32,
    /// Enable request caching
    pub enable_request_caching: bool,
    /// Cache configuration
    pub cache: CacheConfig,
    /// Enable content compression
    pub enable_content_compression: bool,
    /// Compression algorithms
    pub compression_algorithms: Vec<CompressionAlgorithm>,
    /// Enable HTTP/2 support
    pub enable_http2: bool,
    /// Enable HTTP/3 support
    pub enable_http3: bool,
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Cache type
    pub cache_type: CacheType,
    /// Maximum cache size in bytes
    pub max_size_bytes: u64,
    /// Default TTL in seconds
    pub default_ttl_seconds: u64,
    /// Enable cache compression
    pub enable_compression: bool,
    /// Cache eviction policy
    pub eviction_policy: CacheEvictionPolicy,
}

/// Cache types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CacheType {
    /// In-memory cache
    Memory,
    /// Redis cache
    Redis,
    /// Memcached
    Memcached,
    /// File-based cache
    File,
    /// Distributed cache
    Distributed,
}

/// Cache eviction policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CacheEvictionPolicy {
    /// Least Recently Used
    Lru,
    /// Least Frequently Used
    Lfu,
    /// First In First Out
    Fifo,
    /// Time-based expiration
    Ttl,
    /// Random eviction
    Random,
}

/// Compression algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompressionAlgorithm {
    /// Gzip compression
    Gzip,
    /// Deflate compression
    Deflate,
    /// Brotli compression
    Brotli,
    /// Zstandard compression
    Zstd,
    /// LZ4 compression
    Lz4,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: LogLevel,
    /// Log format
    pub format: LogFormat,
    /// Log output
    pub output: LogOutput,
    /// Enable request logging
    pub enable_request_logging: bool,
    /// Enable response logging
    pub enable_response_logging: bool,
    /// Enable error logging
    pub enable_error_logging: bool,
    /// Enable performance logging
    pub enable_performance_logging: bool,
    /// Enable security logging
    pub enable_security_logging: bool,
    /// Log rotation configuration
    pub rotation: LogRotationConfig,
}

/// Log levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LogLevel {
    /// Trace level
    Trace,
    /// Debug level
    Debug,
    /// Info level
    Info,
    /// Warn level
    Warn,
    /// Error level
    Error,
}

/// Log formats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogFormat {
    /// Plain text format
    Plain,
    /// JSON format
    Json,
    /// Structured format
    Structured,
    /// Custom format
    Custom(String),
}

/// Log outputs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogOutput {
    /// Standard output
    Stdout,
    /// Standard error
    Stderr,
    /// File output
    File(String),
    /// Syslog
    Syslog,
    /// Multiple outputs
    Multiple(Vec<LogOutput>),
}

/// Log rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRotationConfig {
    /// Enable log rotation
    pub enabled: bool,
    /// Maximum file size in bytes
    pub max_size_bytes: u64,
    /// Maximum number of files
    pub max_files: u32,
    /// Rotation interval in hours
    pub rotation_interval_hours: u32,
    /// Enable compression of rotated files
    pub enable_compression: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: crate::zhtp::DEFAULT_ZHTP_PORT,
            request_timeout_seconds: crate::zhtp::DEFAULT_REQUEST_TIMEOUT,
            max_request_size: crate::zhtp::MAX_REQUEST_SIZE,
            max_response_size: 64 * 1024 * 1024, // 64MB
            max_connections: 1000,
            keep_alive_timeout_seconds: 60,
            enable_compression: true,
            compression_level: 6,
            enable_tls: false,
            tls_cert_path: None,
            tls_key_path: None,
            economic: EconomicConfig::default(),
            security: SecurityConfig::default(),
            networking: NetworkingConfig::default(),
            performance: PerformanceConfig::default(),
            logging: LoggingConfig::default(),
            custom: HashMap::new(),
        }
    }
}

impl Default for EconomicConfig {
    fn default() -> Self {
        Self {
            enable_dao_fees: true,
            dao_fee_percentage: 0.02, // 2%
            min_dao_fee_wei: 1000,
            max_dao_fee_wei: 1_000_000_000_000_000_000, // 1 ETH
            enable_ubi: true,
            ubi_percentage: 0.8, // 80% of DAO fees go to UBI
            validation_timeout_seconds: 30,
            enable_incentives: true,
            incentive_method: IncentiveMethod::Percentage(0.001), // 0.1%
            payment_processor: PaymentProcessorConfig::default(),
        }
    }
}

impl Default for PaymentProcessorConfig {
    fn default() -> Self {
        Self {
            enable_multi_wallet: true,
            supported_wallets: vec![
                WalletType::MetaMask,
                WalletType::Phantom,
                WalletType::ZhtpNative,
                WalletType::WalletConnect,
            ],
            default_wallet: WalletType::ZhtpNative,
            payment_timeout_seconds: 300, // 5 minutes
            enable_auto_refunds: true,
            refund_timeout_seconds: 3600, // 1 hour
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_zk_proofs: true,
            zk_proof_timeout_seconds: 60,
            enable_post_quantum: true,
            post_quantum_algorithm: PostQuantumAlgorithm::DilithiumKyber,
            enable_request_signing: true,
            required_signature_algorithms: vec![
                SignatureAlgorithm::Dilithium,
                SignatureAlgorithm::Ed25519,
            ],
            enable_rate_limiting: true,
            rate_limiting: RateLimitConfig::default(),
            enable_ddos_protection: true,
            ddos_protection: DDoSProtectionConfig::default(),
            enable_access_control: true,
            access_control: AccessControlConfig::default(),
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 100,
            burst_size: 20,
            limit_by_ip: true,
            limit_by_identity: true,
            limit_by_dao_account: true,
        }
    }
}

impl Default for DDoSProtectionConfig {
    fn default() -> Self {
        Self {
            connection_threshold_per_ip: 10,
            request_threshold_per_ip_per_minute: 1000,
            block_duration_seconds: 3600, // 1 hour
            enable_adaptive_thresholds: true,
            enable_geofencing: false,
            allowed_countries: vec![],
            blocked_countries: vec![],
        }
    }
}

impl Default for AccessControlConfig {
    fn default() -> Self {
        Self {
            default_policy: AccessPolicy::RequireAuth,
            require_authentication: true,
            auth_methods: vec![
                AuthMethod::ZkProof,
                AuthMethod::WalletSignature,
                AuthMethod::Jwt,
            ],
            enable_rbac: true,
            enable_abac: false,
            access_timeout_seconds: 300, // 5 minutes
        }
    }
}

impl Default for NetworkingConfig {
    fn default() -> Self {
        Self {
            enable_mesh: true,
            mesh: MeshConfig::default(),
            enable_isp_bypass: true,
            isp_bypass: IspBypassConfig::default(),
            enable_p2p: true,
            p2p: P2pConfig::default(),
            enable_zdns: true,
            zdns: ZdnsConfig::default(),
        }
    }
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            max_connections: 50,
            discovery_timeout_seconds: 30,
            enable_auto_routing: true,
            routing_algorithm: MeshRoutingAlgorithm::Hybrid,
            enable_load_balancing: true,
            load_balancing_strategy: LoadBalancingStrategy::EconomicPriority,
        }
    }
}

impl Default for IspBypassConfig {
    fn default() -> Self {
        Self {
            enable_tor: false,
            enable_i2p: false,
            enable_vpn: false,
            vpn_providers: vec![],
            enable_doh: true,
            doh_servers: vec![
                "https://cloudflare-dns.com/dns-query".to_string(),
                "https://dns.google/dns-query".to_string(),
            ],
            enable_dot: true,
            dot_servers: vec![
                "1.1.1.1:853".to_string(),
                "8.8.8.8:853".to_string(),
            ],
        }
    }
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            protocol: P2pProtocol::ZhtpP2p,
            bootstrap_nodes: vec![],
            max_connections: 100,
            discovery_interval_seconds: 60,
            enable_nat_traversal: true,
            nat_traversal_methods: vec![
                NatTraversalMethod::Stun,
                NatTraversalMethod::Ice,
                NatTraversalMethod::Upnp,
            ],
        }
    }
}

impl Default for ZdnsConfig {
    fn default() -> Self {
        Self {
            resolvers: vec![
                "zdns://127.0.0.1".to_string(),
            ],
            enable_caching: true,
            cache_ttl_seconds: 3600, // 1 hour
            enable_validation: true,
            validation_timeout_seconds: 30,
            enable_ownership_verification: true,
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            worker_threads: None, // Auto-detect
            enable_connection_pooling: true,
            connection_pool_size: 100,
            enable_request_caching: true,
            cache: CacheConfig::default(),
            enable_content_compression: true,
            compression_algorithms: vec![
                CompressionAlgorithm::Brotli,
                CompressionAlgorithm::Gzip,
                CompressionAlgorithm::Zstd,
            ],
            enable_http2: false, // ZHTP protocol
            enable_http3: false, // ZHTP protocol
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            cache_type: CacheType::Memory,
            max_size_bytes: 1024 * 1024 * 1024, // 1GB
            default_ttl_seconds: 3600, // 1 hour
            enable_compression: true,
            eviction_policy: CacheEvictionPolicy::Lru,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Structured,
            output: LogOutput::Stdout,
            enable_request_logging: true,
            enable_response_logging: false,
            enable_error_logging: true,
            enable_performance_logging: true,
            enable_security_logging: true,
            rotation: LogRotationConfig::default(),
        }
    }
}

impl Default for LogRotationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_size_bytes: 100 * 1024 * 1024, // 100MB
            max_files: 10,
            rotation_interval_hours: 24,
            enable_compression: true,
        }
    }
}

impl ServerConfig {
    /// Create a development configuration
    pub fn development() -> Self {
        let mut config = Self::default();
        config.security.enable_rate_limiting = false;
        config.security.enable_ddos_protection = false;
        config.security.access_control.default_policy = AccessPolicy::AllowAll;
        config.logging.level = LogLevel::Debug;
        config.economic.enable_dao_fees = false;
        config
    }
    
    /// Create a production configuration
    pub fn production() -> Self {
        let mut config = Self::default();
        config.enable_tls = true;
        config.security.enable_rate_limiting = true;
        config.security.enable_ddos_protection = true;
        config.security.enable_access_control = true;
        config.logging.level = LogLevel::Info;
        config.logging.output = LogOutput::File("/var/log/zhtp/server.log".to_string());
        config
    }
    
    /// Create a testing configuration
    pub fn testing() -> Self {
        let mut config = Self::default();
        config.port = 0; // Random port
        config.security.enable_rate_limiting = false;
        config.security.enable_ddos_protection = false;
        config.security.access_control.default_policy = AccessPolicy::AllowAll;
        config.logging.level = LogLevel::Debug;
        config.logging.output = LogOutput::Stderr;
        config.economic.enable_dao_fees = false;
        config.networking.enable_mesh = false;
        config.networking.enable_isp_bypass = false;
        config.networking.enable_p2p = false;
        config
    }
    
    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.port == 0 && !cfg!(test) {
            return Err("Port cannot be 0 in non-test environment".to_string());
        }
        
        if self.max_request_size == 0 {
            return Err("Maximum request size cannot be 0".to_string());
        }
        
        if self.max_response_size == 0 {
            return Err("Maximum response size cannot be 0".to_string());
        }
        
        if self.economic.dao_fee_percentage < 0.0 || self.economic.dao_fee_percentage > 1.0 {
            return Err("DAO fee percentage must be between 0.0 and 1.0".to_string());
        }
        
        if self.economic.ubi_percentage < 0.0 || self.economic.ubi_percentage > 1.0 {
            return Err("UBI percentage must be between 0.0 and 1.0".to_string());
        }
        
        if self.compression_level < 1 || self.compression_level > 9 {
            return Err("Compression level must be between 1 and 9".to_string());
        }
        
        Ok(())
    }
    
    /// Get effective worker thread count
    pub fn effective_worker_threads(&self) -> usize {
        self.performance.worker_threads.unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();
        assert_eq!(config.port, crate::zhtp::DEFAULT_ZHTP_PORT);
        assert!(config.economic.enable_dao_fees);
        assert!(config.security.enable_zk_proofs);
        assert!(config.networking.enable_mesh);
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn test_development_config() {
        let config = ServerConfig::development();
        assert!(!config.security.enable_rate_limiting);
        assert!(!config.economic.enable_dao_fees);
        assert_eq!(config.logging.level, LogLevel::Debug);
    }

    #[test]
    fn test_production_config() {
        let config = ServerConfig::production();
        assert!(config.enable_tls);
        assert!(config.security.enable_rate_limiting);
        assert_eq!(config.logging.level, LogLevel::Info);
    }

    #[test]
    fn test_testing_config() {
        let config = ServerConfig::testing();
        assert_eq!(config.port, 0);
        assert!(!config.networking.enable_mesh);
        assert!(!config.economic.enable_dao_fees);
    }

    #[test]
    fn test_config_validation() {
        let mut config = ServerConfig::default();
        assert_eq!(config.validate(), Ok(()));
        
        config.economic.dao_fee_percentage = 1.5;
        assert!(config.validate().is_err());
        
        config.economic.dao_fee_percentage = 0.02;
        config.compression_level = 15;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_effective_worker_threads() {
        let mut config = ServerConfig::default();
        assert!(config.effective_worker_threads() >= 1);
        
        config.performance.worker_threads = Some(8);
        assert_eq!(config.effective_worker_threads(), 8);
    }
}
