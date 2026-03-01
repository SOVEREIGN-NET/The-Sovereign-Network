//! Configuration Aggregation from All ZHTP Packages
//!
//! Combines configurations from crypto, zk, identity, storage, network,
//! blockchain, consensus, economics, protocols packages into unified NodeConfig

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::collections::HashMap;
use super::{MeshMode, SecurityLevel, Environment, ConfigError, CliArgs, NodeType};

/// Partial configuration for simple TOML files with optional sections
/// This allows users to provide minimal config files with just the sections they need:
/// ```toml
/// [network_config]
/// bootstrap_peers = ["192.168.1.1:9334"]
/// 
/// [consensus_config]
/// validator_enabled = true
/// ```
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PartialConfig {
    #[serde(default)]
    pub environment: Option<super::Environment>,
    #[serde(default)]
    pub runtime_role: Option<RuntimeRole>,
    #[serde(default)]
    pub network: Option<PartialNetworkConfig>,
    #[serde(default)]
    pub network_config: Option<PartialNetworkConfig>,
    #[serde(default)]
    pub consensus_config: Option<PartialConsensusConfig>,
    #[serde(default)]
    pub blockchain_config: Option<PartialBlockchainConfig>,
    #[serde(default)]
    pub storage_config: Option<PartialStorageConfig>,
    #[serde(default)]
    pub validator_config: Option<PartialValidatorConfig>,
}

/// Partial network configuration (matches user-friendly [network_config] section)
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PartialNetworkConfig {
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,
    /// Optional SPKI SHA-256 pins for bootstrap peers (hex-encoded).
    /// Key = "host:port", Value = 64-char hex SHA-256 hash.
    /// When configured, the TLS certificate SPKI must match; TOFU is disabled for that peer.
    /// Peers without a pin entry still use TOFU.
    #[serde(default)]
    pub bootstrap_peer_pins: HashMap<String, String>,
    #[serde(default)]
    pub mesh_port: Option<u16>,
    #[serde(default)]
    pub max_peers: Option<usize>,
    #[serde(default)]
    pub network_id: Option<String>,
    /// Bootstrap validators for pre-seeding the ValidatorManager before on-chain txs are mined.
    /// Enables proposer rotation from block 0 in multi-node setups.
    #[serde(default)]
    pub bootstrap_validators: Vec<BootstrapValidator>,
}

/// Partial consensus configuration (matches [consensus_config] section)
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PartialConsensusConfig {
    #[serde(default)]
    pub validator_enabled: Option<bool>,
    #[serde(default)]
    pub consensus_type: Option<String>,
    #[serde(default)]
    pub dao_enabled: Option<bool>,
    #[serde(default)]
    pub min_stake: Option<u64>,
}

/// Partial blockchain configuration (matches [blockchain_config] section)
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PartialBlockchainConfig {
    #[serde(default)]
    pub network_id: Option<String>,
    #[serde(default)]
    pub edge_mode: Option<bool>,
    #[serde(default)]
    pub edge_max_headers: Option<usize>,
    #[serde(default)]
    pub smart_contracts: Option<bool>,
}

/// Partial storage configuration (matches [storage_config] section)
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PartialStorageConfig {
    #[serde(default)]
    pub hosted_storage_gb: Option<u64>,
    #[serde(default)]
    pub blockchain_storage_gb: Option<u64>,
}

/// Partial validator configuration (matches [validator_config] section)
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PartialValidatorConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub stake: Option<u64>,
}

/// Runtime node typology used for invariant enforcement.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeRole {
    Full,
    Edge,
    Validator,
    Relay,
    Bootstrap,
    Service,
}

impl Default for RuntimeRole {
    fn default() -> Self {
        RuntimeRole::Full
    }
}

/// Complete node configuration aggregating all packages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    // Core node settings
    pub node_id: [u8; 32],
    pub mesh_mode: MeshMode,
    pub security_level: SecurityLevel,
    pub environment: Environment,
    pub data_directory: String,

    // Canonical node type - SINGLE SOURCE OF TRUTH
    // Determined at startup from config and immutable thereafter.
    // 
    // - If explicitly set in config (e.g., `node_type = "relay"`), that value is used.
    // - If not set, auto-derived as Validator/EdgeNode/FullNode based on config flags.
    // - **Important**: Relay nodes MUST be explicitly configured (cannot be auto-derived).
    #[serde(default)]
    pub node_type: Option<NodeType>,

    #[serde(default)]
    pub runtime_role: RuntimeRole,

    // Node role determines what operations this node can perform
    // This is derived from validator_enabled and other config settings during aggregation
    #[serde(skip)]
    pub node_role: crate::runtime::node_runtime::NodeRole,

    // Package-specific configurations
    pub crypto_config: CryptoConfig,
    pub zk_config: ZkConfig,
    pub identity_config: IdentityConfig,
    pub storage_config: StorageConfig,
    pub network_config: NetworkConfig,
    pub blockchain_config: BlockchainConfig,
    pub consensus_config: ConsensusConfig,
    pub economics_config: EconomicsConfig,
    pub protocols_config: ProtocolsConfig,
    pub rewards_config: RewardsConfig,

    // Validator configuration (Gap 5)
    #[serde(default)]
    pub validator_config: Option<ValidatorConfig>,

    // Cross-package coordination
    pub port_assignments: HashMap<String, u16>,
    pub resource_allocations: ResourceAllocations,
    pub integration_settings: IntegrationSettings,
}

/// Cryptography package configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    pub post_quantum_enabled: bool,
    pub dilithium_level: u8,  // 2, 3, or 5
    pub kyber_level: u16,     // 512, 768, or 1024
    pub hybrid_mode: bool,    // PQ + classical crypto
    pub memory_security: bool, // Secure memory wiping
}

/// Zero-knowledge proof configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkConfig {
    pub plonky2_enabled: bool,
    pub proof_cache_size: usize,
    pub circuit_cache_enabled: bool,
    pub parallel_proving: bool,
    pub verification_threads: usize,
}

/// Identity management configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    pub auto_citizenship: bool,
    pub ubi_registration: bool,
    pub dao_auto_join: bool,
    pub recovery_modes: Vec<String>, // biometric, mnemonic, social
    pub reputation_enabled: bool,
}

/// Storage system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub dht_port: u16,
    /// DEPRECATED: Use blockchain_storage_gb instead
    /// This field is kept for backward compatibility with old configs
    #[serde(default)]
    pub storage_capacity_gb: u64,
    /// Dedicated storage for blockchain data (blocks, transactions, state)
    /// This grows dynamically with the blockchain but should be allocated upfront
    #[serde(default = "default_blockchain_storage")]
    pub blockchain_storage_gb: u64,
    /// Maximum storage to allocate for hosting others' data (DHT, IPFS-style)
    /// This is capped and used for earning storage rewards
    /// Set to 0 to disable hosting (edge nodes)
    #[serde(default)]
    pub hosted_storage_gb: u64,
    /// Personal data storage (user's own files, unlimited by design)
    /// Not counted toward edge node detection
    #[serde(default)]
    pub personal_storage_gb: u64,
    pub replication_factor: u8,
    pub erasure_coding: bool,
    pub pricing_tier: String, // hot, warm, cold, archive
}

fn default_blockchain_storage() -> u64 {
    100 // 100 GB default for blockchain data
}

/// Network and mesh configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub mesh_port: u16,
    pub max_peers: usize,
    pub protocols: Vec<String>, // bluetooth, wifi_direct, lorawan, tcp
    pub bootstrap_peers: Vec<String>,
    pub long_range_relays: bool,

    /// Optional SPKI SHA-256 pins for bootstrap peers (hex-encoded).
    /// Key = "host:port", Value = 64-char hex SHA-256 hash.
    /// When configured, the TLS certificate SPKI must match; TOFU is disabled for that peer.
    #[serde(default)]
    pub bootstrap_peer_pins: HashMap<String, String>,

    // Bootstrap validators for multi-node genesis (Gap 5)
    #[serde(default)]
    pub bootstrap_validators: Vec<BootstrapValidator>,
}

/// Blockchain configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainConfig {
    pub network_id: String,
    pub block_time_seconds: u64,
    pub max_block_size: usize,
    pub zk_transactions: bool,
    pub smart_contracts: bool,
    #[serde(default)]
    pub edge_mode: bool,
    #[serde(default = "default_edge_max_headers")]
    pub edge_max_headers: usize,
}

fn default_edge_max_headers() -> usize {
    500
}

/// Consensus configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    pub consensus_type: String, // PoS, PoStorage, PoUW, Hybrid, BFT
    pub dao_enabled: bool,
    pub validator_enabled: bool,
    pub min_stake: u64,
    pub reward_multipliers: HashMap<String, f64>,
    /// Bootstrap Council configuration (dao-1)
    #[serde(default)]
    pub council: lib_blockchain::dao::CouncilBootstrapConfig,
}

/// Economics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicsConfig {
    pub ubi_enabled: bool,
    pub daily_ubi_amount: u64,
    pub dao_fee_percentage: f64,
    pub mesh_rewards: bool,
    pub token_economics: TokenEconomics,
}

/// Token economics settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEconomics {
    pub total_supply: u64,
    pub inflation_rate: f64,
    pub burn_rate: f64,
    pub reward_pool_percentage: f64,
}

/// Protocols configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolsConfig {
    pub lib_enabled: bool,
    pub zdns_enabled: bool,
    pub api_port: u16,
    pub max_connections: usize,
    pub request_timeout_ms: u64,

    /// QUIC port for mesh connections (default: 9334)
    /// Can be overridden via ZHTP_QUIC_PORT environment variable
    #[serde(default = "default_quic_port")]
    pub quic_port: u16,

    /// Legacy/unicast discovery port for peer announcements (default: 9333)
    /// Note: multicast peer discovery uses fixed port 37775/UDP (see NETWORK_RULES.md)
    /// Can be overridden via ZHTP_DISCOVERY_PORT environment variable
    #[serde(default = "default_discovery_port")]
    pub discovery_port: u16,

    // Mesh protocol settings (authoritative config from config.toml)
    /// Enable QUIC protocol (required, default: true)
    /// QUIC is the mandatory transport for mesh bootstrap and is always enabled
    #[serde(default = "default_enable_quic")]
    pub enable_quic: bool,

    /// Enable Bluetooth LE protocol (default: false)
    /// When false, Bluetooth discovery is skipped (defensive guard prevents execution)
    #[serde(default = "default_enable_bluetooth")]
    pub enable_bluetooth: bool,

    /// Enable mDNS discovery (reserved for future use, default: true)
    /// Currently not integrated but available for mDNS-based peer discovery
    #[serde(default = "default_enable_mdns")]
    pub enable_mdns: bool,

    /// QUIC protocol priority weight (reserved for future use, default: 1)
    /// When multiple protocols are available, higher priority is preferred
    /// Currently not used - future implementation for dynamic protocol selection
    #[serde(default = "default_quic_priority")]
    pub quic_priority: u8,

    /// Enable RPC gateway mode (SERVICE runtime role only, default: false)
    /// When true, node acts as an RPC gateway. Only valid when runtime_role=SERVICE.
    #[serde(default)]
    pub gateway_enabled: bool,
}

fn default_quic_port() -> u16 {
    std::env::var("ZHTP_QUIC_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(9334)
}

fn default_discovery_port() -> u16 {
    std::env::var("ZHTP_DISCOVERY_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(9333)
}

fn default_enable_quic() -> bool {
    true
}

fn default_enable_bluetooth() -> bool {
    false
}

fn default_enable_mdns() -> bool {
    true
}

fn default_quic_priority() -> u8 {
    1
}

impl ProtocolsConfig {
    /// Filter mesh protocols based on config settings (AUTHORITATIVE CONFIG LAYER)
    ///
    /// This is the policy enforcement point. Disabled protocols must NEVER reach lib-network.
    /// Configuration must be resolved at the zhtp boundary before lib-network is invoked.
    pub fn filter_mesh_protocols(&self, requested: Vec<lib_network::protocols::NetworkProtocol>) -> Vec<lib_network::protocols::NetworkProtocol> {
        use lib_network::protocols::NetworkProtocol;

        requested
            .into_iter()
            .filter(|protocol| {
                let allowed = match protocol {
                    NetworkProtocol::BluetoothLE => {
                        if !self.enable_bluetooth {
                            tracing::info!("⊘ FILTERED: Bluetooth LE disabled by config (enable_bluetooth=false)");
                            false
                        } else {
                            true
                        }
                    }
                    NetworkProtocol::QUIC => {
                        if !self.enable_quic {
                            tracing::info!("⊘ FILTERED: QUIC disabled by config (enable_quic=false)");
                            false
                        } else {
                            true
                        }
                    }
                    // Add other protocol filters as needed
                    _ => true,
                };

                if allowed {
                    tracing::debug!("✓ Protocol allowed: {:?}", protocol);
                }
                allowed
            })
            .collect()
    }
}

/// Automatic rewards configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardsConfig {
    // Global reward settings
    pub enabled: bool,
    pub auto_claim: bool,
    
    // Routing rewards
    pub routing_rewards_enabled: bool,
    pub routing_check_interval_secs: u64,
    pub routing_minimum_threshold: u64,
    pub routing_max_batch_size: u64,
    
    // Storage rewards
    pub storage_rewards_enabled: bool,
    pub storage_check_interval_secs: u64,
    pub storage_minimum_threshold: u64,
    pub storage_max_batch_size: u64,
    
    // Rate limiting
    pub max_claims_per_hour: u32,
    pub cooldown_period_secs: u64,
}

impl Default for RewardsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_claim: true,
            routing_rewards_enabled: true,
            routing_check_interval_secs: 600,  // 10 minutes
            routing_minimum_threshold: 100,
            routing_max_batch_size: 10_000,
            storage_rewards_enabled: true,
            storage_check_interval_secs: 600,  // 10 minutes
            storage_minimum_threshold: 100,
            storage_max_batch_size: 10_000,
            max_claims_per_hour: 6,  // Once every 10 minutes
            cooldown_period_secs: 600,
        }
    }
}

/// Validator node configuration (Gap 5)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConfig {
    pub enabled: bool,
    pub identity_id: String,  // DID or identity hash
    pub stake: u64,           // Minimum stake required (REQUIRED)
    pub storage_provided: u64, // Storage capacity in bytes (OPTIONAL - set to 0 for pure validators)
    pub consensus_key_path: String, // Path to consensus keypair
    pub commission_rate: u16, // Commission percentage (0-10000 = 0-100%)
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            identity_id: String::new(),
            stake: 1000 * 1_000_000, // 1000 SOV minimum stake
            storage_provided: 0, // 0 = pure validator (no storage), can be increased for storage bonus
            consensus_key_path: "./data/consensus_key.pem".to_string(),
            commission_rate: 500, // 5% default
        }
    }
}

/// Bootstrap validator for multi-node genesis (Gap 5)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapValidator {
    pub identity_id: String,
    /// Optional explicit consensus public key (hex). When empty, the key is derived
    /// deterministically from identity_id using blake3 domain separation.
    #[serde(default)]
    pub consensus_key: String,
    #[serde(default = "default_bootstrap_stake")]
    pub stake: u64,
    #[serde(default)]
    pub storage_provided: u64,
    #[serde(default)]
    pub commission_rate: u16,
    #[serde(default)]
    pub endpoints: Vec<String>,
}

fn default_bootstrap_stake() -> u64 {
    1000
}

/// Resource allocation across packages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAllocations {
    pub max_memory_mb: usize,
    pub max_cpu_threads: usize,
    pub max_disk_gb: u64,
    pub bandwidth_allocation: HashMap<String, u64>, // package -> bytes/sec
}

/// Cross-package integration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationSettings {
    pub event_bus_enabled: bool,
    pub service_discovery: bool,
    pub health_check_interval_ms: u64,
    pub cross_package_timeouts: HashMap<String, u64>,
}

/// Package-specific configuration types for loading from package config files

/// Network package configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfigPackage {
    pub protocols: Vec<String>,
    pub max_peers: usize,
    pub bootstrap_peers: Vec<String>,
    pub enable_mesh_discovery: bool,
    pub long_range_relays: bool,
}

/// Storage package configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfigPackage {
    pub max_storage_gb: u64,
    pub replication_factor: u8,
    pub enable_erasure_coding: bool,
    pub storage_tiers: Vec<String>,
    pub enable_compression: bool,
}

/// Blockchain package configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainConfigPackage {
    pub network_id: String,
    pub target_block_time_secs: u64,
    pub max_block_size: usize,
    pub enable_zk_transactions: bool,
    pub enable_smart_contracts: bool,
}

/// Economics package configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicsConfigPackage {
    pub daily_ubi_amount: u64,
    pub dao_fee_percentage: f64,
    pub enable_mesh_rewards: bool,
    pub token_supply: u64,
    pub inflation_rate: f64,
}

/// Consensus package configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfigPackage {
    pub consensus_mechanism: String,
    pub enable_validator: bool,
    pub minimum_stake: u64,
    pub enable_dao: bool,
    pub byzantine_tolerance: f64,
}

/// Identity package configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfigPackage {
    pub auto_citizenship_registration: bool,
    pub auto_ubi_registration: bool,
    pub recovery_methods: Vec<String>,
    pub enable_reputation: bool,
    pub privacy_level: String,
}

/// ZK package configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkConfigPackage {
    pub proof_cache_size: usize,
    pub enable_circuit_cache: bool,
    pub enable_parallel_proving: bool,
    pub verification_threads: usize,
    pub privacy_level: String,
}

/// Protocols package configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolsConfigPackage {
    pub api_port: u16,
    pub max_concurrent_connections: usize,
    pub request_timeout_ms: u64,
    pub enable_zhtp: bool,
    pub enable_zdns: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_id: [0u8; 32], // Will be generated during initialization
            runtime_role: RuntimeRole::Full,
            mesh_mode: MeshMode::Hybrid,
            security_level: SecurityLevel::High,
            environment: Environment::Development,
            data_directory: "./lib-data".to_string(),

            // node_type is not set by default; it will be derived during aggregation
            node_type: None,

            // Default to Observer - can be overridden during aggregation
            // based on validator_enabled and storage configuration
            node_role: crate::runtime::node_runtime::NodeRole::Observer,

            crypto_config: CryptoConfig {
                post_quantum_enabled: true,
                dilithium_level: 3,
                kyber_level: 768,
                hybrid_mode: true,
                memory_security: true,
            },
            
            zk_config: ZkConfig {
                plonky2_enabled: true,
                proof_cache_size: 1000,
                circuit_cache_enabled: true,
                parallel_proving: true,
                verification_threads: 4,
            },
            
            identity_config: IdentityConfig {
                auto_citizenship: true,
                ubi_registration: true,
                dao_auto_join: true,
                recovery_modes: vec!["mnemonic".to_string(), "biometric".to_string()],
                reputation_enabled: true,
            },
            
            storage_config: StorageConfig {
                dht_port: 33442,
                blockchain_storage_gb: 100,
                hosted_storage_gb: 100,
                personal_storage_gb: 0,
                storage_capacity_gb: 100,
                replication_factor: 3,
                erasure_coding: true,
                pricing_tier: "warm".to_string(),
            },
            
            network_config: NetworkConfig {
                mesh_port: 33444, // DEFAULT_MESH_PORT
                max_peers: 100,
                protocols: vec![
                    "mesh".to_string(),
                    "bluetooth".to_string(),
                    "wifi_direct".to_string(),
                    "lorawan".to_string(),
                    "quic".to_string(),
                ],
                bootstrap_peers: vec![
                    "127.0.0.1:9333".to_string(),
                    "127.0.0.1:9334".to_string(),
                ],
                long_range_relays: false,
                bootstrap_peer_pins: HashMap::new(),
                bootstrap_validators: Vec::new(), // Gap 5: Empty by default
            },
            
            blockchain_config: BlockchainConfig {
                network_id: "lib-mainnet".to_string(),
                block_time_seconds: 5,
                max_block_size: 1_048_576,
                zk_transactions: true,
                smart_contracts: true,
                edge_mode: false,
                edge_max_headers: 500,
            },
            
            consensus_config: ConsensusConfig {
                consensus_type: "Hybrid".to_string(),
                dao_enabled: true,
                validator_enabled: false,
                min_stake: 1000,
                reward_multipliers: HashMap::new(),
                council: lib_blockchain::dao::CouncilBootstrapConfig::default(),
            },
            
            economics_config: EconomicsConfig {
                ubi_enabled: true,
                daily_ubi_amount: 50,
                dao_fee_percentage: 2.0,
                mesh_rewards: true,
                token_economics: TokenEconomics {
                    total_supply: 1_000_000_000,
                    inflation_rate: 2.0,
                    burn_rate: 1.0,
                    reward_pool_percentage: 10.0,
                },
            },
            
            protocols_config: ProtocolsConfig {
                lib_enabled: true,
                zdns_enabled: true,
                api_port: 9333,  // Legacy port for API/HTTP traffic (distinct from QUIC mesh on 9334)
                max_connections: 1000,
                request_timeout_ms: 30000,
                quic_port: default_quic_port(),
                discovery_port: default_discovery_port(),
                enable_quic: true,          // QUIC is required
                enable_bluetooth: false,    // Bluetooth disabled by default
                enable_mdns: true,          // mDNS enabled for peer discovery
                quic_priority: 1,           // Default priority weight
                gateway_enabled: false,     // Gateway disabled by default
            },
            
            rewards_config: RewardsConfig::default(),
            
            validator_config: None, // Gap 5: Disabled by default
            
            port_assignments: HashMap::new(),
            resource_allocations: ResourceAllocations {
                max_memory_mb: 2048,
                max_cpu_threads: 8,
                max_disk_gb: 500,
                bandwidth_allocation: HashMap::new(),
            },
            
            integration_settings: IntegrationSettings {
                event_bus_enabled: true,
                service_discovery: true,
                health_check_interval_ms: 30000,
                cross_package_timeouts: HashMap::new(),
            },
        }
    }
}

impl NodeConfig {
    /// Count of packages being coordinated
    pub fn package_count(&self) -> usize {
        9 // crypto, zk, identity, storage, network, blockchain, consensus, economics, protocols
    }
    
    /// Apply CLI argument overrides to configuration
    pub fn apply_cli_overrides(&mut self, args: &CliArgs) -> Result<()> {
        // Only override mesh_port if explicitly specified via CLI
        if let Some(port) = args.mesh_port {
            self.network_config.mesh_port = port;
            tracing::info!("CLI override: mesh_port = {}", port);
        }
        
        self.mesh_mode = if args.pure_mesh { MeshMode::PureMesh } else { MeshMode::Hybrid };
        self.environment = args.environment;
        self.data_directory = args.data_dir.to_string_lossy().to_string();
        
        // If pure mesh mode is enabled, remove TCP protocols
        if args.pure_mesh {
            self.network_config.protocols.retain(|protocol| protocol != "tcp");
        }
        
        // Update port assignments
        self.port_assignments.insert("mesh".to_string(), self.network_config.mesh_port);
        self.port_assignments.insert("dht".to_string(), self.storage_config.dht_port);
        self.port_assignments.insert("api".to_string(), self.protocols_config.api_port);
        
        Ok(())
    }
    
    /// Apply environment-specific configuration
    /// Note: This applies environment defaults for settings NOT explicitly specified in the config file.
    /// The validator_enabled setting is always taken from the config file and is not overridden here.
    pub fn apply_environment_config(&mut self, _env_config: super::environment::EnvironmentConfig) -> Result<()> {
        match self.environment {
            Environment::Development => {
                self.security_level = SecurityLevel::Medium;
                // Note: validator_enabled is NOT overridden here - respect the config file setting
                self.economics_config.ubi_enabled = true; // For testing
            }
            Environment::Testnet => {
                self.security_level = SecurityLevel::High;
                self.blockchain_config.network_id = "lib-testnet".to_string();
                self.consensus_config.min_stake = 100; // Lower for testing
            }
            Environment::Mainnet => {
                self.security_level = SecurityLevel::Maximum;
                self.crypto_config.dilithium_level = 5; // Highest security
                self.zk_config.verification_threads = 8; // More verification power
            }
        }
        
        Ok(())
    }
    
    /// Check if configuration is valid for pure mesh mode
    pub fn validate_pure_mesh_mode(&self) -> Result<()> {
        if self.mesh_mode == MeshMode::PureMesh {
            // Ensure no TCP/IP protocols are enabled
            if self.network_config.protocols.contains(&"tcp".to_string()) {
                return Err(ConfigError::InvalidMeshMode {
                    reason: "TCP protocol not allowed in pure mesh mode".to_string()
                }.into());
            }

            // Ensure long-range relays are available
            if !self.network_config.long_range_relays {
                tracing::warn!("Pure mesh mode without long-range relays may have limited coverage");
            }
        }

        Ok(())
    }

    /// Derive node role from configuration settings
    /// Maps validator_enabled and storage settings to the appropriate NodeRole
    ///
    /// The role determines what operations this node can perform:
    /// - FullValidator: Can mine blocks and participate in consensus (requires validator_enabled=true)
    /// - Observer: Verifies blocks but doesn't participate in consensus (full blockchain, no mining)
    /// - LightNode: Only stores headers and ZK proofs (minimal storage)
    /// - EdgeNode: Minimal storage, BLE-optimized (if hosted_storage_gb=0)
    pub fn derive_node_role(&mut self) {
        use crate::runtime::node_runtime::NodeRole;

        // Primary determination: Is this node configured to be a validator?
        self.node_role = if self.consensus_config.validator_enabled {
            // Validator is enabled - use FullValidator role for mining and consensus participation
            tracing::info!(
                "✓ Deriving NodeRole: validator_enabled=true → FullValidator (mines blocks, validates, stores full blockchain)"
            );
            NodeRole::FullValidator
        } else {
            // Use the same edge criteria as derive_node_type() so NodeRole never diverges from
            // NodeType when edge_mode is explicitly set in config.
            let is_edge = Self::is_edge_node_config(
                self.consensus_config.validator_enabled,
                self.blockchain_config.edge_mode,
                self.blockchain_config.smart_contracts,
                self.storage_config.hosted_storage_gb,
            );
            if is_edge {
                tracing::info!(
                    "✓ Deriving NodeRole: edge detection (edge_mode={}, hosted_storage_gb={}) → LightNode (headers only)",
                    self.blockchain_config.edge_mode,
                    self.storage_config.hosted_storage_gb
                );
                NodeRole::LightNode
            } else {
                // Full node but not a validator: acts as observer
                tracing::info!(
                    "✓ Deriving NodeRole: validator_enabled=false, hosted_storage_gb={} → Observer (full blockchain, no mining/consensus)",
                    self.storage_config.hosted_storage_gb
                );
                NodeRole::Observer
            }
        };
    }

    /// Check if this node configuration represents an edge node
    /// 
    /// Unified edge detection: A node is considered an edge node if:
    /// 1. NOT configured as a validator (validator_enabled=false)
    /// 2. NOT running smart contracts
    /// 3. Hosted storage is zero (no DHT/hosting) OR edge_mode is explicitly enabled
    fn is_edge_node_config(
        validator_enabled: bool,
        edge_mode: bool,
        smart_contracts: bool,
        hosted_storage_gb: u64,
    ) -> bool {
        !validator_enabled && !smart_contracts && (edge_mode || hosted_storage_gb == 0)
    }

    /// Derive node type from configuration settings
    ///
    /// # Derivation Rules
    /// 
    /// This method determines the node type based on configuration flags when
    /// `node_type` is not explicitly set in the config file.
    ///
    /// ## Explicit Configuration (Recommended for Relay)
    /// 
    /// If `node_type` is explicitly set in the config (e.g., `node_type = "relay"`),
    /// that value is used as-is and no derivation occurs. **This is the ONLY way to
    /// configure a Relay node** since Relay nodes have no distinguishing config flags
    /// to derive from (they are routing-only with no blockchain state).
    ///
    /// ## Auto-Derivation Logic (when node_type is unset)
    ///
    /// When `node_type` is not explicitly configured, the following rules apply:
    /// 
    /// 1. **Validator**: If `validator_enabled = true`
    ///    - Full blockchain + block production + consensus participation
    ///    
    /// 2. **EdgeNode**: If edge node criteria met:
    ///    - `validator_enabled = false`
    ///    - `edge_mode = true` OR minimal storage settings
    ///    - Headers-only mode, ZK proof validation, no mining
    ///    
    /// 3. **FullNode**: Default fallback
    ///    - Complete blockchain sync and verification
    ///    - No block production (read-only consensus participation)
    ///
    /// **Note**: `NodeType::Relay` is never auto-derived and must be explicitly
    /// configured via `node_type = "relay"` in the config file.
    pub fn derive_node_type(&mut self) {
        // Only derive if node_type was not explicitly set
        if self.node_type.is_some() {
            tracing::info!(
                "✓ Using explicitly configured NodeType: {:?}",
                self.node_type.as_ref().unwrap()
            );
            return;
        }

        // Logic for determining node type from config fields
        // Note: Relay is NOT included here - it must be explicitly configured
        let derived_type = if self.consensus_config.validator_enabled {
            // Validator enabled => this is a Validator node
            tracing::info!(
                "✓ Deriving NodeType: validator_enabled=true → Validator (full blockchain + block production)"
            );
            NodeType::Validator
        } else if Self::is_edge_node_config(
            self.consensus_config.validator_enabled,
            self.blockchain_config.edge_mode,
            self.blockchain_config.smart_contracts,
            self.storage_config.hosted_storage_gb,
        ) {
            // Edge node criteria met
            tracing::info!(
                "✓ Deriving NodeType: edge detection (validator={}, edge_mode={}, hosted_storage={}) → EdgeNode (headers only)",
                self.consensus_config.validator_enabled,
                self.blockchain_config.edge_mode,
                self.storage_config.hosted_storage_gb
            );
            NodeType::EdgeNode
        } else {
            // Default: Full node (complete blockchain, no mining)
            tracing::info!(
                "✓ Deriving NodeType: default → FullNode (complete blockchain, read-only)"
            );
            NodeType::FullNode
        };

        self.node_type = Some(derived_type);
    }
}

/// Aggregate configurations from all package configuration files
pub async fn aggregate_all_package_configs(config_path: &Path) -> Result<NodeConfig> {
    let mut config = NodeConfig::default();
    
    tracing::info!("Loading package configurations from directory: {}", config_path.display());
    
    // Try to load main node configuration file
    if config_path.exists() {
        let config_content = tokio::fs::read_to_string(config_path).await?;

        // First try full NodeConfig parsing
        match toml::from_str::<NodeConfig>(&config_content) {
            Ok(loaded_config) => {
                tracing::info!("Loaded main configuration file (full NodeConfig)");
                tracing::debug!("  validator_enabled = {}", loaded_config.consensus_config.validator_enabled);
                config = loaded_config;
            }
            Err(e) => {
                tracing::debug!("Full NodeConfig parsing failed: {}", e);
                // Fall back to partial config parsing (for config files with optional sections)
                if let Ok(partial) = toml::from_str::<PartialConfig>(&config_content) {
                    tracing::info!("Loaded partial configuration file (merging with defaults)");
                    
                    // Merge top-level environment if present
                    if let Some(env) = partial.environment {
                        tracing::info!("Loaded environment = {:?} from config file", env);
                        config.environment = env;
                    }
                    if let Some(role) = partial.runtime_role {
                        tracing::info!("Loaded runtime_role = {:?} from config file", role);
                        config.runtime_role = role;
                    }
                    
                    // Merge [network] section (legacy support)
                    if let Some(network) = partial.network {
                        if !network.bootstrap_peers.is_empty() {
                            tracing::info!("Loaded {} bootstrap peer(s) from [network] section", network.bootstrap_peers.len());
                            config.network_config.bootstrap_peers = network.bootstrap_peers;
                        }
                        if !network.bootstrap_peer_pins.is_empty() {
                            tracing::info!("Loaded {} bootstrap peer pin(s) from [network] section", network.bootstrap_peer_pins.len());
                            config.network_config.bootstrap_peer_pins = network.bootstrap_peer_pins;
                        }
                        if !network.bootstrap_validators.is_empty() {
                            tracing::info!("Loaded {} bootstrap validator(s) from [network] section", network.bootstrap_validators.len());
                            config.network_config.bootstrap_validators = network.bootstrap_validators;
                        }
                        if let Some(mesh_port) = network.mesh_port {
                            config.network_config.mesh_port = mesh_port;
                        }
                        if let Some(max_peers) = network.max_peers {
                            config.network_config.max_peers = max_peers;
                        }
                        if let Some(network_id) = network.network_id {
                            config.blockchain_config.network_id = network_id;
                        }
                    }

                    // Merge [network_config] section
                    if let Some(network) = partial.network_config {
                        if !network.bootstrap_peers.is_empty() {
                            tracing::info!("Loaded {} bootstrap peer(s) from [network_config] section", network.bootstrap_peers.len());
                            config.network_config.bootstrap_peers = network.bootstrap_peers;
                        }
                        if !network.bootstrap_peer_pins.is_empty() {
                            tracing::info!("Loaded {} bootstrap peer pin(s) from [network_config] section", network.bootstrap_peer_pins.len());
                            config.network_config.bootstrap_peer_pins = network.bootstrap_peer_pins;
                        }
                        if !network.bootstrap_validators.is_empty() {
                            tracing::info!("Loaded {} bootstrap validator(s) from [network_config] section", network.bootstrap_validators.len());
                            config.network_config.bootstrap_validators = network.bootstrap_validators;
                        }
                        if let Some(mesh_port) = network.mesh_port {
                            config.network_config.mesh_port = mesh_port;
                        }
                        if let Some(max_peers) = network.max_peers {
                            config.network_config.max_peers = max_peers;
                        }
                        if let Some(network_id) = network.network_id {
                            config.blockchain_config.network_id = network_id;
                        }
                    }
                    
                    // Merge [consensus_config] section - CRITICAL for validator_enabled
                    if let Some(consensus) = partial.consensus_config {
                        if let Some(validator_enabled) = consensus.validator_enabled {
                            tracing::info!("Loaded validator_enabled = {} from [consensus_config] section", validator_enabled);
                            config.consensus_config.validator_enabled = validator_enabled;
                        }
                        if let Some(consensus_type) = consensus.consensus_type {
                            config.consensus_config.consensus_type = consensus_type;
                        }
                        if let Some(dao_enabled) = consensus.dao_enabled {
                            config.consensus_config.dao_enabled = dao_enabled;
                        }
                        if let Some(min_stake) = consensus.min_stake {
                            config.consensus_config.min_stake = min_stake;
                        }
                    }
                    
                    // Merge [blockchain_config] section
                    if let Some(blockchain) = partial.blockchain_config {
                        if let Some(network_id) = blockchain.network_id {
                            config.blockchain_config.network_id = network_id;
                        }
                        if let Some(edge_mode) = blockchain.edge_mode {
                            config.blockchain_config.edge_mode = edge_mode;
                        }
                        if let Some(edge_max_headers) = blockchain.edge_max_headers {
                            config.blockchain_config.edge_max_headers = edge_max_headers;
                        }
                        if let Some(smart_contracts) = blockchain.smart_contracts {
                            tracing::info!("Loaded smart_contracts = {} from [blockchain_config] section", smart_contracts);
                            config.blockchain_config.smart_contracts = smart_contracts;
                        }
                    }
                    
                    // Merge [storage_config] section - CRITICAL for edge node detection
                    if let Some(storage) = partial.storage_config {
                        if let Some(hosted_storage_gb) = storage.hosted_storage_gb {
                            tracing::info!("Loaded hosted_storage_gb = {} from [storage_config] section", hosted_storage_gb);
                            config.storage_config.hosted_storage_gb = hosted_storage_gb;
                        }
                        if let Some(blockchain_storage_gb) = storage.blockchain_storage_gb {
                            config.storage_config.blockchain_storage_gb = blockchain_storage_gb;
                        }
                    }
                    
                    // Merge [validator_config] section
                    if let Some(validator) = partial.validator_config {
                        if validator.enabled.unwrap_or(false) || validator.stake.is_some() {
                            tracing::info!("Loaded [validator_config] section");
                            // If validator_config is specified, also enable validator_enabled in consensus
                            if validator.enabled.unwrap_or(false) {
                                config.consensus_config.validator_enabled = true;
                                tracing::info!("  validator_config.enabled = true implies consensus_config.validator_enabled = true");
                            }
                        }
                    }
                } else {
                    tracing::warn!("Config file exists but could not be parsed - using defaults");
                }
            }
        }
    } else {
        tracing::info!("Using default configuration (no config file found)");
    }
    
    // Load package-specific configurations if available
    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    
    // Try to load crypto package config
    if let Ok(crypto_config) = load_package_config::<CryptoConfig>(config_dir, "crypto").await {
        config.crypto_config = crypto_config;
        tracing::debug!("Loaded crypto package configuration");
    }
    
    // Try to load other package configs when available
    // Load available package configurations from their default locations
    
    // Try to load crypto package config
    if let Ok(crypto_config) = load_package_config::<CryptoConfig>(config_dir, "lib-crypto").await {
        config.crypto_config = crypto_config;
        tracing::debug!("Loaded lib-crypto package configuration");
    }
    
    // Try to load network package config  
    if let Ok(network_config) = load_package_config::<NetworkConfigPackage>(config_dir, "lib-network").await {
        // Apply network-specific settings to main config
        config.network_config.protocols = network_config.protocols;
        config.network_config.max_peers = network_config.max_peers;
        if !network_config.bootstrap_peers.is_empty() {
            config.network_config.bootstrap_peers = network_config.bootstrap_peers;
        }
        tracing::debug!("Loaded lib-network package configuration");
    }
    
    // Try to load storage package config
    if let Ok(storage_config) = load_package_config::<StorageConfigPackage>(config_dir, "lib-storage").await {
        config.storage_config.storage_capacity_gb = storage_config.max_storage_gb;
        config.storage_config.replication_factor = storage_config.replication_factor;
        config.storage_config.erasure_coding = storage_config.enable_erasure_coding;
        tracing::debug!("Loaded lib-storage package configuration");
    }
    
    // Try to load blockchain package config
    if let Ok(blockchain_config) = load_package_config::<BlockchainConfigPackage>(config_dir, "lib-blockchain").await {
        config.blockchain_config.network_id = blockchain_config.network_id;
        config.blockchain_config.block_time_seconds = blockchain_config.target_block_time_secs;
        config.blockchain_config.max_block_size = blockchain_config.max_block_size;
        tracing::debug!("Loaded lib-blockchain package configuration");
    }
    
    // Try to load economics package config
    if let Ok(economics_config) = load_package_config::<EconomicsConfigPackage>(config_dir, "lib-economy").await {
        config.economics_config.daily_ubi_amount = economics_config.daily_ubi_amount;
        config.economics_config.dao_fee_percentage = economics_config.dao_fee_percentage;
        config.economics_config.mesh_rewards = economics_config.enable_mesh_rewards;
        tracing::debug!("Loaded lib-economy package configuration");
    }
    
    // Try to load consensus package config
    if let Ok(consensus_config) = load_package_config::<ConsensusConfigPackage>(config_dir, "lib-consensus").await {
        config.consensus_config.consensus_type = consensus_config.consensus_mechanism;
        config.consensus_config.validator_enabled = consensus_config.enable_validator;
        config.consensus_config.min_stake = consensus_config.minimum_stake;
        tracing::debug!("Loaded lib-consensus package configuration");
    }
    
    // Try to load identity package config
    if let Ok(identity_config) = load_package_config::<IdentityConfigPackage>(config_dir, "lib-identity").await {
        config.identity_config.auto_citizenship = identity_config.auto_citizenship_registration;
        config.identity_config.ubi_registration = identity_config.auto_ubi_registration;
        config.identity_config.recovery_modes = identity_config.recovery_methods;
        tracing::debug!("Loaded lib-identity package configuration");
    }
    
    // Try to load ZK package config
    if let Ok(zk_config) = load_package_config::<ZkConfigPackage>(config_dir, "lib-proofs").await {
        config.zk_config.proof_cache_size = zk_config.proof_cache_size;
        config.zk_config.circuit_cache_enabled = zk_config.enable_circuit_cache;
        config.zk_config.parallel_proving = zk_config.enable_parallel_proving;
        config.zk_config.verification_threads = zk_config.verification_threads;
        tracing::debug!("Loaded lib-proofs package configuration");
    }
    
    // Try to load protocols package config
    if let Ok(protocols_config) = load_package_config::<ProtocolsConfigPackage>(config_dir, "lib-protocols").await {
        config.protocols_config.api_port = protocols_config.api_port;
        config.protocols_config.max_connections = protocols_config.max_concurrent_connections;
        config.protocols_config.request_timeout_ms = protocols_config.request_timeout_ms;
        tracing::debug!("Loaded lib-protocols package configuration");
    }

    // CRITICAL: Derive node role from configuration settings
    // This must be done after all config sections have been loaded/merged
    // Maps validator_enabled and storage settings to the appropriate NodeRole
    config.derive_node_role();

    // CRITICAL: Derive canonical node type (SINGLE SOURCE OF TRUTH)
    // This determines the node's primary mode: Full, Edge, Validator, or Relay
    config.derive_node_type();

    Ok(config)
}

/// Load configuration for a specific package
async fn load_package_config<T: for<'de> Deserialize<'de>>(
    config_dir: &Path,
    package_name: &str,
) -> Result<T> {
    let config_file = config_dir.join(format!("{}.toml", package_name));

    if config_file.exists() {
        let content = tokio::fs::read_to_string(&config_file).await?;
        let config: T = toml::from_str(&content)?;
        Ok(config)
    } else {
        Err(ConfigError::PackageMissing {
            package: package_name.to_string()
        }.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_network::protocols::NetworkProtocol;

    #[test]
    fn test_protocol_filtering_bluetooth_disabled() {
        // REGRESSION TEST: Verify that disabled protocols are filtered out
        // This prevents accidental re-enablement of Bluetooth when disabled in config

        let config = ProtocolsConfig {
            lib_enabled: true,
            zdns_enabled: true,
            api_port: 8080,
            max_connections: 100,
            request_timeout_ms: 5000,
            quic_port: 9334,
            discovery_port: 9333,
            enable_quic: true,
            enable_bluetooth: false,  // POLICY: Bluetooth disabled
            enable_mdns: true,
            quic_priority: 1,
            gateway_enabled: false,
        };

        let requested = vec![
            NetworkProtocol::BluetoothLE,
            NetworkProtocol::QUIC,
            NetworkProtocol::WiFiDirect,
        ];

        let filtered = config.filter_mesh_protocols(requested);

        // ASSERTION: Bluetooth must NOT be in filtered list
        assert!(
            !filtered.contains(&NetworkProtocol::BluetoothLE),
            "REGRESSION: Bluetooth LE should be filtered when enable_bluetooth=false"
        );

        // ASSERTION: QUIC must still be in filtered list
        assert!(
            filtered.contains(&NetworkProtocol::QUIC),
            "QUIC should be allowed when enable_quic=true"
        );

        // ASSERTION: WiFiDirect should pass through (no explicit disable)
        assert!(
            filtered.contains(&NetworkProtocol::WiFiDirect),
            "WiFiDirect should be allowed when not explicitly disabled"
        );
    }

    #[test]
    fn test_protocol_filtering_bluetooth_enabled() {
        // NORMAL CASE: When Bluetooth is enabled, it should NOT be filtered

        let config = ProtocolsConfig {
            lib_enabled: true,
            zdns_enabled: true,
            api_port: 8080,
            max_connections: 100,
            request_timeout_ms: 5000,
            quic_port: 9334,
            discovery_port: 9333,
            enable_quic: true,
            enable_bluetooth: true,  // POLICY: Bluetooth enabled
            enable_mdns: true,
            quic_priority: 1,
            gateway_enabled: false,
        };

        let requested = vec![
            NetworkProtocol::BluetoothLE,
            NetworkProtocol::QUIC,
        ];

        let filtered = config.filter_mesh_protocols(requested);

        // ASSERTION: Bluetooth must be in filtered list when enabled
        assert!(
            filtered.contains(&NetworkProtocol::BluetoothLE),
            "Bluetooth LE should be allowed when enable_bluetooth=true"
        );
    }

    #[test]
    fn test_protocol_filtering_quic_disabled() {
        // Edge case: QUIC disabled should be filtered

        let config = ProtocolsConfig {
            lib_enabled: true,
            zdns_enabled: true,
            api_port: 8080,
            max_connections: 100,
            request_timeout_ms: 5000,
            quic_port: 9334,
            discovery_port: 9333,
            enable_quic: false,  // POLICY: QUIC disabled
            enable_bluetooth: true,
            enable_mdns: true,
            quic_priority: 1,
            gateway_enabled: false,
        };

        let requested = vec![
            NetworkProtocol::QUIC,
            NetworkProtocol::BluetoothLE,
        ];

        let filtered = config.filter_mesh_protocols(requested);

        // ASSERTION: QUIC must NOT be in filtered list
        assert!(
            !filtered.contains(&NetworkProtocol::QUIC),
            "QUIC should be filtered when enable_quic=false"
        );

        // ASSERTION: Bluetooth must be in filtered list
        assert!(
            filtered.contains(&NetworkProtocol::BluetoothLE),
            "Bluetooth should be allowed when enable_bluetooth=true"
        );
    }

    #[test]
    fn test_protocol_filtering_empty_list() {
        // Edge case: Empty protocol list should remain empty

        let config = ProtocolsConfig {
            lib_enabled: true,
            zdns_enabled: true,
            api_port: 8080,
            max_connections: 100,
            request_timeout_ms: 5000,
            quic_port: 9334,
            discovery_port: 9333,
            enable_quic: true,
            enable_bluetooth: false,
            enable_mdns: true,
            quic_priority: 1,
            gateway_enabled: false,
        };

        let requested = vec![];
        let filtered = config.filter_mesh_protocols(requested);

        assert!(
            filtered.is_empty(),
            "Filtering empty list should return empty list"
        );
    }

    /// Test TOML parsing of bootstrap_peer_pins (Issue #922)
    #[test]
    fn test_partial_config_bootstrap_peer_pins() {
        let toml_str = r#"
[network_config]
bootstrap_peers = ["77.42.37.161:9334"]

[network_config.bootstrap_peer_pins]
"77.42.37.161:9334" = "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8"
"#;

        let partial: PartialConfig = toml::from_str(toml_str)
            .expect("Failed to parse TOML with bootstrap_peer_pins");

        let network = partial.network_config.expect("network_config should be present");
        assert_eq!(network.bootstrap_peers.len(), 1);
        assert_eq!(network.bootstrap_peers[0], "77.42.37.161:9334");
        assert_eq!(network.bootstrap_peer_pins.len(), 1);
        assert_eq!(
            network.bootstrap_peer_pins.get("77.42.37.161:9334").unwrap(),
            "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8"
        );
    }

    /// Test that missing bootstrap_peer_pins defaults to empty map
    #[test]
    fn test_partial_config_no_pins_defaults_empty() {
        let toml_str = r#"
[network_config]
bootstrap_peers = ["10.0.0.1:9334"]
"#;

        let partial: PartialConfig = toml::from_str(toml_str)
            .expect("Failed to parse TOML without bootstrap_peer_pins");

        let network = partial.network_config.expect("network_config should be present");
        assert_eq!(network.bootstrap_peers.len(), 1);
        assert!(network.bootstrap_peer_pins.is_empty());
    }

    /// Test that multiple pins can be configured
    #[test]
    fn test_partial_config_multiple_pins() {
        let toml_str = r#"
[network_config]
bootstrap_peers = ["10.0.0.1:9334", "10.0.0.2:9334"]

[network_config.bootstrap_peer_pins]
"10.0.0.1:9334" = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"10.0.0.2:9334" = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
"#;

        let partial: PartialConfig = toml::from_str(toml_str)
            .expect("Failed to parse TOML with multiple bootstrap_peer_pins");

        let network = partial.network_config.expect("network_config should be present");
        assert_eq!(network.bootstrap_peer_pins.len(), 2);
    }

    /// Test that explicitly configured Relay node type is preserved (Issue #454)
    #[test]
    fn test_derive_node_type_preserves_explicit_relay() {
        // Create a minimal NodeConfig with explicitly set Relay type
        let mut config = NodeConfig::default();
        config.node_type = Some(NodeType::Relay);
        
        // Call derive_node_type - it should NOT overwrite the explicit Relay setting
        config.derive_node_type();
        
        assert_eq!(
            config.node_type,
            Some(NodeType::Relay),
            "derive_node_type must preserve explicitly configured Relay node type"
        );
    }

    /// Test that Relay is never auto-derived (Issue #454)
    #[test]
    fn test_derive_node_type_never_produces_relay() {
        // Test 1: Validator enabled -> should produce Validator, not Relay
        let mut config1 = NodeConfig::default();
        config1.node_type = None;
        config1.consensus_config.validator_enabled = true;
        config1.derive_node_type();
        assert_eq!(config1.node_type, Some(NodeType::Validator));

        // Test 2: Edge node config -> should produce EdgeNode, not Relay
        let mut config2 = NodeConfig::default();
        config2.node_type = None;
        config2.consensus_config.validator_enabled = false;
        config2.blockchain_config.edge_mode = true;
        config2.derive_node_type();
        assert_eq!(config2.node_type, Some(NodeType::EdgeNode));

        // Test 3: Default config -> should produce FullNode, not Relay
        let mut config3 = NodeConfig::default();
        config3.node_type = None;
        config3.consensus_config.validator_enabled = false;
        config3.blockchain_config.edge_mode = false;
        config3.derive_node_type();
        assert_eq!(config3.node_type, Some(NodeType::FullNode));
    }

    /// Test that explicit node_type is always preserved during derivation
    #[test]
    fn test_derive_node_type_preserves_all_explicit_types() {
        // Test each explicit node type is preserved
        for explicit_type in [NodeType::Validator, NodeType::EdgeNode, NodeType::FullNode, NodeType::Relay] {
            let mut config = NodeConfig::default();
            config.node_type = Some(explicit_type);
            
            // Set conflicting config that would normally derive a different type
            config.consensus_config.validator_enabled = true;
            
            config.derive_node_type();
            
            assert_eq!(
                config.node_type,
                Some(explicit_type),
                "derive_node_type must preserve explicit {:?} configuration",
                explicit_type
            );
        }
    }
}
