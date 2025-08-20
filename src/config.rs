use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::env;

/// Main configuration structure for ZHTP node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpConfig {
    pub network: NetworkConfig,
    pub node: NodeConfig,
    pub consensus: ConsensusConfig,
    pub storage: StorageConfig,
    pub security: SecurityConfig,
    pub dns: DnsConfig,
    pub logging: LoggingConfig,
    pub api: ApiServerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub listen_address: SocketAddr,
    pub public_address: Option<String>,
    pub bootstrap_peers: Vec<SocketAddr>,
    pub max_connections: usize,
    pub connection_timeout: u64,
    pub heartbeat_interval: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub name: String,
    pub node_id: Option<String>,
    pub keypair_path: Option<PathBuf>,
    pub data_dir: PathBuf,
    pub validator: bool,
    pub mining_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    pub min_validators: usize,
    pub block_time: u64,
    pub finalization_depth: u64,
    pub stake_threshold: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub dht_enabled: bool,
    pub storage_quota: u64,
    pub replication_factor: usize,
    pub gc_interval: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub enable_tls: bool,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    pub auth_required: bool,
    pub rate_limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    pub enabled: bool,
    pub listen_address: SocketAddr,
    pub authoritative_domains: Vec<String>,
    pub cache_ttl: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file_path: Option<PathBuf>,
    pub max_file_size: u64,
    pub max_files: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiServerConfig {
    pub listen_address: SocketAddr,
    pub enable_cors: bool,
    pub rate_limit_requests_per_minute: u32,
    pub request_timeout_seconds: u64,
    pub max_request_body_size: usize,
}

impl Default for ZhtpConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            node: NodeConfig::default(),
            consensus: ConsensusConfig::default(),
            storage: StorageConfig::default(),
            security: SecurityConfig::default(),
            dns: DnsConfig::default(),
            logging: LoggingConfig::default(),
            api: ApiServerConfig::default(),
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_address: "0.0.0.0:19847".parse().expect("Valid default address"),
            public_address: None,
            bootstrap_peers: vec![],
            max_connections: 100,
            connection_timeout: 30,
            heartbeat_interval: 60,
        }
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            name: "zhtp-node".to_string(),
            node_id: None,
            keypair_path: None,
            data_dir: PathBuf::from("./data"),
            validator: false,
            mining_enabled: false,
        }
    }
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            min_validators: 3,
            block_time: 5000, // 5 seconds
            finalization_depth: 12,
            stake_threshold: 1000,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            dht_enabled: true,
            storage_quota: 10 * 1024 * 1024 * 1024, // 10GB
            replication_factor: 3,
            gc_interval: 3600, // 1 hour
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_tls: true,
            cert_path: None,
            key_path: None,
            auth_required: true,
            rate_limit: Some(1000), // requests per minute
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_address: "0.0.0.0:5353".parse().expect("Valid DNS address"),
            authoritative_domains: vec!["zhtp".to_string()],
            cache_ttl: 300, // 5 minutes
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file_path: Some(PathBuf::from("./logs/zhtp.log")),
            max_file_size: 100 * 1024 * 1024, // 100MB
            max_files: 5,
        }
    }
}

impl Default for ApiServerConfig {
    fn default() -> Self {
        Self {
            listen_address: "127.0.0.1:8080".parse().expect("Valid default address"),
            enable_cors: true,
            rate_limit_requests_per_minute: 100,
            request_timeout_seconds: 30,
            max_request_body_size: 1024 * 1024, // 1MB
        }
    }
}

impl ZhtpConfig {
    /// Load configuration from file and environment variables
    pub fn load() -> Result<Self> {
        let mut config = Self::default();
        
        // Try to load from config file
        if let Ok(config_path) = env::var("ZHTP_CONFIG_PATH") {
            config = Self::from_file(&config_path)?;
        } else if std::path::Path::new("zhtp.toml").exists() {
            config = Self::from_file("zhtp.toml")?;
        }
        
        // Override with environment variables
        config.apply_env_overrides()?;
        
        // Validate configuration
        config.validate()?;
        
        Ok(config)
    }
    
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .context("Failed to read configuration file")?;
        
        let config: Self = toml::from_str(&content)
            .context("Failed to parse configuration file")?;
        
        Ok(config)
    }
    
    /// Apply environment variable overrides
    fn apply_env_overrides(&mut self) -> Result<()> {
        if let Ok(addr) = env::var("ZHTP_LISTEN_ADDRESS") {
            self.network.listen_address = addr.parse()
                .context("Invalid ZHTP_LISTEN_ADDRESS")?;
        }
        
        if let Ok(addr) = env::var("ZHTP_PUBLIC_ADDRESS") {
            self.network.public_address = Some(addr);
        }
        
        if let Ok(peers) = env::var("ZHTP_BOOTSTRAP_PEERS") {
            self.network.bootstrap_peers = peers
                .split(',')
                .map(|s| s.trim().parse())
                .collect::<Result<Vec<_>, _>>()
                .context("Invalid ZHTP_BOOTSTRAP_PEERS")?;
        }
        
        if let Ok(name) = env::var("ZHTP_NODE_NAME") {
            self.node.name = name;
        }
        
        if let Ok(id) = env::var("ZHTP_NODE_ID") {
            self.node.node_id = Some(id);
        }
        
        if let Ok(dir) = env::var("ZHTP_DATA_DIR") {
            self.node.data_dir = PathBuf::from(dir);
        }
        
        if let Ok(val) = env::var("ZHTP_VALIDATOR") {
            self.node.validator = val.parse().unwrap_or(false);
        }
        
        if let Ok(level) = env::var("ZHTP_LOG_LEVEL") {
            self.logging.level = level;
        }
        
        Ok(())
    }
    
    /// Validate configuration
    fn validate(&self) -> Result<()> {
        // Validate network configuration
        if self.network.max_connections == 0 {
            anyhow::bail!("max_connections must be greater than 0");
        }
        
        if self.consensus.min_validators == 0 {
            anyhow::bail!("min_validators must be greater than 0");
        }
        
        if self.storage.replication_factor == 0 {
            anyhow::bail!("replication_factor must be greater than 0");
        }
        
        // Validate paths exist or can be created
        if let Some(parent) = self.node.data_dir.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .context("Failed to create data directory")?;
            }
        }
        
        Ok(())
    }
    
    /// Save configuration to file
    pub fn save<P: AsRef<std::path::Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .context("Failed to serialize configuration")?;
        
        std::fs::write(path, content)
            .context("Failed to write configuration file")?;
        
        Ok(())
    }
}

/// Helper function to get a configuration value with fallback
pub fn get_env_or_default<T>(env_var: &str, default: T) -> T 
where 
    T: std::str::FromStr,
{
    env::var(env_var)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
   
    #[test]
    fn test_default_config() {
        let config = ZhtpConfig::default();
        assert_eq!(config.node.name, "zhtp-node");
        assert_eq!(config.consensus.min_validators, 3);
        assert!(config.security.auth_required);
    }
    
    #[test]
    fn test_config_validation() {
        let mut config = ZhtpConfig::default();
        config.consensus.min_validators = 0;
        
        assert!(config.validate().is_err());
    }
    
    #[test]
    fn test_config_serialization() {
        let config = ZhtpConfig::default();
        let toml_str = toml::to_string(&config).unwrap();
        let parsed: ZhtpConfig = toml::from_str(&toml_str).unwrap();
        
        assert_eq!(config.node.name, parsed.node.name);
    }
    
    #[test]
    fn test_env_override() {
        unsafe {
            env::set_var("ZHTP_NODE_NAME", "test-node");
        }
        
        let mut config = ZhtpConfig::default();
        config.apply_env_overrides().unwrap();
        
        assert_eq!(config.node.name, "test-node");
        
        unsafe {
            env::remove_var("ZHTP_NODE_NAME");
        }
    }
}
