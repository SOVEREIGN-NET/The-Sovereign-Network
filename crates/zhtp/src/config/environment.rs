//! Environment-Specific Configuration
//! 
//! Handles development, testnet, and mainnet environment settings

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Deployment environments
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Environment {
    Development,
    Testnet,
    Mainnet,
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Environment::Development => write!(f, "Development"),
            Environment::Testnet => write!(f, "Testnet"),
            Environment::Mainnet => write!(f, "Mainnet"),
        }
    }
}

impl Default for Environment {
    fn default() -> Self {
        Environment::Development
    }
}

impl Environment {
    /// Returns the chain ID for this environment
    /// - Mainnet: 0x01
    /// - Testnet: 0x02
    /// - Development: 0x03
    pub fn chain_id(&self) -> u8 {
        match self {
            Environment::Mainnet => 0x01,
            Environment::Testnet => 0x02,
            Environment::Development => 0x03,
        }
    }
}

/// Environment-specific configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentConfig {
    pub environment: Environment,
    pub network_settings: NetworkSettings,
    pub security_settings: SecuritySettings,
    pub economic_settings: EconomicSettings,
    pub logging_settings: LoggingSettings,
    pub performance_settings: PerformanceSettings,
}

/// Network configuration per environment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSettings {
    pub network_id: String,
    pub bootstrap_peers: Vec<String>,
    pub max_peers: usize,
    pub connection_timeout_ms: u64,
    pub peer_discovery_interval_ms: u64,
}

/// Security settings per environment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    pub require_signatures: bool,
    pub allow_unsafe_operations: bool,
    pub rate_limiting: bool,
    pub audit_logging: bool,
    pub penetration_testing_mode: bool,
}

/// Economic parameters per environment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicSettings {
    pub ubi_daily_amount: u64,
    pub transaction_fees: FeeSettings,
    pub validator_rewards: RewardSettings,
    pub dao_treasury_percentage: f64,
}

/// Transaction fee configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeSettings {
    pub base_fee: u64,
    pub per_byte_fee: u64,
    pub priority_multiplier: f64,
    pub dao_fee_percentage: f64,
}

/// Validator reward configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardSettings {
    pub block_reward: u64,
    pub validation_reward: u64,
    pub mesh_participation_reward: u64,
    pub storage_provision_reward: u64,
}

/// Logging configuration per environment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingSettings {
    pub level: String,
    pub file_logging: bool,
    pub console_logging: bool,
    pub structured_logging: bool,
    pub performance_metrics: bool,
    pub security_events: bool,
}

/// Performance tuning per environment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSettings {
    pub max_concurrent_operations: usize,
    pub cache_sizes: CacheSettings,
    pub thread_pool_sizes: ThreadPoolSettings,
    pub memory_limits: MemorySettings,
}

/// Cache size configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheSettings {
    pub zk_proof_cache: usize,
    pub block_cache: usize,
    pub transaction_cache: usize,
    pub peer_cache: usize,
}

/// Thread pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadPoolSettings {
    pub crypto_threads: usize,
    pub zk_verification_threads: usize,
    pub network_threads: usize,
    pub storage_threads: usize,
}

/// Memory limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySettings {
    pub max_heap_mb: usize,
    pub max_cache_mb: usize,
    pub gc_threshold_mb: usize,
}

impl Environment {
    /// Get network-specific data directory
    /// 
    /// Returns the base data directory path for this environment.
    /// Each environment uses a separate directory to prevent data contamination.
    pub fn data_directory(&self) -> String {
        match self {
            Environment::Development => "./data/dev".to_string(),
            Environment::Testnet => "./data/testnet".to_string(),
            Environment::Mainnet => "./data/mainnet".to_string(),
        }
    }
    
    /// Get blockchain database path for this environment
    pub fn blockchain_db_path(&self) -> String {
        format!("{}/blockchain.db", self.data_directory())
    }
    
    /// Get wallet database path for this environment
    pub fn wallet_db_path(&self) -> String {
        format!("{}/wallet.db", self.data_directory())
    }
    
    /// Get identity registry database path for this environment
    pub fn identity_db_path(&self) -> String {
        format!("{}/identity.db", self.data_directory())
    }
    
    /// Get state database path for this environment
    pub fn state_db_path(&self) -> String {
        format!("{}/state.db", self.data_directory())
    }
    
    /// Get network configuration path for this environment
    pub fn network_config_path(&self) -> String {
        match self {
            Environment::Development => "./configs/full-node.toml".to_string(),
            Environment::Testnet => "./configs/testnet-full-node.toml".to_string(),
            Environment::Mainnet => "./configs/mainnet-full-node.toml".to_string(),
        }
    }
    
    /// Get logs directory for this environment
    pub fn logs_directory(&self) -> String {
        format!("{}/logs", self.data_directory())
    }
    
    /// Get default configuration for this environment
    pub fn get_default_config(&self) -> EnvironmentConfig {
        match self {
            Environment::Development => EnvironmentConfig {
                environment: *self,
                network_settings: NetworkSettings {
                    network_id: "lib-dev".to_string(),
                    bootstrap_peers: vec![
                        "127.0.0.1:9333".to_string(),
                        "localhost:9334".to_string(),
                        "192.168.1.245:9333".to_string(),
                    ],
                    max_peers: 10,
                    connection_timeout_ms: 5000,
                    peer_discovery_interval_ms: 10000,
                },
                security_settings: SecuritySettings {
                    require_signatures: false, // Relaxed for development
                    allow_unsafe_operations: true,
                    rate_limiting: false,
                    audit_logging: false,
                    penetration_testing_mode: false,
                },
                economic_settings: EconomicSettings {
                    ubi_daily_amount: 100, // Higher for testing
                    transaction_fees: FeeSettings {
                        base_fee: 1,
                        per_byte_fee: 1,
                        priority_multiplier: 1.0,
                        dao_fee_percentage: 1.0, // Lower DAO fees for development
                    },
                    validator_rewards: RewardSettings {
                        block_reward: 50,
                        validation_reward: 10,
                        mesh_participation_reward: 5,
                        storage_provision_reward: 2,
                    },
                    dao_treasury_percentage: 10.0,
                },
                logging_settings: LoggingSettings {
                    level: "debug".to_string(),
                    file_logging: true,
                    console_logging: true,
                    structured_logging: false,
                    performance_metrics: true,
                    security_events: true,
                },
                performance_settings: PerformanceSettings {
                    max_concurrent_operations: 100,
                    cache_sizes: CacheSettings {
                        zk_proof_cache: 100,
                        block_cache: 50,
                        transaction_cache: 200,
                        peer_cache: 50,
                    },
                    thread_pool_sizes: ThreadPoolSettings {
                        crypto_threads: 2,
                        zk_verification_threads: 2,
                        network_threads: 4,
                        storage_threads: 2,
                    },
                    memory_limits: MemorySettings {
                        max_heap_mb: 512,
                        max_cache_mb: 128,
                        gc_threshold_mb: 256,
                    },
                },
            },
            
            Environment::Testnet => EnvironmentConfig {
                environment: *self,
                network_settings: NetworkSettings {
                    network_id: "lib-testnet".to_string(),
                    bootstrap_peers: vec![
                        "127.0.0.1:9333".to_string(),
                        "192.168.1.245:9333".to_string(),
                    ],
                    max_peers: 50,
                    connection_timeout_ms: 10000,
                    peer_discovery_interval_ms: 30000,
                },
                security_settings: SecuritySettings {
                    require_signatures: true,
                    allow_unsafe_operations: false,
                    rate_limiting: true,
                    audit_logging: true,
                    penetration_testing_mode: true, // Allow testing attacks
                },
                economic_settings: EconomicSettings {
                    ubi_daily_amount: 50,
                    transaction_fees: FeeSettings {
                        base_fee: 10,
                        per_byte_fee: 1,
                        priority_multiplier: 2.0,
                        dao_fee_percentage: 2.0,
                    },
                    validator_rewards: RewardSettings {
                        block_reward: 25,
                        validation_reward: 5,
                        mesh_participation_reward: 3,
                        storage_provision_reward: 1,
                    },
                    dao_treasury_percentage: 15.0,
                },
                logging_settings: LoggingSettings {
                    level: "info".to_string(),
                    file_logging: true,
                    console_logging: true,
                    structured_logging: true,
                    performance_metrics: true,
                    security_events: true,
                },
                performance_settings: PerformanceSettings {
                    max_concurrent_operations: 500,
                    cache_sizes: CacheSettings {
                        zk_proof_cache: 500,
                        block_cache: 200,
                        transaction_cache: 1000,
                        peer_cache: 200,
                    },
                    thread_pool_sizes: ThreadPoolSettings {
                        crypto_threads: 4,
                        zk_verification_threads: 4,
                        network_threads: 8,
                        storage_threads: 4,
                    },
                    memory_limits: MemorySettings {
                        max_heap_mb: 1024,
                        max_cache_mb: 256,
                        gc_threshold_mb: 512,
                    },
                },
            },
            
            Environment::Mainnet => EnvironmentConfig {
                environment: *self,
                network_settings: NetworkSettings {
                    network_id: "lib-mainnet".to_string(),
                    bootstrap_peers: vec![
                        "127.0.0.1:9333".to_string(),
                        "192.168.1.245:9333".to_string(),
                    ],
                    max_peers: 100,
                    connection_timeout_ms: 30000,
                    peer_discovery_interval_ms: 60000,
                },
                security_settings: SecuritySettings {
                    require_signatures: true,
                    allow_unsafe_operations: false,
                    rate_limiting: true,
                    audit_logging: true,
                    penetration_testing_mode: false, // No testing in production
                },
                economic_settings: EconomicSettings {
                    ubi_daily_amount: 33, // UBI amount
                    transaction_fees: FeeSettings {
                        base_fee: 100,
                        per_byte_fee: 10,
                        priority_multiplier: 5.0,
                        dao_fee_percentage: 2.0, // Standard DAO fee
                    },
                    validator_rewards: RewardSettings {
                        block_reward: 12, // block reward
                        validation_reward: 2,
                        mesh_participation_reward: 1,
                        storage_provision_reward: 1,
                    },
                    dao_treasury_percentage: 20.0,
                },
                logging_settings: LoggingSettings {
                    level: "warn".to_string(),
                    file_logging: true,
                    console_logging: false, // No console logging in production
                    structured_logging: true,
                    performance_metrics: true,
                    security_events: true,
                },
                performance_settings: PerformanceSettings {
                    max_concurrent_operations: 2000,
                    cache_sizes: CacheSettings {
                        zk_proof_cache: 2000,
                        block_cache: 1000,
                        transaction_cache: 5000,
                        peer_cache: 500,
                    },
                    thread_pool_sizes: ThreadPoolSettings {
                        crypto_threads: 8,
                        zk_verification_threads: 8,
                        network_threads: 16,
                        storage_threads: 8,
                    },
                    memory_limits: MemorySettings {
                        max_heap_mb: 4096,
                        max_cache_mb: 1024,
                        gc_threshold_mb: 2048,
                    },
                },
            },
        }
    }
    
    /// Validate environment-specific requirements
    pub fn validate_requirements(&self) -> Result<()> {
        match self {
            Environment::Development => {
                // Minimal requirements for development
                Ok(())
            }
            Environment::Testnet => {
                // Validate testnet requirements
                if std::env::var("ZHTP_TESTNET_KEY").is_err() {
                    tracing::warn!("ZHTP_TESTNET_KEY environment variable not set");
                }
                Ok(())
            }
            Environment::Mainnet => {
                // Validate production requirements
                if std::env::var("ZHTP_MAINNET_KEY").is_err() {
                    return Err(anyhow::anyhow!("ZHTP_MAINNET_KEY environment variable required for mainnet"));
                }
                
                // Check for sufficient resources
                let available_memory = get_available_memory_mb();
                if available_memory < 2048 {
                    tracing::warn!("Insufficient memory for mainnet operation: {}MB available", available_memory);
                }
                
                Ok(())
            }
        }
    }
}

/// Load environment-specific configuration
pub async fn load_environment_config(environment: Environment) -> Result<EnvironmentConfig> {
    tracing::info!("Loading configuration for {} environment", environment);
    
    // Validate environment requirements
    environment.validate_requirements()?;
    
    // Get default config for environment
    let mut config = environment.get_default_config();
    
    // Load environment-specific overrides if available
    if let Ok(env_override) = std::env::var("ZHTP_CONFIG_OVERRIDE") {
        tracing::info!("Loading environment config override from: {}", env_override);
        
        if let Ok(override_content) = tokio::fs::read_to_string(&env_override).await {
            if let Ok(override_config) = toml::from_str::<EnvironmentConfig>(&override_content) {
                config = override_config;
                tracing::info!("Applied environment configuration override");
            }
        }
    }
    
    Ok(config)
}

/// Get available system memory in MB
fn get_available_memory_mb() -> usize {
    // Simple implementation - in production would use proper system info
    // Command would be used for system memory detection in production
    
    #[cfg(windows)]
    {
        // Windows implementation would go here
        4096 // Default assumption
    }
    
    #[cfg(unix)]
    {
        // Unix implementation would go here
        4096 // Default assumption
    }
    
    #[cfg(not(any(windows, unix)))]
    {
        2048 // Conservative default
    }
}

impl Environment {
    // NOTE: GenesisConfig is handled internally by lib_blockchain
    // The to_genesis_config() method has been removed as it's not needed
}
