//! Multi-Package Configuration Management
//! 
//! Aggregates and validates configurations from all 11 ZHTP packages

pub mod aggregation;
pub mod validation;
pub mod environment;
pub mod mesh_modes;
pub mod security;
pub mod network_isolation;

use anyhow::Result;

use std::path::{Path, PathBuf};

// Re-export configuration types
pub use aggregation::NodeConfig;
pub use mesh_modes::MeshMode;
pub use security::SecurityLevel;
pub use environment::Environment;
pub use network_isolation::NetworkIsolationConfig;

/// Configuration for identity seed storage.
#[derive(Debug, Clone)]
pub struct SeedStorageConfig {
    pub storage_dir: PathBuf,
    pub file_name: String,
}

impl SeedStorageConfig {
    pub fn default_for_keystore(keystore_path: &Path) -> Self {
        Self {
            storage_dir: keystore_path.to_path_buf(),
            file_name: "seed_storage.json".to_string(),
        }
    }

    pub fn storage_path(&self) -> PathBuf {
        self.storage_dir.join(&self.file_name)
    }
}

impl Default for SeedStorageConfig {
    fn default() -> Self {
        let storage_dir = if let Some(home) = dirs::home_dir() {
            home.join(".zhtp").join("keystore")
        } else {
            let fallback = std::env::temp_dir().join("zhtp").join("keystore");
            tracing::warn!(
                "Home directory could not be determined; using temporary directory for seed storage: {}",
                fallback.display()
            );
            fallback
        };

        Self {
            storage_dir,
            file_name: "seed_storage.json".to_string(),
        }
    }
}

/// Command line arguments structure
#[derive(Debug, Clone)]
pub struct CliArgs {
    pub mesh_port: Option<u16>,  // Optional: only override if specified
    pub pure_mesh: bool,
    pub config: PathBuf,
    pub environment: Environment,
    pub log_level: String,
    pub data_dir: PathBuf,
}

/// Load and validate complete node configuration
pub async fn load_configuration(args: &CliArgs) -> Result<NodeConfig> {
    tracing::info!("Loading configuration from {} packages...", 11);
    
    // Load environment-specific settings
    let env_config = environment::load_environment_config(args.environment).await?;
    
    // Aggregate configurations from all packages
    let mut node_config = aggregation::aggregate_all_package_configs(&args.config).await?;
    
    // Apply CLI argument overrides
    node_config.apply_cli_overrides(args)?;
    
    // Create data directory if it doesn't exist
    if !args.data_dir.exists() {
        std::fs::create_dir_all(&args.data_dir)?;
        tracing::info!("Created data directory: {}", args.data_dir.display());
    }
    
    // Apply environment-specific settings
    node_config.apply_environment_config(env_config)?;
    
    // Validate cross-package configuration consistency
    validation::validate_complete_configuration(&node_config).await?;
    
    tracing::info!("Configuration validated: {} mode, {} security level", 
                  node_config.mesh_mode, node_config.security_level);
    
    Ok(node_config)
}

/// Configuration validation error
#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("Package configuration missing: {package}")]
    PackageMissing { package: String },
    
    #[error("Port conflict detected: {port} used by multiple packages")]
    PortConflict { port: u16 },
    
    #[error("Invalid mesh mode configuration: {reason}")]
    InvalidMeshMode { reason: String },
    
    #[error("Security level mismatch between packages")]
    SecurityMismatch,
    
    #[error("Resource requirements conflict: {details}")]
    ResourceConflict { details: String },
    
    #[error("File system error: {0}")]
    FileSystem(#[from] std::io::Error),
    
    #[error("Configuration parsing error: {0}")]
    Parsing(#[from] toml::de::Error),
}
