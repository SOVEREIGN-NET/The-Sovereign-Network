//! Unit Tests for Configuration Module
//! 
//! Tests configuration loading, validation, and aggregation

use anyhow::Result;
use tempfile::TempDir;

use zhtp::config::{
    CliArgs, Environment, MeshMode, SecurityLevel,
    load_configuration, NodeConfig,
};

#[tokio::test]
async fn test_default_configuration() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join("config");
    
    let args = CliArgs {
        mesh_port: 8001, // Unique port for default config test
        pure_mesh: false,
        config: config_path,
        environment: Environment::Development,
        log_level: "info".to_string(),
        data_dir: temp_dir.path().join("data"),
    };
    
    let config = load_configuration(&args).await?;
    
    // Verify basic configuration structure
    assert!(!config.node_id.is_empty());
    assert!(matches!(config.mesh_mode, MeshMode::Hybrid | MeshMode::PureMesh));
    assert!(matches!(config.security_level, SecurityLevel::Basic | SecurityLevel::Medium | SecurityLevel::High | SecurityLevel::Maximum));
    assert!(matches!(config.environment, Environment::Development | Environment::Testnet | Environment::Mainnet));
    
    Ok(())
}

#[tokio::test]
async fn test_cli_argument_overrides() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    let args = CliArgs {
        mesh_port: 9999,
        pure_mesh: true,
        config: temp_dir.path().join("config"),
        environment: Environment::Testnet,
        log_level: "debug".to_string(),
        data_dir: temp_dir.path().join("custom_data"),
    };
    
    let config = load_configuration(&args).await?;
    
    // Verify CLI overrides are applied
    assert_eq!(config.environment, Environment::Testnet);
    assert_eq!(config.mesh_mode, MeshMode::PureMesh);
    
    Ok(())
}

#[tokio::test]
async fn test_environment_specific_config() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    // Test development environment
    let dev_args = CliArgs {
        mesh_port: 8002, // Unique port for environment test
        pure_mesh: false,
        config: temp_dir.path().join("config"),
        environment: Environment::Development,
        log_level: "debug".to_string(),
        data_dir: temp_dir.path().join("data"),
    };
    
    let dev_config = load_configuration(&dev_args).await?;
    assert_eq!(dev_config.environment, Environment::Development);
    
    // Test testnet environment
    let testnet_args = CliArgs {
        mesh_port: 8003,
        pure_mesh: false,
        config: temp_dir.path().join("config"),
        environment: Environment::Testnet,
        log_level: "info".to_string(),
        data_dir: temp_dir.path().join("data"),
    };
    
    let testnet_config = load_configuration(&testnet_args).await?;
    assert_eq!(testnet_config.environment, Environment::Testnet);
    
    Ok(())
}

#[tokio::test]
async fn test_mesh_mode_configuration() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    // Test hybrid mode
    let hybrid_args = CliArgs {
        mesh_port: 8004, // Unique port for mesh mode test
        pure_mesh: false,
        config: temp_dir.path().join("config"),
        environment: Environment::Development,
        log_level: "info".to_string(),
        data_dir: temp_dir.path().join("data"),
    };
    
    let hybrid_config = load_configuration(&hybrid_args).await?;
    assert_eq!(hybrid_config.mesh_mode, MeshMode::Hybrid);
    
    // Test pure mesh mode
    let pure_args = CliArgs {
        mesh_port: 8005,
        pure_mesh: true,
        config: temp_dir.path().join("config"),
        environment: Environment::Development,
        log_level: "info".to_string(),
        data_dir: temp_dir.path().join("data"),
    };
    
    let pure_config = load_configuration(&pure_args).await?;
    assert_eq!(pure_config.mesh_mode, MeshMode::PureMesh);
    
    Ok(())
}

#[tokio::test]
async fn test_security_level_configuration() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    let args = CliArgs {
        mesh_port: 8006, // Unique port for security level test
        pure_mesh: false,
        config: temp_dir.path().join("config"),
        environment: Environment::Development,
        log_level: "info".to_string(),
        data_dir: temp_dir.path().join("data"),
    };
    
    let config = load_configuration(&args).await?;
    
    // Verify security level is set appropriately
    assert!(matches!(config.security_level, SecurityLevel::Basic | SecurityLevel::Medium | SecurityLevel::High | SecurityLevel::Maximum));
    
    Ok(())
}

#[tokio::test]
async fn test_data_directory_configuration() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let custom_data_dir = temp_dir.path().join("custom_data_location");
    
    let args = CliArgs {
        mesh_port: 8007, // Unique port for data directory test
        pure_mesh: false,
        config: temp_dir.path().join("config"),
        environment: Environment::Development,
        log_level: "info".to_string(),
        data_dir: custom_data_dir.clone(),
    };
    
    let config = load_configuration(&args).await?;
    
    // Verify data directory is set correctly
    assert_eq!(config.data_directory, custom_data_dir.to_string_lossy().to_string());
    
    Ok(())
}

#[tokio::test]
async fn test_port_configuration() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    let custom_port = 9876;
    let args = CliArgs {
        mesh_port: custom_port,
        pure_mesh: false,
        config: temp_dir.path().join("config"),
        environment: Environment::Development,
        log_level: "info".to_string(),
        data_dir: temp_dir.path().join("data"),
    };
    
    let config = load_configuration(&args).await?;
    
    // Verify port configuration
    assert_eq!(config.network_config.mesh_port, custom_port);
    
    Ok(())
}

#[tokio::test]
async fn test_configuration_validation() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    // Test with valid configuration
    let valid_args = CliArgs {
        mesh_port: 8008, // Unique port for validation test
        pure_mesh: false,
        config: temp_dir.path().join("config"),
        environment: Environment::Development,
        log_level: "info".to_string(),
        data_dir: temp_dir.path().join("data"),
    };
    
    let config = load_configuration(&valid_args).await?;
    
    // Basic validation checks
    assert!(!config.node_id.is_empty());
    assert!(config.network_config.mesh_port > 0);
    // Note: mesh_port is u16, so it's always <= 65535
    
    Ok(())
}

#[tokio::test]
async fn test_multiple_configuration_loads() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    // Load configuration multiple times to test consistency
    let args = CliArgs {
        mesh_port: 8009, // Unique port for multiple loads test
        pure_mesh: false,
        config: temp_dir.path().join("config"),
        environment: Environment::Development,
        log_level: "info".to_string(),
        data_dir: temp_dir.path().join("data"),
    };
    
    let config1 = load_configuration(&args).await?;
    let config2 = load_configuration(&args).await?;
    
    // Node IDs may be different (randomly generated), but other settings should match
    assert_eq!(config1.environment, config2.environment);
    assert_eq!(config1.mesh_mode, config2.mesh_mode);
    assert_eq!(config1.security_level, config2.security_level);
    assert_eq!(config1.network_config.mesh_port, config2.network_config.mesh_port);
    
    Ok(())
}

#[tokio::test]
async fn test_configuration_with_different_log_levels() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    let log_levels = vec!["trace", "debug", "info", "warn", "error"];
    
    for level in log_levels {
        let args = CliArgs {
            mesh_port: 8010, // Unique port for log levels test
            pure_mesh: false,
            config: temp_dir.path().join("config"),
            environment: Environment::Development,
            log_level: level.to_string(),
            data_dir: temp_dir.path().join("data"),
        };
        
        let config = load_configuration(&args).await?;
        
        // Configuration should load successfully with any valid log level
        assert!(!config.node_id.is_empty());
    }
    
    Ok(())
}
