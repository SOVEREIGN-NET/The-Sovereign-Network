//! CLI Module Tests
//! 
//! Tests command-line interface and interactive shell

use anyhow::Result;
use std::path::PathBuf;

use zhtp::cli::{
    parse_arguments, display_startup_banner, start_interactive_shell, InteractiveShell
};
use zhtp::config::{CliArgs, Environment};

#[tokio::test]
async fn test_banner_display() -> Result<()> {
    // Test banner display doesn't panic
    display_startup_banner();
    
    // Banner display is a side effect function, so we just verify it runs
    Ok(())
}

#[tokio::test]
async fn test_interactive_shell_creation() -> Result<()> {
    let shell = start_interactive_shell().await?;
    
    // Test shell was created successfully
    // The shell exists and we can interact with it
    drop(shell);
    
    Ok(())
}

#[tokio::test]
async fn test_interactive_shell_direct() -> Result<()> {
    let shell = InteractiveShell::new().await?;
    
    // Test basic shell functionality
    // Since we can't easily test interactive input, 
    // we just verify the shell can be created
    drop(shell);
    
    Ok(())
}

#[tokio::test]
async fn test_cli_args_structure() -> Result<()> {
    // Test CliArgs creation
    let args = CliArgs {
        mesh_port: 33444,
        pure_mesh: true,
        config: PathBuf::from("test.toml"),
        environment: Environment::Development,
        log_level: "debug".to_string(),
        data_dir: PathBuf::from("/tmp/lib-test"),
    };
    
    // Verify the structure is valid
    assert_eq!(args.mesh_port, 33444);
    assert!(args.pure_mesh);
    assert_eq!(args.config, PathBuf::from("test.toml"));
    assert!(matches!(args.environment, Environment::Development));
    assert_eq!(args.log_level, "debug");
    assert_eq!(args.data_dir, PathBuf::from("/tmp/lib-test"));
    
    Ok(())
}

#[tokio::test]
async fn test_environment_types() -> Result<()> {
    // Test Environment enum variants
    let _dev = Environment::Development;
    let _testnet = Environment::Testnet;
    let _mainnet = Environment::Mainnet;
    
    // All environment types should be constructible
    Ok(())
}

#[tokio::test]
async fn test_cli_module_integration() -> Result<()> {
    // Test that all CLI module components work together
    display_startup_banner();
    
    let _shell = start_interactive_shell().await?;
    
    // Test CLI args with various configurations
    let args_dev = CliArgs {
        mesh_port: 8080,
        pure_mesh: false,
        config: PathBuf::from("dev.toml"),
        environment: Environment::Development,
        log_level: "debug".to_string(),
        data_dir: PathBuf::from("/tmp/dev"),
    };
    
    let args_prod = CliArgs {
        mesh_port: 443,
        pure_mesh: true,
        config: PathBuf::from("prod.toml"),
        environment: Environment::Mainnet,
        log_level: "info".to_string(),
        data_dir: PathBuf::from("/var/lib/zhtp"),
    };
    
    // Verify different configurations are valid
    assert_eq!(args_dev.mesh_port, 8080);
    assert_eq!(args_prod.mesh_port, 443);
    assert!(!args_dev.pure_mesh);
    assert!(args_prod.pure_mesh);
    
    Ok(())
}
