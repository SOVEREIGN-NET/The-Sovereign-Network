//! Command Line Argument Parsing
//! 
//! Uses clap to parse ZHTP node command line arguments

use anyhow::Result;
use clap::{Arg, Command};
use std::path::PathBuf;
use super::super::config::{CliArgs, Environment};

/// Parse command line arguments using clap
pub async fn parse_cli_arguments() -> Result<CliArgs> {
    let matches = Command::new("zhtp")
        .version(env!("CARGO_PKG_VERSION"))
        .about("ZHTP Network Node - Complete Internet Replacement System")
        .long_about(r#"
ZHTP (Zero Knowledge Hypertext Transfer Protocol) Network Node

This is the main orchestrator binary that coordinates all ZHTP packages
into a unified network node capable of:

• Complete ISP replacement through mesh networking
• Zero-knowledge privacy for all communications  
• Universal Basic Income through network participation
• Quantum-resistant cryptographic security
• Decentralized governance through DAO integration
• Revolutionary Web4 protocol stack

Operation Modes:
  --pure-mesh    Complete ISP bypass using only mesh protocols
  [default]      Hybrid mesh networking with TCP/IP fallback
"#)
        .arg(Arg::new("mesh-port")
            .long("mesh-port")
            .value_name("PORT")
            .help("Mesh network port for peer-to-peer communication")
            .default_value("33444")
            .value_parser(clap::value_parser!(u16)))
        
        .arg(Arg::new("pure-mesh")
            .long("pure-mesh")
            .help("Run in pure mesh mode (complete ISP bypass)")
            .action(clap::ArgAction::SetTrue))
        
        .arg(Arg::new("config")
            .short('c')
            .long("config")
            .value_name("FILE")
            .help("Configuration file path")
            .default_value("lib-node.toml")
            .value_parser(clap::value_parser!(PathBuf)))
        
        .arg(Arg::new("environment")
            .short('e')
            .long("environment")
            .value_name("ENV")
            .help("Deployment environment")
            .default_value("development")
            .value_parser(["development", "testnet", "mainnet"]))
        
        .arg(Arg::new("log-level")
            .short('l')
            .long("log-level")
            .value_name("LEVEL")
            .help("Logging level")
            .default_value("info")
            .value_parser(["trace", "debug", "info", "warn", "error"]))
        
        .arg(Arg::new("data-dir")
            .short('d')
            .long("data-dir")
            .value_name("DIR")
            .help("Data directory for node storage")
            .default_value("./lib-data")
            .value_parser(clap::value_parser!(PathBuf)))
        
        .arg(Arg::new("validator")
            .long("validator")
            .help("Enable validator mode for consensus participation")
            .action(clap::ArgAction::SetTrue))
        
        .arg(Arg::new("bootstrap-peers")
            .long("bootstrap-peers")
            .value_name("PEERS")
            .help("Comma-separated list of bootstrap peer addresses")
            .value_delimiter(','))
        
        .arg(Arg::new("max-peers")
            .long("max-peers")
            .value_name("COUNT")
            .help("Maximum number of peer connections")
            .default_value("100")
            .value_parser(clap::value_parser!(usize)))
        
        .arg(Arg::new("security-level")
            .long("security-level")
            .value_name("LEVEL")
            .help("Security level (basic, medium, high, maximum)")
            .default_value("high")
            .value_parser(["basic", "medium", "high", "maximum"]))
        
        .arg(Arg::new("disable-ubi")
            .long("disable-ubi")
            .help("Disable Universal Basic Income features")
            .action(clap::ArgAction::SetTrue))
        
        .arg(Arg::new("disable-dao")
            .long("disable-dao")
            .help("Disable DAO governance features")
            .action(clap::ArgAction::SetTrue))
        
        .arg(Arg::new("api-port")
            .long("api-port")
            .value_name("PORT")
            .help("API server port for Web4 protocols")
            .default_value("8080")
            .value_parser(clap::value_parser!(u16)))
        
        .arg(Arg::new("storage-capacity")
            .long("storage-capacity")
            .value_name("GB")
            .help("Storage capacity to contribute to the network (GB)")
            .default_value("100")
            .value_parser(clap::value_parser!(u64)))
        
        .arg(Arg::new("interactive")
            .short('i')
            .long("interactive")
            .help("Start interactive shell after initialization")
            .action(clap::ArgAction::SetTrue))
        
        .arg(Arg::new("daemon")
            .long("daemon")
            .help("Run as background daemon")
            .action(clap::ArgAction::SetTrue))
        
        .get_matches();

    // Parse environment
    let environment = match matches.get_one::<String>("environment").unwrap().as_str() {
        "development" => Environment::Development,
        "testnet" => Environment::Testnet,
        "mainnet" => Environment::Mainnet,
        _ => Environment::Development, // Should not happen due to value_parser
    };

    // Validate environment-specific requirements
    if environment == Environment::Mainnet && matches.get_flag("pure-mesh") {
        tracing::warn!("⚠️ Pure mesh mode in mainnet - ensure adequate long-range relay coverage");
    }

    // Create CLI args structure
    let args = CliArgs {
        mesh_port: *matches.get_one::<u16>("mesh-port").unwrap(),
        pure_mesh: matches.get_flag("pure-mesh"),
        config: matches.get_one::<PathBuf>("config").unwrap().clone(),
        environment,
        log_level: matches.get_one::<String>("log-level").unwrap().clone(),
        data_dir: matches.get_one::<PathBuf>("data-dir").unwrap().clone(),
    };

    // Log parsed arguments
    tracing::debug!("📋 Parsed CLI arguments:");
    tracing::debug!("   Mesh port: {}", args.mesh_port);
    tracing::debug!("   Pure mesh mode: {}", args.pure_mesh);
    tracing::debug!("   Config file: {}", args.config.display());
    tracing::debug!("   Environment: {}", args.environment);
    tracing::debug!("   Log level: {}", args.log_level);
    tracing::debug!("   Data directory: {}", args.data_dir.display());

    Ok(args)
}

/// Validate command line arguments for consistency
pub fn validate_cli_arguments(args: &CliArgs) -> Result<()> {
    // Check port ranges
    if args.mesh_port < 1024 {
        tracing::warn!("⚠️ Using privileged port {} - may require administrator privileges", args.mesh_port);
    }

    // Check data directory
    if !args.data_dir.exists() {
        tracing::info!("📁 Creating data directory: {}", args.data_dir.display());
        std::fs::create_dir_all(&args.data_dir)?;
    }

    // Check config file
    if !args.config.exists() {
        tracing::info!("📝 Configuration file not found, using defaults: {}", args.config.display());
    }

    // Environment-specific validations
    match args.environment {
        Environment::Mainnet => {
            if args.log_level == "debug" || args.log_level == "trace" {
                tracing::warn!("⚠️ Debug logging enabled in mainnet environment");
            }
        }
        Environment::Development => {
            if args.pure_mesh {
                tracing::info!("🧪 Development + Pure mesh mode - testing ISP replacement");
            }
        }
        _ => {}
    }

    Ok(())
}

/// Display help information for specific features
pub fn display_feature_help(feature: &str) {
    match feature {
        "pure-mesh" => {
            println!(r#"
Pure Mesh Mode - Complete ISP Replacement
========================================

Pure mesh mode enables the ZHTP node to operate completely independently
of traditional internet service providers (ISPs) by using only mesh
networking protocols:

• Bluetooth LE for device-to-device communication
• WiFi Direct for high-bandwidth local networking  
• LoRaWAN for long-range coverage (up to 15km)
• Satellite uplinks for global connectivity

Key Features:
• Complete ISP bypass - no traditional internet required
• Economic incentives for sharing connectivity
• Global coverage through long-range relays
• Zero-knowledge privacy for all communications
• Revolutionary internet replacement technology

Requirements:
• At least one mesh protocol must be available
• Long-range relays recommended for global coverage
• Sufficient peers in local area for connectivity

Usage: zhtp --pure-mesh --mesh-port 33444
"#);
        }
        "ubi" => {
            println!(r#"
Universal Basic Income (UBI) System
===================================

The ZHTP network provides Universal Basic Income to all citizens
through network participation:

• Daily UBI payments (default: 50 ZHTP tokens)
• Automatic citizen registration and onboarding
• Economic incentives for mesh participation
• DAO governance over UBI parameters

How it works:
1. Register as a citizen with ZK-DID identity
2. Participate in mesh networking
3. Receive daily UBI payments automatically
4. Vote on DAO proposals to govern the system

Requirements:
• Valid ZK-DID identity
• Network participation (routing, storage, or validation)
• DAO membership for governance participation

Disable with: zhtp --disable-ubi
"#);
        }
        "security" => {
            println!(r#"
Security Levels and Post-Quantum Cryptography
=============================================

ZHTP provides multiple security levels with post-quantum cryptography:

Basic (Development only):
• Classical cryptography only
• Minimal resource usage
• Not suitable for production

Medium (Testing):
• CRYSTALS-Dilithium Level 2 (128-bit security)
• CRYSTALS-Kyber 512 encryption
• Hybrid classical + post-quantum mode

High (Production default):
• CRYSTALS-Dilithium Level 3 (192-bit security)
• CRYSTALS-Kyber 768 encryption
• Full post-quantum security

Maximum (High-security environments):
• CRYSTALS-Dilithium Level 5 (256-bit security)
• CRYSTALS-Kyber 1024 encryption
• Pure post-quantum mode

Usage: zhtp --security-level maximum
"#);
        }
        _ => {
            println!("Unknown feature: {}", feature);
            println!("Available help topics: pure-mesh, ubi, security");
        }
    }
}
