//! Command Line Argument Parsing
//! 
//! Uses clap to parse ZHTP node command line arguments

use anyhow::Result;
use clap::{Arg, Command};
use std::path::PathBuf;
use super::super::config::{CliArgs, Environment};

/// Command mode - either node management or operations
#[derive(Debug, Clone)]
pub enum ZhtpCommand {
    /// Node management (start the node)
    Node(CliArgs),
    /// Wallet operations
    Wallet(WalletCommand),
    /// DAO operations  
    Dao(DaoCommand),
    /// Identity operations
    Identity(IdentityCommand),
    /// Zero-knowledge proof operations
    Zk(ZkCommand),
    /// Blockchain operations
    Blockchain(BlockchainCommand),
    /// Network operations
    Network(NetworkCommand),
}

#[derive(Debug, Clone)]
pub enum WalletCommand {
    Create { name: String, wallet_type: String },
    Balance { address: String },
    Transfer { to: String, amount: u64, fee: Option<u64> },
    History { address: String },
    Import { file: String, password: String },
    Sign { address: String, data: String },
}

#[derive(Debug, Clone)]
pub enum DaoCommand {
    Info,
    Propose { title: String, description: String },
    Vote { proposal_id: u64, choice: bool },
    Treasury,
    ClaimUbi,
}

#[derive(Debug, Clone)]
pub enum IdentityCommand {
    Create { name: String },
    List,
    Info { id: String },
    Export { id: String },
    Verify { proof: String },
    CreateZkDid { name: String },
}

#[derive(Debug, Clone)]
pub enum ZkCommand {
    Generate { circuit_type: String, input: String },
    Verify { proof: String },
    Commit { data: String },
}

#[derive(Debug, Clone)]
pub enum BlockchainCommand {
    Block { hash: Option<String> },
    Transaction { hash: String },
    Mempool,
    Stats,
}

#[derive(Debug, Clone)]
pub enum NetworkCommand {
    Peers,
    Mesh,
    IspBypass,
    Test,
}

/// Parse command line arguments using clap
pub async fn parse_cli_arguments() -> Result<ZhtpCommand> {
    let matches = Command::new("zhtp")
        .version(env!("CARGO_PKG_VERSION"))
        .about("ZHTP Network Node - Complete Internet Replacement System")
        .long_about(r#"
ZHTP (Zero Knowledge Hypertext Transfer Protocol) Network Node

This can be used in two modes:
1. Node Management: Start/manage the ZHTP node infrastructure
2. Operations: Interact with running ZHTP network (wallet, DAO, identity, etc.)

Examples:
  zhtp --interactive                    # Start node in interactive mode
  zhtp wallet create --name "mywallet"  # Create a new wallet
  zhtp dao info                         # Show DAO information
  zhtp identity create --name "alice"   # Create new identity
"#)
        .subcommand_required(false)
        .subcommand(Command::new("wallet")
            .about("Wallet operations")
            .subcommand_required(true)
            .subcommand(Command::new("create")
                .about("Create a new wallet")
                .arg(Arg::new("name")
                    .long("name")
                    .value_name("NAME")
                    .help("Name for the wallet")
                    .required(true))
                .arg(Arg::new("type")
                    .long("type")
                    .value_name("TYPE")
                    .help("Wallet type (zhtp, metamask, phantom)")
                    .default_value("zhtp")))
            .subcommand(Command::new("balance")
                .about("Check wallet balance")
                .arg(Arg::new("address")
                    .long("address")
                    .value_name("ADDRESS")
                    .help("Wallet address")
                    .required(true)))
            .subcommand(Command::new("transfer")
                .about("Transfer tokens")
                .arg(Arg::new("to")
                    .long("to")
                    .value_name("ADDRESS")
                    .help("Recipient address")
                    .required(true))
                .arg(Arg::new("amount")
                    .long("amount")
                    .value_name("AMOUNT")
                    .help("Amount to transfer")
                    .value_parser(clap::value_parser!(u64))
                    .required(true))
                .arg(Arg::new("fee")
                    .long("fee")
                    .value_name("FEE")
                    .help("Transaction fee")
                    .value_parser(clap::value_parser!(u64))))
            .subcommand(Command::new("history")
                .about("Show transaction history")
                .arg(Arg::new("address")
                    .long("address")
                    .value_name("ADDRESS")
                    .help("Wallet address")
                    .required(true)))
            .subcommand(Command::new("import")
                .about("Import wallet from file")
                .arg(Arg::new("file")
                    .long("file")
                    .value_name("FILE")
                    .help("Wallet file path")
                    .required(true))
                .arg(Arg::new("password")
                    .long("password")
                    .value_name("PASSWORD")
                    .help("Wallet password")
                    .required(true)))
            .subcommand(Command::new("sign")
                .about("Sign data with wallet")
                .arg(Arg::new("address")
                    .long("address")
                    .value_name("ADDRESS")
                    .help("Wallet address")
                    .required(true))
                .arg(Arg::new("data")
                    .long("data")
                    .value_name("DATA")
                    .help("Data to sign")
                    .required(true))))
        
        .subcommand(Command::new("dao")
            .about("DAO governance operations")
            .subcommand_required(true)
            .subcommand(Command::new("info")
                .about("Show DAO information"))
            .subcommand(Command::new("propose")
                .about("Create a new proposal")
                .arg(Arg::new("title")
                    .long("title")
                    .value_name("TITLE")
                    .help("Proposal title")
                    .required(true))
                .arg(Arg::new("description")
                    .long("description")
                    .value_name("DESCRIPTION")
                    .help("Proposal description")
                    .required(true)))
            .subcommand(Command::new("vote")
                .about("Vote on a proposal")
                .arg(Arg::new("proposal-id")
                    .long("proposal-id")
                    .value_name("ID")
                    .help("Proposal ID")
                    .value_parser(clap::value_parser!(u64))
                    .required(true))
                .arg(Arg::new("choice")
                    .long("choice")
                    .value_name("CHOICE")
                    .help("Vote choice (yes/no)")
                    .value_parser(["yes", "no"])
                    .required(true)))
            .subcommand(Command::new("treasury")
                .about("Show DAO treasury status"))
            .subcommand(Command::new("claim-ubi")
                .about("Claim UBI payment")))
        
        .subcommand(Command::new("identity")
            .about("Identity management operations")
            .subcommand_required(true)
            .subcommand(Command::new("create")
                .about("Create a new identity")
                .arg(Arg::new("name")
                    .long("name")
                    .value_name("NAME")
                    .help("Identity name")
                    .required(true)))
            .subcommand(Command::new("list")
                .about("List all identities"))
            .subcommand(Command::new("info")
                .about("Show identity information")
                .arg(Arg::new("id")
                    .long("id")
                    .value_name("ID")
                    .help("Identity ID")
                    .required(true)))
            .subcommand(Command::new("export")
                .about("Export identity")
                .arg(Arg::new("id")
                    .long("id")
                    .value_name("ID")
                    .help("Identity ID")
                    .required(true)))
            .subcommand(Command::new("verify")
                .about("Verify identity proof")
                .arg(Arg::new("proof")
                    .long("proof")
                    .value_name("PROOF")
                    .help("Identity proof")
                    .required(true)))
            .subcommand(Command::new("create-zk-did")
                .about("Create zero-knowledge DID")
                .arg(Arg::new("name")
                    .long("name")
                    .value_name("NAME")
                    .help("DID name")
                    .required(true))))
        
        .subcommand(Command::new("zk")
            .about("Zero-knowledge proof operations")
            .subcommand_required(true)
            .subcommand(Command::new("generate")
                .about("Generate ZK proof")
                .arg(Arg::new("circuit-type")
                    .long("circuit-type")
                    .value_name("TYPE")
                    .help("Circuit type (identity, transaction, vote)")
                    .required(true))
                .arg(Arg::new("input")
                    .long("input")
                    .value_name("INPUT")
                    .help("Input data")
                    .required(true)))
            .subcommand(Command::new("verify")
                .about("Verify ZK proof")
                .arg(Arg::new("proof")
                    .long("proof")
                    .value_name("PROOF")
                    .help("Proof to verify")
                    .required(true)))
            .subcommand(Command::new("commit")
                .about("Create ZK commitment")
                .arg(Arg::new("data")
                    .long("data")
                    .value_name("DATA")
                    .help("Data to commit")
                    .required(true))))
        
        .subcommand(Command::new("blockchain")
            .about("Blockchain operations")
            .subcommand_required(true)
            .subcommand(Command::new("block")
                .about("Show block information")
                .arg(Arg::new("hash")
                    .long("hash")
                    .value_name("HASH")
                    .help("Block hash (latest if not specified)")))
            .subcommand(Command::new("transaction")
                .about("Show transaction information")
                .arg(Arg::new("hash")
                    .long("hash")
                    .value_name("HASH")
                    .help("Transaction hash")
                    .required(true)))
            .subcommand(Command::new("mempool")
                .about("Show mempool status"))
            .subcommand(Command::new("stats")
                .about("Show blockchain statistics")))
        
        .subcommand(Command::new("network")
            .about("Network operations")
            .subcommand_required(true)
            .subcommand(Command::new("peers")
                .about("List network peers"))
            .subcommand(Command::new("mesh")
                .about("Show mesh network status"))
            .subcommand(Command::new("isp-bypass")
                .about("Show  status"))
            .subcommand(Command::new("test")
                .about("Test network connectivity")))
        .arg(Arg::new("mesh-port")
            .long("mesh-port")
            .value_name("PORT")
            .help("Mesh network port for peer-to-peer communication")
            .default_value("33444")
            .value_parser(clap::value_parser!(u16)))
        
        .arg(Arg::new("pure-mesh")
            .long("pure-mesh")
            .help("Run in pure mesh mode (complete )")
            .action(clap::ArgAction::SetTrue))
        
        .arg(Arg::new("node-type")
            .short('t')
            .long("node-type")
            .value_name("TYPE")
            .help("Node type with pre-configured settings")
            .value_parser(["full", "validator", "storage", "edge", "dev"])
            .help_heading("Node Configuration"))
        
        .arg(Arg::new("config")
            .short('c')
            .long("config")
            .value_name("FILE")
            .help("Configuration file path (overrides --node-type)")
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
            .default_value("9333")
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

    // Check if a subcommand was provided
    match matches.subcommand() {
        Some(("wallet", wallet_matches)) => {
            match wallet_matches.subcommand() {
                Some(("create", create_matches)) => {
                    Ok(ZhtpCommand::Wallet(WalletCommand::Create {
                        name: create_matches.get_one::<String>("name").unwrap().clone(),
                        wallet_type: create_matches.get_one::<String>("type").unwrap().clone(),
                    }))
                }
                Some(("balance", balance_matches)) => {
                    Ok(ZhtpCommand::Wallet(WalletCommand::Balance {
                        address: balance_matches.get_one::<String>("address").unwrap().clone(),
                    }))
                }
                Some(("transfer", transfer_matches)) => {
                    Ok(ZhtpCommand::Wallet(WalletCommand::Transfer {
                        to: transfer_matches.get_one::<String>("to").unwrap().clone(),
                        amount: *transfer_matches.get_one::<u64>("amount").unwrap(),
                        fee: transfer_matches.get_one::<u64>("fee").copied(),
                    }))
                }
                Some(("history", history_matches)) => {
                    Ok(ZhtpCommand::Wallet(WalletCommand::History {
                        address: history_matches.get_one::<String>("address").unwrap().clone(),
                    }))
                }
                Some(("import", import_matches)) => {
                    Ok(ZhtpCommand::Wallet(WalletCommand::Import {
                        file: import_matches.get_one::<String>("file").unwrap().clone(),
                        password: import_matches.get_one::<String>("password").unwrap().clone(),
                    }))
                }
                Some(("sign", sign_matches)) => {
                    Ok(ZhtpCommand::Wallet(WalletCommand::Sign {
                        address: sign_matches.get_one::<String>("address").unwrap().clone(),
                        data: sign_matches.get_one::<String>("data").unwrap().clone(),
                    }))
                }
                _ => Err(anyhow::anyhow!("Invalid wallet subcommand")),
            }
        }
        Some(("dao", dao_matches)) => {
            match dao_matches.subcommand() {
                Some(("info", _)) => Ok(ZhtpCommand::Dao(DaoCommand::Info)),
                Some(("propose", propose_matches)) => {
                    Ok(ZhtpCommand::Dao(DaoCommand::Propose {
                        title: propose_matches.get_one::<String>("title").unwrap().clone(),
                        description: propose_matches.get_one::<String>("description").unwrap().clone(),
                    }))
                }
                Some(("vote", vote_matches)) => {
                    let choice = vote_matches.get_one::<String>("choice").unwrap().as_str() == "yes";
                    Ok(ZhtpCommand::Dao(DaoCommand::Vote {
                        proposal_id: *vote_matches.get_one::<u64>("proposal-id").unwrap(),
                        choice,
                    }))
                }
                Some(("treasury", _)) => Ok(ZhtpCommand::Dao(DaoCommand::Treasury)),
                Some(("claim-ubi", _)) => Ok(ZhtpCommand::Dao(DaoCommand::ClaimUbi)),
                _ => Err(anyhow::anyhow!("Invalid DAO subcommand")),
            }
        }
        Some(("identity", identity_matches)) => {
            match identity_matches.subcommand() {
                Some(("create", create_matches)) => {
                    Ok(ZhtpCommand::Identity(IdentityCommand::Create {
                        name: create_matches.get_one::<String>("name").unwrap().clone(),
                    }))
                }
                Some(("list", _)) => Ok(ZhtpCommand::Identity(IdentityCommand::List)),
                Some(("info", info_matches)) => {
                    Ok(ZhtpCommand::Identity(IdentityCommand::Info {
                        id: info_matches.get_one::<String>("id").unwrap().clone(),
                    }))
                }
                Some(("export", export_matches)) => {
                    Ok(ZhtpCommand::Identity(IdentityCommand::Export {
                        id: export_matches.get_one::<String>("id").unwrap().clone(),
                    }))
                }
                Some(("verify", verify_matches)) => {
                    Ok(ZhtpCommand::Identity(IdentityCommand::Verify {
                        proof: verify_matches.get_one::<String>("proof").unwrap().clone(),
                    }))
                }
                Some(("create-zk-did", did_matches)) => {
                    Ok(ZhtpCommand::Identity(IdentityCommand::CreateZkDid {
                        name: did_matches.get_one::<String>("name").unwrap().clone(),
                    }))
                }
                _ => Err(anyhow::anyhow!("Invalid identity subcommand")),
            }
        }
        Some(("zk", zk_matches)) => {
            match zk_matches.subcommand() {
                Some(("generate", generate_matches)) => {
                    Ok(ZhtpCommand::Zk(ZkCommand::Generate {
                        circuit_type: generate_matches.get_one::<String>("circuit-type").unwrap().clone(),
                        input: generate_matches.get_one::<String>("input").unwrap().clone(),
                    }))
                }
                Some(("verify", verify_matches)) => {
                    Ok(ZhtpCommand::Zk(ZkCommand::Verify {
                        proof: verify_matches.get_one::<String>("proof").unwrap().clone(),
                    }))
                }
                Some(("commit", commit_matches)) => {
                    Ok(ZhtpCommand::Zk(ZkCommand::Commit {
                        data: commit_matches.get_one::<String>("data").unwrap().clone(),
                    }))
                }
                _ => Err(anyhow::anyhow!("Invalid ZK subcommand")),
            }
        }
        Some(("blockchain", blockchain_matches)) => {
            match blockchain_matches.subcommand() {
                Some(("block", block_matches)) => {
                    Ok(ZhtpCommand::Blockchain(BlockchainCommand::Block {
                        hash: block_matches.get_one::<String>("hash").cloned(),
                    }))
                }
                Some(("transaction", tx_matches)) => {
                    Ok(ZhtpCommand::Blockchain(BlockchainCommand::Transaction {
                        hash: tx_matches.get_one::<String>("hash").unwrap().clone(),
                    }))
                }
                Some(("mempool", _)) => Ok(ZhtpCommand::Blockchain(BlockchainCommand::Mempool)),
                Some(("stats", _)) => Ok(ZhtpCommand::Blockchain(BlockchainCommand::Stats)),
                _ => Err(anyhow::anyhow!("Invalid blockchain subcommand")),
            }
        }
        Some(("network", network_matches)) => {
            match network_matches.subcommand() {
                Some(("peers", _)) => Ok(ZhtpCommand::Network(NetworkCommand::Peers)),
                Some(("mesh", _)) => Ok(ZhtpCommand::Network(NetworkCommand::Mesh)),
                Some(("isp-bypass", _)) => Ok(ZhtpCommand::Network(NetworkCommand::IspBypass)),
                Some(("test", _)) => Ok(ZhtpCommand::Network(NetworkCommand::Test)),
                _ => Err(anyhow::anyhow!("Invalid network subcommand")),
            }
        }
        None => {
            // No subcommand provided, this is node management mode
            // Parse environment
            let environment = match matches.get_one::<String>("environment").unwrap().as_str() {
                "development" => Environment::Development,
                "testnet" => Environment::Testnet,
                "mainnet" => Environment::Mainnet,
                _ => Environment::Development, // Should not happen due to value_parser
            };

            // Validate environment-specific requirements
            if environment == Environment::Mainnet && matches.get_flag("pure-mesh") {
                tracing::warn!("Pure mesh mode in mainnet - ensure adequate long-range relay coverage");
            }

            // Determine configuration file path
            let config_path = if let Some(config) = matches.get_one::<PathBuf>("config") {
                // Explicit config file provided
                config.clone()
            } else if let Some(node_type) = matches.get_one::<String>("node-type") {
                // Use pre-configured node type
                PathBuf::from(format!("./configs/{}-node.toml", node_type))
            } else {
                // Default config
                PathBuf::from("lib-node.toml")
            };

            // Create CLI args structure
            let args = CliArgs {
                mesh_port: *matches.get_one::<u16>("mesh-port").unwrap(),
                pure_mesh: matches.get_flag("pure-mesh"),
                config: config_path,
                environment,
                log_level: matches.get_one::<String>("log-level").unwrap().clone(),
                data_dir: matches.get_one::<PathBuf>("data-dir").unwrap().clone(),
            };

            // Log parsed arguments
            tracing::debug!("Parsed CLI arguments:");
            tracing::debug!("   Mesh port: {}", args.mesh_port);
            tracing::debug!("   Pure mesh mode: {}", args.pure_mesh);
            tracing::debug!("   Config file: {}", args.config.display());
            tracing::debug!("   Environment: {}", args.environment);
            tracing::debug!("   Log level: {}", args.log_level);
            tracing::debug!("   Data directory: {}", args.data_dir.display());

            Ok(ZhtpCommand::Node(args))
        }
        Some((cmd, _)) => Err(anyhow::anyhow!("Unknown subcommand: {}", cmd)),
    }
}

/// Validate command line arguments for consistency
pub fn validate_cli_arguments(args: &CliArgs) -> Result<()> {
    // Check port ranges
    if args.mesh_port < 1024 {
        tracing::warn!("Using privileged port {} - may require administrator privileges", args.mesh_port);
    }

    // Check data directory
    if !args.data_dir.exists() {
        tracing::info!("📁 Creating data directory: {}", args.data_dir.display());
        std::fs::create_dir_all(&args.data_dir)?;
    }

    // Check config file
    if !args.config.exists() {
        tracing::info!("Configuration file not found, using defaults: {}", args.config.display());
    }

    // Environment-specific validations
    match args.environment {
        Environment::Mainnet => {
            if args.log_level == "debug" || args.log_level == "trace" {
                tracing::warn!("Debug logging enabled in mainnet environment");
            }
        }
        Environment::Development => {
            if args.pure_mesh {
                tracing::info!(" Development + Pure mesh mode - testing ISP replacement");
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
• Complete  - no traditional internet required
• Economic incentives for sharing connectivity
• Global coverage through long-range relays
• Zero-knowledge privacy for all communications
• internet replacement technology

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
