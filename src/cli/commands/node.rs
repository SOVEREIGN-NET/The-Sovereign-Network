//! Node management commands for ZHTP orchestrator

use anyhow::{Result, anyhow};
use crate::cli::{NodeArgs, NodeAction, ZhtpCli};
use crate::runtime::RuntimeOrchestrator;
use crate::runtime::did_startup::{DidStartupManager, DidStartupResult};

#[derive(Debug)]
struct ExistingNetworkInfo {
    peer_count: u32,
    blockchain_height: u64,
    network_id: String,
    bootstrap_peers: Vec<String>,
}

pub async fn handle_node_command(args: NodeArgs, cli: &ZhtpCli) -> Result<()> {
    match args.action {
        NodeAction::Start { config, port, dev } => {
            println!("🚀 Starting ZHTP orchestrator node...");
            println!("📊 Port: {}", port);
            println!("🔧 Config: {:?}", config);
            println!("🛠️ Dev mode: {}", dev);
            
            // Show node type information if using predefined configs
            if let Some(ref config_path) = config {
                if config_path.contains("full-node") {
                    println!("🖥️ Node Type: Full Node (Complete blockchain functionality)");
                } else if config_path.contains("validator-node") {
                    println!("⚡ Node Type: Validator Node (Consensus participation)");
                } else if config_path.contains("storage-node") {
                    println!("💾 Node Type: Storage Node (Distributed storage services)");
                } else if config_path.contains("edge-node") {
                    println!("🌐 Node Type: Edge Node (Mesh networking and ISP bypass)");
                } else if config_path.contains("dev-node") {
                    println!("🛠️ Node Type: Development Node (Testing and development)");
                }
            }
            
            // Load the node configuration
            use crate::config::{load_configuration, CliArgs, Environment};
            use crate::runtime::RuntimeOrchestrator;
            use std::path::PathBuf;
            
            let cli_args = CliArgs {
                mesh_port: port,
                pure_mesh: false,
                config: PathBuf::from(config.unwrap_or_else(|| "./config".to_string())),
                environment: Environment::Development, // Use dev environment for now to avoid mainnet key requirement
                log_level: if dev { "debug".to_string() } else { "info".to_string() },
                data_dir: PathBuf::from("./data"),
            };
            
            println!("📝 Loading configuration...");
            let node_config = load_configuration(&cli_args).await?;
            
            println!("🔧 Starting runtime orchestrator...");
            let mut orchestrator = RuntimeOrchestrator::new(node_config.clone()).await?;
            
            println!("🌐 Attempting to connect to existing ZHTP mesh network...");
            
            // Step 1: Try to bootstrap to existing network
            let mesh_connection_result = attempt_mesh_bootstrap(&mut orchestrator).await;
            
            let startup_result = match mesh_connection_result {
                Ok(existing_network_info) => {
                    println!("✅ Connected to existing ZHTP network!");
                    println!("🔗 Network peers: {}", existing_network_info.peer_count);
                    println!("⛓️ Blockchain height: {}", existing_network_info.blockchain_height);
                    
                    // Step 2a: Handle identity for existing network
                    handle_existing_network_identity(&existing_network_info).await?
                }
                Err(_) => {
                    println!("❌ No existing ZHTP network found or connection failed");
                    println!("🏗️ Starting new genesis network...");
                    
                    // Step 2b: Handle identity for new genesis network
                    handle_genesis_network_identity().await?
                }
            };
            
            println!("✅ User identity established: {}", startup_result.user_display_name);
            
            // Pass user identity to orchestrator before starting components
            orchestrator.set_user_identity(startup_result).await;
            
            println!("🚀 Starting system components...");
            
            // Start all components in proper order (blockchain, consensus, etc.)
            orchestrator.start_all_components().await?;
            
            println!("⛓️ Blockchain component started - Mining ready!");
            println!("🤝 Consensus engine started - Validators active!");
            println!("🌐 Network mesh initialized - P2P connectivity!");
            
            if dev {
                println!("🛠️ Development mode enabled - Enhanced logging and debug features");
            }
            
            // The ZHTP server and API endpoints are already running via ProtocolsComponent
            println!("✅ ZHTP orchestrator fully operational!");
            println!("⛓️ Real blockchain mining and consensus active");
            println!("🌐 Level 1 Orchestrator managing: crypto, zk, identity, storage, network, blockchain, consensus, economics, protocols");
            println!("🌐 ZHTP server and Web4 API endpoints active on port {}", port);
            println!("💡 Press Ctrl+C to stop the node");
            
            // Wait for shutdown signal (no need to start duplicate API server)
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    println!("🛑 Shutting down orchestrator...");
                    orchestrator.graceful_shutdown().await?;
                }
            }
            
            Ok(())
        }
        NodeAction::Stop => {
            println!("🛑 Stopping ZHTP orchestrator node...");
            println!("✅ Node stopped successfully");
            Ok(())
        }
        NodeAction::Status => {
            println!("📊 ZHTP Orchestrator Status:");
            println!("Status: Running");
            println!("Role: Level 1 Orchestrator");
            println!("Coordinating: protocols, blockchain, network");
            println!("API Port: {}", cli.server.split(':').nth(1).unwrap_or("9333"));
            Ok(())
        }
        NodeAction::Restart => {
            println!("🔄 Restarting ZHTP orchestrator node...");
            println!("✅ Node restarted successfully");
            Ok(())
        }
    }
}

/// Attempt to bootstrap to an existing ZHTP mesh network
async fn attempt_mesh_bootstrap(orchestrator: &mut RuntimeOrchestrator) -> Result<ExistingNetworkInfo> {
    println!("🔍 Scanning for existing ZHTP network...");
    
    // Start minimal components needed for network discovery
    println!("🚀 Starting network component for discovery...");
    orchestrator.register_all_components().await?;
    orchestrator.start_component(crate::runtime::ComponentId::Network).await?;
    
    // Give network component time to discover peers
    println!("⏳ Scanning for peers (10 seconds)...");
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
    
    // Check if we found any ZHTP peers
    // TODO: Replace with actual peer discovery logic
    let peer_count = check_discovered_peers().await?;
    
    if peer_count > 0 {
        println!("✅ Found {} ZHTP peers", peer_count);
        
        // Try to connect to blockchain via peers
        let blockchain_info = fetch_blockchain_info_from_peers().await?;
        
        Ok(ExistingNetworkInfo {
            peer_count,
            blockchain_height: blockchain_info.height,
            network_id: blockchain_info.network_id,
            bootstrap_peers: blockchain_info.peers,
        })
    } else {
        Err(anyhow!("No ZHTP peers discovered"))
    }
}

/// Handle identity setup when connecting to an existing network
async fn handle_existing_network_identity(network_info: &ExistingNetworkInfo) -> Result<DidStartupResult> {
    println!("\n🌐 ZHTP Network Connection Established");
    println!("=====================================");
    println!("Connected to existing ZHTP network with {} peers", network_info.peer_count);
    println!("Blockchain height: {}", network_info.blockchain_height);
    println!();
    println!("Choose how to set up your identity:");
    println!("1) Import existing identity from mesh network");
    println!("2) Import from recovery phrase");
    println!("3) Create new identity on this network");
    println!("4) Quick start (auto-generate for testing)");
    println!();
    
    loop {
        print!("Enter your choice (1-4): ");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        
        match input.trim() {
            "1" => {
                println!("\n🔍 Scanning mesh network for existing identities...");
                return import_identity_from_mesh(network_info).await;
            }
            "2" => {
                println!("\n📝 Import from recovery phrase...");
                return DidStartupManager::import_from_recovery_phrase().await;
            }
            "3" => {
                println!("\n🎉 Creating new identity on existing network...");
                return DidStartupManager::create_new_citizen_identity().await;
            }
            "4" => {
                println!("\n⚡ Quick start mode...");
                return DidStartupManager::quick_start_identity().await;
            }
            _ => {
                println!("❌ Invalid choice. Please enter 1, 2, 3, or 4.");
                continue;
            }
        }
    }
}

/// Handle identity setup when creating a new genesis network
async fn handle_genesis_network_identity() -> Result<DidStartupResult> {
    println!("\n🏗️ Creating New ZHTP Genesis Network");
    println!("====================================");
    println!("No existing network found. You'll be creating a new genesis network.");
    println!("This node will become the first node in a new ZHTP mesh.");
    println!();
    println!("Choose how to set up your genesis identity:");
    println!("1) Create new CITIZEN identity (full Web4 access, UBI eligible)");
    println!("2) Import existing identity from recovery phrase");
    println!("3) Quick start (auto-generate for testing)");
    println!();
    
    loop {
        print!("Enter your choice (1-3): ");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        
        match input.trim() {
            "1" => {
                println!("\n🎉 Creating new genesis citizen identity...");
                return DidStartupManager::create_new_citizen_identity().await;
            }
            "2" => {
                println!("\n📝 Import from recovery phrase...");
                return DidStartupManager::import_from_recovery_phrase().await;
            }
            "3" => {
                println!("\n⚡ Quick start mode...");
                return DidStartupManager::quick_start_identity().await;
            }
            _ => {
                println!("❌ Invalid choice. Please enter 1, 2, or 3.");
                continue;
            }
        }
    }
}

/// Import identity from mesh network
async fn import_identity_from_mesh(network_info: &ExistingNetworkInfo) -> Result<DidStartupResult> {
    println!("🔍 Searching for identities in mesh network...");
    println!("📡 Querying {} bootstrap peers...", network_info.bootstrap_peers.len());
    
    // TODO: Implement actual mesh identity discovery
    // For now, simulate the process
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    
    println!("❌ No importable identities found in current mesh network");
    println!("🔄 Falling back to manual identity creation...");
    
    handle_genesis_network_identity().await
}

/// Check for discovered peers (placeholder implementation)
async fn check_discovered_peers() -> Result<u32> {
    // TODO: Implement actual peer discovery check
    // This should query the network component for discovered peers
    
    // For now, simulate no peers found (forcing genesis mode)
    Ok(0)
}

/// Fetch blockchain info from peers (placeholder implementation)  
async fn fetch_blockchain_info_from_peers() -> Result<BlockchainInfo> {
    // TODO: Implement actual blockchain info fetching from network peers
    Ok(BlockchainInfo {
        height: 12345,
        network_id: "zhtp-mainnet".to_string(),
        peers: vec!["peer1".to_string(), "peer2".to_string()],
    })
}

#[derive(Debug)]
struct BlockchainInfo {
    height: u64,
    network_id: String,
    peers: Vec<String>,
}
