//! Node management commands for ZHTP orchestrator

use anyhow::{Result, anyhow};
use crate::cli::{NodeArgs, NodeAction, ZhtpCli};
use crate::config::environment::Environment;
use crate::runtime::RuntimeOrchestrator;
use crate::runtime::did_startup::WalletStartupManager;
use std::path::PathBuf;





pub async fn handle_node_command(args: NodeArgs, cli: &ZhtpCli) -> Result<()> {
    match args.action {
        NodeAction::Start { config, port, dev, pure_mesh, network, edge_mode, edge_max_headers, .. } => {
            println!(" Starting ZHTP orchestrator node...");
            if let Some(p) = port {
                println!("Port override: {}", p);
            }
            println!("Config: {:?}", config);
            println!("Dev mode: {}", dev);
            println!("Pure mesh mode: {}", pure_mesh);
            
            if edge_mode {
                println!(" Edge Mode: ENABLED (lightweight sync)");
                println!("   Max headers: {} (~{} KB storage)", 
                    edge_max_headers, 
                    (edge_max_headers * 200) / 1024);
            }
            
            // Parse network override if provided
            let network_override = network.as_ref().and_then(|n| {
                match n.as_str() {
                    "mainnet" => Some(Environment::Mainnet),
                    "testnet" => Some(Environment::Testnet),
                    "dev" => Some(Environment::Development),
                    _ => None,
                }
            });
            
            if let Some(ref net) = network_override {
                println!(" Network Override: {}", net);
            }
            
            // Load the node configuration
            use crate::config::{load_configuration, CliArgs};
            
            let cli_args = CliArgs {
                mesh_port: port,
                pure_mesh,
                config: PathBuf::from(config.unwrap_or_else(|| "./config".to_string())),
                environment: network_override.unwrap_or(Environment::Development), // Use CLI override or default
                log_level: if dev { "debug".to_string() } else { "info".to_string() },
                data_dir: PathBuf::from("./data"),
            };
            
            println!("Loading configuration...");
            let mut node_config = load_configuration(&cli_args).await?;
            
            // Detect node type
            let hosted_storage = if node_config.storage_config.hosted_storage_gb > 0 {
                node_config.storage_config.hosted_storage_gb
            } else {
                node_config.storage_config.storage_capacity_gb
            };
            
            let is_edge_node = if edge_mode {
                true
            } else {
                !node_config.consensus_config.validator_enabled 
                && !node_config.blockchain_config.smart_contracts
                && hosted_storage < 100
            };
            
            let is_validator = node_config.consensus_config.validator_enabled;
            
            if is_edge_node {
                println!(" Node Type: EDGE NODE");
            } else if is_validator {
                println!("🔶 Node Type: VALIDATOR");
            } else {
                println!(" Node Type: FULL NODE");
            }
            
            // Apply network override
            if let Some(network_env) = network_override {
                node_config.environment = network_env;
            }
            
            // Apply network isolation if pure mesh mode is enabled
            if pure_mesh {
                println!(" Applying network isolation for pure mesh mode...");
                use crate::config::network_isolation::NetworkIsolationConfig;
                let isolation_config = NetworkIsolationConfig::default();
                if let Err(e) = isolation_config.apply_isolation().await {
                    println!(" Failed to apply network isolation: {}", e);
                }
            }
            
            println!("Starting runtime orchestrator...");
            let mut orchestrator = RuntimeOrchestrator::new(node_config.clone()).await?;
            
            if is_edge_node {
                orchestrator.set_edge_node(true).await;
                orchestrator.set_edge_max_headers(edge_max_headers).await;
            }
            
            // PHASE 1: Start minimal components for peer discovery
            println!("🔌 Starting network components for peer discovery...");
            orchestrator.start_network_components_for_discovery().await?;
            
            println!("   → Waiting for network stack to initialize...");
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            
            // PHASE 2: Discover existing network
            let network_info_opt = orchestrator.discover_network_with_retry(is_edge_node).await?;
            
            // PHASE 3: Setup identity and blockchain
            let startup_result = if let Some(network_info) = network_info_opt {
                println!("\n✓ Connected to existing ZHTP network!");
                println!("   Network peers: {}", network_info.peer_count);
                println!("   Blockchain height: {}", network_info.blockchain_height);
                
                // Start blockchain sync
                println!("\n📦 Initializing blockchain for sync...");
                orchestrator.start_blockchain_sync(&network_info).await?;
                
                // Wait for initial sync
                println!("   ⏳ Waiting for initial sync to start...");
                if let Err(e) = orchestrator.wait_for_initial_sync(tokio::time::Duration::from_secs(30)).await {
                    println!("⚠ Initial sync timeout: {} - will continue syncing in background", e);
                }
                
                orchestrator.set_joined_existing_network(true).await?;
                
                // Guest mode for existing network
                println!("\nℹ Starting in guest mode - blockchain will sync, then users can create identities via mobile app");
                WalletStartupManager::quick_start_wallet().await?
            } else {
                println!("\nℹ No existing ZHTP network found");
                
                if is_edge_node {
                    return Err(anyhow!("Edge nodes must find an existing network"));
                }
                
                println!("📝 Starting new genesis network...");
                orchestrator.set_joined_existing_network(false).await?;
                
                // Interactive setup for genesis network
                WalletStartupManager::handle_startup_wallet_flow().await?
            };
            
            println!(" User wallet established: {}", startup_result.wallet_name);
            orchestrator.set_user_wallet(startup_result).await?;
            
            // PHASE 4: Register and start remaining components
            println!("  Registering remaining system components...");
            orchestrator.register_all_components().await?;
            
            println!("  Starting remaining system components...");
            orchestrator.start_all_components().await?;
            
            println!("ZHTP orchestrator fully operational!");
            println!("Press Ctrl+C to stop the node");
            
            // Run main loop
            orchestrator.run_main_loop().await?;
            
            Ok(())
        }
        NodeAction::Stop => {
            println!("Stopping ZHTP orchestrator node...");
            Ok(())
        }
        NodeAction::Status => {
            println!("ZHTP Orchestrator Status: Running");
            println!("API Port: {}", cli.server.split(':').nth(1).unwrap_or("9333"));
            Ok(())
        }
        NodeAction::Restart => {
            println!(" Restarting ZHTP orchestrator node...");
            Ok(())
        }
    }
}



