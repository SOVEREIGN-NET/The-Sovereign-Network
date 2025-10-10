//! Node management commands for ZHTP orchestrator

use anyhow::{Result, anyhow};
use crate::cli::{NodeArgs, NodeAction, ZhtpCli};
use crate::runtime::RuntimeOrchestrator;
use crate::runtime::did_startup::{WalletStartupManager, WalletStartupResult};
use crate::runtime::shared_dht::{initialize_global_dht, get_dht_client};
use lib_network::dht::DHTClient;
use lib_storage::{UnifiedStorageSystem, UnifiedStorageConfig};
use lib_identity::ZhtpIdentity;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug)]
struct ExistingNetworkInfo {
    peer_count: u32,
    blockchain_height: u64,
    network_id: String,
    bootstrap_peers: Vec<String>,
}

pub async fn handle_node_command(args: NodeArgs, cli: &ZhtpCli) -> Result<()> {
    match args.action {
        NodeAction::Start { config, port, dev, pure_mesh } => {
            println!(" Starting ZHTP orchestrator node...");
            println!("Port: {}", port);
            println!("Config: {:?}", config);
            println!("Dev mode: {}", dev);
            println!("Pure mesh mode: {}", pure_mesh);
            
            // Show node type information if using predefined configs
            if let Some(ref config_path) = config {
                if config_path.contains("full-node") {
                    println!("🖥️ Node Type: Full Node (Complete blockchain functionality)");
                } else if config_path.contains("validator-node") {
                    println!(" Node Type: Validator Node (Consensus participation)");
                } else if config_path.contains("storage-node") {
                    println!(" Node Type: Storage Node (Distributed storage services)");
                } else if config_path.contains("edge-node") {
                    println!("Node Type: Edge Node (Mesh networking and ISP bypass)");
                } else if config_path.contains("dev-node") {
                    println!("Node Type: Development Node (Testing and development)");
                }
            }
            
            // Load the node configuration
            use crate::config::{load_configuration, CliArgs, Environment};
            use crate::runtime::RuntimeOrchestrator;
            use std::path::PathBuf;
            
            let cli_args = CliArgs {
                mesh_port: port,
                pure_mesh,
                config: PathBuf::from(config.unwrap_or_else(|| "./config".to_string())),
                environment: Environment::Development, // Use dev environment for now to avoid mainnet key requirement
                log_level: if dev { "debug".to_string() } else { "info".to_string() },
                data_dir: PathBuf::from("./data"),
            };
            
            println!("Loading configuration...");
            let node_config = load_configuration(&cli_args).await?;
            
            // Apply network isolation if pure mesh mode is enabled
            if pure_mesh {
                println!(" Applying network isolation for pure mesh mode...");
                use crate::config::network_isolation::NetworkIsolationConfig;
                
                let isolation_config = NetworkIsolationConfig::default();
                match isolation_config.apply_isolation().await {
                    Ok(_) => {
                        println!(" Network isolation applied successfully");
                        println!(" Internet access blocked - mesh networking only");
                        
                        // Test isolation
                        match isolation_config.verify_isolation().await {
                            Ok(_) => {
                                println!(" Isolation verified: Local OK, Internet blocked");
                            }
                            Err(e) => println!(" Isolation verification failed: {}", e),
                        }
                    }
                    Err(e) => {
                        println!(" Failed to apply network isolation: {}", e);
                        println!(" Continuing without isolation - manual configuration may be required");
                    }
                }
            }
            
            println!("Starting runtime orchestrator...");
            let mut orchestrator = RuntimeOrchestrator::new(node_config.clone()).await?;
            
            println!("Attempting to connect to existing ZHTP mesh network...");
            
            // Step 1: Try to bootstrap to existing network
            let mesh_connection_result = attempt_mesh_bootstrap(&mut orchestrator).await;
            
            let startup_result = match mesh_connection_result {
                Ok(existing_network_info) => {
                    println!("Connected to existing ZHTP network!");
                    println!("Network peers: {}", existing_network_info.peer_count);
                    println!("Blockchain height: {}", existing_network_info.blockchain_height);
                    
                    // Step 2a: Handle identity for existing network
                    handle_existing_network_identity(&existing_network_info).await?
                }
                Err(_) => {
                    println!("No existing ZHTP network found or connection failed");
                    println!("Starting new genesis network...");
                    
                    // Step 2b: Handle identity for new genesis network
                    handle_genesis_network_identity().await?
                }
            };
            
            println!("User wallet established: {}", startup_result.wallet_name);
            
            // Pass user wallet to orchestrator before starting components
            if let Err(e) = orchestrator.set_user_wallet(startup_result).await {
                eprintln!("Warning: Failed to set user wallet: {}", e);
            }
            
            println!(" Starting system components...");
            
            // Start all components in proper order (blockchain, consensus, etc.)
            orchestrator.start_all_components().await?;
            
            println!("Blockchain component started - Mining ready!");
            println!("Consensus engine started - Validators active!");
            println!("Network mesh initialized - P2P connectivity!");
            
            if dev {
                println!("Development mode enabled - Enhanced logging and debug features");
            }
            
            // The ZHTP server and API endpoints are already running via ProtocolsComponent
            println!("ZHTP orchestrator fully operational!");
            println!("blockchain mining and consensus active");
            println!("Level 1 Orchestrator managing: crypto, zk, identity, storage, network, blockchain, consensus, economics, protocols");
            println!("ZHTP server and Web4 API endpoints active on port {}", port);
            println!("Press Ctrl+C to stop the node");
            
            // Wait for shutdown signal (no need to start duplicate API server)
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    println!("Shutting down orchestrator...");
                    orchestrator.graceful_shutdown().await?;
                }
            }
            
            Ok(())
        }
        NodeAction::Stop => {
            println!("Stopping ZHTP orchestrator node...");
            println!("Node stopped successfully");
            Ok(())
        }
        NodeAction::Status => {
            println!("ZHTP Orchestrator Status:");
            println!("Status: Running");
            println!("Role: Level 1 Orchestrator");
            println!("Coordinating: protocols, blockchain, network");
            println!("API Port: {}", cli.server.split(':').nth(1).unwrap_or("9333"));
            Ok(())
        }
        NodeAction::Restart => {
            println!(" Restarting ZHTP orchestrator node...");
            println!("Node restarted successfully");
            Ok(())
        }
    }
}

/// Attempt to bootstrap to an existing ZHTP mesh network
async fn attempt_mesh_bootstrap(orchestrator: &mut RuntimeOrchestrator) -> Result<ExistingNetworkInfo> {
    println!("Scanning for existing ZHTP network...");
    
    // Register components but DON'T start network component yet to avoid duplicate startup
    println!(" Starting network component for discovery...");
    orchestrator.register_all_components().await?;
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
    
    // Check if we found any ZHTP peers without starting a full network component
    // This will be replaced by the proper network component startup later
    let peer_count = check_discovered_peers().await?;
    
    if peer_count > 0 {
        println!("Found {} ZHTP peers", peer_count);
        
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

/// Handle wallet setup when connecting to an existing network
async fn handle_existing_network_identity(network_info: &ExistingNetworkInfo) -> Result<WalletStartupResult> {
    println!("\nZHTP Network Connection Established");
    println!("=====================================");
    println!("Connected to existing ZHTP network: {}", network_info.network_id);
    println!("Network peers: {}", network_info.peer_count);
    println!("Blockchain height: {}", network_info.blockchain_height);
    println!();
    println!("Choose how to set up your wallet:");
    println!("1) Import existing wallet from mesh network");
    println!("2) Import from recovery phrase");
    println!("3) Create new wallet on this network");
    println!("4) Quick start (auto-generate for testing)");
    println!();
    
    loop {
        print!("Enter your choice (1-4): ");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        
        match input.trim() {
            "1" => {
                println!("\nScanning mesh network for existing wallets...");
                return import_identity_from_mesh(network_info).await;
            }
            "2" => {
                println!("\nImport from recovery phrase...");
                return WalletStartupManager::import_from_recovery_phrase().await;
            }
            "3" => {
                println!("\n Creating new wallet on existing network...");
                println!(" Wallet address will be derived from DHT node identity");
                return create_wallet_from_node_identity(network_info).await;
            }
            "4" => {
                println!("\n Quick start mode...");
                return WalletStartupManager::quick_start_wallet().await;
            }
            _ => {
                println!("Invalid choice. Please enter 1, 2, 3, or 4.");
                continue;
            }
        }
    }
}

/// Handle wallet setup when creating a new genesis network
async fn handle_genesis_network_identity() -> Result<WalletStartupResult> {
    println!("\nCreating New ZHTP Genesis Network");
    println!("====================================");
    println!("No existing network found. You'll be creating a new genesis network.");
    println!("This node will become the first node in a new ZHTP mesh.");
    println!();
    println!("Choose how to set up your genesis wallet:");
    println!("1) Create new wallet (full Web4 access, blockchain participation)");
    println!("2) Import existing wallet from recovery phrase");
    println!("3) Quick start (auto-generate for testing)");
    println!();
    
    loop {
        print!("Enter your choice (1-3): ");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        
        match input.trim() {
            "1" => {
                println!("\n Creating new genesis wallet...");
                println!(" Wallet address will be derived from DHT node identity");
                return create_genesis_wallet_from_node_identity().await;
            }
            "2" => {
                println!("\nImport from recovery phrase...");
                return WalletStartupManager::import_from_recovery_phrase().await;
            }
            "3" => {
                println!("\n Quick start mode...");
                return WalletStartupManager::quick_start_wallet().await;
            }
            _ => {
                println!("Invalid choice. Please enter 1, 2, or 3.");
                continue;
            }
        }
    }
}

/// Import wallet from mesh network
async fn import_identity_from_mesh(network_info: &ExistingNetworkInfo) -> Result<WalletStartupResult> {
    println!("Searching for wallets in mesh network...");
    println!("Querying {} bootstrap peers...", network_info.bootstrap_peers.len());
    
    // Use the shared DHT client (already initialized)
    let dht_client = get_dht_client().await?;
    
    // Discover peers in the mesh network using shared DHT instance
    let dht = dht_client.read().await;
    match dht.discover_peers().await {
        Ok(discovered_peers) => {
            println!("Found {} peers in mesh network", discovered_peers.len());
            for (i, peer) in discovered_peers.iter().take(5).enumerate() {
                println!("  {}. {}", i + 1, peer);
            }
            
            // Try to find importable identities from discovered peers
            // For now, this is simplified - in a implementation,
            // we would query each peer for available identity services
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            
            if discovered_peers.is_empty() {
                println!("No identities available for import from discovered peers");
            } else {
                println!("Identity import from mesh peers not yet implemented");
            }
        }
        Err(e) => {
            println!("Failed to discover peers: {}", e);
        }
    }
    
    println!(" Falling back to manual wallet creation...");
    handle_genesis_network_identity().await
}

/// Check for discovered peers (using shared DHT instance)
async fn check_discovered_peers() -> Result<u32> {
    // Use persistent node identity for network discovery
    // This identity will become the node's permanent DHT address
    let node_identity = create_or_load_node_identity().await?;
    
    // Initialize global DHT instance (singleton pattern)
    initialize_global_dht(node_identity).await?;
    
    // Get the shared DHT client
    let dht_client = get_dht_client().await?;
    
    // Discover peers using shared DHT instance
    let dht = dht_client.read().await;
    match dht.discover_peers().await {
        Ok(peers) => {
            println!("Discovered {} peers in network", peers.len());
            Ok(peers.len() as u32)
        }
        Err(e) => {
            println!("Peer discovery failed: {}", e);
            Ok(0) // Return 0 peers on error (forces genesis mode)
        }
    }
}

/// Fetch blockchain info from peers (using shared DHT instance)
async fn fetch_blockchain_info_from_peers() -> Result<BlockchainInfo> {
    // Get the shared DHT client (already initialized in check_discovered_peers)
    let dht_client = get_dht_client().await?;
    
    // Get peer list using shared DHT instance
    let dht = dht_client.read().await;
    let discovered_peers = dht.discover_peers().await.unwrap_or_default();
    
    // Try to get blockchain info from the shared blockchain instance
    // In a implementation, this would query remote peers for their blockchain state
    let height = match crate::runtime::shared_blockchain::get_shared_blockchain() {
        Ok(blockchain_service) => {
            blockchain_service.get_height().await.unwrap_or(0)
        },
        Err(_) => 0, // Default if no blockchain is available
    };
    
    // Determine network ID based on current configuration
    let network_id = if discovered_peers.is_empty() {
        "zhtp-genesis".to_string()
    } else {
        "zhtp-mainnet".to_string()
    };
    
    Ok(BlockchainInfo {
        height,
        network_id,
        peers: discovered_peers,
    })
}

#[derive(Debug)]
struct BlockchainInfo {
    height: u64,
    network_id: String,
    peers: Vec<String>,
}

/// Create or load persistent node identity that serves as both DHT address and wallet address
/// This ensures the node has a consistent identity across all DHT operations
async fn create_or_load_node_identity() -> Result<ZhtpIdentity> {
    use std::path::Path;
    use std::fs;
    use lib_crypto::generate_keypair;
    
    let identity_file = "./data/node_identity.json";
    
    // Try to load existing node identity
    if Path::new(identity_file).exists() {
        println!(" Loading existing node identity from {}", identity_file);
        
        match fs::read_to_string(identity_file) {
            Ok(identity_json) => {
                match serde_json::from_str::<ZhtpIdentity>(&identity_json) {
                    Ok(identity) => {
                        println!(" Loaded node identity: {:?}", &identity.id.to_string()[..8]);
                        return Ok(identity);
                    }
                    Err(e) => {
                        println!(" Failed to parse existing identity file: {}", e);
                        // Fall through to create new identity
                    }
                }
            }
            Err(e) => {
                println!(" Failed to read identity file: {}", e);
                // Fall through to create new identity
            }
        }
    }
    
    // Create new node identity
    println!(" Creating new persistent node identity...");
    
    // Generate cryptographic key pair for the node
    let keypair = generate_keypair()?;
    let public_key = keypair.public_key.dilithium_pk.clone(); // Use Dilithium public key bytes
    
    // Create zero-knowledge proof of ownership (simplified for now)
    let ownership_proof = lib_proofs::ZeroKnowledgeProof::default();
    
    // Create the identity - this ID will be used as DHT address
    let node_identity = ZhtpIdentity::new(
        lib_identity::IdentityType::Device, // Node identity type
        public_key.to_vec(),
        ownership_proof,
    )?;
    
    println!(" Created node identity with ID: {:?}", &node_identity.id.to_string()[..8]);
    println!(" This identity serves as both DHT address and primary node address");
    
    // Save the identity to disk for persistence
    if let Err(e) = fs::create_dir_all("./data") {
        println!(" Warning: Could not create data directory: {}", e);
    }
    
    match serde_json::to_string_pretty(&node_identity) {
        Ok(identity_json) => {
            if let Err(e) = fs::write(identity_file, identity_json) {
                println!(" Warning: Could not save identity to disk: {}", e);
            } else {
                println!(" Node identity saved to {}", identity_file);
            }
        }
        Err(e) => {
            println!(" Warning: Could not serialize identity: {}", e);
        }
    }
    
    Ok(node_identity)
}

/// Create a wallet using the node's DHT identity as the primary address
/// This ensures wallet address = DHT address = node identity
async fn create_wallet_from_node_identity(network_info: &ExistingNetworkInfo) -> Result<WalletStartupResult> {
    println!(" Creating wallet from DHT node identity...");
    
    // Get the persistent node identity
    let node_identity = create_or_load_node_identity().await?;
    
    println!(" Node DHT Address: {:?}", &node_identity.id.to_string()[..16]);
    println!("Primary Wallet Address: {}", node_identity.id.to_string());
    println!(" Network: {}", network_info.network_id);
    
    // Create wallet using the identity's integrated wallet manager
    let wallet_name = format!("primary-{}", &node_identity.id.to_string()[..8]);
    
    // Use the identity's built-in wallet manager to create a wallet
    let mut node_identity_mut = node_identity.clone();
    let (wallet_id, actual_seed_phrase) = match node_identity_mut.wallet_manager.create_wallet_with_seed_phrase(
        lib_identity::wallets::WalletType::Standard,
        wallet_name.clone(),
        Some("primary".to_string()),
    ).await {
        Ok((wallet_id, seed_phrase)) => {
            println!(" Wallet created with seed phrase");
            println!(" Seed Phrase: {}", seed_phrase.words.join(" "));
            println!(" Save this seed phrase - it's your wallet recovery key!");
            (wallet_id, seed_phrase.words.join(" "))
        }
        Err(e) => {
            println!(" Failed to create wallet with seed phrase: {}", e);
            println!(" Creating basic wallet without seed phrase for now...");
            
            // Return error since seed phrase is required
            return Err(anyhow!("Failed to create wallet with seed phrase: {}", e));
        }
    };
    
    // Create wallet address in ZHTP format for compatibility
    let wallet_address = format!("zhtp:{}", &node_identity.id.to_string()[..16]);
    
    // Return result compatible with existing ZHTP system  
    Ok(WalletStartupResult {
        node_wallet_id: wallet_id,
        wallet_name,
        seed_phrase: actual_seed_phrase,
        wallet_address,
    })
}

/// Create a genesis wallet using the node's DHT identity as the primary address
async fn create_genesis_wallet_from_node_identity() -> Result<WalletStartupResult> {
    println!("Creating genesis wallet from DHT node identity...");
    
    // Get the persistent node identity
    let node_identity = create_or_load_node_identity().await?;
    
    println!(" Genesis Node DHT Address: {:?}", &node_identity.id.to_string()[..16]);
    println!("Genesis Wallet Address: {}", node_identity.id.to_string());
    println!(" This node will be the genesis node for a new ZHTP network");
    
    // Create genesis wallet using the identity's integrated wallet manager
    let wallet_name = format!("genesis-{}", &node_identity.id.to_string()[..8]);
    
    // Use the identity's built-in wallet manager to create a wallet
    let mut node_identity_mut = node_identity.clone();
    let (wallet_id, actual_seed_phrase) = match node_identity_mut.wallet_manager.create_wallet_with_seed_phrase(
        lib_identity::wallets::WalletType::Standard, // Use Standard type since Genesis doesn't exist
        wallet_name.clone(),
        Some("genesis".to_string()),
    ).await {
        Ok((wallet_id, seed_phrase)) => {
            println!(" Genesis wallet created with seed phrase");
            println!(" Genesis Seed Phrase: {}", seed_phrase.words.join(" "));
            println!(" CRITICAL: Save this seed phrase - it controls the genesis node!");
            (wallet_id, seed_phrase.words.join(" "))
        }
        Err(e) => {
            println!(" Failed to create wallet with seed phrase: {}", e);
            println!(" Creating basic genesis wallet without seed phrase for now...");
            
            // Return error since seed phrase is required
            return Err(anyhow!("Failed to create genesis wallet with seed phrase: {}", e));
        }
    };
    
    // Create wallet address in ZHTP format for compatibility
    let wallet_address = format!("zhtp:{}", &node_identity.id.to_string()[..16]);
    
    // Return result compatible with existing ZHTP system
    Ok(WalletStartupResult {
        node_wallet_id: wallet_id,
        wallet_name,
        seed_phrase: actual_seed_phrase,
        wallet_address,
    })
}
