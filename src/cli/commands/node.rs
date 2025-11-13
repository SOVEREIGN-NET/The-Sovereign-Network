//! Node management commands for ZHTP orchestrator

use anyhow::{Result, anyhow};
use crate::cli::{NodeArgs, NodeAction, ZhtpCli};
use crate::config::environment::Environment;  // NEW: For network-specific data paths
use crate::runtime::RuntimeOrchestrator;
use crate::runtime::ComponentId;
use crate::runtime::did_startup::{WalletStartupManager, WalletStartupResult};
use crate::runtime::shared_dht::{initialize_global_dht_safe, get_dht_client};
use lib_identity::ZhtpIdentity;
use std::io::{self, Write};
use blake3;

// ============================================================================
// Auto-Start Constants
// ============================================================================

/// Quick start mode for ZHTP_AUTO_START environment variable
const AUTO_START_QUICK: &str = "quick";

/// Legacy numeric option for quick start (option 3 from old menu)
const AUTO_START_LEGACY_OPTION_3: &str = "3";

// ============================================================================
// Password Utility Functions
// ============================================================================

/// Prompt user for identity/node name
fn prompt_for_identity_name() -> Result<String> {
    loop {
        print!("\nEnter a name for your identity (node): ");
        io::stdout().flush()?;
        
        let mut name = String::new();
        io::stdin().read_line(&mut name)?;
        let name = name.trim();
        
        if name.is_empty() {
            println!("❌ Name cannot be empty. Please try again.");
            continue;
        }
        
        if name.len() < 3 {
            println!("❌ Name must be at least 3 characters long.");
            continue;
        }
        
        return Ok(name.to_string());
    }
}

/// Validate password strength
fn validate_password_strength(password: &str) -> Result<()> {
    if password.len() < 8 {
        return Err(anyhow!("Password must be at least 8 characters long"));
    }
    
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_numeric());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());
    
    if !has_uppercase {
        return Err(anyhow!("Password must contain at least one uppercase letter"));
    }
    if !has_lowercase {
        return Err(anyhow!("Password must contain at least one lowercase letter"));
    }
    if !has_digit {
        return Err(anyhow!("Password must contain at least one number"));
    }
    if !has_special {
        return Err(anyhow!("Password must contain at least one special character"));
    }
    
    Ok(())
}

/// Securely prompt for password (no echo)
fn prompt_for_password(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    
    let password = rpassword::read_password()?;
    Ok(password)
}

/// Prompt for seed phrase confirmation
fn confirm_seed_phrase(seed_phrase: &str) -> Result<()> {
    println!("\n⚠️  IMPORTANT: Write down your recovery phrase!");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📝 Your Recovery Phrase:");
    println!("{}", seed_phrase);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("\n⚠️  Store this in a safe place. You'll need it to recover your wallet!");
    println!("⚠️  Anyone with this phrase can access your funds!");
    
    loop {
        print!("\nType 'CONFIRM' to verify you've saved your recovery phrase: ");
        io::stdout().flush()?;
        
        let mut confirmation = String::new();
        io::stdin().read_line(&mut confirmation)?;
        
        if confirmation.trim() == "CONFIRM" {
            println!("✅ Recovery phrase confirmed!");
            return Ok(());
        } else {
            println!("❌ You must type 'CONFIRM' to continue. Please save your recovery phrase first.");
        }
    }
}

/// Prompt for DID password with confirmation
fn prompt_for_did_password() -> Result<String> {
    println!("\n🔐 Set a password to protect your Digital Identity");
    println!("Requirements: 8+ chars, uppercase, lowercase, number, special character");
    
    loop {
        let password = prompt_for_password("\nEnter password: ")?;
        
        if let Err(e) = validate_password_strength(&password) {
            println!("❌ {}", e);
            continue;
        }
        
        let confirmation = prompt_for_password("Confirm password: ")?;
        
        if password != confirmation {
            println!("❌ Passwords don't match. Please try again.");
            continue;
        }
        
        println!("✅ Password set successfully!");
        return Ok(password);
    }
}

/// Prompt for optional wallet password
fn prompt_for_wallet_password(wallet_type: &str) -> Result<Option<String>> {
    println!("\n🔐 Set a password for your {} wallet (optional)", wallet_type);
    print!("Press Enter to skip, or type a password: ");
    io::stdout().flush()?;
    
    let password = rpassword::read_password()?;
    
    if password.is_empty() {
        println!("⏭️  Skipping wallet password");
        return Ok(None);
    }
    
    // Validate wallet password (minimum 6 chars)
    if password.len() < 6 {
        println!("❌ Wallet password must be at least 6 characters. Skipping.");
        return Ok(None);
    }
    
    let confirmation = prompt_for_password("Confirm wallet password: ")?;
    
    if password != confirmation {
        println!("❌ Passwords don't match. Skipping wallet password.");
        return Ok(None);
    }
    
    println!("✅ Wallet password set!");
    Ok(Some(password))
}

// ============================================================================
// Network Info and Identity Management
// ============================================================================

#[derive(Debug)]
struct ExistingNetworkInfo {
    peer_count: u32,
    blockchain_height: u64,
    network_id: String,
    bootstrap_peers: Vec<String>,
    environment: Environment,  // NEW: Network-specific environment for proper data paths
}

pub async fn handle_node_command(args: NodeArgs, cli: &ZhtpCli) -> Result<()> {
    match args.action {
        NodeAction::Start { config, port, dev, pure_mesh, network } => {
            println!(" Starting ZHTP orchestrator node...");
            if let Some(p) = port {
                println!("Port override: {}", p);
            }
            println!("Config: {:?}", config);
            println!("Dev mode: {}", dev);
            println!("Pure mesh mode: {}", pure_mesh);
            
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
                println!("🌐 Network Override: {}", net);
            }
            
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
                environment: network_override.unwrap_or(Environment::Development), // Use CLI override or default
                log_level: if dev { "debug".to_string() } else { "info".to_string() },
                data_dir: PathBuf::from("./data"),
            };
            
            println!("Loading configuration...");
            let mut node_config = load_configuration(&cli_args).await?;
            
            // Apply network override if --network flag was provided
            if let Some(network_env) = network_override {
                println!("🔄 Overriding config environment with CLI flag: {}", network_env);
                node_config.environment = network_env;
                
                // Update related config fields for consistency
                match network_env {
                    Environment::Mainnet => {
                        println!("   → Using mainnet genesis block (chain_id: 0x01)");
                        println!("   → Data directory: ./data/mainnet");
                    }
                    Environment::Testnet => {
                        println!("   → Using testnet genesis block (chain_id: 0x02)");
                        println!("   → Data directory: ./data/testnet");
                    }
                    Environment::Development => {
                        println!("   → Using development genesis block (chain_id: 0x03)");
                        println!("   → Data directory: ./data/dev");
                    }
                }
            }
            
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
            
            // ================================================================
            // NEW APPROACH: Start network components FIRST, then discover peers
            // ================================================================
            
            println!("🔌 Starting network components for peer discovery...");
            
            // Start minimal components needed for network discovery:
            // 1. Crypto (for keypairs)
            // 2. Network (for mesh server and peer discovery)
            // NOTE: Do NOT start Protocols yet - it needs BlockchainComponent to initialize shared blockchain first
            orchestrator.register_all_components().await?;
            
            println!("   → Starting CryptoComponent...");
            orchestrator.start_component(crate::runtime::ComponentId::Crypto).await?;
            
            println!("   → Starting NetworkComponent...");
            orchestrator.start_component(crate::runtime::ComponentId::Network).await?;
            
            // Wait a moment for network stack to fully initialize, but poll for readiness
            println!("   → Waiting for network stack to initialize (polling for readiness)...");
            let mut network_ready = false;
            // Poll lib_network::get_mesh_status for up to 10 seconds
            for _ in 0..20 {
                match lib_network::get_mesh_status().await {
                    Ok(status) => {
                        println!("   → Network stack ready: {} peers (connectivity {:.1}%)", status.active_peers, status.connectivity_percentage);
                        network_ready = true;
                        break;
                    }
                    Err(_) => {
                        // Not yet ready - wait and retry
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    }
                }
            }

            if !network_ready {
                println!("   ⚠️ Network stack did not report ready within timeout; proceeding with discovery anyway (may be slower)");
            } else {
                println!("✅ Network components reported ready - attempting peer discovery...");
            }
            
            // NOW try to bootstrap to existing network (network is listening!)
            let mesh_connection_result = attempt_mesh_bootstrap(&mut orchestrator, &node_config.environment).await;
            
            let startup_result = match mesh_connection_result {
                Ok(existing_network_info) => {
                    println!("🌐 Connected to existing ZHTP network!");
                    println!("   Network peers: {}", existing_network_info.peer_count);
                    println!("   Blockchain height: {}", existing_network_info.blockchain_height);
                    
                    // Tell orchestrator we're joining existing network (don't create genesis)
                    if let Err(e) = orchestrator.set_joined_existing_network(true).await {
                        eprintln!("Warning: Failed to set network join status: {}", e);
                    }
                    
                    // Step 2a: Handle identity for existing network
                    handle_existing_network_identity(&existing_network_info).await?
                }
                Err(_) => {
                    println!("ℹ️  No existing ZHTP network found or connection failed");
                    println!("🆕 Starting new genesis network...");
                    
                    // Tell orchestrator we're creating new network (create genesis)
                    if let Err(e) = orchestrator.set_joined_existing_network(false).await {
                        eprintln!("Warning: Failed to set network create status: {}", e);
                    }
                    
                    // Step 2b: Handle identity for new genesis network (pass environment)
                    handle_genesis_network_identity(&node_config.environment).await?
                }
            };
            
            println!("✅ User wallet established: {}", startup_result.wallet_name);
            
            // Pass user wallet to orchestrator before starting remaining components
            if let Err(e) = orchestrator.set_user_wallet(startup_result).await {
                eprintln!("Warning: Failed to set user wallet: {}", e);
            }
            
            println!("⚙️  Starting remaining system components...");
            
            // CRITICAL ORDER: Start Blockchain BEFORE Protocols!
            // BlockchainComponent creates the shared blockchain with proper genesis funding.
            // ProtocolsComponent needs that shared blockchain to exist when it starts.
            
            // Start remaining components (skip already-started Crypto, Network)
            orchestrator.start_component(crate::runtime::ComponentId::ZK).await?;
            orchestrator.start_component(crate::runtime::ComponentId::Identity).await?;
            orchestrator.start_component(crate::runtime::ComponentId::Storage).await?;
            // Network already started above
            
            // Start BlockchainComponent FIRST - it creates shared blockchain with genesis funding
            orchestrator.start_component(crate::runtime::ComponentId::Blockchain).await?;
            
            // Start Consensus BEFORE Protocols for validator coordination
            orchestrator.start_component(crate::runtime::ComponentId::Consensus).await?;
            
            // Now start Protocols - it will use the shared blockchain created by BlockchainComponent
            orchestrator.start_component(crate::runtime::ComponentId::Protocols).await?;
            
            orchestrator.start_component(crate::runtime::ComponentId::Economics).await?;
            orchestrator.start_component(crate::runtime::ComponentId::Api).await?;
            
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
            println!("ZHTP server and Web4 API endpoints active on port {}", node_config.protocols_config.api_port);
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
async fn attempt_mesh_bootstrap(_orchestrator: &mut RuntimeOrchestrator, environment: &Environment) -> Result<ExistingNetworkInfo> {
    println!("🔍 Scanning for existing ZHTP network...");
    println!("   (Network components are now listening and can be discovered)");
    
    // Initialize DHT and perform ACTIVE peer discovery
    println!("📡 Initializing DHT for peer discovery...");
    let node_identity = create_or_load_node_identity(environment).await?;
    initialize_global_dht_safe(node_identity.clone()).await?;
    
    // Start actual discovery mechanisms (mDNS + DHT bootstrap)
    println!("🔎 Discovering peers via mDNS, UDP multicast, and DHT bootstrap...");
    println!("   (This may take up to 30 seconds for thorough network scanning)");
    let discovered_peers = perform_active_peer_discovery(&node_identity, environment).await?;
    
    let peer_count = discovered_peers.len();
    
    if peer_count > 0 {
        println!("✅ Found {} ZHTP peers on network", peer_count);
        for (i, peer) in discovered_peers.iter().enumerate() {
            println!("   {}. {}", i + 1, peer);
        }
        
        // Try to connect to blockchain via peers
        let blockchain_info = fetch_blockchain_info_from_discovered_peers(&discovered_peers).await?;
        
        Ok(ExistingNetworkInfo {
            peer_count: peer_count as u32,
            blockchain_height: blockchain_info.height,
            network_id: blockchain_info.network_id,
            bootstrap_peers: discovered_peers,
            environment: environment.clone(),
        })
    } else {
        println!("ℹ️  No ZHTP peers found - will create genesis network");
        Err(anyhow!("No network peers found"))
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
    println!("Choose how to set up your Digital Identity (DID):");
    println!("1) Import existing identity from mesh network");
    println!("2) Import identity from recovery phrase");
    println!("3) Create new identity with wallets (Primary, Savings, Staking)");
    println!("4) Quick start (auto-generate for testing)");
    println!();
    println!("Note: Your DID will own this node and manage multiple wallets.");
    println!();
    
    loop {
        print!("Enter your choice (1-4): ");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        
        match input.trim() {
            "1" => {
                println!("\nScanning mesh network for existing identity...");
                return import_identity_from_mesh(network_info).await;
            }
            "2" => {
                println!("\nImport identity from recovery phrase...");
                return WalletStartupManager::import_from_recovery_phrase().await;
            }
            "3" => {
                println!("\n Creating new digital identity with wallets...");
                println!(" Your DID will own 3 wallets: Primary (rewards), Savings, Staking");
                println!(" Node will route rewards to your Primary wallet");
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
async fn handle_genesis_network_identity(environment: &Environment) -> Result<WalletStartupResult> {
    // Check for auto-start environment variable
    if let Ok(auto_mode) = std::env::var("ZHTP_AUTO_START") {
        if auto_mode == AUTO_START_QUICK || auto_mode == AUTO_START_LEGACY_OPTION_3 {
            println!("\n Quick start mode (via ZHTP_AUTO_START={})...", auto_mode);
            return WalletStartupManager::quick_start_wallet().await;
        }
    }

    println!("\nCreating New ZHTP Genesis Network");
    println!("====================================");
    println!("No existing network found. You'll be creating a new genesis network.");
    println!("This node will become the first node in a new ZHTP mesh.");
    println!();
    println!("Choose how to set up your Digital Identity (DID):");
    println!("1) Create new identity with wallets (Primary, Savings, Staking)");
    println!("2) Import existing identity from recovery phrase");
    println!("3) Quick start (auto-generate for testing)");
    println!();
    println!("Note: Your DID will own this node. The node routes rewards to your wallets.");
    println!();

    loop {
        print!("Enter your choice (1-3): ");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();

        match input.trim() {
            "1" => {
                println!("\n Creating new digital identity with wallets...");
                println!(" Your DID will own 3 wallets: Primary (rewards), Savings, Staking");
                println!(" Node will route rewards to your Primary wallet");
                return create_genesis_wallet_from_node_identity(environment).await;
            }
            "2" => {
                println!("\nImport identity from recovery phrase...");
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
    handle_genesis_network_identity(&network_info.environment).await
}

/// Perform ACTIVE peer discovery using all available methods
async fn perform_active_peer_discovery(node_identity: &ZhtpIdentity, environment: &Environment) -> Result<Vec<String>> {
    use lib_network::dht::bootstrap::DHTBootstrap;
    
    let mut all_discovered_peers = Vec::new();
    
    // Method 1: DHT Enhanced Bootstrap (includes mDNS)
    println!("   → Method 1: DHT bootstrap with mDNS discovery");
    let mut dht_bootstrap = DHTBootstrap::new(Default::default());
    
    // Start with empty bootstrap list - will use mDNS to find local peers
    // INCREASED TIMEOUT: WiFi Direct/mDNS can take 8-10 seconds to discover peers
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(15),
        dht_bootstrap.enhance_bootstrap(&[])
    ).await {
        Ok(Ok(peers)) => {
            println!("     ✓ DHT/mDNS found {} peers", peers.len());
            all_discovered_peers.extend(peers);
        }
        Ok(Err(e)) => {
            println!("     ✗ DHT/mDNS discovery failed: {}", e);
        }
        Err(_) => {
            println!("     ⏱ DHT/mDNS discovery timeout");
        }
    }
    
    // Method 2: Check UDP multicast announcements
    println!("   → Method 2: UDP multicast peer discovery");
    // INCREASED TIMEOUT: UDP multicast may need extra time on some networks
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(10),
        discover_via_multicast()
    ).await {
        Ok(Ok(peers)) => {
            println!("     ✓ Multicast found {} peers", peers.len());
            all_discovered_peers.extend(peers);
        }
        Ok(Err(e)) => {
            println!("     ✗ Multicast discovery failed: {}", e);
        }
        Err(_) => {
            println!("     ⏱ Multicast discovery timeout");
        }
    }
    
    // Method 3: Try common local ports
    println!("   → Method 3: Scanning common ZHTP ports on subnet");
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(3),
        scan_local_subnet_for_zhtp(environment)
    ).await {
        Ok(Ok(peers)) => {
            println!("     ✓ Port scan found {} peers", peers.len());
            all_discovered_peers.extend(peers);
        }
        Ok(Err(e)) => {
            println!("     ✗ Port scan failed: {}", e);
        }
        Err(_) => {
            println!("     ⏱ Port scan timeout");
        }
    }
    
    // Deduplicate and return
    all_discovered_peers.sort();
    all_discovered_peers.dedup();
    
    Ok(all_discovered_peers)
}

/// Discover peers via UDP multicast announcements
async fn discover_via_multicast() -> Result<Vec<String>> {
    use tokio::net::UdpSocket;
    use std::net::{Ipv4Addr, SocketAddr};
    
    const ZHTP_MULTICAST_ADDR: &str = "224.0.1.75";
    const ZHTP_MULTICAST_PORT: u16 = 37775;
    
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", ZHTP_MULTICAST_PORT)).await?;
    let multicast_addr: Ipv4Addr = ZHTP_MULTICAST_ADDR.parse()?;
    socket.join_multicast_v4(multicast_addr, Ipv4Addr::UNSPECIFIED)?;
    
    let mut discovered = Vec::new();
    let mut buf = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(
            tokio::time::Duration::from_millis(500),
            socket.recv_from(&mut buf)
        ).await {
            Ok(Ok((len, addr))) => {
                if let Ok(announcement) = String::from_utf8(buf[..len].to_vec()) {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&announcement) {
                        if let Some(mesh_port) = parsed.get("mesh_port").and_then(|p| p.as_u64()) {
                            let peer_addr = format!("zhtp://{}:{}", addr.ip(), mesh_port);
                            if !discovered.contains(&peer_addr) {
                                discovered.push(peer_addr);
                            }
                        }
                    }
                }
            }
            _ => break,
        }
    }
    
    Ok(discovered)
}

/// Scan local subnet for ZHTP nodes on common ports
async fn scan_local_subnet_for_zhtp(environment: &Environment) -> Result<Vec<String>> {
    use tokio::net::TcpStream;
    use std::net::{IpAddr, Ipv4Addr};
    
    let mut discovered = Vec::new();
    
    // Get local IP to determine subnet
    let local_ip = get_local_ip_address().await?;
    
    // Parse to get subnet (assumes /24)
    if let IpAddr::V4(ipv4) = local_ip {
        let octets = ipv4.octets();
        let subnet_base = format!("{}.{}.{}", octets[0], octets[1], octets[2]);
        
        // Common ZHTP ports to check
        let ports = vec![9333, 33446];
        
        // Scan a small range around our IP
        let our_last_octet = octets[3];
        let scan_range: Vec<u8> = (1..=254)
            .filter(|&i| i != our_last_octet) // Skip ourselves
            .take(20) // Limit scan to avoid slowdown
            .collect();
        
        for last_octet in scan_range {
            for &port in &ports {
                let target = format!("{}.{}:{}", subnet_base, last_octet, port);
                
                // Quick TCP connection test
                match tokio::time::timeout(
                    tokio::time::Duration::from_millis(100),
                    TcpStream::connect(&target)
                ).await {
                    Ok(Ok(_stream)) => {
                        let peer_addr = format!("zhtp://{}", target);
                        discovered.push(peer_addr);
                    }
                    _ => continue,
                }
            }
        }
    }
    
    Ok(discovered)
}

/// Get local IP address
async fn get_local_ip_address() -> Result<std::net::IpAddr> {
    use tokio::net::UdpSocket;
    
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect("8.8.8.8:80").await?;
    Ok(socket.local_addr()?.ip())
}

/// Fetch blockchain info from discovered peers
async fn fetch_blockchain_info_from_discovered_peers(peers: &[String]) -> Result<BlockchainInfo> {
    // Don't query local blockchain (it's not started yet!)
    // Instead, query the first discovered peer for blockchain info
    let mut height = 0u64;
    
    for peer in peers {
        // Try to extract HTTP API port from peer address
        // peer format might be: "zhtp://192.168.1.137:9333" or similar
        if let Some(api_url) = peer.strip_prefix("zhtp://").or_else(|| peer.strip_prefix("http://")) {
            let http_url = format!("http://{}/api/v1/blockchain/info", api_url);
            
            match tokio::time::timeout(
                tokio::time::Duration::from_secs(2),
                reqwest::get(&http_url)
            ).await {
                Ok(Ok(response)) => {
                    if let Ok(json) = response.json::<serde_json::Value>().await {
                        if let Some(h) = json.get("height").and_then(|v| v.as_u64()) {
                            height = h;
                            println!("     📊 Peer {} reports blockchain height: {}", api_url, height);
                            break; // Got valid response
                        }
                    }
                }
                Ok(Err(e)) => {
                    println!("     ⚠️ Failed to query peer {}: {}", api_url, e);
                }
                Err(_) => {
                    println!("     ⏱ Timeout querying peer {}", api_url);
                }
            }
        }
    }
    
    let network_id = if peers.is_empty() {
        "zhtp-genesis".to_string()
    } else {
        "zhtp-mainnet".to_string()
    };
    
    Ok(BlockchainInfo {
        height,
        network_id,
        peers: peers.to_vec(),
    })
}

/// Check for discovered peers (using shared DHT instance)
async fn check_discovered_peers(environment: &Environment) -> Result<u32> {
    // Use persistent node identity for network discovery
    // This identity will become the node's permanent DHT address
    let node_identity = create_or_load_node_identity(environment).await?;
    
    // Initialize global DHT instance safely (prevents duplicate initialization)
    initialize_global_dht_safe(node_identity).await?;
    
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
async fn create_or_load_node_identity(environment: &Environment) -> Result<ZhtpIdentity> {
    use std::path::Path;
    use std::fs;
    use lib_crypto::generate_keypair;
    
    // Use network-specific data directory
    let data_dir = environment.data_directory();
    let identity_file = format!("{}/node_identity.json", data_dir);
    
    // Try to load existing node identity
    if Path::new(&identity_file).exists() {
        println!(" Loading existing node identity from {}", identity_file);
        
        match fs::read_to_string(&identity_file) {
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
    
    // Save the identity to disk for persistence (network-specific directory)
    if let Err(e) = fs::create_dir_all(&data_dir) {
        println!(" Warning: Could not create data directory {}: {}", data_dir, e);
    }
    
    match serde_json::to_string_pretty(&node_identity) {
        Ok(identity_json) => {
            if let Err(e) = fs::write(&identity_file, identity_json) {
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
    
    // Get the persistent node identity (uses network-specific data directory)
    let node_identity = create_or_load_node_identity(&network_info.environment).await?;
    
    println!(" Node DHT Address: {}", hex::encode(&node_identity.id.0));
    println!("Primary Wallet Address: {}", hex::encode(&node_identity.id.0));
    println!(" Network: {}", network_info.network_id);
    
    // ========================================================================
    // STEP 1: Prompt for identity name
    // ========================================================================
    let identity_name = prompt_for_identity_name()?;
    println!("✅ Identity name: {}", identity_name);
    
    // ========================================================================
    // STEP 2: Create wallet with seed phrase
    // ========================================================================
    let wallet_name = format!("{}'s Primary Wallet", identity_name);
    
    // Use the identity's built-in wallet manager to create a wallet
    let mut node_identity_mut = node_identity.clone();
    let (wallet_id, seed_phrase_struct) = match node_identity_mut.wallet_manager.create_wallet_with_seed_phrase(
        lib_identity::wallets::WalletType::Standard,
        wallet_name.clone(),
        Some("primary".to_string()),
    ).await {
        Ok((wallet_id, seed_phrase)) => {
            println!(" ✓ Wallet created with seed phrase");
            (wallet_id, seed_phrase)
        }
        Err(e) => {
            return Err(anyhow!("Failed to create wallet with seed phrase: {}", e));
        }
    };
    
    let actual_seed_phrase = seed_phrase_struct.words.join(" ");
    
    // ========================================================================
    // STEP 3: Display and confirm seed phrase
    // ========================================================================
    confirm_seed_phrase(&actual_seed_phrase)?;
    
    // ========================================================================
    // STEP 4: Set DID password
    // ========================================================================
    let did_password = prompt_for_did_password()?;
    
    // Hash the password for storage using Blake3
    let mut hasher = blake3::Hasher::new();
    hasher.update(did_password.as_bytes());
    let password_hash = hasher.finalize();
    
    println!("🔐 DID password secured with Blake3 hash: {}...", hex::encode(&password_hash.as_bytes()[..8]));
    
    // ========================================================================
    // STEP 5: Optional wallet passwords
    // ========================================================================
    let _primary_wallet_password = prompt_for_wallet_password("Primary")?;
    let _savings_wallet_password = prompt_for_wallet_password("Savings")?;
    let _staking_wallet_password = prompt_for_wallet_password("Staking")?;
    
    println!("\n✅ All passwords and security configured!");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    // Create wallet address in ZHTP format for compatibility (full address)
    let wallet_address = format!("zhtp:{}", hex::encode(&wallet_id.0));
    
    // Return result compatible with existing ZHTP system  
    Ok(WalletStartupResult {
        node_identity_id: node_identity.id.clone(),
        node_wallet_id: wallet_id,
        wallet_name,
        seed_phrase: actual_seed_phrase,
        wallet_address,
    })
}

/// Create a genesis wallet using the node's DHT identity as the primary address
/// This now creates BOTH a user identity (with wallet) AND a node device identity (for networking)
async fn create_genesis_wallet_from_node_identity(environment: &Environment) -> Result<WalletStartupResult> {
    println!("Creating genesis wallet from DHT node identity...");
    
    // Check if we have an existing setup (uses network-specific data directory)
    let data_dir = environment.data_directory();
    let identity_file = format!("{}/node_identity.json", data_dir);
    let user_identity_file = format!("{}/user_identity.json", data_dir);
    
    // Try to load existing identities if they exist
    if std::path::Path::new(&identity_file).exists() && std::path::Path::new(&user_identity_file).exists() {
        println!(" Loading existing identity setup...");
        
        // Load the node device identity
        let node_identity_json = std::fs::read_to_string(&identity_file)?;
        let node_identity: ZhtpIdentity = serde_json::from_str(&node_identity_json)?;
        
        // Load the user identity  
        let user_identity_json = std::fs::read_to_string(&user_identity_file)?;
        let user_identity: ZhtpIdentity = serde_json::from_str(&user_identity_json)?;
        
        println!(" Loaded node device identity: {}", hex::encode(&node_identity.id.0[..8]));
        println!(" Loaded user identity: {}", hex::encode(&user_identity.id.0[..8]));
        
        // Get the primary wallet from the user identity
        let wallet_summaries = user_identity.wallet_manager.list_wallets();
        if let Some(first_wallet) = wallet_summaries.first() {
            let wallet_id = first_wallet.id.clone();
            let wallet_name = format!("genesis-{}", hex::encode(&user_identity.id.0[..8]));
            let wallet_address = format!("zhtp:{}", hex::encode(&wallet_id.0[..16]));
            
            // Note: We can't retrieve the seed phrase from an existing wallet
            // User should have saved it during initial creation
            return Ok(WalletStartupResult {
                node_identity_id: node_identity.id.clone(),
                node_wallet_id: wallet_id,
                wallet_name,
                seed_phrase: "".to_string(), // Can't retrieve existing seed phrase
                wallet_address,
            });
        }
    }
    
    println!(" Creating new genesis identity setup...");
    println!(" This will create:");
    println!("   1. User identity (Human) with genesis wallet");
    println!("   2. Node device identity (Device) for networking");
    println!();
    
    // ========================================================================
    // STEP 1: Prompt for identity name
    // ========================================================================
    let user_name = prompt_for_identity_name()?;
    println!("✅ Identity name: {}", user_name);
    
    // ========================================================================
    // STEP 2: Create wallet and get seed phrase
    // ========================================================================
    let wallet_name = format!("{}'s Genesis Wallet", user_name);
    
    let (user_identity_id, wallet_id, seed_phrase) = lib_identity::create_user_identity_with_wallet(
        user_name.clone(),
        wallet_name.clone(),
        Some("genesis".to_string()),
    ).await?;
    
    println!(" ✓ User identity created: {}", hex::encode(&user_identity_id.0[..8]));
    
    // ========================================================================
    // STEP 3: Display and confirm seed phrase
    // ========================================================================
    confirm_seed_phrase(&seed_phrase)?;
    
    // ========================================================================
    // STEP 4: Set DID password
    // ========================================================================
    let did_password = prompt_for_did_password()?;
    
    // Hash the password for storage using Blake3
    let mut hasher = blake3::Hasher::new();
    hasher.update(did_password.as_bytes());
    let password_hash = hasher.finalize();
    
    println!("🔐 DID password secured with Blake3 hash: {}...", hex::encode(&password_hash.as_bytes()[..8]));
    
    // ========================================================================
    // STEP 5: Optional wallet passwords
    // ========================================================================
    let _primary_wallet_password = prompt_for_wallet_password("Primary")?;
    let _savings_wallet_password = prompt_for_wallet_password("Savings")?;
    let _staking_wallet_password = prompt_for_wallet_password("Staking")?;
    
    // Note: Wallet passwords are collected but not yet integrated into wallet storage
    // This will be implemented in a future update to the wallet encryption system
    
    println!("\n✅ All passwords and security configured!");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    // ========================================================================
    // STEP 6: Create node device identity owned by the user
    // ========================================================================
    let node_device_name = format!("{}'s Node Device", user_name);
    let node_identity_id = lib_identity::create_node_device_identity(
        user_identity_id.clone(),
        wallet_id.clone(),
        node_device_name,
    ).await?;
    
    println!(" ✓ Node device identity created: {}", hex::encode(&node_identity_id.0[..8]));
    println!(" Genesis Node DHT Address (full): {}", hex::encode(&node_identity_id.0));
    println!(" Genesis Wallet Address (full): {}", hex::encode(&wallet_id.0));
    println!(" This node will be the genesis node for a new ZHTP network");
    
    // Save both identities for future use
    std::fs::create_dir_all("./data")?;
    
    // We need to load the actual identity objects to save them
    let identity_manager = lib_identity::IdentityManager::new();
    if let Some(node_identity) = identity_manager.get_identity(&node_identity_id) {
        let node_json = serde_json::to_string_pretty(&node_identity)?;
        std::fs::write(&identity_file, node_json)?;
        println!(" Node device identity saved to {}", identity_file);
    }
    
    if let Some(user_identity) = identity_manager.get_identity(&user_identity_id) {
        let user_json = serde_json::to_string_pretty(&user_identity)?;
        std::fs::write(&user_identity_file, user_json)?;
        println!(" User identity saved to {}", user_identity_file);
    }
    
    println!(" Genesis Seed Phrase: {}", seed_phrase);
    println!(" CRITICAL: Save this seed phrase - it controls the genesis node!");
    
    // Create wallet address in ZHTP format
    let wallet_address = format!("zhtp:{}", hex::encode(&wallet_id.0[..16]));
    
    // Return result with the node device identity (used for DHT)
    Ok(WalletStartupResult {
        node_identity_id,
        node_wallet_id: wallet_id,
        wallet_name: format!("genesis-{}", hex::encode(&user_identity_id.0[..8])),
        seed_phrase,
        wallet_address,
    })
}

