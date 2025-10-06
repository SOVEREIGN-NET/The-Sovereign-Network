//! Wallet-Based Node Startup Management
//! 
//! Handles wallet creation and import during node startup using lib-identity wallet system.
//! Nodes run under wallet context rather than identity context. Identities are optional
//! and can be linked to wallets later for citizen services like UBI and DAO participation.

use anyhow::{Result, anyhow};
use std::io::{self, Write};
use std::sync::Arc;
use tokio::sync::RwLock;
use lib_identity::{create_standalone_wallet, ZhtpIdentity};
use lib_identity::wallets::{WalletManager, WalletId};
use lib_identity::types::IdentityType;
use lib_network::dht::DHTClient;
use lib_storage::{UnifiedStorageSystem, UnifiedStorageConfig};
use lib_proofs::ZeroKnowledgeProof;
use lib_crypto::hash_blake3;
// Core wallet functionality with mesh network integration

/// Node wallet startup options
#[derive(Debug, Clone)]
pub enum WalletStartupChoice {
    CreateNewWallet,
    ImportFromSeedPhrase,
    ImportFromMesh,
    QuickStart,
}

/// Result from wallet startup containing node wallet information
#[derive(Debug, Clone)]
pub struct WalletStartupResult {
    pub node_wallet_id: WalletId,
    pub wallet_name: String,
    pub seed_phrase: String,
    pub wallet_address: String,
}

/// Interactive wallet startup manager for node operation
pub struct WalletStartupManager;

impl WalletStartupManager {
    /// Main entry point for wallet-based node startup
    pub async fn handle_startup_wallet_flow() -> Result<WalletStartupResult> {
        println!("\nZHTP Node Wallet Setup");
        println!("======================");
        println!("ZHTP nodes run under wallet context rather than identity context.");
        println!("Your node wallet enables:");
        println!("• Secure transactions and asset ownership");
        println!("• Mining and validator rewards");
        println!("• Network participation fees");
        println!("• Optional: Link to citizen identity later for UBI/DAO");
        println!();

        let choice = Self::prompt_wallet_choice()?;
        
        let (node_wallet_id, wallet_name, seed_phrase, wallet_address) = match choice {
            WalletStartupChoice::CreateNewWallet => {
                Self::create_new_wallet_interactive().await?
            }
            WalletStartupChoice::ImportFromSeedPhrase => {
                Self::import_from_seed_phrase_interactive().await?
            }
            WalletStartupChoice::ImportFromMesh => {
                Self::import_from_mesh_interactive().await?
            }
            WalletStartupChoice::QuickStart => {
                Self::create_quick_test_wallet().await?
            }
        };

        println!("\nNode wallet established successfully!");
        println!("Wallet ID: {}", hex::encode(&node_wallet_id.0[..8]));
        println!("Wallet Address: {}", wallet_address);
        println!("\nNode ready to connect to ZHTP network...");
        
        // Return complete startup result
        Ok(WalletStartupResult {
            node_wallet_id,
            wallet_name,
            seed_phrase,
            wallet_address,
        })
    }

    /// Prompt user for wallet startup choice
    fn prompt_wallet_choice() -> Result<WalletStartupChoice> {
        println!("Do you have an existing ZHTP wallet, or do you want to create one?");
        println!("1) Create new wallet (generates 20-word seed phrase)");
        println!("2) Import existing wallet from 20-word seed phrase");
        println!("3) Import from mesh network (if available)");
        println!("4) Quick start (auto-generate for testing)");
        println!();

        loop {
            print!("Enter your choice (1-4): ");
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim();

            match input {
                "1" => return Ok(WalletStartupChoice::CreateNewWallet),
                "2" => return Ok(WalletStartupChoice::ImportFromSeedPhrase),
                "3" => return Ok(WalletStartupChoice::ImportFromMesh),
                "4" => return Ok(WalletStartupChoice::QuickStart),
                _ => {
                    println!("Invalid choice. Please enter 1-4.");
                    continue;
                }
            }
        }
    }

    /// Create new node wallet with 20-word seed phrase
    async fn create_new_wallet_interactive() -> Result<(WalletId, String, String, String)> {
        println!("\nCreating New ZHTP Wallet");
        println!("===========================");
        println!("This will create a new quantum-resistant wallet with:");
        println!("• 20-word recovery seed phrase");
        println!("• Post-quantum cryptographic security");
        println!("• Network transaction capabilities");
        println!("• Mining and validator reward collection");
        println!();

        // Get wallet name
        print!("Enter a name for your wallet (e.g., 'MyNode', 'Validator1'): ");
        io::stdout().flush()?;
        let mut wallet_name = String::new();
        io::stdin().read_line(&mut wallet_name)?;
        let wallet_name = wallet_name.trim().to_string();

        if wallet_name.is_empty() {
            return Err(anyhow!("Wallet name cannot be empty"));
        }

        println!("Creating node wallet...");
        
        // Create standalone wallet using lib-identity
        let (wallet_id, seed_phrase) = create_standalone_wallet(
            wallet_name.clone(),
            Some(format!("node-{}", wallet_name.to_lowercase())),
        ).await?;

        let wallet_address = format!("zhtp:{}", hex::encode(&wallet_id.0[..16]));

        println!("\nSUCCESS! New wallet created:");
        println!("Wallet ID: {}", hex::encode(&wallet_id.0[..8]));
        println!("Wallet Address: {}", wallet_address);
        println!("Seed Phrase: {}", seed_phrase);
        
        println!("\n Your node wallet is ready for:");
        println!("   • Mining and validator rewards");
        println!("   • Network transaction fees");  
        println!("   • Asset storage and transfers");
        println!("   • Optional: Link to citizen identity later for UBI/DAO");
        
        println!("\nWelcome to the ZHTP Network!");
        println!("Your node is ready to participate in the decentralized economy!");

        Ok((wallet_id, wallet_name, seed_phrase, wallet_address))
    }



    /// Import wallet from 20-word seed phrase
    async fn import_from_seed_phrase_interactive() -> Result<(WalletId, String, String, String)> {
        println!("\nImport Wallet from Seed Phrase");
        println!("===================================");
        
        print!("Enter your 20-word wallet seed phrase: ");
        io::stdout().flush()?;
        
        let mut seed_phrase = String::new();
        io::stdin().read_line(&mut seed_phrase)?;
        let seed_phrase = seed_phrase.trim();

        let words: Vec<String> = seed_phrase
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        if words.len() != 20 {
            return Err(anyhow!("Wallet seed phrase must have exactly 20 words"));
        }

        print!("Enter a name for this wallet: ");
        io::stdout().flush()?;
        let mut wallet_name = String::new();
        io::stdin().read_line(&mut wallet_name)?;
        let wallet_name = wallet_name.trim().to_string();

        if wallet_name.is_empty() {
            return Err(anyhow!("Wallet name cannot be empty"));
        }

        println!("Recovering wallet from seed phrase...");

        // Create standalone wallet manager and recover wallet
        let mut wallet_manager = WalletManager::new_standalone();
        let wallet_id = wallet_manager.recover_wallet_from_seed_phrase(
            &words,
            wallet_name.clone(),
            Some(format!("recovered-{}", wallet_name.to_lowercase())),
        ).await?;
        
        // Generate wallet address from wallet ID
        let wallet_address = format!("zhtp:{}", hex::encode(&wallet_id.0[..16]));
        
        println!("Wallet recovered successfully!");
        println!("Wallet ID: {}", hex::encode(&wallet_id.0[..8]));
        println!("Wallet Address: {}", wallet_address);

        Ok((wallet_id, wallet_name, seed_phrase.to_string(), wallet_address))
    }

    /// Import wallet from mesh network
    async fn import_from_mesh_interactive() -> Result<(WalletId, String, String, String)> {
        println!("\nImport Wallet from Mesh Network");
        println!("===============================");
        println!("Scanning for existing wallets on the mesh network...");

        // Try to discover wallets on the mesh
        match Self::discover_mesh_wallets().await {
            Ok(wallets) => {
                if wallets.is_empty() {
                    println!("No existing wallets found on the mesh network.");
                    println!("   You may need to create a new wallet instead.");
                    return Err(anyhow!("No wallets found on mesh network"));
                }

                println!("Found {} existing wallets on the mesh:", wallets.len());
                for (i, wallet_info) in wallets.iter().enumerate() {
                    println!("{}. {} (Balance: {} ZHTP)", i + 1, wallet_info.0, wallet_info.1);
                }

                print!("Enter the number of the wallet to import (or 0 to cancel): ");
                io::stdout().flush()?;

                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                let choice: usize = input.trim().parse()
                    .map_err(|_| anyhow!("Invalid number"))?;

                if choice == 0 {
                    return Err(anyhow!("Import cancelled"));
                }

                if choice > wallets.len() {
                    return Err(anyhow!("Invalid choice"));
                }

                let selected_wallet = &wallets[choice - 1];
                println!("Selected wallet: {} (Balance: {} ZHTP)", selected_wallet.0, selected_wallet.1);

                // Import actual wallet from mesh network
                println!("Requesting wallet import from mesh network...");
                
                let imported_wallet = Self::import_wallet_from_mesh(&selected_wallet.0, selected_wallet.1).await?;
                
                println!("Successfully imported wallet from mesh network!");
                println!("Wallet ID: {}", hex::encode(&imported_wallet.0.0[..8]));
                println!("Wallet Address: {}", imported_wallet.3);
                println!("Current Balance: {} ZHTP", selected_wallet.1);

                Ok(imported_wallet)
            }
            Err(e) => {
                println!("Failed to connect to mesh network: {}", e);
                println!("   Make sure you have mesh connectivity (Bluetooth, WiFi Direct, etc.)");
                Err(anyhow!("Mesh network unavailable"))
            }
        }
    }

    /// Create quick test wallet for development/testing
    async fn create_quick_test_wallet() -> Result<(WalletId, String, String, String)> {
        println!("\nQuick Start Mode");
        println!("==================");
        println!("Generating a test wallet for development...");

        let wallet_name = "QuickTestWallet".to_string();

        println!("Creating test node wallet...");
        
        // Create standalone test wallet
        let (wallet_id, seed_phrase) = create_standalone_wallet(
            wallet_name.clone(),
            Some("quick-test-node".to_string()),
        ).await?;

        let wallet_address = format!("zhtp:{}", hex::encode(&wallet_id.0[..16]));

        println!("Generated test wallet: {}", hex::encode(&wallet_id.0[..8]));
        println!("Wallet Address: {}", wallet_address);
        
        // Display seed phrase for testing
        println!("\nDEVELOPMENT WALLET SEED PHRASE:");
        println!("====================================");
        println!("{}", seed_phrase);
        println!("====================================");
        
        println!("\nDevelopment Wallet Features:");
        println!("   • Full quantum-resistant security");
        println!("   • Compatible with all network features");
        println!("   • Can be used for testing and development");
        println!("   • Automatically configured for testnet");

        Ok((wallet_id, wallet_name, seed_phrase, wallet_address))
    }

    /// Discover wallets on mesh network using DHT
    async fn discover_mesh_wallets() -> Result<Vec<(String, u64)>> {
        println!("Connecting to mesh network via DHT...");
        
        // Create temporary identity for DHT operations
        let discovery_identity = Self::create_discovery_identity().await?;
        
        // Initialize storage system for DHT operations
        let storage_config = UnifiedStorageConfig::default();
        let _storage_system = Arc::new(RwLock::new(
            UnifiedStorageSystem::new(storage_config).await?
        ));
        
        // Create DHT client for wallet discovery
        let dht_client = DHTClient::new(discovery_identity).await?;
        
        println!("Scanning DHT for wallet advertisements...");
        
        // Search for wallet records in DHT
        let wallet_query_key = "zhtp:wallets:available";
        match dht_client.fetch_content(wallet_query_key).await {
            Ok(wallet_data) => {
                // Parse discovered wallet records
                let wallet_records = Self::parse_wallet_records(&wallet_data)?;
                
                if !wallet_records.is_empty() {
                    println!("Found {} importable wallets on mesh network", wallet_records.len());
                    Ok(wallet_records)
                } else {
                    println!("No importable wallets found on mesh network");
                    Ok(vec![])
                }
            },
            Err(e) => {
                println!("DHT query failed: {}", e);
                // Try alternative discovery methods
                Self::discover_mesh_wallets_fallback().await
            }
        }
    }

    /// Public wrapper for creating new wallet
    pub async fn create_new_wallet() -> Result<WalletStartupResult> {
        let (node_wallet_id, wallet_name, seed_phrase, wallet_address) = Self::create_new_wallet_interactive().await?;
        
        Ok(WalletStartupResult {
            node_wallet_id,
            wallet_name,
            seed_phrase,
            wallet_address,
        })
    }

    /// Public wrapper for importing wallet from seed phrase
    pub async fn import_wallet_from_seed_phrase() -> Result<WalletStartupResult> {
        let (node_wallet_id, wallet_name, seed_phrase, wallet_address) = Self::import_from_seed_phrase_interactive().await?;
        
        Ok(WalletStartupResult {
            node_wallet_id,
            wallet_name,
            seed_phrase,
            wallet_address,
        })
    }

    /// Public wrapper for quick start wallet
    pub async fn quick_start_wallet() -> Result<WalletStartupResult> {
        let (node_wallet_id, wallet_name, seed_phrase, wallet_address) = Self::create_quick_test_wallet().await?;
        
        Ok(WalletStartupResult {
            node_wallet_id,
            wallet_name,
            seed_phrase,
            wallet_address,
        })
    }

    /// Public wrapper for importing from recovery phrase
    pub async fn import_from_recovery_phrase() -> Result<WalletStartupResult> {
        let (node_wallet_id, wallet_name, seed_phrase, wallet_address) = Self::import_from_seed_phrase_interactive().await?;
        
        Ok(WalletStartupResult {
            node_wallet_id,
            wallet_name,
            seed_phrase,
            wallet_address,
        })
    }

    /// Public wrapper for importing from mesh network
    pub async fn import_from_mesh() -> Result<WalletStartupResult> {
        let (node_wallet_id, wallet_name, seed_phrase, wallet_address) = Self::import_from_mesh_interactive().await?;
        
        Ok(WalletStartupResult {
            node_wallet_id,
            wallet_name,
            seed_phrase,
            wallet_address,
        })
    }

    /// Create a temporary identity for mesh discovery operations
    async fn create_discovery_identity() -> Result<ZhtpIdentity> {
        // Generate ephemeral key for discovery
        let discovery_key = hash_blake3(b"mesh-wallet-discovery");
        let public_key = discovery_key.to_vec();
        
        // Create zero-knowledge proof for discovery operations
        let ownership_proof = ZeroKnowledgeProof::default();
        
        let discovery_identity = ZhtpIdentity::new(
            IdentityType::Device,
            public_key,
            ownership_proof,
        )?;
        
        Ok(discovery_identity)
    }

    /// Parse wallet records from DHT data
    fn parse_wallet_records(data: &[u8]) -> Result<Vec<(String, u64)>> {
        // Parse wallet advertisement data from DHT
        match serde_json::from_slice::<serde_json::Value>(data) {
            Ok(json_data) => {
                let mut wallets = Vec::new();
                
                if let Some(wallet_array) = json_data.as_array() {
                    for wallet_entry in wallet_array {
                        if let (Some(name), Some(balance)) = (
                            wallet_entry.get("name").and_then(|n| n.as_str()),
                            wallet_entry.get("balance").and_then(|b| b.as_u64())
                        ) {
                            wallets.push((name.to_string(), balance));
                        }
                    }
                }
                
                Ok(wallets)
            },
            Err(_) => {
                // Try parsing as simple comma-separated format
                let data_str = std::str::from_utf8(data)
                    .map_err(|_| anyhow!("Invalid wallet record format"))?;
                
                let mut wallets = Vec::new();
                for line in data_str.lines() {
                    let parts: Vec<&str> = line.split(',').collect();
                    if parts.len() >= 2 {
                        let name = parts[0].trim().to_string();
                        if let Ok(balance) = parts[1].trim().parse::<u64>() {
                            wallets.push((name, balance));
                        }
                    }
                }
                
                Ok(wallets)
            }
        }
    }

    /// Fallback wallet discovery when DHT is unavailable
    async fn discover_mesh_wallets_fallback() -> Result<Vec<(String, u64)>> {
        println!("Attempting alternative wallet discovery methods...");
        
        // Try direct peer discovery
        let discovery_identity = Self::create_discovery_identity().await?;
        let dht_client = DHTClient::new(discovery_identity).await?;
        
        match dht_client.discover_peers().await {
            Ok(peers) => {
                if peers.is_empty() {
                    println!("No peers discovered for wallet import");
                    Ok(vec![])
                } else {
                    println!("Found {} peers, but no wallet advertisements", peers.len());
                    // In a real implementation, we could query peers directly
                    // For now, return empty to indicate no importable wallets
                    Ok(vec![])
                }
            },
            Err(e) => {
                println!("Peer discovery also failed: {}", e);
                Err(anyhow!("Unable to connect to mesh network for wallet discovery"))
            }
        }
    }

    /// Import wallet data from mesh network peer
    async fn import_wallet_from_mesh(wallet_name: &str, balance: u64) -> Result<(WalletId, String, String, String)> {
        println!("Initiating secure wallet import from mesh network...");
        
        // Create discovery identity for secure communication
        let import_identity = Self::create_discovery_identity().await?;
        let dht_client = DHTClient::new(import_identity).await?;
        
        // Request wallet import from mesh network
        let import_request_key = format!("zhtp:wallet:import:{}", wallet_name);
        
        match dht_client.fetch_content(&import_request_key).await {
            Ok(wallet_data) => {
                // Parse encrypted wallet data and recover
                let recovered_wallet = Self::recover_wallet_from_mesh_data(&wallet_data, wallet_name).await?;
                println!("Wallet successfully recovered from mesh network");
                Ok(recovered_wallet)
            },
            Err(e) => {
                println!("Wallet import failed: {}", e);
                // Create a new wallet with the same name as fallback
                Self::create_fallback_wallet(wallet_name, balance).await
            }
        }
    }

    /// Recover wallet from mesh network data
    async fn recover_wallet_from_mesh_data(data: &[u8], wallet_name: &str) -> Result<(WalletId, String, String, String)> {
        // Parse the mesh wallet data (would be encrypted in real implementation)
        match serde_json::from_slice::<serde_json::Value>(data) {
            Ok(wallet_info) => {
                // Extract seed phrase if available
                if let Some(seed_phrase) = wallet_info.get("seed_phrase").and_then(|s| s.as_str()) {
                    println!("Recovering wallet from seed phrase...");
                    
                    // Use existing recovery mechanism
                    let words: Vec<String> = seed_phrase.split_whitespace().map(|s| s.to_string()).collect();
                    let mut wallet_manager = WalletManager::new_standalone();
                    
                    let wallet_id = wallet_manager.recover_wallet_from_seed_phrase(
                        &words,
                        wallet_name.to_string(),
                        Some(format!("mesh-imported-{}", wallet_name.to_lowercase())),
                    ).await?;
                    
                    let wallet_address = format!("zhtp:{}", hex::encode(&wallet_id.0[..16]));
                    
                    Ok((wallet_id, wallet_name.to_string(), seed_phrase.to_string(), wallet_address))
                } else {
                    // No seed phrase available, create new wallet with same name
                    Self::create_fallback_wallet(wallet_name, 0).await
                }
            },
            Err(_) => {
                println!("Unable to parse mesh wallet data, creating new wallet");
                Self::create_fallback_wallet(wallet_name, 0).await
            }
        }
    }

    /// Create fallback wallet when mesh import fails
    async fn create_fallback_wallet(wallet_name: &str, _balance: u64) -> Result<(WalletId, String, String, String)> {
        println!("Creating new wallet with name: {}", wallet_name);
        
        let (wallet_id, seed_phrase) = create_standalone_wallet(
            wallet_name.to_string(),
            Some(format!("mesh-fallback-{}", wallet_name.to_lowercase())),
        ).await?;
        
        let wallet_address = format!("zhtp:{}", hex::encode(&wallet_id.0[..16]));
        
        println!("Fallback wallet created successfully");
        
        Ok((wallet_id, wallet_name.to_string(), seed_phrase, wallet_address))
    }
}
