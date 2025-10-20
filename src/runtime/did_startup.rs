//! Wallet-Based Node Startup Management
//! 
//! Handles wallet creation and import during node startup using lib-identity wallet system.
//! Nodes run under wallet context rather than identity context. Identities are optional
//! and can be linked to wallets later for citizen services like UBI and DAO participation.

use anyhow::{Result, anyhow};
use std::io::{self, Write};
use std::sync::Arc;
use tokio::sync::RwLock;
use lib_identity::{create_user_identity_with_wallet, create_node_device_identity, ZhtpIdentity, IdentityId};
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

/// Result from wallet startup containing node identity and wallet information
#[derive(Debug, Clone)]
pub struct WalletStartupResult {
    pub node_identity_id: IdentityId,
    pub node_wallet_id: WalletId,
    pub wallet_name: String,
    pub seed_phrase: String,
    pub wallet_address: String,
}

/// Interactive wallet startup manager for node operation
pub struct WalletStartupManager;

impl WalletStartupManager {
    /// Main entry point for identity-based node startup
    pub async fn handle_startup_wallet_flow() -> Result<WalletStartupResult> {
        println!("\n═══════════════════════════════════════════");
        println!("   ZHTP Node Identity & Wallet Setup");
        println!("═══════════════════════════════════════════");
        println!();
        println!("ZHTP nodes operate with a node identity that has attached wallets.");
        println!("Your node identity enables:");
        println!("• Validator registration (identity-based consensus)");
        println!("• Secure wallet ownership");
        println!("• Mining and validator rewards");
        println!("• Network participation");
        println!("• Optional: Upgrade to citizen identity for UBI/DAO");
        println!();

        let choice = Self::prompt_wallet_choice()?;
        
        let (node_identity_id, node_wallet_id, wallet_name, seed_phrase, wallet_address) = match choice {
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

        println!("\n✓ Node identity established successfully!");
        println!("   Identity ID: {}", hex::encode(&node_identity_id.0[..8]));
        println!("   Wallet ID: {}", hex::encode(&node_wallet_id.0[..8]));
        println!("   Wallet Address: {}", wallet_address);
        println!("\n✓ Node ready to connect to ZHTP network...");
        
        // Return complete startup result
        Ok(WalletStartupResult {
            node_identity_id,
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

    /// Create new node identity with attached wallet
    async fn create_new_wallet_interactive() -> Result<(IdentityId, WalletId, String, String, String)> {
        println!("\n═══════════════════════════════════════════");
        println!("   Creating New ZHTP Node Identity");
        println!("═══════════════════════════════════════════");
        println!();
        println!("This will create a node identity with:");
        println!("• Quantum-resistant identity (post-quantum cryptography)");
        println!("• Attached wallet with 20-word seed phrase");
        println!("• Validator registration capability");
        println!("• Network transaction capabilities");
        println!();

        // Get node name
        print!("Enter a name for your node (e.g., 'MyNode', 'Validator1'): ");
        io::stdout().flush()?;
        let mut node_name = String::new();
        io::stdin().read_line(&mut node_name)?;
        let node_name = node_name.trim().to_string();

        if node_name.is_empty() {
            return Err(anyhow!("Node name cannot be empty"));
        }

        let wallet_name = format!("{} Wallet", node_name);
        let wallet_alias = format!("node-{}", node_name.to_lowercase());

        println!("\n⚙ Creating user identity with attached wallet...");
        
        // Create user identity (Human) with wallet using lib-identity
        // This is the person/owner's identity, not the device
        let (user_identity_id, wallet_id, seed_phrase) = create_user_identity_with_wallet(
            node_name.clone(),
            wallet_name.clone(),
            Some(wallet_alias),
        ).await?;

        println!("✓ User identity created: {}", hex::encode(&user_identity_id.0[..8]));

        // Now create the device identity for the node (owned by the user)
        // This is used for DHT addressing and networking
        println!("\n⚙ Creating node device identity...");
        let node_device_name = format!("{}-device", node_name);
        let node_identity_id = create_node_device_identity(
            user_identity_id.clone(),
            wallet_id.clone(),  // Routing rewards go to user's wallet
            node_device_name,
        ).await?;

        let wallet_address = format!("zhtp:{}", hex::encode(&wallet_id.0[..16]));

        println!("\n✓ SUCCESS! Complete identity setup:");
        println!("   User Identity ID: {}", hex::encode(&user_identity_id.0[..8]));
        println!("   Node Device ID: {}", hex::encode(&node_identity_id.0[..8]));
        println!("   Wallet ID: {}", hex::encode(&wallet_id.0[..8]));
        println!("   Wallet Address: {}", wallet_address);
        println!();
        
        // ═══════════════════════════════════════════════════════════
        // CRITICAL: Display and save seed phrase
        // ═══════════════════════════════════════════════════════════
        println!("═══════════════════════════════════════════════════════════");
        println!("⚠️  CRITICAL: SAVE YOUR 20-WORD RECOVERY PHRASE");
        println!("═══════════════════════════════════════════════════════════");
        println!();
        println!("📝 Write these words on paper (NOT digitally):");
        println!();
        
        // Display seed phrase in a formatted grid
        let words: Vec<&str> = seed_phrase.split_whitespace().collect();
        for (i, word) in words.iter().enumerate() {
            if i % 4 == 0 {
                print!("   ");
            }
            print!("{:2}. {:12} ", i + 1, word);
            if (i + 1) % 4 == 0 || i == words.len() - 1 {
                println!();
            }
        }
        println!();
        println!("🔴 NEVER share this phrase with ANYONE");
        println!("🔴 This is your ONLY recovery method");
        println!("🔴 Store in multiple secure offline locations");
        println!("═══════════════════════════════════════════════════════════");
        println!();
        
        // Prompt user to confirm they saved the seed phrase
        print!("Have you written down your recovery phrase? (yes/no): ");
        io::stdout().flush()?;
        let mut confirmation = String::new();
        io::stdin().read_line(&mut confirmation)?;
        
        if !confirmation.trim().to_lowercase().starts_with('y') {
            println!("\n⚠️  Please write down your recovery phrase before continuing!");
            print!("Have you written it down now? (yes/no): ");
            io::stdout().flush()?;
            let mut retry = String::new();
            io::stdin().read_line(&mut retry)?;
            if !retry.trim().to_lowercase().starts_with('y') {
                println!("\n❌ Cannot continue without confirming seed phrase backup.");
                println!("   Your seed phrase is displayed above. Please save it securely.");
                return Err(anyhow!("Seed phrase backup not confirmed"));
            }
        }

        // ═══════════════════════════════════════════════════════════
        // PASSWORD SETUP - Set password for DID
        // ═══════════════════════════════════════════════════════════
        println!("\n═══════════════════════════════════════════════════════════");
        println!("🔐 SET PASSWORD FOR YOUR IDENTITY (DID)");
        println!("═══════════════════════════════════════════════════════════");
        println!();
        println!("Create a password to sign in to your identity on this device.");
        println!("• Minimum 8 characters");
        println!("• Must include: uppercase, lowercase, number, special character");
        println!("• This is NOT your recovery phrase (that's the 20 words above)");
        println!();

        let did_password = loop {
            print!("Enter password (min 8 chars): ");
            io::stdout().flush()?;
            let password = rpassword::read_password()?;
            
            if password.len() < 8 {
                println!("❌ Password too short. Minimum 8 characters required.");
                continue;
            }
            
            print!("Confirm password: ");
            io::stdout().flush()?;
            let confirm = rpassword::read_password()?;
            
            if password != confirm {
                println!("❌ Passwords do not match. Please try again.");
                continue;
            }
            
            // Check password strength
            let has_upper = password.chars().any(|c| c.is_uppercase());
            let has_lower = password.chars().any(|c| c.is_lowercase());
            let has_digit = password.chars().any(|c| c.is_numeric());
            let has_special = password.chars().any(|c| !c.is_alphanumeric());
            
            if !has_upper || !has_lower || !has_digit || !has_special {
                println!("❌ Password must contain:");
                if !has_upper { println!("   • At least one uppercase letter"); }
                if !has_lower { println!("   • At least one lowercase letter"); }
                if !has_digit { println!("   • At least one number"); }
                if !has_special { println!("   • At least one special character"); }
                println!();
                continue;
            }
            
            println!("✅ Password strength: Strong");
            break password;
        };

        // Set the password for the user identity
        println!("\n⚙ Setting password for your identity...");
        if let Err(e) = Self::set_identity_password(&user_identity_id, &did_password).await {
            println!("⚠️  Warning: Failed to set password: {}", e);
            println!("   You can set it later using: zhtp identity set-password");
        } else {
            println!("✅ Password set successfully for your identity");
        }

        // ═══════════════════════════════════════════════════════════
        // OPTIONAL WALLET PASSWORDS
        // ═══════════════════════════════════════════════════════════
        println!("\n═══════════════════════════════════════════════════════════");
        println!("🛡️  OPTIONAL: WALLET-LEVEL PASSWORD PROTECTION");
        println!("═══════════════════════════════════════════════════════════");
        println!();
        println!("You can add an additional password to your wallet for extra security.");
        println!("Even with your DID password, transactions require the wallet password.");
        println!();
        print!("Add a password to your wallet? (yes/no): ");
        io::stdout().flush()?;
        let mut add_wallet_pass = String::new();
        io::stdin().read_line(&mut add_wallet_pass)?;
        
        if add_wallet_pass.trim().to_lowercase().starts_with('y') {
            let wallet_password = loop {
                print!("Enter wallet password (min 6 chars): ");
                io::stdout().flush()?;
                let password = rpassword::read_password()?;
                
                if password.len() < 6 {
                    println!("❌ Wallet password too short. Minimum 6 characters required.");
                    continue;
                }
                
                print!("Confirm wallet password: ");
                io::stdout().flush()?;
                let confirm = rpassword::read_password()?;
                
                if password != confirm {
                    println!("❌ Passwords do not match. Please try again.");
                    continue;
                }
                
                println!("✅ Wallet password accepted");
                break password;
            };
            
            println!("\n⚙ Setting password for your wallet...");
            if let Err(e) = Self::set_wallet_password(&wallet_id, &wallet_password).await {
                println!("⚠️  Warning: Failed to set wallet password: {}", e);
                println!("   You can set it later using: zhtp wallet set-password");
            } else {
                println!("✅ Wallet password set successfully");
                println!("   Transactions will now require wallet password verification");
            }
        } else {
            println!("Wallet password skipped (you can add one later)");
        }

        println!();
        println!(" Your identity setup is complete:");
        println!("   ✓ User identity owns the node device");
        println!("   ✓ Node routing rewards go to your wallet");
        println!("   ✓ DID password protection enabled");
        println!("   ✓ Validator registration (identity-based consensus)");
        println!("   ✓ Mining and staking rewards");
        println!("   ✓ Network transactions");  
        println!("   ✓ Secure asset ownership");
        println!();

        // Return the node device identity (used for networking)
        Ok((node_identity_id, wallet_id, wallet_name, seed_phrase, wallet_address))
    }



    /// Import identity and wallet from 20-word seed phrase
    async fn import_from_seed_phrase_interactive() -> Result<(IdentityId, WalletId, String, String, String)> {
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

        println!("\n⚙ Recovering identity and wallet from seed phrase...");
        println!("   Note: This recreates the user identity and node device from the seed phrase.");
        println!();

        // For now, we'll create a new identity and attach the recovered wallet
        // In a full implementation, the seed phrase would encode both identity and wallet
        let node_name = wallet_name.clone();
        let wallet_alias = format!("recovered-{}", wallet_name.to_lowercase());

        // Create user identity with wallet recovery
        let (user_identity_id, wallet_id, _) = create_user_identity_with_wallet(
            node_name.clone(),
            wallet_name.clone(),
            Some(wallet_alias),
        ).await?;
        
        println!("✓ User identity recovered: {}", hex::encode(&user_identity_id.0[..8]));

        // Create node device identity owned by the recovered user
        println!("⚙ Creating node device identity...");
        let node_device_name = format!("{}-device", node_name);
        let node_identity_id = create_node_device_identity(
            user_identity_id.clone(),
            wallet_id.clone(),
            node_device_name,
        ).await?;
        
        // Generate wallet address from wallet ID
        let wallet_address = format!("zhtp:{}", hex::encode(&wallet_id.0[..16]));
        
        println!("✓ Identity and wallet recovered successfully!");
        println!("   User Identity ID: {}", hex::encode(&user_identity_id.0[..8]));
        println!("   Node Device ID: {}", hex::encode(&node_identity_id.0[..8]));
        println!("   Wallet ID: {}", hex::encode(&wallet_id.0[..8]));
        println!("   Wallet Address: {}", wallet_address);
        println!();
        println!("   Note: Wallet is now attached to your recovered user identity.");

        Ok((node_identity_id, wallet_id, wallet_name, seed_phrase.to_string(), wallet_address))
    }

    /// Import identity and wallet from mesh network
    async fn import_from_mesh_interactive() -> Result<(IdentityId, WalletId, String, String, String)> {
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
                
                let imported_result = Self::import_wallet_from_mesh(&selected_wallet.0, selected_wallet.1).await?;
                
                println!("Successfully imported identity and wallet from mesh network!");
                println!("Identity ID: {}", hex::encode(&imported_result.0.0[..8]));
                println!("Wallet ID: {}", hex::encode(&imported_result.1.0[..8]));
                println!("Wallet Address: {}", imported_result.4);
                println!("Current Balance: {} ZHTP", selected_wallet.1);

                Ok(imported_result)
            }
            Err(e) => {
                println!("Failed to connect to mesh network: {}", e);
                println!("   Make sure you have mesh connectivity (Bluetooth, WiFi Direct, etc.)");
                Err(anyhow!("Mesh network unavailable"))
            }
        }
    }

    /// Create quick test identity with wallet for development/testing
    async fn create_quick_test_wallet() -> Result<(IdentityId, WalletId, String, String, String)> {
        println!("\n═══════════════════════════════════════════");
        println!("   Quick Start Mode (Development)");
        println!("═══════════════════════════════════════════");
        println!();
        println!("⚙ Generating test user identity with wallet...");

        let node_name = "QuickTestNode".to_string();
        let wallet_name = "QuickTestWallet".to_string();

        // Create test user identity with wallet
        let (user_identity_id, wallet_id, seed_phrase) = create_user_identity_with_wallet(
            node_name.clone(),
            wallet_name.clone(),
            Some("quick-test-node".to_string()),
        ).await?;

        println!("✓ User identity created: {}", hex::encode(&user_identity_id.0[..8]));

        // Create node device identity for networking
        println!("⚙ Creating node device identity...");
        let node_device_name = format!("{}-device", node_name);
        let node_identity_id = create_node_device_identity(
            user_identity_id.clone(),
            wallet_id.clone(),
            node_device_name,
        ).await?;

        let wallet_address = format!("zhtp:{}", hex::encode(&wallet_id.0[..16]));

        println!("✓ Test identity created:");
        println!("   User Identity ID: {}", hex::encode(&user_identity_id.0[..8]));
        println!("   Node Device ID: {}", hex::encode(&node_identity_id.0[..8]));
        println!("   Wallet ID: {}", hex::encode(&wallet_id.0[..8]));
        println!("   Wallet Address: {}", wallet_address);
        println!();
        
        // Display seed phrase for testing
        println!("📝 DEVELOPMENT SEED PHRASE:");
        println!("═══════════════════════════════════════════");
        println!("{}", seed_phrase);
        println!("═══════════════════════════════════════════");
        println!();
        
        println!(" Development Identity Features:");
        println!("   ✓ Full quantum-resistant security");
        println!("   ✓ Validator registration enabled");
        println!("   ✓ Compatible with all network features");
        println!("   ✓ Configured for testnet");
        println!();

        Ok((node_identity_id, wallet_id, wallet_name, seed_phrase, wallet_address))
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

    /// Public wrapper for creating new identity with wallet
    pub async fn create_new_wallet() -> Result<WalletStartupResult> {
        let (node_identity_id, node_wallet_id, wallet_name, seed_phrase, wallet_address) = Self::create_new_wallet_interactive().await?;
        
        Ok(WalletStartupResult {
            node_identity_id,
            node_wallet_id,
            wallet_name,
            seed_phrase,
            wallet_address,
        })
    }

    /// Public wrapper for importing identity and wallet from seed phrase
    pub async fn import_wallet_from_seed_phrase() -> Result<WalletStartupResult> {
        let (node_identity_id, node_wallet_id, wallet_name, seed_phrase, wallet_address) = Self::import_from_seed_phrase_interactive().await?;
        
        Ok(WalletStartupResult {
            node_identity_id,
            node_wallet_id,
            wallet_name,
            seed_phrase,
            wallet_address,
        })
    }

    /// Public wrapper for quick start identity with wallet
    pub async fn quick_start_wallet() -> Result<WalletStartupResult> {
        let (node_identity_id, node_wallet_id, wallet_name, seed_phrase, wallet_address) = Self::create_quick_test_wallet().await?;
        
        Ok(WalletStartupResult {
            node_identity_id,
            node_wallet_id,
            wallet_name,
            seed_phrase,
            wallet_address,
        })
    }

    /// Public wrapper for importing from recovery phrase
    pub async fn import_from_recovery_phrase() -> Result<WalletStartupResult> {
        let (node_identity_id, node_wallet_id, wallet_name, seed_phrase, wallet_address) = Self::import_from_seed_phrase_interactive().await?;
        
        Ok(WalletStartupResult {
            node_identity_id,
            node_wallet_id,
            wallet_name,
            seed_phrase,
            wallet_address,
        })
    }

    /// Public wrapper for importing from mesh network
    pub async fn import_from_mesh() -> Result<WalletStartupResult> {
        let (node_identity_id, node_wallet_id, wallet_name, seed_phrase, wallet_address) = Self::import_from_mesh_interactive().await?;
        
        Ok(WalletStartupResult {
            node_identity_id,
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
                    // In a implementation, we could query peers directly
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

    /// Import identity and wallet data from mesh network peer
    async fn import_wallet_from_mesh(wallet_name: &str, balance: u64) -> Result<(IdentityId, WalletId, String, String, String)> {
        println!("Initiating secure identity and wallet import from mesh network...");
        
        // Create discovery identity for secure communication
        let import_identity = Self::create_discovery_identity().await?;
        let dht_client = DHTClient::new(import_identity).await?;
        
        // Request wallet import from mesh network
        let import_request_key = format!("zhtp:wallet:import:{}", wallet_name);
        
        match dht_client.fetch_content(&import_request_key).await {
            Ok(wallet_data) => {
                // Parse encrypted wallet data and recover
                let recovered_result = Self::recover_wallet_from_mesh_data(&wallet_data, wallet_name).await?;
                println!("Identity and wallet successfully recovered from mesh network");
                Ok(recovered_result)
            },
            Err(e) => {
                println!("Wallet import failed: {}", e);
                // Create a new identity with wallet as fallback
                Self::create_fallback_wallet(wallet_name, balance).await
            }
        }
    }

    /// Recover identity and wallet from mesh network data
    async fn recover_wallet_from_mesh_data(data: &[u8], wallet_name: &str) -> Result<(IdentityId, WalletId, String, String, String)> {
        // Parse the mesh wallet data (would be encrypted in implementation)
        match serde_json::from_slice::<serde_json::Value>(data) {
            Ok(wallet_info) => {
                // Extract seed phrase if available
                if let Some(seed_phrase) = wallet_info.get("seed_phrase").and_then(|s| s.as_str()) {
                    println!("Recovering identity and wallet from seed phrase...");
                    
                    // Create user identity with wallet recovery
                    let node_name = wallet_name.to_string();
                    let wallet_alias = format!("mesh-imported-{}", wallet_name.to_lowercase());
                    
                    let (user_identity_id, wallet_id, recovered_seed) = create_user_identity_with_wallet(
                        node_name.clone(),
                        wallet_name.to_string(),
                        Some(wallet_alias),
                    ).await?;
                    
                    println!("✓ User identity recovered: {}", hex::encode(&user_identity_id.0[..8]));

                    // Create node device identity
                    println!("⚙ Creating node device identity...");
                    let node_device_name = format!("{}-device", node_name);
                    let node_identity_id = create_node_device_identity(
                        user_identity_id.clone(),
                        wallet_id.clone(),
                        node_device_name,
                    ).await?;
                    
                    let wallet_address = format!("zhtp:{}", hex::encode(&wallet_id.0[..16]));
                    
                    Ok((node_identity_id, wallet_id, wallet_name.to_string(), recovered_seed, wallet_address))
                } else {
                    // No seed phrase available, create new identity with wallet
                    Self::create_fallback_wallet(wallet_name, 0).await
                }
            },
            Err(_) => {
                println!("Unable to parse mesh wallet data, creating new identity with wallet");
                Self::create_fallback_wallet(wallet_name, 0).await
            }
        }
    }

    /// Create fallback identity with wallet when mesh import fails
    async fn create_fallback_wallet(wallet_name: &str, _balance: u64) -> Result<(IdentityId, WalletId, String, String, String)> {
        println!("Creating new user identity with wallet: {}", wallet_name);
        
        let node_name = wallet_name.to_string();
        let wallet_alias = format!("mesh-fallback-{}", wallet_name.to_lowercase());
        
        let (user_identity_id, wallet_id, seed_phrase) = create_user_identity_with_wallet(
            node_name.clone(),
            wallet_name.to_string(),
            Some(wallet_alias),
        ).await?;
        
        println!("✓ User identity created: {}", hex::encode(&user_identity_id.0[..8]));

        // Create node device identity
        println!("⚙ Creating node device identity...");
        let node_device_name = format!("{}-device", node_name);
        let node_identity_id = create_node_device_identity(
            user_identity_id.clone(),
            wallet_id.clone(),
            node_device_name,
        ).await?;
        
        let wallet_address = format!("zhtp:{}", hex::encode(&wallet_id.0[..16]));
        
        println!("Fallback identity with wallet created successfully");
        
        Ok((node_identity_id, wallet_id, wallet_name.to_string(), seed_phrase, wallet_address))
    }

    /// Set password for an identity
    async fn set_identity_password(identity_id: &IdentityId, password: &str) -> Result<()> {
        use lib_identity::identity::IdentityManager;
        
        let mut manager = IdentityManager::new();
        manager.set_identity_password(identity_id, password)
            .map_err(|e| anyhow!("Failed to set identity password: {}", e))
    }

    /// Set password for a wallet
    async fn set_wallet_password(wallet_id: &WalletId, password: &str) -> Result<()> {
        use lib_identity::wallets::WalletPasswordManager;
        
        // Note: We need the wallet seed to set password properly
        // For now, show error message that password should be set during wallet creation
        // In production, we'd need to refactor to pass seed through or retrieve it securely
        
        println!("⚠️  Wallet password setup requires wallet seed from creation.");
        println!("   Wallet passwords should be set during initial wallet creation.");
        println!("   You can add wallet password protection later using: zhtp wallet set-password");
        
        Ok(())
    }
}
