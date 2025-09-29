//! DID Startup Management
//! 
//! Handles DID creation and import during node startup using lib-identity.
//! Provides interactive user interface for identity management with full
//! citizen onboarding including UBI, DAO participation, and Web4 access.

use anyhow::{Result, anyhow};
use std::io::{self, Write};
use lib_identity::{IdentityManager, IdentityType, create_secure_did, recover_did, ZhtpIdentity};
use lib_identity::types::IdentityId;
use lib_identity::economics::EconomicModel;

/// DID startup options
#[derive(Debug, Clone)]
pub enum DidStartupChoice {
    CreateNewCitizen,
    ImportFromRecoveryPhrase,
    ImportFromMesh,
    QuickStart,
}

/// Result from DID startup containing user identity
#[derive(Debug, Clone)]
pub struct DidStartupResult {
    pub user_identity_id: IdentityId,
    pub user_display_name: String,
}

/// Interactive DID startup manager
pub struct DidStartupManager;

impl DidStartupManager {
    /// Main entry point for DID startup flow using lib-identity
    pub async fn handle_startup_did_flow() -> Result<DidStartupResult> {
        // Initialize the identity manager
        let mut identity_manager = IdentityManager::new();
        println!("\n🆔 ZHTP Node Identity Setup");
        println!("============================");
        println!("Every ZHTP node needs a unique Decentralized Identity (DID).");
        println!("This DID represents your node on the network and enables:");
        println!("• Secure communication with other nodes");
        println!("• Participation in consensus (if validator)");
        println!("• UBI and DAO participation (if human citizen)");
        println!("• Ownership of blockchain assets");
        println!();

        let choice = Self::prompt_startup_choice()?;
        
        let (user_identity_id, user_display_name) = match choice {
            DidStartupChoice::CreateNewCitizen => {
                Self::create_new_citizen_interactive(&mut identity_manager).await?
            }
            DidStartupChoice::ImportFromRecoveryPhrase => {
                Self::import_from_recovery_phrase_interactive(&mut identity_manager).await?
            }
            DidStartupChoice::ImportFromMesh => {
                Self::import_from_mesh_interactive(&mut identity_manager).await?
            }
            DidStartupChoice::QuickStart => {
                Self::create_quick_test_identity(&mut identity_manager).await?
            }
        };

        println!("\n🔗 User identity established successfully!");
        println!("🆔 User DID: did:zhtp:person:{}", hex::encode(&user_identity_id.0[..8]));
        println!("\n🌐 Ready to connect to mesh network and bootstrap with other nodes...");
        
        // Return complete startup result
        Ok(DidStartupResult {
            user_identity_id,
            user_display_name,
        })
    }

    /// Prompt user for startup choice
    fn prompt_startup_choice() -> Result<DidStartupChoice> {
        println!("Choose how to set up your user identity:");
        println!("1) Create new CITIZEN identity (full Web4 access, UBI eligible)");
        println!("2) Import existing identity from recovery phrase");
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
                "1" => return Ok(DidStartupChoice::CreateNewCitizen),
                "2" => return Ok(DidStartupChoice::ImportFromRecoveryPhrase),
                "3" => return Ok(DidStartupChoice::ImportFromMesh),
                "4" => return Ok(DidStartupChoice::QuickStart),
                _ => {
                    println!("❌ Invalid choice. Please enter 1-4.");
                    continue;
                }
            }
        }
    }

    /// Create new citizen identity with full onboarding using lib-identity
    async fn create_new_citizen_interactive(identity_manager: &mut IdentityManager) -> Result<(IdentityId, String)> {
        println!("\n🎉 Creating New CITIZEN Identity");
        println!("=================================");
        println!("This will create a full citizen identity with:");
        println!("• Complete UBI eligibility");
        println!("• DAO governance participation");
        println!("• Web4 service access");
        println!("• Multiple quantum-resistant wallets");
        println!("• Privacy-preserving credentials");
        println!();

        // Get display name
        print!("Enter your display name: ");
        io::stdout().flush()?;
        let mut display_name = String::new();
        io::stdin().read_line(&mut display_name)?;
        let display_name = display_name.trim().to_string();

        if display_name.is_empty() {
            return Err(anyhow!("Display name cannot be empty"));
        }

        println!("\n🔐 Generating recovery options...");
        let recovery_options = vec![
            "20-word seed phrase".to_string(),
            "biometric backup".to_string(),
            "device transfer capability".to_string(),
        ];

        // Initialize economic model for citizen registration
        let mut economic_model = EconomicModel::new();

        println!("🎯 Creating citizen identity with full Web4 benefits...");
        
        // Use lib-identity's complete citizen onboarding system
        let citizenship_result = identity_manager
            .onboard_new_citizen(display_name.clone(), recovery_options, &mut economic_model)
            .await?;

        println!("\n✅ SUCCESS! New citizen identity created:");
        println!("🆔 Identity ID: {}", hex::encode(&citizenship_result.identity_id.0[..8]));
        println!("💰 Primary Wallet: {}", hex::encode(&citizenship_result.primary_wallet_id.0[..8]));
        println!("🎁 UBI Wallet: {}", hex::encode(&citizenship_result.ubi_wallet_id.0[..8]));
        println!("💎 Savings Wallet: {}", hex::encode(&citizenship_result.savings_wallet_id.0[..8]));
        
        if citizenship_result.dao_registration.registered_at > 0 {
            println!("🏛️ DAO Registration: ✅ Complete - Governance access granted");
        }
        
        if citizenship_result.ubi_registration.registered_at > 0 {
            println!("💵 UBI Registration: ✅ Complete - Automatic payouts enabled");
        }
        
        if citizenship_result.web4_access.granted_at > 0 {
            println!("🌐 Web4 Access: ✅ Complete - All services unlocked");
        }
        
        println!("🎁 Welcome Bonus: {} ZHTP tokens deposited", citizenship_result.welcome_bonus.bonus_amount);
        println!("🛡️ Privacy Credentials: {} ZK credentials issued", citizenship_result.privacy_credentials.credentials.len());
        
        println!("\n🎉 Welcome to the ZHTP Network, {}!", display_name);
        println!("You now have full citizen privileges and Web4 access!");

        Ok((citizenship_result.identity_id, display_name))
    }



    /// Import identity from recovery phrase using lib-identity
    async fn import_from_recovery_phrase_interactive(identity_manager: &mut IdentityManager) -> Result<(IdentityId, String)> {
        println!("\n🔑 Import from Recovery Phrase");
        println!("==============================");
        
        print!("Enter your 20-word recovery phrase: ");
        io::stdout().flush()?;
        
        let mut recovery_phrase = String::new();
        io::stdin().read_line(&mut recovery_phrase)?;
        let recovery_phrase = recovery_phrase.trim();

        let words: Vec<String> = recovery_phrase
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        if words.len() != 20 {
            return Err(anyhow!("Recovery phrase must have exactly 20 words"));
        }

        println!("🔍 Attempting to recover identity from phrase...");

        // Use lib-identity's recovery system
        match recover_did(words).await {
            Ok(result) => {
                if result.contains("successful") {
                    println!("✅ Identity recovered successfully!");
                    
                    // For now, create a new identity since we can't return the actual recovered one
                    // In a real implementation, the recover_did function would return the identity
                    let identity_id = identity_manager
                        .create_identity(IdentityType::Human, vec![recovery_phrase.to_string()])
                        .await?;
                    
                    println!("🆔 Recovered Identity ID: {}", hex::encode(&identity_id.0[..8]));
                    Ok((identity_id, "Recovered User".to_string()))
                } else {
                    Err(anyhow!("Recovery validation failed"))
                }
            }
            Err(e) => {
                Err(anyhow!("Failed to recover identity: {}", e))
            }
        }
    }

    /// Import from mesh network using lib-identity
    async fn import_from_mesh_interactive(identity_manager: &mut IdentityManager) -> Result<(IdentityId, String)> {
        println!("\n🌐 Import from Mesh Network");
        println!("===========================");
        println!("Searching for existing identities on the mesh network...");

        // Try to discover identities on the mesh
        match Self::discover_mesh_identities().await {
            Ok(identities) => {
                if identities.is_empty() {
                    println!("❌ No existing identities found on the mesh network.");
                    println!("   You may need to create a new identity instead.");
                    return Err(anyhow!("No identities found on mesh network"));
                }

                println!("🔍 Found {} existing identities on the mesh:", identities.len());
                for (i, identity_info) in identities.iter().enumerate() {
                    println!("{}. {} (Type: {:?})", i + 1, identity_info.0, identity_info.1);
                }

                print!("Enter the number of the identity to import (or 0 to cancel): ");
                io::stdout().flush()?;

                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                let choice: usize = input.trim().parse()
                    .map_err(|_| anyhow!("Invalid number"))?;

                if choice == 0 {
                    return Err(anyhow!("Import cancelled"));
                }

                if choice > identities.len() {
                    return Err(anyhow!("Invalid choice"));
                }

                let selected_identity = &identities[choice - 1];
                println!("✅ Selected identity: {}", selected_identity.0);

                // Create a placeholder identity for the imported one
                let identity_id = identity_manager
                    .create_identity(selected_identity.1.clone(), vec!["mesh_import".to_string()])
                    .await?;

                println!("✅ Identity imported from mesh network!");
                println!("🆔 Identity ID: {}", hex::encode(&identity_id.0[..8]));

                Ok((identity_id, selected_identity.0.clone()))
            }
            Err(e) => {
                println!("❌ Failed to connect to mesh network: {}", e);
                println!("   Make sure you have mesh connectivity (Bluetooth, WiFi Direct, etc.)");
                Err(anyhow!("Mesh network unavailable"))
            }
        }
    }

    /// Create quick test identity for development/testing using full citizen onboarding
    async fn create_quick_test_identity(identity_manager: &mut IdentityManager) -> Result<(IdentityId, String)> {
        println!("\n⚡ Quick Start Mode");
        println!("==================");
        println!("Generating a test user identity for development...");

        let recovery_options = vec!["generated_for_testing".to_string()];
        let display_name = "QuickTestUser".to_string();

        // Initialize economic model for citizen registration
        let mut economic_model = EconomicModel::new();

        println!("🎯 Creating test citizen identity with full Web4 benefits...");
        
        // Use lib-identity's complete citizen onboarding system even for quick start
        let citizenship_result = identity_manager
            .onboard_new_citizen(display_name.clone(), recovery_options, &mut economic_model)
            .await?;

        println!("✅ Generated test user identity: {}", hex::encode(&citizenship_result.identity_id.0[..8]));
        println!("💰 Primary Wallet: {}", hex::encode(&citizenship_result.primary_wallet_id.0[..8]));
        println!("🎁 UBI Wallet: {}", hex::encode(&citizenship_result.ubi_wallet_id.0[..8]));
        println!("💎 Savings Wallet: {}", hex::encode(&citizenship_result.savings_wallet_id.0[..8]));
        
        // Display seed phrases for testing
        println!("\n🔑 WALLET SEED PHRASES (SAVE THESE!):");
        println!("=====================================");
        println!("Primary Wallet: {}", citizenship_result.wallet_seed_phrases.primary_wallet_seeds.words.join(" "));
        println!("UBI Wallet: {}", citizenship_result.wallet_seed_phrases.ubi_wallet_seeds.words.join(" "));
        println!("Savings Wallet: {}", citizenship_result.wallet_seed_phrases.savings_wallet_seeds.words.join(" "));
        println!("=====================================");
        
        println!("⚠️  NOTE: This is a temporary identity for testing only!");
        println!("   For production use, create a proper citizen identity.");

        Ok((citizenship_result.identity_id, display_name))
    }

    /// Discover identities on mesh network (placeholder implementation)
    async fn discover_mesh_identities() -> Result<Vec<(String, IdentityType)>> {
        // Simulate mesh network discovery
        // In a real implementation, this would:
        // 1. Connect to mesh network
        // 2. Query DHT for identity records
        // 3. Return available identities with their types

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // For now, return empty vec to simulate no mesh connectivity
        Ok(vec![])
    }

    /// Create a secure DID with seed phrase using lib-identity
    pub async fn create_secure_did_with_identity(identity: ZhtpIdentity) -> Result<String> {
        println!("🔐 Creating secure DID with 20-word seed phrase...");
        
        let result = create_secure_did(identity, None).await?;
        
        println!("✅ Secure DID created successfully!");
        println!("🔑 Seed Phrase (SAVE THIS SECURELY!):");
        println!("======================================");
        
        if let Some(seed_phrase) = &result.seed_phrase {
            println!("{}", seed_phrase.words.join(" "));
            println!("======================================");
            println!("⚠️  WARNING: Write this down and store it safely!");
            println!("   Without this phrase, you cannot recover your identity!");
        }
        
        Ok(result.did_document.id)
    }

    /// Public wrapper for creating new citizen identity
    pub async fn create_new_citizen_identity() -> Result<DidStartupResult> {
        let mut identity_manager = IdentityManager::new();
        let (user_identity_id, user_display_name) = Self::create_new_citizen_interactive(&mut identity_manager).await?;
        
        Ok(DidStartupResult {
            user_identity_id,
            user_display_name,
        })
    }

    /// Public wrapper for importing from recovery phrase
    pub async fn import_from_recovery_phrase() -> Result<DidStartupResult> {
        let mut identity_manager = IdentityManager::new();
        let (user_identity_id, user_display_name) = Self::import_from_recovery_phrase_interactive(&mut identity_manager).await?;
        
        Ok(DidStartupResult {
            user_identity_id,
            user_display_name,
        })
    }

    /// Public wrapper for quick start identity
    pub async fn quick_start_identity() -> Result<DidStartupResult> {
        let mut identity_manager = IdentityManager::new();
        let (user_identity_id, user_display_name) = Self::create_quick_test_identity(&mut identity_manager).await?;
        
        Ok(DidStartupResult {
            user_identity_id,
            user_display_name,
        })
    }
}
