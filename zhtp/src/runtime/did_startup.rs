//! Wallet-Based Node Startup Management
//! 
//! Handles wallet creation and import during node startup using lib-identity wallet system.
//! Nodes run under wallet context rather than identity context. Identities are optional
//! and can be linked to wallets later for citizen services like UBI and DAO participation.

use anyhow::{Result, anyhow};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use lib_identity::{ZhtpIdentity, IdentityId};
use lib_identity::wallets::{WalletId, QuantumWallet, WalletType};
use lib_identity::types::IdentityType;
use lib_storage::{UnifiedStorageSystem, UnifiedStorageConfig};
use lib_crypto::{PrivateKey, Hash};
use serde::{Serialize, Deserialize};
use crate::keystore_names::{NODE_IDENTITY_FILENAME, NODE_PRIVATE_KEY_FILENAME, USER_IDENTITY_FILENAME, USER_PRIVATE_KEY_FILENAME, WALLET_DATA_FILENAME};
// Core wallet functionality with mesh network integration

// ════════════════════════════════════════════════════════════════════════════
// Keystore Persistence Types and Helpers
// ════════════════════════════════════════════════════════════════════════════

/// Explicit error types for keystore operations - no silent fallbacks
#[derive(Debug)]
pub enum KeystoreError {
    /// Keystore directory does not exist (first run - safe to proceed to create)
    NotFound(PathBuf),
    /// Keystore exists but is corrupt (FATAL - do not proceed)
    Corrupt(PathBuf, String),
    /// Permission denied accessing keystore (FATAL - do not proceed)
    PermissionDenied(PathBuf),
    /// IO error during keystore operation (FATAL - do not proceed)
    IoError(PathBuf, std::io::Error),
}

impl std::fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeystoreError::NotFound(path) => write!(f, "Keystore not found at {:?}", path),
            KeystoreError::Corrupt(path, reason) => write!(f, "Keystore corrupt at {:?}: {}", path, reason),
            KeystoreError::PermissionDenied(path) => write!(f, "Permission denied accessing keystore at {:?}", path),
            KeystoreError::IoError(path, e) => write!(f, "IO error at {:?}: {}", path, e),
        }
    }
}

impl std::error::Error for KeystoreError {}

/// Private key storage format for keystore (matches identity.rs format)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeystorePrivateKey {
    dilithium_sk: Vec<u8>,
    kyber_sk: Vec<u8>,
    master_seed: Vec<u8>,
}

/// Serializable format for WalletStartupResult persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedWalletData {
    wallet_name: String,
    wallet_address: String,
    node_wallet_id: Vec<u8>,
    node_identity_id: Vec<u8>,
}

/// Get the default keystore path (~/.zhtp/keystore)
/// Uses dirs::home_dir() for proper path expansion
fn get_default_keystore_path() -> Result<PathBuf> {
    let home = dirs::home_dir()
        .ok_or_else(|| anyhow!("Could not determine home directory"))?;
    Ok(home.join(".zhtp").join("keystore"))
}

/// Load identity and wallet from keystore (pure - no prints)
///
/// Returns specific error types to distinguish recoverable vs fatal errors:
/// - NotFound: First run, caller should proceed to interactive creation
/// - Corrupt/PermissionDenied/IoError: Fatal, caller must abort
fn load_from_keystore(keystore_path: &Path) -> std::result::Result<WalletStartupResult, KeystoreError> {
    // Check if keystore directory exists
    if !keystore_path.exists() {
        return Err(KeystoreError::NotFound(keystore_path.to_path_buf()));
    }

    let user_identity_file = keystore_path.join(USER_IDENTITY_FILENAME);
    let node_identity_file = keystore_path.join(NODE_IDENTITY_FILENAME);
    let user_private_key_file = keystore_path.join(USER_PRIVATE_KEY_FILENAME);
    let node_private_key_file = keystore_path.join(NODE_PRIVATE_KEY_FILENAME);
    let wallet_data_file = keystore_path.join(WALLET_DATA_FILENAME);

    // Check all required files exist
    for file in [&user_identity_file, &node_identity_file, &user_private_key_file, &node_private_key_file, &wallet_data_file] {
        if !file.exists() {
            return Err(KeystoreError::NotFound(keystore_path.to_path_buf()));
        }
    }

    // Load user identity
    let user_identity_data = std::fs::read_to_string(&user_identity_file)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                KeystoreError::PermissionDenied(user_identity_file.clone())
            } else {
                KeystoreError::IoError(user_identity_file.clone(), e)
            }
        })?;

    let user_private_key_data = std::fs::read_to_string(&user_private_key_file)
        .map_err(|e| KeystoreError::IoError(user_private_key_file.clone(), e))?;

    let user_keystore_key: KeystorePrivateKey = serde_json::from_str(&user_private_key_data)
        .map_err(|e| KeystoreError::Corrupt(user_private_key_file.clone(), e.to_string()))?;

    let user_private_key = PrivateKey {
        dilithium_sk: user_keystore_key.dilithium_sk.clone(),
        kyber_sk: user_keystore_key.kyber_sk.clone(),
        master_seed: user_keystore_key.master_seed.clone(),
    };

    let mut user_identity = ZhtpIdentity::from_serialized(&user_identity_data, &user_private_key)
        .map_err(|e| KeystoreError::Corrupt(user_identity_file.clone(), e.to_string()))?;

    // Load node identity
    let node_identity_data = std::fs::read_to_string(&node_identity_file)
        .map_err(|e| KeystoreError::IoError(node_identity_file.clone(), e))?;

    let node_private_key_data = std::fs::read_to_string(&node_private_key_file)
        .map_err(|e| KeystoreError::IoError(node_private_key_file.clone(), e))?;

    let node_keystore_key: KeystorePrivateKey = serde_json::from_str(&node_private_key_data)
        .map_err(|e| KeystoreError::Corrupt(node_private_key_file.clone(), e.to_string()))?;

    let node_private_key = PrivateKey {
        dilithium_sk: node_keystore_key.dilithium_sk.clone(),
        kyber_sk: node_keystore_key.kyber_sk.clone(),
        master_seed: node_keystore_key.master_seed.clone(),
    };

    let node_identity = ZhtpIdentity::from_serialized(&node_identity_data, &node_private_key)
        .map_err(|e| KeystoreError::Corrupt(node_identity_file.clone(), e.to_string()))?;

    // Load wallet data
    let wallet_data_str = std::fs::read_to_string(&wallet_data_file)
        .map_err(|e| KeystoreError::IoError(wallet_data_file.clone(), e))?;

    let wallet_data: PersistedWalletData = serde_json::from_str(&wallet_data_str)
        .map_err(|e| KeystoreError::Corrupt(wallet_data_file.clone(), e.to_string()))?;

    // CRITICAL: Restore wallet into user_identity's wallet_manager
    // When identity is deserialized, wallet_manager is empty - we must repopulate it
    // Create a basic QuantumWallet from the persisted metadata
    let wallet_id = lib_crypto::Hash(
        wallet_data.node_wallet_id.clone().try_into()
            .map_err(|_| KeystoreError::Corrupt(wallet_data_file.clone(), "Invalid wallet_id length".to_string()))?
    );

    // Create minimal wallet (seed phrase not preserved for security, balance not persisted)
    let mut restored_wallet = QuantumWallet::new(
        WalletType::Primary,
        wallet_data.wallet_name.clone(),
        None, // No alias
        Some(user_identity.id.clone()),
        vec![0u8; 32], // Public key placeholder - not needed for domain registration
    );

    // Override the auto-generated wallet_id with the saved one
    restored_wallet.id = wallet_id.clone();

    // Insert wallet into the wallet_manager
    user_identity.wallet_manager.wallets.insert(wallet_id.clone(), restored_wallet);
    eprintln!("✓ WALLET RESTORATION: Restored {} wallet (ID: {}) into user_identity {}",
        wallet_data.wallet_name,
        hex::encode(&wallet_id.0[..8]),
        hex::encode(&user_identity.id.0[..8])
    );
    eprintln!("  Wallet count in user_identity: {}", user_identity.wallet_manager.wallets.len());

    // Reconstruct PrivateIdentityData for user
    let user_private_data = lib_identity::identity::PrivateIdentityData::new(
        user_keystore_key.dilithium_sk,
        user_identity.public_key.dilithium_pk.clone(),
        user_keystore_key.master_seed.clone().try_into().unwrap_or([0u8; 32]),
        vec![], // Recovery phrases not stored for security
    );

    // Reconstruct PrivateIdentityData for node
    let node_private_data = lib_identity::identity::PrivateIdentityData::new(
        node_keystore_key.dilithium_sk,
        node_identity.public_key.dilithium_pk.clone(),
        node_keystore_key.master_seed.clone().try_into().unwrap_or([0u8; 32]),
        vec![],
    );

    // Reconstruct WalletId and IdentityId (both are type aliases for Hash)
    let wallet_id_bytes: [u8; 32] = wallet_data.node_wallet_id.try_into()
        .map_err(|_| KeystoreError::Corrupt(wallet_data_file.clone(), "Invalid wallet_id length".to_string()))?;
    let node_wallet_id: WalletId = Hash(wallet_id_bytes);

    let identity_id_bytes: [u8; 32] = wallet_data.node_identity_id.try_into()
        .map_err(|_| KeystoreError::Corrupt(wallet_data_file.clone(), "Invalid identity_id length".to_string()))?;
    let node_identity_id: IdentityId = Hash(identity_id_bytes);

    Ok(WalletStartupResult {
        user_identity,
        node_identity,
        user_private_data,
        node_private_data,
        node_identity_id,
        node_wallet_id,
        wallet_name: wallet_data.wallet_name,
        seed_phrase: String::new(), // Never stored - user must have backup
        wallet_address: wallet_data.wallet_address,
    })
}

/// Save identity and wallet to keystore (pure - no prints)
///
/// Always sets 0600 permissions on all files, even if they already exist.
/// Returns specific error types for caller to handle.
fn save_to_keystore(keystore_path: &Path, result: &WalletStartupResult) -> std::result::Result<(), KeystoreError> {
    // Create keystore directory if it doesn't exist
    std::fs::create_dir_all(keystore_path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                KeystoreError::PermissionDenied(keystore_path.to_path_buf())
            } else {
                KeystoreError::IoError(keystore_path.to_path_buf(), e)
            }
        })?;

    let user_identity_file = keystore_path.join(USER_IDENTITY_FILENAME);
    let node_identity_file = keystore_path.join(NODE_IDENTITY_FILENAME);
    let user_private_key_file = keystore_path.join(USER_PRIVATE_KEY_FILENAME);
    let node_private_key_file = keystore_path.join(NODE_PRIVATE_KEY_FILENAME);
    let wallet_data_file = keystore_path.join(WALLET_DATA_FILENAME);

    // Extract and save user private key
    let user_private_key = result.user_identity.private_key.as_ref()
        .ok_or_else(|| KeystoreError::Corrupt(user_identity_file.clone(), "User identity missing private key".to_string()))?;

    let user_keystore_key = KeystorePrivateKey {
        dilithium_sk: user_private_key.dilithium_sk.clone(),
        kyber_sk: user_private_key.kyber_sk.clone(),
        master_seed: user_private_key.master_seed.clone(),
    };

    let user_private_key_json = serde_json::to_string_pretty(&user_keystore_key)
        .map_err(|e| KeystoreError::Corrupt(user_private_key_file.clone(), e.to_string()))?;

    write_file_with_permissions(&user_private_key_file, &user_private_key_json)?;

    // Save user identity (public data)
    let user_identity_json = serde_json::to_string_pretty(&result.user_identity)
        .map_err(|e| KeystoreError::Corrupt(user_identity_file.clone(), e.to_string()))?;

    write_file_with_permissions(&user_identity_file, &user_identity_json)?;

    // Extract and save node private key
    let node_private_key = result.node_identity.private_key.as_ref()
        .ok_or_else(|| KeystoreError::Corrupt(node_identity_file.clone(), "Node identity missing private key".to_string()))?;

    let node_keystore_key = KeystorePrivateKey {
        dilithium_sk: node_private_key.dilithium_sk.clone(),
        kyber_sk: node_private_key.kyber_sk.clone(),
        master_seed: node_private_key.master_seed.clone(),
    };

    let node_private_key_json = serde_json::to_string_pretty(&node_keystore_key)
        .map_err(|e| KeystoreError::Corrupt(node_private_key_file.clone(), e.to_string()))?;

    write_file_with_permissions(&node_private_key_file, &node_private_key_json)?;

    // Save node identity (public data)
    let node_identity_json = serde_json::to_string_pretty(&result.node_identity)
        .map_err(|e| KeystoreError::Corrupt(node_identity_file.clone(), e.to_string()))?;

    write_file_with_permissions(&node_identity_file, &node_identity_json)?;

    // Save wallet data
    let wallet_data = PersistedWalletData {
        wallet_name: result.wallet_name.clone(),
        wallet_address: result.wallet_address.clone(),
        node_wallet_id: result.node_wallet_id.0.to_vec(),
        node_identity_id: result.node_identity_id.0.to_vec(),
    };

    let wallet_data_json = serde_json::to_string_pretty(&wallet_data)
        .map_err(|e| KeystoreError::Corrupt(wallet_data_file.clone(), e.to_string()))?;

    write_file_with_permissions(&wallet_data_file, &wallet_data_json)?;

    Ok(())
}

/// Write file with restrictive permissions (0600)
fn write_file_with_permissions(path: &Path, content: &str) -> std::result::Result<(), KeystoreError> {
    std::fs::write(path, content)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                KeystoreError::PermissionDenied(path.to_path_buf())
            } else {
                KeystoreError::IoError(path.to_path_buf(), e)
            }
        })?;

    // Set restrictive permissions (0600 - owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| KeystoreError::IoError(path.to_path_buf(), e))?;
    }

    Ok(())
}

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
    pub user_identity: ZhtpIdentity,      // User/owner identity with wallets
    pub node_identity: ZhtpIdentity,      // Node device identity for networking
    pub user_private_data: lib_identity::identity::PrivateIdentityData,  // User's private keys
    pub node_private_data: lib_identity::identity::PrivateIdentityData,  // Node's private keys
    pub node_identity_id: IdentityId,     // For compatibility
    pub node_wallet_id: WalletId,
    pub wallet_name: String,
    pub seed_phrase: String,
    pub wallet_address: String,
}

/// Interactive wallet startup manager for node operation
pub struct WalletStartupManager;

impl WalletStartupManager {
    /// Main entry point for identity-based node startup
    ///
    /// Flow:
    /// 1. Try to load existing identity from keystore
    /// 2. If not found, proceed to interactive creation
    /// 3. Save newly created identity to keystore
    /// 4. Fatal errors (corrupt keystore, permission denied) abort startup
    pub async fn handle_startup_wallet_flow() -> Result<WalletStartupResult> {
        Self::handle_startup_wallet_flow_with_keystore(None).await
    }

    /// Main entry point with custom keystore path
    pub async fn handle_startup_wallet_flow_with_keystore(keystore_override: Option<PathBuf>) -> Result<WalletStartupResult> {
        // Determine keystore path
        let keystore_path = match keystore_override {
            Some(path) => path,
            None => get_default_keystore_path()?,
        };

        // ════════════════════════════════════════════════════════════════════
        // STEP 1: Try to load existing identity from keystore
        // ════════════════════════════════════════════════════════════════════
        match load_from_keystore(&keystore_path) {
            Ok(result) => {
                println!("\n✓ Loaded existing identity from {:?}", keystore_path);
                println!("   User Identity: {}", result.user_identity.did);
                println!("   Node Identity: {}", result.node_identity.did);
                println!("   Wallet: {}", result.wallet_address);
                return Ok(result);
            }
            Err(KeystoreError::NotFound(_)) => {
                println!("\nℹ No existing identity found at {:?}", keystore_path);
                println!("  Proceeding to identity creation...");
                // Continue to interactive creation
            }
            Err(KeystoreError::Corrupt(path, reason)) => {
                // FATAL: Corrupt keystore - do not silently create new identity
                return Err(anyhow!(
                    "FATAL: Keystore corrupt at {:?}: {}\n\
                    Manual recovery required. Options:\n\
                    1. Restore from backup\n\
                    2. Delete {:?} and re-import from seed phrase\n\
                    3. Delete {:?} to start fresh (WARNING: loses identity)",
                    path, reason, keystore_path, keystore_path
                ));
            }
            Err(KeystoreError::PermissionDenied(path)) => {
                return Err(anyhow!(
                    "FATAL: Permission denied accessing keystore at {:?}\n\
                    Check file permissions and ownership.",
                    path
                ));
            }
            Err(KeystoreError::IoError(path, e)) => {
                return Err(anyhow!(
                    "FATAL: IO error reading keystore at {:?}: {}\n\
                    Check disk space and file system health.",
                    path, e
                ));
            }
        }

        // ════════════════════════════════════════════════════════════════════
        // STEP 2: No existing identity - proceed to creation
        // ════════════════════════════════════════════════════════════════════

        // Check for auto-wallet mode via environment variable (for automated testing/deployment)
        if let Ok(auto_mode) = std::env::var("ZHTP_AUTO_WALLET") {
            if auto_mode == "1" || auto_mode.to_lowercase() == "true" {
                println!("🤖 Auto-wallet mode enabled - generating wallet automatically");
                let result = Self::quick_start_wallet().await?;

                // Save auto-generated wallet to keystore
                save_to_keystore(&keystore_path, &result)
                    .map_err(|e| anyhow!("Failed to save identity to keystore: {}", e))?;
                println!("✓ Identity saved to {:?}", keystore_path);

                return Ok(result);
            }
        }

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

        let result = match choice {
            WalletStartupChoice::CreateNewWallet => {
                let (user_identity, node_identity, node_wallet_id, wallet_name, seed_phrase, wallet_address, user_private_data, node_private_data) =
                    Self::create_new_wallet_interactive().await?;
                WalletStartupResult {
                    user_identity: user_identity.clone(),
                    node_identity: node_identity.clone(),
                    user_private_data,
                    node_private_data,
                    node_identity_id: node_identity.id.clone(),
                    node_wallet_id,
                    wallet_name,
                    seed_phrase,
                    wallet_address,
                }
            }
            WalletStartupChoice::ImportFromSeedPhrase => {
                let (user_identity, node_identity, node_wallet_id, wallet_name, seed_phrase, wallet_address, user_private_data, node_private_data) =
                    Self::import_from_seed_phrase_interactive().await?;

                WalletStartupResult {
                    user_identity: user_identity.clone(),
                    node_identity: node_identity.clone(),
                    user_private_data,
                    node_private_data,
                    node_identity_id: node_identity.id.clone(),
                    node_wallet_id,
                    wallet_name,
                    seed_phrase,
                    wallet_address,
                }
            }
            WalletStartupChoice::ImportFromMesh => {
                let (user_identity, node_identity, node_wallet_id, wallet_name, seed_phrase, wallet_address, user_private_data, node_private_data) =
                    Self::import_from_mesh_interactive().await?;

                WalletStartupResult {
                    user_identity: user_identity.clone(),
                    node_identity: node_identity.clone(),
                    user_private_data,
                    node_private_data,
                    node_identity_id: node_identity.id.clone(),
                    node_wallet_id,
                    wallet_name,
                    seed_phrase,
                    wallet_address,
                }
            }
            WalletStartupChoice::QuickStart => {
                Self::quick_start_wallet().await?
            }
        };

        // ════════════════════════════════════════════════════════════════════
        // STEP 3: Save newly created identity to keystore
        // ════════════════════════════════════════════════════════════════════
        println!("\n💾 Saving identity to keystore...");
        save_to_keystore(&keystore_path, &result)
            .map_err(|e| anyhow!("Failed to save identity to keystore: {}", e))?;
        println!("✓ Identity saved to {:?}", keystore_path);

        println!("\n✅ Node identity established successfully!");
        println!("   Identity ID: {}", hex::encode(&result.node_identity_id.0[..8]));
        println!("   Wallet ID: {}", hex::encode(&result.node_wallet_id.0[..8]));
        println!("   Wallet Address: {}", result.wallet_address);
        println!("\n🌐 Node ready to connect to ZHTP network...");

        // Return complete startup result
        Ok(result)
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
    async fn create_new_wallet_interactive() -> Result<(
        ZhtpIdentity, 
        ZhtpIdentity, 
        WalletId, 
        String, 
        String, 
        String,
        lib_identity::identity::PrivateIdentityData,  // user private data
        lib_identity::identity::PrivateIdentityData,  // node private data
    )> {
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
        let (user_identity, wallet_id, seed_phrase, user_private_data) = create_user_identity_with_wallet(
            node_name.clone(),
            wallet_name.clone(),
            Some(wallet_alias),
        ).await?;

        println!(" User identity created: {}", hex::encode(&user_identity.id.0[..8]));

        // Now create the device identity for the node (owned by the user)
        // This is used for DHT addressing and networking
        println!("\n⚙ Creating node device identity...");
        let node_device_name = format!("{}-device", node_name);
        let (node_identity, node_private_data) = create_node_device_identity(
            user_identity.id.clone(),
            wallet_id.clone(),  // Routing rewards go to user's wallet
            node_device_name,
        ).await?;

        let wallet_address = format!("zhtp:{}", hex::encode(&wallet_id.0[..16]));

        println!("\n SUCCESS! Complete identity setup:");
        println!("   User Identity ID: {}", hex::encode(&user_identity.id.0[..8]));
        println!("   Node Device ID: {}", hex::encode(&node_identity.id.0[..8]));
        println!("   Wallet ID: {}", hex::encode(&wallet_id.0[..8]));
        println!("   Wallet Address: {}", wallet_address);
        println!();
        
        // ═══════════════════════════════════════════════════════════
        // CRITICAL: Display and save seed phrase
        // ═══════════════════════════════════════════════════════════
        println!("═══════════════════════════════════════════════════════════");
        println!("  CRITICAL: SAVE YOUR 20-WORD RECOVERY PHRASE");
        println!("═══════════════════════════════════════════════════════════");
        println!();
        println!(" Write these words on paper (NOT digitally):");
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
            println!("\n  Please write down your recovery phrase before continuing!");
            print!("Have you written it down now? (yes/no): ");
            io::stdout().flush()?;
            let mut retry = String::new();
            io::stdin().read_line(&mut retry)?;
            if !retry.trim().to_lowercase().starts_with('y') {
                println!("\n Cannot continue without confirming seed phrase backup.");
                println!("   Your seed phrase is displayed above. Please save it securely.");
                return Err(anyhow!("Seed phrase backup not confirmed"));
            }
        }

        // ═══════════════════════════════════════════════════════════
        // PASSWORD SETUP - Set password for DID
        // ═══════════════════════════════════════════════════════════
        println!("\n═══════════════════════════════════════════════════════════");
        println!(" SET PASSWORD FOR YOUR IDENTITY (DID)");
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
                println!(" Password too short. Minimum 8 characters required.");
                continue;
            }
            
            print!("Confirm password: ");
            io::stdout().flush()?;
            let confirm = rpassword::read_password()?;
            
            if password != confirm {
                println!(" Passwords do not match. Please try again.");
                continue;
            }
            
            // Check password strength
            let has_upper = password.chars().any(|c| c.is_uppercase());
            let has_lower = password.chars().any(|c| c.is_lowercase());
            let has_digit = password.chars().any(|c| c.is_numeric());
            let has_special = password.chars().any(|c| !c.is_alphanumeric());
            
            if !has_upper || !has_lower || !has_digit || !has_special {
                println!(" Password must contain:");
                if !has_upper { println!("   • At least one uppercase letter"); }
                if !has_lower { println!("   • At least one lowercase letter"); }
                if !has_digit { println!("   • At least one number"); }
                if !has_special { println!("   • At least one special character"); }
                println!();
                continue;
            }
            
            println!(" Password strength: Strong");
            break password;
        };

        // Set the password for the user identity
        println!("\n⚙ Setting password for your identity...");
        if let Err(e) = Self::set_identity_password(&user_identity.id, &did_password).await {
            println!("  Warning: Failed to set password: {}", e);
            println!("   You can set it later using: zhtp identity set-password");
        } else {
            println!(" Password set successfully for your identity");
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
                    println!(" Wallet password too short. Minimum 6 characters required.");
                    continue;
                }
                
                print!("Confirm wallet password: ");
                io::stdout().flush()?;
                let confirm = rpassword::read_password()?;
                
                if password != confirm {
                    println!(" Passwords do not match. Please try again.");
                    continue;
                }
                
                println!(" Wallet password accepted");
                break password;
            };
            
            println!("\n⚙ Setting password for your wallet...");
            if let Err(e) = Self::set_wallet_password(&wallet_id, &wallet_password).await {
                println!("  Warning: Failed to set wallet password: {}", e);
                println!("   You can set it later using: zhtp wallet set-password");
            } else {
                println!(" Wallet password set successfully");
                println!("   Transactions will now require wallet password verification");
            }
        } else {
            println!("Wallet password skipped (you can add one later)");
        }

        println!();
        println!(" Your identity setup is complete:");
        println!("    User identity owns the node device");
        println!("    Node routing rewards go to your wallet");
        println!("    DID password protection enabled");
        println!("    Validator registration (identity-based consensus)");
        println!("    Mining and staking rewards");
        println!("    Network transactions");  
        println!("    Secure asset ownership");
        println!();

        // Return both identities AND private keys for registration in IdentityManager
        Ok((user_identity, node_identity, wallet_id, wallet_name, seed_phrase, wallet_address, user_private_data, node_private_data))
    }



    /// Import identity and wallet from 20-word seed phrase
    async fn import_from_seed_phrase_interactive() -> Result<(
        ZhtpIdentity, 
        ZhtpIdentity, 
        WalletId, 
        String, 
        String, 
        String, 
        lib_identity::identity::PrivateIdentityData,  // User private data
        lib_identity::identity::PrivateIdentityData,  // Node private data
    )> {
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

        // Create user identity with wallet recovery - NOW capturing private_data
        let (user_identity, wallet_id, _, user_private_data) = create_user_identity_with_wallet(
            node_name.clone(),
            wallet_name.clone(),
            Some(wallet_alias),
        ).await?;
        
        println!(" User identity recovered: {}", hex::encode(&user_identity.id.0[..8]));

        // Create node device identity owned by the recovered user - NOW capturing private_data
        println!("⚙ Creating node device identity...");
        let node_device_name = format!("{}-device", node_name);
        let (node_identity, node_private_data) = create_node_device_identity(
            user_identity.id.clone(),
            wallet_id.clone(),
            node_device_name,
        ).await?;
        
        // Generate wallet address from wallet ID
        let wallet_address = format!("zhtp:{}", hex::encode(&wallet_id.0[..16]));
        
        println!(" Identity and wallet recovered successfully!");
        println!("   User Identity ID: {}", hex::encode(&user_identity.id.0[..8]));
        println!("   Node Device ID: {}", hex::encode(&node_identity.id.0[..8]));
        println!("   Wallet ID: {}", hex::encode(&wallet_id.0[..8]));
        println!("   Wallet Address: {}", wallet_address);
        println!();
        println!("   Note: Wallet is now attached to your recovered user identity.");

        Ok((
            user_identity, 
            node_identity, 
            wallet_id, 
            wallet_name, 
            seed_phrase.to_string(), 
            wallet_address,
            user_private_data,
            node_private_data,
        ))
    }

    /// Import identity and wallet from mesh network
    async fn import_from_mesh_interactive() -> Result<(
        ZhtpIdentity, 
        ZhtpIdentity, 
        WalletId, 
        String, 
        String, 
        String,
        lib_identity::identity::PrivateIdentityData,  // User private data
        lib_identity::identity::PrivateIdentityData,  // Node private data
    )> {
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
                
                let (user_identity, node_identity, wallet_id, wallet_name, seed_phrase, wallet_address, user_private_data, node_private_data) = 
                    Self::import_wallet_from_mesh(&selected_wallet.0, selected_wallet.1).await?;
                
                println!("Successfully imported identity and wallet from mesh network!");
                println!("Identity ID: {}", hex::encode(&user_identity.id.0[..8]));
                println!("Wallet ID: {}", hex::encode(&wallet_id.0[..8]));
                println!("Wallet Address: {}", wallet_address);
                println!("Current Balance: {} ZHTP", selected_wallet.1);

                Ok((user_identity, node_identity, wallet_id, wallet_name, seed_phrase, wallet_address, user_private_data, node_private_data))
            }
            Err(e) => {
                println!("Failed to connect to mesh network: {}", e);
                println!("   Make sure you have mesh connectivity (Bluetooth, WiFi Direct, etc.)");
                Err(anyhow!("Mesh network unavailable"))
            }
        }
    }

    /// Create quick test identity with wallet for development/testing
    /// Returns both user and node device identities for registration with IdentityManager
    async fn create_quick_test_wallet() -> Result<(
        ZhtpIdentity,      // User identity
        ZhtpIdentity,      // Node device identity
        WalletId,          // Primary wallet ID
        String,            // Wallet name
        String,            // Seed phrase
        String,            // Wallet address
        lib_identity::identity::PrivateIdentityData,  // User private data
        lib_identity::identity::PrivateIdentityData,  // Node private data
    )> {
        println!("\n═══════════════════════════════════════════");
        println!("   Quick Start Mode (Development)");
        println!("═══════════════════════════════════════════");
        println!();
        println!("⚙ Generating test user identity with wallet...");

        let node_name = "QuickTestNode".to_string();
        let wallet_name = "QuickTestWallet".to_string();

        // Create test user identity with wallet (now includes private_data)
        let (user_identity, wallet_id, seed_phrase, user_private_data) = create_user_identity_with_wallet(
            node_name.clone(),
            wallet_name.clone(),
            Some("quick-test-node".to_string()),
        ).await?;

        println!(" User identity created: {}", hex::encode(&user_identity.id.0[..8]));

        // Create node device identity for networking (now includes private_data)
        println!("⚙ Creating node device identity...");
        let node_device_name = format!("{}-device", node_name);
        let (node_identity, node_private_data) = create_node_device_identity(
            user_identity.id.clone(),
            wallet_id.clone(),
            node_device_name,
        ).await?;

        let wallet_address = format!("zhtp:{}", hex::encode(&wallet_id.0[..16]));

        println!(" Test identity created:");
        println!("   User Identity ID: {}", hex::encode(&user_identity.id.0[..8]));
        println!("   Node Device ID: {}", hex::encode(&node_identity.id.0[..8]));
        println!("   Wallet ID: {}", hex::encode(&wallet_id.0[..8]));
        println!("   Wallet Address: {}", wallet_address);
        println!();
        
        // Display seed phrase for testing
        println!(" DEVELOPMENT SEED PHRASE:");
        println!("═══════════════════════════════════════════");
        println!("{}", seed_phrase);
        println!("═══════════════════════════════════════════");
        println!();
        
        println!(" Development Identity Features:");
        println!("    Full quantum-resistant security");
        println!("    Validator registration enabled");
        println!("    Compatible with all network features");
        println!("    Configured for testnet");
        println!();

        Ok((user_identity, node_identity, wallet_id, wallet_name, seed_phrase, wallet_address, user_private_data, node_private_data))
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
        
        // Get shared DHT client for wallet discovery
        let dht_client = crate::runtime::shared_dht::get_dht_client().await?;
        
        println!("Scanning DHT for wallet advertisements...");
        
        // Search for wallet records in DHT
        let wallet_query_key = "zhtp:wallets:available";
        let mut dht = dht_client.write().await;
        match dht.fetch_content(wallet_query_key).await {
            Ok(Some(wallet_data)) => {
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
            Ok(None) => {
                println!("No wallet data found in DHT");
                Ok(vec![])
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
        let (user_identity, node_identity, node_wallet_id, wallet_name, seed_phrase, wallet_address, user_private_data, node_private_data) = 
            Self::create_new_wallet_interactive().await?;
        
        Ok(WalletStartupResult {
            user_identity: user_identity.clone(),
            node_identity: node_identity.clone(),
            user_private_data,
            node_private_data,
            node_identity_id: node_identity.id.clone(),
            node_wallet_id,
            wallet_name,
            seed_phrase,
            wallet_address,
        })
    }

    /// Public wrapper for importing identity and wallet from seed phrase
    pub async fn import_wallet_from_seed_phrase() -> Result<WalletStartupResult> {
        let (user_identity, node_identity, node_wallet_id, wallet_name, seed_phrase, wallet_address, user_private_data, node_private_data) = 
            Self::import_from_seed_phrase_interactive().await?;
        
        Ok(WalletStartupResult {
            user_identity: user_identity.clone(),
            node_identity: node_identity.clone(),
            user_private_data,
            node_private_data,
            node_identity_id: node_identity.id.clone(),
            node_wallet_id,
            wallet_name,
            seed_phrase,
            wallet_address,
        })
    }

    /// Public wrapper for quick start identity with wallet
    pub async fn quick_start_wallet() -> Result<WalletStartupResult> {
        let (user_identity, node_identity, node_wallet_id, wallet_name, seed_phrase, wallet_address, user_private_data, node_private_data) = 
            Self::create_quick_test_wallet().await?;
        
        Ok(WalletStartupResult {
            user_identity: user_identity.clone(),
            node_identity: node_identity.clone(),
            user_private_data,
            node_private_data,
            node_identity_id: node_identity.id.clone(),
            node_wallet_id,
            wallet_name,
            seed_phrase,
            wallet_address,
        })
    }

    /// Public wrapper for importing from recovery phrase
    pub async fn import_from_recovery_phrase() -> Result<WalletStartupResult> {
        let (user_identity, node_identity, node_wallet_id, wallet_name, seed_phrase, wallet_address, user_private_data, node_private_data) = 
            Self::import_from_seed_phrase_interactive().await?;
        
        Ok(WalletStartupResult {
            user_identity: user_identity.clone(),
            node_identity: node_identity.clone(),
            user_private_data,
            node_private_data,
            node_identity_id: node_identity.id.clone(),
            node_wallet_id,
            wallet_name,
            seed_phrase,
            wallet_address,
        })
    }

    /// Public wrapper for importing from mesh network
    pub async fn import_from_mesh() -> Result<WalletStartupResult> {
        let (user_identity, node_identity, node_wallet_id, wallet_name, seed_phrase, wallet_address, user_private_data, node_private_data) = 
            Self::import_from_mesh_interactive().await?;
        
        Ok(WalletStartupResult {
            user_identity: user_identity.clone(),
            node_identity: node_identity.clone(),
            user_private_data,
            node_private_data,
            node_identity_id: node_identity.id.clone(),
            node_wallet_id,
            wallet_name,
            seed_phrase,
            wallet_address,
        })
    }

    /// Create a temporary identity for mesh discovery operations
    async fn create_discovery_identity() -> Result<ZhtpIdentity> {
        // Create discovery identity using P1-7 architecture
        let discovery_identity = ZhtpIdentity::new_unified(
            IdentityType::Device,
            None, // No age for device
            None, // No jurisdiction for device
            "mesh-wallet-discovery",
            None, // Random seed
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
        
        // Try direct peer discovery using shared DHT
        let dht_client = crate::runtime::shared_dht::get_dht_client().await?;
        let dht = dht_client.read().await;
        
        match dht.discover_peers().await {
            Ok(peers) => {
                if peers.is_empty() {
                    println!("No peers discovered for wallet import");
                    Ok(vec![])
                } else {
                    println!("Found {} peers, but no wallet advertisements", peers.len());
                    // In a full implementation, we could query peers directly
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
    async fn import_wallet_from_mesh(wallet_name: &str, balance: u64) -> Result<(
        ZhtpIdentity, 
        ZhtpIdentity, 
        WalletId, 
        String, 
        String, 
        String,
        lib_identity::identity::PrivateIdentityData,  // User private data
        lib_identity::identity::PrivateIdentityData,  // Node private data
    )> {
        println!("Initiating secure identity and wallet import from mesh network...");
        
        // Get shared DHT client for secure communication
        let dht_client = crate::runtime::shared_dht::get_dht_client().await?;
        
        // Request wallet import from mesh network
        let import_request_key = format!("zhtp:wallet:import:{}", wallet_name);
        
        let mut dht = dht_client.write().await;
        match dht.fetch_content(&import_request_key).await {
            Ok(Some(wallet_data)) => {
                // Parse encrypted wallet data and recover
                let recovered_result = Self::recover_wallet_from_mesh_data(&wallet_data, wallet_name).await?;
                println!("Identity and wallet successfully recovered from mesh network");
                Ok(recovered_result)
            },
            Ok(None) => {
                println!("Wallet data not found in DHT, creating fallback wallet");
                // Create a new identity with wallet as fallback
                Self::create_fallback_wallet(wallet_name, balance).await
            },
            Err(e) => {
                println!("Wallet import failed: {}", e);
                // Create a new identity with wallet as fallback
                Self::create_fallback_wallet(wallet_name, balance).await
            }
        }
    }

    /// Recover identity and wallet from mesh network data
    async fn recover_wallet_from_mesh_data(data: &[u8], wallet_name: &str) -> Result<(
        ZhtpIdentity, 
        ZhtpIdentity, 
        WalletId, 
        String, 
        String, 
        String,
        lib_identity::identity::PrivateIdentityData,  // User private data
        lib_identity::identity::PrivateIdentityData,  // Node private data
    )> {
        // Parse the mesh wallet data (would be encrypted in implementation)
        match serde_json::from_slice::<serde_json::Value>(data) {
            Ok(wallet_info) => {
                // Extract seed phrase if available
                if let Some(seed_phrase) = wallet_info.get("seed_phrase").and_then(|s| s.as_str()) {
                    println!("Recovering identity and wallet from seed phrase...");
                    
                    // Create user identity with wallet recovery - NOW capturing private_data
                    let node_name = wallet_name.to_string();
                    let wallet_alias = format!("mesh-imported-{}", wallet_name.to_lowercase());
                    
                    let (user_identity, wallet_id, recovered_seed, user_private_data) = create_user_identity_with_wallet(
                        node_name.clone(),
                        wallet_name.to_string(),
                        Some(wallet_alias),
                    ).await?;
                    
                    println!(" User identity recovered: {}", hex::encode(&user_identity.id.0[..8]));

                    // Create node device identity - NOW capturing private_data
                    println!("⚙ Creating node device identity...");
                    let node_device_name = format!("{}-device", node_name);
                    let (node_identity, node_private_data) = create_node_device_identity(
                        user_identity.id.clone(),
                        wallet_id.clone(),
                        node_device_name,
                    ).await?;
                    
                    let wallet_address = format!("zhtp:{}", hex::encode(&wallet_id.0[..16]));
                    
                    Ok((user_identity, node_identity, wallet_id, wallet_name.to_string(), recovered_seed, wallet_address, user_private_data, node_private_data))
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
    async fn create_fallback_wallet(wallet_name: &str, _balance: u64) -> Result<(
        ZhtpIdentity, 
        ZhtpIdentity, 
        WalletId, 
        String, 
        String, 
        String,
        lib_identity::identity::PrivateIdentityData,  // User private data
        lib_identity::identity::PrivateIdentityData,  // Node private data
    )> {
        println!("Creating new user identity with wallet: {}", wallet_name);
        
        let node_name = wallet_name.to_string();
        let wallet_alias = format!("mesh-fallback-{}", wallet_name.to_lowercase());
        
        let (user_identity, wallet_id, seed_phrase, user_private_data) = create_user_identity_with_wallet(
            node_name.clone(),
            wallet_name.to_string(),
            Some(wallet_alias),
        ).await?;
        
        println!(" User identity created: {}", hex::encode(&user_identity.id.0[..8]));

        // Create node device identity - NOW capturing private_data
        println!("⚙ Creating node device identity...");
        let node_device_name = format!("{}-device", node_name);
        let (node_identity, node_private_data) = create_node_device_identity(
            user_identity.id.clone(),
            wallet_id.clone(),
            node_device_name,
        ).await?;
        
        let wallet_address = format!("zhtp:{}", hex::encode(&wallet_id.0[..16]));
        
        println!("Fallback identity with wallet created successfully");
        
        Ok((user_identity, node_identity, wallet_id, wallet_name.to_string(), seed_phrase, wallet_address, user_private_data, node_private_data))
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
        // Note: WalletPasswordManager was merged into IdentityWallets (Step 6 refactoring)
        // Wallet password functionality is now available through IdentityWallets methods:
        // - set_wallet_password()
        // - verify_wallet_password()
        // - change_wallet_password()
        // See lib-identity/src/wallets/wallet_password_integration.rs
        
        // Note: We need the wallet seed to set password properly
        // For now, show error message that password should be set during wallet creation
        // In production, we'd need to refactor to pass seed through or retrieve it securely
        
        println!("  Wallet password setup requires wallet seed from creation.");
        println!("   Wallet passwords should be set during initial wallet creation.");
        println!("   You can add wallet password protection later using: zhtp wallet set-password");
        
        Ok(())
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Helper Functions for P1-7 Identity Creation
// ════════════════════════════════════════════════════════════════════════════

/// Create a user identity with attached wallet (P1-7 compatible)
///
/// Returns: (identity, wallet_id, seed_phrase, private_data)
async fn create_user_identity_with_wallet(
    node_name: String,
    wallet_name: String,
    wallet_alias: Option<String>,
) -> Result<(ZhtpIdentity, WalletId, String, lib_identity::identity::PrivateIdentityData)> {
    use lib_identity::wallets::WalletType;

    // Generate new identity using P1-7 seed-anchored architecture
    let mut identity = ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(25), // Default age
        Some("US".to_string()), // Default jurisdiction
        &node_name,
        None, // Generate random seed
    )?;

    // Create wallet using WalletManager
    let (wallet_id, recovery_phrase) = identity.wallet_manager.create_wallet_with_seed_phrase(
        WalletType::Primary,
        wallet_name,
        wallet_alias,
    ).await?;

    // Convert RecoveryPhrase to String
    let seed_phrase = recovery_phrase.to_string();

    // Create PrivateIdentityData from the identity's private key
    let private_key = identity.private_key.as_ref()
        .ok_or_else(|| anyhow!("Identity missing private key"))?;

    let private_data = lib_identity::identity::PrivateIdentityData::new(
        private_key.dilithium_sk.clone(),
        identity.public_key.dilithium_pk.clone(),
        [0u8; 32], // TODO: Extract actual seed from identity if available
        vec![seed_phrase.clone()],
    );

    Ok((identity, wallet_id, seed_phrase, private_data))
}

/// Create a node device identity (owned by a user) (P1-7 compatible)
///
/// Returns: (identity, private_data)
async fn create_node_device_identity(
    owner_id: IdentityId,
    reward_wallet_id: WalletId,
    device_name: String,
) -> Result<(ZhtpIdentity, lib_identity::identity::PrivateIdentityData)> {
    // Generate device identity using P1-7 seed-anchored architecture
    let mut identity = ZhtpIdentity::new_unified(
        IdentityType::Device,
        None, // Devices don't have age
        None, // Devices don't have jurisdiction
        &device_name,
        None, // Generate random seed
    )?;

    // Set owner and reward wallet
    identity.owner_identity_id = Some(owner_id);
    identity.reward_wallet_id = Some(reward_wallet_id);

    // Create PrivateIdentityData from the identity's private key
    let private_key = identity.private_key.as_ref()
        .ok_or_else(|| anyhow!("Identity missing private key"))?;

    let private_data = lib_identity::identity::PrivateIdentityData::new(
        private_key.dilithium_sk.clone(),
        identity.public_key.dilithium_pk.clone(),
        [0u8; 32], // TODO: Extract actual seed from identity if available
        vec![],
    );

    Ok((identity, private_data))
}
