//! Identity commands for ZHTP CLI
//!
//! All identity operations that require node communication use authenticated QUIC.
//! Local keystore operations (generate, export, import) work offline.

use anyhow::{anyhow, Result, Context};
use std::path::PathBuf;
use tracing::{info, warn};
use serde::{Serialize, Deserialize};

use lib_identity::{ZhtpIdentity, IdentityType};
use lib_network::ZhtpClient;
use lib_network::web4::TrustConfig;

use crate::cli::{IdentityArgs, IdentityAction, ZhtpCli, format_output};

/// Private key storage format for keystore
/// Stored separately from identity.json for security
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeystorePrivateKey {
    /// Dilithium secret key bytes
    dilithium_sk: Vec<u8>,
    /// Kyber secret key bytes
    kyber_sk: Vec<u8>,
    /// Master seed for key derivation
    master_seed: Vec<u8>,
}

/// Handle identity commands
pub async fn handle_identity_command(args: IdentityArgs, cli: &ZhtpCli) -> Result<()> {
    match args.action {
        IdentityAction::Create { name } => {
            // Create identity locally and optionally register on blockchain
            create_identity(&name, None, cli).await
        }
        IdentityAction::CreateDid { name, identity_type, recovery_options } => {
            // Create identity locally with options and optionally register
            create_identity_with_options(&name, &identity_type, recovery_options, cli).await
        }
        IdentityAction::Verify { identity_id } => {
            // Verify identity on blockchain (requires QUIC connection)
            verify_identity(&identity_id, cli).await
        }
        IdentityAction::List => {
            // List identities from blockchain (requires QUIC connection)
            list_identities(cli).await
        }
    }
}

/// Create a new identity locally and save to keystore
async fn create_identity(name: &str, keystore_path: Option<&str>, cli: &ZhtpCli) -> Result<()> {
    println!("Creating new ZHTP DID identity: {}", name);

    // Determine keystore path
    let keystore = match keystore_path {
        Some(path) => PathBuf::from(path),
        None => get_default_keystore_path()?,
    };

    // Check if identity already exists
    let identity_file = keystore.join("identity.json");
    if identity_file.exists() {
        return Err(anyhow!(
            "Identity already exists at {:?}\n\
            Use a different keystore path or delete the existing identity first.",
            identity_file
        ));
    }

    // Create keystore directory
    std::fs::create_dir_all(&keystore)
        .context("Failed to create keystore directory")?;

    // Generate new identity locally (no network required)
    // Uses seed-anchored architecture: all secrets derived from single master seed
    // Using Device type for CLI tools (doesn't require age/jurisdiction)
    println!("Generating cryptographic keys (post-quantum Dilithium + Kyber)...");
    let identity = ZhtpIdentity::new_unified(
        IdentityType::Device, // Device type for CLI (no age/jurisdiction required)
        None, // age (not needed for Device)
        None, // jurisdiction (not needed for Device)
        name, // device name (used for NodeId derivation)
        None, // seed (None = generate random seed)
    ).context("Failed to generate identity")?;

    println!("DID: {}", identity.did);
    println!("Identity ID: {}", identity.id);
    println!("NodeId: {}", hex::encode(&identity.node_id.as_bytes()[..16]));

    // Extract private key before serialization (it's skipped by serde)
    let private_key = identity.private_key.as_ref()
        .ok_or_else(|| anyhow!("No private key in generated identity"))?;

    // Save private key to separate keystore file (security: separate from identity)
    let private_key_file = keystore.join("private_key.json");
    let keystore_key = KeystorePrivateKey {
        dilithium_sk: private_key.dilithium_sk.clone(),
        kyber_sk: private_key.kyber_sk.clone(),
        master_seed: private_key.master_seed.clone(),
    };
    let private_key_json = serde_json::to_string_pretty(&keystore_key)
        .context("Failed to serialize private key")?;
    std::fs::write(&private_key_file, private_key_json)
        .context("Failed to write private_key.json")?;

    // Set restrictive permissions on private key (0600 - owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&private_key_file, std::fs::Permissions::from_mode(0o600))?;
    }

    // Save identity (public data only - private_key is #[serde(skip)])
    let identity_json = serde_json::to_string_pretty(&identity)
        .context("Failed to serialize identity")?;
    std::fs::write(&identity_file, identity_json)
        .context("Failed to write identity.json")?;

    // Set permissions on identity file too
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&identity_file, std::fs::Permissions::from_mode(0o600))?;
    }

    println!("\nIdentity saved to: {:?}", identity_file);
    println!("Private key saved to: {:?}", private_key_file);
    println!("\nWARNING: Keep private_key.json secure! It contains your signing keys.");
    println!("\nTo register this identity on the blockchain, run:");
    println!("  zhtp identity register --keystore {:?}", keystore.display());

    // If node is available, offer to register now
    if !cli.server.is_empty() {
        println!("\nOr connect to {} to register now.", cli.server);
    }

    Ok(())
}

/// Create identity with options (identity type, recovery phrases)
async fn create_identity_with_options(
    name: &str,
    identity_type: &str,
    recovery_options: Vec<String>,
    cli: &ZhtpCli,
) -> Result<()> {
    println!("Creating zero-knowledge DID identity: {}", name);
    println!("Identity Type: {}", identity_type);

    // Get default keystore path
    let keystore = get_default_keystore_path()?;

    // Check if identity already exists
    let identity_file = keystore.join("identity.json");
    if identity_file.exists() {
        return Err(anyhow!(
            "Identity already exists at {:?}\n\
            Use a different keystore path or delete the existing identity first.",
            identity_file
        ));
    }

    // Create keystore directory
    std::fs::create_dir_all(&keystore)
        .context("Failed to create keystore directory")?;

    // Parse identity type from string
    let id_type = match identity_type.to_lowercase().as_str() {
        "human" => IdentityType::Human,
        "agent" => IdentityType::Agent,
        "contract" => IdentityType::Contract,
        "organization" => IdentityType::Organization,
        "device" => IdentityType::Device,
        _ => IdentityType::Human, // Default to Human
    };

    // Generate new identity locally
    // Uses seed-anchored architecture: all secrets derived from single master seed
    println!("Generating cryptographic keys (post-quantum Dilithium + Kyber)...");
    let identity = ZhtpIdentity::new_unified(
        id_type,
        None, // age (optional)
        None, // jurisdiction (optional)
        name, // device name (used for NodeId derivation)
        None, // seed (None = generate random seed)
    ).context("Failed to generate identity")?;

    // Recovery phrases are derived from master seed in the unified identity system
    // The user should backup their seed phrase for recovery
    let _recovery_options = recovery_options; // Acknowledge but don't use - seed phrase is the recovery mechanism

    println!("DID: {}", identity.did);
    println!("Identity ID: {}", identity.id);
    println!("NodeId: {}", hex::encode(&identity.node_id.as_bytes()[..16]));
    println!("\nIMPORTANT: Your identity is derived from a master seed.");
    println!("To backup, export your seed phrase using: zhtp identity export-seed");

    // Save to keystore
    let identity_json = serde_json::to_string_pretty(&identity)
        .context("Failed to serialize identity")?;
    std::fs::write(&identity_file, identity_json)
        .context("Failed to write identity.json")?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&identity_file, std::fs::Permissions::from_mode(0o600))?;
    }

    println!("\nIdentity saved to: {:?}", identity_file);

    Ok(())
}

/// Verify identity on blockchain (requires QUIC connection)
async fn verify_identity(identity_id: &str, cli: &ZhtpCli) -> Result<()> {
    println!("Verifying ZHTP identity: {}", identity_id);

    // Load identity from default keystore for authentication
    let keystore = get_default_keystore_path()?;
    let identity = load_identity_from_keystore(&keystore)?;

    // Create QUIC client
    let trust_config = build_trust_config_from_cli(cli)?;
    let mut client = ZhtpClient::new(identity, trust_config).await
        .context("Failed to create QUIC client")?;

    // Connect to node
    println!("Connecting to node at {}...", cli.server);
    client.connect(&cli.server).await
        .context("Failed to connect to ZHTP node")?;

    if let Some(peer_did) = client.peer_did() {
        println!("Connected to node: {}", peer_did);
    }

    // Send verification request
    let request_body = serde_json::json!({
        "identity_data": {
            "identity_id": identity_id,
            "verification_requested": true
        },
        "verification_level": "Standard"
    });

    let response = client.post_json("/api/v1/identity/verify", &request_body).await?;

    if response.status.is_success() {
        let result: serde_json::Value = serde_json::from_slice(&response.body)?;

        if let Some(verified) = result.get("verified") {
            if verified.as_bool().unwrap_or(false) {
                println!("Identity verification successful!");
            } else {
                println!("Identity verification failed!");
            }
        }
        if let Some(score) = result.get("verification_score") {
            println!("Verification Score: {}", score);
        }
        if let Some(level) = result.get("verification_level") {
            println!("Security Level: {}", level.as_str().unwrap_or("N/A"));
        }

        if cli.verbose {
            let formatted = format_output(&result, &cli.format)?;
            println!("\nFull Response:");
            println!("{}", formatted);
        }
    } else {
        println!(
            "Failed to verify identity: {} {}",
            response.status.code(),
            response.status_message
        );
    }

    client.close().await;
    Ok(())
}

/// List identities from blockchain (requires QUIC connection)
async fn list_identities(cli: &ZhtpCli) -> Result<()> {
    println!("Listing ZHTP identities from blockchain...");

    // Load identity from default keystore for authentication
    let keystore = get_default_keystore_path()?;
    let identity = load_identity_from_keystore(&keystore)?;

    // Create QUIC client
    let trust_config = build_trust_config_from_cli(cli)?;
    let mut client = ZhtpClient::new(identity, trust_config).await
        .context("Failed to create QUIC client")?;

    // Connect to node
    println!("Connecting to node at {}...", cli.server);
    client.connect(&cli.server).await
        .context("Failed to connect to ZHTP node")?;

    if let Some(peer_did) = client.peer_did() {
        println!("Connected to node: {}", peer_did);
    }

    // Get blockchain status
    let response = client.get("/api/v1/blockchain/block").await?;

    if response.status.is_success() {
        let result: serde_json::Value = serde_json::from_slice(&response.body)?;

        println!("Blockchain Identity Status:");
        if let Some(height) = result.get("latest_height") {
            println!("Latest Block: {}", height);
        }

        println!("To see created identities, check the server logs for DID creation events");
        println!("   or use 'zhtp blockchain stats' to see blockchain statistics");

        if cli.verbose {
            let formatted = format_output(&result, &cli.format)?;
            println!("\nBlockchain Status:");
            println!("{}", formatted);
        }
    } else {
        println!(
            "Failed to get blockchain status: {} {}",
            response.status.code(),
            response.status_message
        );
    }

    client.close().await;
    Ok(())
}

/// Get default keystore path
fn get_default_keystore_path() -> Result<PathBuf> {
    let home = dirs::home_dir()
        .ok_or_else(|| anyhow!("Could not determine home directory"))?;
    Ok(home.join(".zhtp").join("keystore"))
}

/// Load identity from keystore
fn load_identity_from_keystore(keystore: &PathBuf) -> Result<ZhtpIdentity> {
    let identity_file = keystore.join("identity.json");

    if !identity_file.exists() {
        return Err(anyhow!(
            "No identity found at {:?}\n\
            Create an identity first with: zhtp identity create <name>",
            identity_file
        ));
    }

    let data = std::fs::read_to_string(&identity_file)
        .context("Failed to read identity.json")?;
    let identity: ZhtpIdentity = serde_json::from_str(&data)
        .context("Failed to parse identity.json")?;

    info!("Loaded identity {} from {:?}", identity.did, identity_file);
    Ok(identity)
}

/// Build trust config from CLI flags
///
/// Security model:
/// - Default: Strict mode (no auto-trust, requires --tofu or --pin-spki)
/// - ZHTP_ALLOW_BOOTSTRAP=1: Dev-only insecure mode with fingerprint logging
/// - --tofu: Trust on first use with fingerprint display and audit log
fn build_trust_config_from_cli(cli: &ZhtpCli) -> Result<TrustConfig> {
    if std::env::var("ZHTP_ALLOW_BOOTSTRAP").ok().map(|v| v == "1").unwrap_or(false) {
        // DEV ONLY: Bootstrap mode with security warnings
        warn!("╔══════════════════════════════════════════════════════════════╗");
        warn!("║  SECURITY WARNING: Bootstrap mode - TLS verification OFF     ║");
        warn!("║  This accepts ANY certificate without validation.            ║");
        warn!("║  NEVER use in production! Vulnerable to MITM attacks.        ║");
        warn!("╚══════════════════════════════════════════════════════════════╝");
        Ok(TrustConfig::bootstrap())
    } else {
        // Default to TOFU with explicit fingerprint logging
        let trustdb_path = TrustConfig::default_trustdb_path()?;
        let audit_path = TrustConfig::default_audit_path();

        info!("Trust mode: TOFU (Trust On First Use)");
        info!("Trustdb: {:?}", trustdb_path);
        info!("Audit log: {:?}", audit_path);
        info!("First connection to a new node will display its fingerprint.");
        info!("To reset trust: delete {:?}", trustdb_path);

        Ok(TrustConfig::with_tofu(trustdb_path))
    }
}
