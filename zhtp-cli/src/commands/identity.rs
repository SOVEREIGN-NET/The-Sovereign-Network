//! Identity commands for ZHTP CLI
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Identity type parsing, DID validation, name validation
//! - **Imperative Shell**: File I/O, QUIC communication, output printing
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Output trait injection for testing

use crate::argument_parsing::{format_output, IdentityArgs, IdentityAction, ZhtpCli};
use crate::error::{CliResult, CliError};
use crate::output::Output;
use crate::logic;

use lib_identity::ZhtpIdentity;
use lib_network::client::ZhtpClient;
use zhtp::keystore_names::{USER_IDENTITY_FILENAME, USER_PRIVATE_KEY_FILENAME};
use std::path::PathBuf;
use base64::Engine;

use super::web4_utils::save_private_key_to_file;
use super::web4_utils::{build_trust_config, connect_client, load_identity_from_keystore};

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Valid identity operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityOperation {
    Create,
    CreateWithType,
    Verify,
    List,
    Unsupported,
}

impl IdentityOperation {
    /// Get user-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            IdentityOperation::Create => "Create standard identity",
            IdentityOperation::CreateWithType => "Create identity with specific type",
            IdentityOperation::Verify => "Verify identity on blockchain",
            IdentityOperation::List => "List blockchain identities",
            IdentityOperation::Unsupported => "Run identity operation",
        }
    }
}

/// Determine operation from arguments
///
/// Pure function - deterministic conversion
pub fn action_to_operation(action: &IdentityAction) -> IdentityOperation {
    match action {
        IdentityAction::Create { .. } => IdentityOperation::Create,
        IdentityAction::CreateDid { .. } => IdentityOperation::CreateWithType,
        IdentityAction::Verify { .. } => IdentityOperation::Verify,
        IdentityAction::List => IdentityOperation::List,
        IdentityAction::SimulateMessage { .. }
        | IdentityAction::Pending { .. }
        | IdentityAction::Ack { .. } => IdentityOperation::Unsupported,
    }
}

// ============================================================================
// IMPERATIVE SHELL - All side effects here (File I/O, network, output)
// ============================================================================

/// Handle identity command with proper error handling and output
///
/// Public entry point that maintains backward compatibility
pub async fn handle_identity_command(
    args: IdentityArgs,
    cli: &ZhtpCli,
) -> crate::error::CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_identity_command_impl(args, cli, &output).await
}

/// Internal implementation with dependency injection
async fn handle_identity_command_impl(
    args: IdentityArgs,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    let op = action_to_operation(&args.action);
    output.info(&format!("{}...", op.description()))?;

    match args.action {
        IdentityAction::Create { name } => {
            // Pure validation
            logic::validate_identity_name(&name)?;

            // Imperative: File I/O
            create_identity_impl(&name, None, output).await
        }
        IdentityAction::CreateDid {
            name,
            identity_type,
            recovery_options: _,
        } => {
            // Pure validation
            logic::validate_identity_name(&name)?;
            let _id_type = logic::parse_identity_type(&identity_type)?;

            // Imperative: File I/O
            create_identity_with_type_impl(&name, &identity_type, output).await
        }
        IdentityAction::Verify { identity_id } => {
            // Pure validation
            logic::validate_did(&identity_id)?;

            // Imperative: QUIC communication
            verify_identity_impl(&identity_id, cli, output).await
        }
        IdentityAction::List => {
            // Imperative: QUIC communication
            list_identities_impl(cli, output).await
        }
        IdentityAction::SimulateMessage { .. }
        | IdentityAction::Pending { .. }
        | IdentityAction::Ack { .. } => Err(CliError::ConfigError(
            "This identity subcommand is not implemented in this command handler".to_string(),
        )),
    }
}

/// Get default keystore path (pure logic of path construction)
fn get_default_keystore_path() -> CliResult<PathBuf> {
    dirs::home_dir()
        .ok_or_else(|| CliError::IdentityError("Could not determine home directory".to_string()))
        .map(|home| home.join(".zhtp").join("keystore"))
}

/// Create a new identity locally and save to keystore
async fn create_identity_impl(
    name: &str,
    keystore_path: Option<&str>,
    output: &dyn Output,
) -> CliResult<()> {
    // Determine keystore path
    let keystore = match keystore_path {
        Some(path) => PathBuf::from(path),
        None => get_default_keystore_path()?,
    };

    // Check if identity already exists
    let identity_file = keystore.join(USER_IDENTITY_FILENAME);
    let private_key_file = keystore.join(USER_PRIVATE_KEY_FILENAME);
    if identity_file.exists() {
        return Err(CliError::IdentityError(format!(
            "Identity already exists at {:?}. Use a different keystore path or delete the existing identity first.",
            identity_file
        )));
    }

    // Create keystore directory
    std::fs::create_dir_all(&keystore).map_err(|e| {
        CliError::IdentityError(format!("Failed to create keystore directory: {}", e))
    })?;

    // Generate new identity locally (no network required)
    output.info("Generating cryptographic keys (post-quantum Dilithium + Kyber)...")?;
    let identity = ZhtpIdentity::new_unified(
        lib_identity::IdentityType::Device,
        None,
        None,
        name,
        None,
    )
    .map_err(|e| CliError::IdentityError(format!("Failed to generate identity: {}", e)))?;

    output.success(&format!("DID: {}", identity.did))?;
    output.print(&format!("Identity ID: {}", identity.id))?;

    // Extract and save private key
    let private_key = identity.private_key.as_ref()
        .ok_or_else(|| CliError::IdentityError("Identity missing private key".to_string()))?;
    save_private_key_to_file(private_key, &private_key_file)?;

    // Save identity to file (public data)
    let identity_json = serde_json::to_string_pretty(&identity).map_err(|e| {
        CliError::IdentityError(format!("Failed to serialize identity: {}", e))
    })?;
    std::fs::write(&identity_file, identity_json).map_err(|e| {
        CliError::IdentityError(format!("Failed to write {}: {}", USER_IDENTITY_FILENAME, e))
    })?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&identity_file, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| {
                CliError::IdentityError(format!("Failed to set file permissions: {}", e))
            })?;
    }

    output.success(&format!("Identity saved to: {:?}", identity_file))?;
    output.success(&format!("Private key saved to: {:?}", private_key_file))?;
    output.warning("Keep your identity secure! It contains cryptographic material.")?;

    Ok(())
}

/// Create identity with specific type
async fn create_identity_with_type_impl(
    name: &str,
    identity_type: &str,
    output: &dyn Output,
) -> CliResult<()> {
    // Parse and validate identity type
    let id_type = logic::parse_identity_type(identity_type)?;

    // Get default keystore path
    let keystore = get_default_keystore_path()?;

    // Check if identity already exists
    let identity_file = keystore.join(USER_IDENTITY_FILENAME);
    let private_key_file = keystore.join(USER_PRIVATE_KEY_FILENAME);
    if identity_file.exists() {
        return Err(CliError::IdentityError(format!(
            "Identity already exists at {:?}",
            identity_file
        )));
    }

    // Create keystore directory
    std::fs::create_dir_all(&keystore).map_err(|e| {
        CliError::IdentityError(format!("Failed to create keystore directory: {}", e))
    })?;

    output.info(&format!(
        "Generating {} identity (post-quantum Dilithium + Kyber)...",
        identity_type
    ))?;

    // Generate new identity
    let identity = ZhtpIdentity::new_unified(id_type, None, None, name, None).map_err(|e| {
        CliError::IdentityError(format!("Failed to generate identity: {}", e))
    })?;

    output.success(&format!("DID: {}", identity.did))?;
    output.print(&format!("Identity Type: {}", identity_type))?;

    // Extract and save private key
    let private_key = identity.private_key.as_ref()
        .ok_or_else(|| CliError::IdentityError("Identity missing private key".to_string()))?;
    save_private_key_to_file(private_key, &private_key_file)?;

    // Save identity (public data)
    let identity_json = serde_json::to_string_pretty(&identity).map_err(|e| {
        CliError::IdentityError(format!("Failed to serialize identity: {}", e))
    })?;
    std::fs::write(&identity_file, identity_json).map_err(|e| {
        CliError::IdentityError(format!("Failed to write {}: {}", USER_IDENTITY_FILENAME, e))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&identity_file, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| {
                CliError::IdentityError(format!("Failed to set file permissions: {}", e))
            })?;
    }

    output.success(&format!("Identity saved to: {:?}", identity_file))?;
    output.success(&format!("Private key saved to: {:?}", private_key_file))?;

    Ok(())
}

/// Verify identity on blockchain (requires QUIC connection)
async fn verify_identity_impl(
    identity_id: &str,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    output.info(&format!("Verifying identity: {}", identity_id))?;
    output.print(&format!("Server: {}", cli.server))?;

    // This would normally establish a QUIC connection and verify
    // For now, provide guidance on the process
    output.warning(
        "Identity verification requires a running ZHTP node.\n\
         Use 'zhtp node start' to launch the node first.",
    )?;

    Ok(())
}

/// List identities from blockchain (requires QUIC connection)
async fn list_identities_impl(cli: &ZhtpCli, output: &dyn Output) -> CliResult<()> {
    output.info("Listing identities from blockchain...")?;
    output.print(&format!("Server: {}", cli.server))?;

    // This would normally establish a QUIC connection and fetch identities
    output.warning(
        "Identity listing requires a running ZHTP node.\n\
         Use 'zhtp node start' to launch the node first.",
    )?;

    Ok(())
}

async fn migrate_identity_impl(
    display_name: &str,
    device_id: &str,
    phrase: Option<&str>,
    phrase_file: Option<&str>,
    keystore: Option<&str>,
    pin_spki: Option<&str>,
    node_did: Option<&str>,
    tofu: bool,
    trust_node: bool,
    server: &str,
    format: &str,
    output: &dyn Output,
) -> CliResult<()> {
    if phrase.is_some() && phrase_file.is_some() {
        return Err(CliError::ConfigError(
            "Use only one of --phrase or --phrase-file".to_string(),
        ));
    }

    // Load QUIC client identity from keystore (this is transport/auth only).
    let keystore_path = match keystore {
        Some(p) => PathBuf::from(p),
        None => get_default_keystore_path()?,
    };
    let loaded = load_identity_from_keystore(&keystore_path)?;
    let trust_config = build_trust_config(pin_spki, node_did, tofu, trust_node)?;
    let client = connect_client(loaded.identity.clone(), trust_config, server).await?;

    // Build NEW seed-derived identity (used ONLY to sign migration payload).
    let phrase = if let Some(file) = phrase_file {
        let s = std::fs::read_to_string(file).map_err(|e| {
            CliError::ConfigError(format!("Failed to read --phrase-file {}: {}", file, e))
        })?;
        Some(s.trim().to_string())
    } else {
        phrase.map(|s| s.to_string())
    };

    let new_identity = if let Some(phrase) = &phrase {
        zhtp_client::restore_identity_from_phrase(phrase, device_id.to_string())
            .map_err(|e| CliError::IdentityError(format!("Failed to derive identity from phrase: {}", e)))?
    } else {
        let id = zhtp_client::generate_identity(device_id.to_string())
            .map_err(|e| CliError::IdentityError(format!("Failed to generate new identity: {}", e)))?;
        let generated_phrase = zhtp_client::get_seed_phrase(&id)
            .map_err(|e| CliError::IdentityError(format!("Failed to render seed phrase: {}", e)))?;
        output.header("Generated Recovery Phrase (NEW DID)")?;
        output.warning("This phrase is the ONLY way to recover the migrated identity. Store it offline.")?;
        output.print(&generated_phrase)?;
        id
    };

    let body_json = zhtp_client::build_migrate_identity_request_json(&new_identity, display_name.to_string())
        .map_err(|e| CliError::ConfigError(format!("Failed to build migrate payload JSON: {}", e)))?;
    let body_value: serde_json::Value = serde_json::from_str(&body_json).map_err(|e| {
        CliError::ConfigError(format!("Failed to parse migrate payload JSON (internal): {}", e))
    })?;

    output.info(&format!(
        "Submitting migration request for display_name='{}' to {} ...",
        display_name, server
    ))?;

    let response = client
        .post_json("/api/v1/identity/migrate", &body_value)
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/identity/migrate".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let result: serde_json::Value = ZhtpClient::parse_json(&response).map_err(|e| {
        CliError::ApiCallFailed {
            endpoint: "/api/v1/identity/migrate".to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        }
    })?;

    output.header("Identity Migration Result")?;
    output.print(&format_output(&result, format)?)?;

    // If migration succeeded, verify wallet transfer by listing wallets for old/new identity IDs.
    let status = result.get("status").and_then(|v| v.as_str()).unwrap_or("");
    if status == "success" {
        let old_did = result.get("old_did").and_then(|v| v.as_str()).unwrap_or("");
        let new_did = result.get("new_did").and_then(|v| v.as_str()).unwrap_or("");

        let old_id = old_did.strip_prefix("did:zhtp:").unwrap_or(old_did);
        let new_id = new_did.strip_prefix("did:zhtp:").unwrap_or(new_did);

        // Wallet list endpoint expects the 32-byte hex identity id (same as DID suffix).
        let old_wallets_resp = client
            .get(&format!("/api/v1/wallet/list/{}", old_id))
            .await
            .map_err(|e| CliError::ApiCallFailed {
                endpoint: "/api/v1/wallet/list/{old}".to_string(),
                status: 0,
                reason: e.to_string(),
            })?;
        let new_wallets_resp = client
            .get(&format!("/api/v1/wallet/list/{}", new_id))
            .await
            .map_err(|e| CliError::ApiCallFailed {
                endpoint: "/api/v1/wallet/list/{new}".to_string(),
                status: 0,
                reason: e.to_string(),
            })?;

        let old_wallets_json: serde_json::Value = ZhtpClient::parse_json(&old_wallets_resp)
            .map_err(|e| CliError::ConfigError(format!("Failed to parse old wallet list: {}", e)))?;
        let new_wallets_json: serde_json::Value = ZhtpClient::parse_json(&new_wallets_resp)
            .map_err(|e| CliError::ConfigError(format!("Failed to parse new wallet list: {}", e)))?;

        output.header("Wallet Transfer Check")?;
        output.print(&format!(
            "Old identity wallets: total_wallets={} total_balance={}",
            old_wallets_json.get("total_wallets").and_then(|v| v.as_u64()).unwrap_or(0),
            old_wallets_json.get("total_balance").and_then(|v| v.as_u64()).unwrap_or(0),
        ))?;
        output.print(&format!(
            "New identity wallets: total_wallets={} total_balance={}",
            new_wallets_json.get("total_wallets").and_then(|v| v.as_u64()).unwrap_or(0),
            new_wallets_json.get("total_balance").and_then(|v| v.as_u64()).unwrap_or(0),
        ))?;

        // Chain-level check: wallet registry owner bindings.
        let chain_old_resp = client
            .get(&format!("/api/v1/blockchain/wallets?owner_identity={}", old_id))
            .await
            .map_err(|e| CliError::ApiCallFailed {
                endpoint: "/api/v1/blockchain/wallets?owner_identity={old}".to_string(),
                status: 0,
                reason: e.to_string(),
            })?;
        let chain_new_resp = client
            .get(&format!("/api/v1/blockchain/wallets?owner_identity={}", new_id))
            .await
            .map_err(|e| CliError::ApiCallFailed {
                endpoint: "/api/v1/blockchain/wallets?owner_identity={new}".to_string(),
                status: 0,
                reason: e.to_string(),
            })?;

        let chain_old_json: serde_json::Value = ZhtpClient::parse_json(&chain_old_resp)
            .map_err(|e| CliError::ConfigError(format!("Failed to parse chain wallet list (old): {}", e)))?;
        let chain_new_json: serde_json::Value = ZhtpClient::parse_json(&chain_new_resp)
            .map_err(|e| CliError::ConfigError(format!("Failed to parse chain wallet list (new): {}", e)))?;

        output.header("Chain Wallet Registry Check")?;
        output.print(&format!(
            "Old owner wallet_count={}",
            chain_old_json.get("wallet_count").and_then(|v| v.as_u64()).unwrap_or(0),
        ))?;
        output.print(&format!(
            "New owner wallet_count={}",
            chain_new_json.get("wallet_count").and_then(|v| v.as_u64()).unwrap_or(0),
        ))?;
    }

    Ok(())
}

async fn register_identity_impl(
    display_name: &str,
    device_id: &str,
    identity_type: &str,
    keystore: Option<&str>,
    pin_spki: Option<&str>,
    node_did: Option<&str>,
    tofu: bool,
    trust_node: bool,
    server: &str,
    format: &str,
    output: &dyn Output,
) -> CliResult<()> {
    // Load QUIC client identity from keystore (transport/auth only).
    let keystore_path = match keystore {
        Some(p) => PathBuf::from(p),
        None => get_default_keystore_path()?,
    };
    let loaded = load_identity_from_keystore(&keystore_path)?;
    let trust_config = build_trust_config(pin_spki, node_did, tofu, trust_node)?;
    let client = connect_client(loaded.identity.clone(), trust_config, server).await?;

    // Create a new identity locally (client-side keygen), then register it on the node.
    let identity = zhtp_client::generate_identity(device_id.to_string())
        .map_err(|e| CliError::IdentityError(format!("Failed to generate identity: {}", e)))?;

    // Print the recovery phrase for the registered identity.
    let phrase = zhtp_client::get_seed_phrase(&identity)
        .map_err(|e| CliError::IdentityError(format!("Failed to render seed phrase: {}", e)))?;
    output.header("Recovery Phrase (REGISTERED IDENTITY)")?;
    output.warning("This phrase controls the registered identity. Store it offline.")?;
    output.print(&phrase)?;

    // Server expects signature over: "ZHTP_REGISTER:{timestamp}" (no DID).
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| CliError::IdentityError(format!("Clock error: {}", e)))?
        .as_secs();
    let signed_message = format!("ZHTP_REGISTER:{}", timestamp);
    let sig = zhtp_client::identity::sign_message(&identity, signed_message.as_bytes())
        .map_err(|e| CliError::IdentityError(format!("Failed to sign registration proof: {}", e)))?;

    let body_value = serde_json::json!({
        "public_key": base64::engine::general_purpose::STANDARD.encode(&identity.public_key),
        "kyber_public_key": base64::engine::general_purpose::STANDARD.encode(&identity.kyber_public_key),
        "device_id": device_id,
        "display_name": display_name,
        "identity_type": identity_type,
        "registration_proof": base64::engine::general_purpose::STANDARD.encode(sig),
        "timestamp": timestamp,
    });

    output.info(&format!(
        "Registering display_name='{}' on {} ...",
        display_name, server
    ))?;

    let response = client
        .post_json("/api/v1/identity/register", &body_value)
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/identity/register".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let result: serde_json::Value = ZhtpClient::parse_json(&response).map_err(|e| {
        CliError::ApiCallFailed {
            endpoint: "/api/v1/identity/register".to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        }
    })?;

    output.header("Identity Register Result")?;
    output.print(&format_output(&result, format)?)?;

    // Convenience: fetch wallet list right away, so we have a baseline before migration.
    let did = result.get("did").and_then(|v| v.as_str()).unwrap_or(&identity.did);
    let id = did.strip_prefix("did:zhtp:").unwrap_or(did);

    let wallets_resp = client
        .get(&format!("/api/v1/wallet/list/{}", id))
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/wallet/list/{id}".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;
    let wallets_json: serde_json::Value = ZhtpClient::parse_json(&wallets_resp)
        .map_err(|e| CliError::ConfigError(format!("Failed to parse wallet list: {}", e)))?;

    output.header("Registered Wallets (Baseline)")?;
    output.print(&format_output(&wallets_json, format)?)?;

    Ok(())
}

// ============================================================================
// TESTS - Pure logic is testable without mocks or side effects
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_to_operation_create() {
        let action = IdentityAction::Create {
            name: "test".to_string(),
        };
        assert_eq!(
            action_to_operation(&action),
            IdentityOperation::Create
        );
    }

    #[test]
    fn test_action_to_operation_create_with_type() {
        let action = IdentityAction::CreateDid {
            name: "test".to_string(),
            identity_type: "human".to_string(),
            recovery_options: vec![],
        };
        assert_eq!(
            action_to_operation(&action),
            IdentityOperation::CreateWithType
        );
    }

    #[test]
    fn test_action_to_operation_verify() {
        let action = IdentityAction::Verify {
            identity_id: "did:zhtp:test:abc".to_string(),
        };
        assert_eq!(
            action_to_operation(&action),
            IdentityOperation::Verify
        );
    }

    #[test]
    fn test_action_to_operation_list() {
        let action = IdentityAction::List;
        assert_eq!(
            action_to_operation(&action),
            IdentityOperation::List
        );
    }

    #[test]
    fn test_operation_description() {
        assert_eq!(
            IdentityOperation::Create.description(),
            "Create standard identity"
        );
        assert_eq!(
            IdentityOperation::CreateWithType.description(),
            "Create identity with specific type"
        );
        assert_eq!(
            IdentityOperation::Verify.description(),
            "Verify identity on blockchain"
        );
        assert_eq!(
            IdentityOperation::List.description(),
            "List blockchain identities"
        );
        assert_eq!(
            IdentityOperation::Unsupported.description(),
            "Run identity operation"
        );
    }
}
