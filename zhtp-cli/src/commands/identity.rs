//! Identity commands for ZHTP CLI
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Identity type parsing, DID validation, name validation
//! - **Imperative Shell**: File I/O, QUIC communication, output printing
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Output trait injection for testing

use crate::argument_parsing::{IdentityArgs, IdentityAction, ZhtpCli, format_output};
use crate::error::{CliResult, CliError};
use crate::output::Output;
use crate::logic;
use crate::commands::web4_utils::connect_default;

use lib_identity::ZhtpIdentity;
use zhtp::keystore_names::{USER_IDENTITY_FILENAME, USER_PRIVATE_KEY_FILENAME};
use std::path::PathBuf;

use super::web4_utils::save_private_key_to_file;

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
    SimulateMessage,
    Pending,
    Ack,
}

impl IdentityOperation {
    /// Get user-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            IdentityOperation::Create => "Create standard identity",
            IdentityOperation::CreateWithType => "Create identity with specific type",
            IdentityOperation::Verify => "Verify identity on blockchain",
            IdentityOperation::List => "List blockchain identities",
            IdentityOperation::SimulateMessage => "Simulate identity message flow",
            IdentityOperation::Pending => "Fetch pending identity envelopes",
            IdentityOperation::Ack => "Acknowledge identity envelope delivery",
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
        IdentityAction::SimulateMessage { .. } => IdentityOperation::SimulateMessage,
        IdentityAction::Pending { .. } => IdentityOperation::Pending,
        IdentityAction::Ack { .. } => IdentityOperation::Ack,
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
        IdentityAction::SimulateMessage { devices, retain_until_ttl } => {
            simulate_message_flow_impl(devices, retain_until_ttl, output).await
        }
        IdentityAction::Pending { recipient_did, device_id } => {
            fetch_pending_envelopes_impl(&recipient_did, &device_id, cli, output).await
        }
        IdentityAction::Ack { recipient_did, device_id, message_id, retain_until_ttl } => {
            acknowledge_identity_delivery_impl(&recipient_did, &device_id, message_id, retain_until_ttl, cli, output).await
        }
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

/// Fetch pending identity envelopes via node API
async fn fetch_pending_envelopes_impl(
    recipient_did: &str,
    device_id: &str,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    output.info("Fetching pending identity envelopes...")?;

    let client = connect_default(&cli.server).await?;
    let body = serde_json::json!({
        "recipient_did": recipient_did,
        "device_id": device_id,
    });

    let response = client
        .post_json("/api/v1/network/identity/pending", &body)
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/network/identity/pending".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let result: serde_json::Value = lib_network::client::ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/network/identity/pending".to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;

    let formatted = format_output(&result, &cli.format)?;
    output.print(&formatted)?;
    Ok(())
}

/// Acknowledge delivery of an identity envelope via node API
async fn acknowledge_identity_delivery_impl(
    recipient_did: &str,
    device_id: &str,
    message_id: u64,
    retain_until_ttl: bool,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    output.info("Acknowledging identity delivery...")?;

    let client = connect_default(&cli.server).await?;
    let body = serde_json::json!({
        "recipient_did": recipient_did,
        "device_id": device_id,
        "message_id": message_id,
        "retain_until_ttl": retain_until_ttl,
    });

    let response = client
        .post_json("/api/v1/network/identity/ack", &body)
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/network/identity/ack".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let result: serde_json::Value = lib_network::client::ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/network/identity/ack".to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;

    let formatted = format_output(&result, &cli.format)?;
    output.print(&formatted)?;
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

/// Simulate identity message flow (local)
async fn simulate_message_flow_impl(
    devices: u32,
    retain_until_ttl: bool,
    output: &dyn Output,
) -> CliResult<()> {
    use lib_identity::{
        ZhtpIdentity, IdentityType,
        create_device_add_update, apply_did_update, store_did_document, set_did_store_memory,
    };
    use lib_protocols::identity_messaging::{
        build_delivery_receipt_envelope, build_identity_envelope_with_retention,
        create_delivery_receipt, extract_device_ciphertext,
    };
    use lib_protocols::types::{IdentityPayload, MessageTtl};
    use lib_network::identity_store_forward::IdentityStoreForward;
    use lib_crypto::keypair::generation::KeyPair;

    set_did_store_memory().map_err(|e| CliError::IdentityError(e))?;

    let sender = ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(30),
        Some("US".to_string()),
        "sender-device",
        None,
    ).map_err(|e| CliError::IdentityError(e.to_string()))?;

    let sender_doc = lib_identity::DidDocument::from_identity(&sender, None)
        .map_err(|e| CliError::IdentityError(e))?;
    let sender_update = create_device_add_update(
        &sender,
        &sender_doc,
        "sender-device",
        &sender.public_key.dilithium_pk,
        &sender.public_key.kyber_pk,
    ).map_err(|e| CliError::IdentityError(e))?;
    let sender_doc = apply_did_update(sender_doc, &sender_update)
        .map_err(|e| CliError::IdentityError(e))?;
    store_did_document(sender_doc.clone()).map_err(|e| CliError::IdentityError(e))?;

    let recipient = ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(30),
        Some("US".to_string()),
        "device-0",
        None,
    ).map_err(|e| CliError::IdentityError(e.to_string()))?;

    let mut doc = lib_identity::DidDocument::from_identity(&recipient, None)
        .map_err(|e| CliError::IdentityError(e))?;

    for i in 0..devices {
        let device_id = format!("device-{}", i);
        let update = create_device_add_update(
            &recipient,
            &doc,
            &device_id,
            &recipient.public_key.dilithium_pk,
            &recipient.public_key.kyber_pk,
        ).map_err(|e| CliError::IdentityError(e))?;
        doc = apply_did_update(doc, &update).map_err(|e| CliError::IdentityError(e))?;
    }

    store_did_document(doc.clone()).map_err(|e| CliError::IdentityError(e))?;

    let payload = IdentityPayload::user_message(b"simulated-message".to_vec());
    let envelope = build_identity_envelope_with_retention(
        "did:zhtp:sender",
        &doc.id,
        &payload,
        MessageTtl::Days7,
        retain_until_ttl,
    ).map_err(|e| CliError::IdentityError(e))?;

    let mut queue = IdentityStoreForward::new(32);
    queue.enqueue(envelope.clone()).map_err(|e| CliError::IdentityError(e))?;

    let pending = queue.get_pending(&doc.id).map_err(|e| CliError::IdentityError(e))?;
    output.success(&format!("Queued envelopes: {}", pending.len()))?;

    if let Some(ct) = extract_device_ciphertext(&envelope, "device-0") {
        output.info(&format!("Device-0 ciphertext bytes: {}", ct.len()))?;
    } else {
        output.warning("No ciphertext found for device-0")?;
    }

    let pending_for_device = queue
        .get_pending_for_device(&doc.id, "device-0")
        .map_err(|e| CliError::IdentityError(e))?;
    output.info(&format!("Pending for device-0: {}", pending_for_device.len()))?;

    let recipient_kp = KeyPair {
        public_key: recipient.public_key.clone(),
        private_key: recipient.private_key.clone().ok_or_else(|| {
            CliError::IdentityError("Recipient missing private key".to_string())
        })?,
    };
    let receipt = create_delivery_receipt(envelope.message_id, "device-0", &recipient_kp)
        .map_err(|e| CliError::IdentityError(e))?;
    let receipt_env = build_delivery_receipt_envelope(
        &doc.id,
        &sender_doc.id,
        &receipt,
        MessageTtl::Days7,
    ).map_err(|e| CliError::IdentityError(e))?;
    output.success(&format!("Receipt envelope payloads: {}", receipt_env.payloads.len()))?;

    let removed = queue.acknowledge_delivery(&doc.id, envelope.message_id)
        .map_err(|e| CliError::IdentityError(e))?;
    output.success(&format!("Store-and-forward acknowledged: {}", removed))?;

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
    fn test_action_to_operation_pending() {
        let action = IdentityAction::Pending {
            recipient_did: "did:zhtp:recipient".to_string(),
            device_id: "device-1".to_string(),
        };
        assert_eq!(
            action_to_operation(&action),
            IdentityOperation::Pending
        );
    }

    #[test]
    fn test_action_to_operation_ack() {
        let action = IdentityAction::Ack {
            recipient_did: "did:zhtp:recipient".to_string(),
            device_id: "device-1".to_string(),
            message_id: 42,
            retain_until_ttl: false,
        };
        assert_eq!(
            action_to_operation(&action),
            IdentityOperation::Ack
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
            IdentityOperation::Pending.description(),
            "Fetch pending identity envelopes"
        );
        assert_eq!(
            IdentityOperation::Ack.description(),
            "Acknowledge identity envelope delivery"
        );
    }
}
