//! Identity commands for ZHTP CLI
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Identity type parsing, DID validation, name validation
//! - **Imperative Shell**: File I/O, QUIC communication, output printing
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Output trait injection for testing

use crate::argument_parsing::{IdentityArgs, IdentityAction, ZhtpCli};
use crate::error::{CliResult, CliError};
use crate::output::Output;
use crate::logic;

use lib_identity::ZhtpIdentity;
use std::path::PathBuf;

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
}

impl IdentityOperation {
    /// Get user-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            IdentityOperation::Create => "Create standard identity",
            IdentityOperation::CreateWithType => "Create identity with specific type",
            IdentityOperation::Verify => "Verify identity on blockchain",
            IdentityOperation::List => "List blockchain identities",
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
    let identity_file = keystore.join("identity.json");
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

    // Save identity to file
    let identity_json = serde_json::to_string_pretty(&identity).map_err(|e| {
        CliError::IdentityError(format!("Failed to serialize identity: {}", e))
    })?;
    std::fs::write(&identity_file, identity_json).map_err(|e| {
        CliError::IdentityError(format!("Failed to write identity.json: {}", e))
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
    let identity_file = keystore.join("identity.json");
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

    // Save identity
    let identity_json = serde_json::to_string_pretty(&identity).map_err(|e| {
        CliError::IdentityError(format!("Failed to serialize identity: {}", e))
    })?;
    std::fs::write(&identity_file, identity_json).map_err(|e| {
        CliError::IdentityError(format!("Failed to write identity.json: {}", e))
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
    }
}
