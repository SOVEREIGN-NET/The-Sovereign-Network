//! Domain management commands for ZHTP CLI
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Domain name validation, availability checking
//! - **Imperative Shell**: Network I/O, file operations, output printing
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Output trait injection for testing

use crate::argument_parsing::{DomainArgs, DomainAction, ZhtpCli};
use crate::commands::web4_utils::{build_trust_config, connect_client, load_identity_from_keystore, resolve_keystore_path, validate_domain};
use crate::error::{CliResult, CliError};
use crate::output::Output;

use std::collections::HashMap;
use lib_crypto::sign_message;

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Valid domain operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainOperation {
    Register,
    Check,
    Info,
    Status,
    Transfer,
    Release,
    Migrate,
}

impl DomainOperation {
    /// Get user-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            DomainOperation::Register => "Register a new domain",
            DomainOperation::Check => "Check domain availability",
            DomainOperation::Info => "Get domain information",
            DomainOperation::Status => "Get domain status",
            DomainOperation::Transfer => "Transfer domain to new owner",
            DomainOperation::Release => "Release domain from use",
            DomainOperation::Migrate => "Migrate legacy domain records",
        }
    }
}

/// Determine operation from arguments
///
/// Pure function - deterministic conversion
pub fn action_to_operation(action: &DomainAction) -> DomainOperation {
    match action {
        DomainAction::Register { .. } => DomainOperation::Register,
        DomainAction::Check { .. } => DomainOperation::Check,
        DomainAction::Info { .. } => DomainOperation::Info,
        DomainAction::Status { .. } => DomainOperation::Status,
        DomainAction::Transfer { .. } => DomainOperation::Transfer,
        DomainAction::Release { .. } => DomainOperation::Release,
        DomainAction::Migrate { .. } => DomainOperation::Migrate,
    }
}

/// Validate domain name format
pub fn validate_domain_name(domain: &str) -> CliResult<()> {
    validate_domain(domain).map(|_| ())
}

fn minimum_registration_fee() -> u64 {
    // Match blockchain's fee calculation formula
    // (lib-blockchain/src/transaction/creation.rs::calculate_minimum_fee)
    // Formula: base_fee + size_fee, where size_fee = (tx_size / bytes_per_zhtp)
    // and size_fee is multiplied by 2 for transactions larger than 10_000 bytes.
    let estimated_tx_size = 9000u64; // Domain registration typically ~8718 bytes
    let base_fee = 1000u64;
    let bytes_per_zhtp = 100u64;
    let threshold_bytes = 10_000u64;
    let mut size_fee = (estimated_tx_size / bytes_per_zhtp).max(1);
    if estimated_tx_size > threshold_bytes {
        size_fee *= 2;
    }
    base_fee + size_fee  // = 1000 + 90 = 1090 SOV for 9000-byte estimate
}

// ============================================================================
// IMPERATIVE SHELL - All side effects here (network I/O, output)
// ============================================================================

/// Handle domain command with proper error handling and output
///
/// Public entry point that maintains backward compatibility
pub async fn handle_domain_command(
    args: DomainArgs,
    cli: &ZhtpCli,
) -> crate::error::CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_domain_command_impl(args, cli, &output).await
}

/// Internal implementation with dependency injection
async fn handle_domain_command_impl(
    args: DomainArgs,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    let op = action_to_operation(&args.action);
    output.info(&format!("{}...", op.description()))?;

    match args.action {
        DomainAction::Register {
            domain,
            duration,
            metadata,
            keystore,
            trust,
        } => {
            // Pure validation
            let domain = validate_domain(&domain)?;

            output.header("Register Domain")?;
            output.print(&format!("Domain: {}", domain))?;
            output.print(&format!("Duration (days): {}", duration))?;

            // Imperative: Network communication
            register_domain_impl(
                &domain,
                duration,
                metadata.as_ref(),
                keystore.as_ref().map(|s| s.as_str()),
                trust.pin_spki.as_deref(),
                trust.node_did.as_deref(),
                trust.tofu,
                trust.trust_node,
                &cli.server,
                output,
            )
            .await
        }
        DomainAction::Check {
            domain,
            keystore,
            trust,
        } => {
            // Pure validation
            let domain = validate_domain(&domain)?;

            output.header("Check Domain Availability")?;
            output.print(&format!("Domain: {}", domain))?;

            // Imperative: Network communication
            check_domain_impl(
                &domain,
                keystore.as_ref().map(|s| s.as_str()),
                trust.pin_spki.as_deref(),
                trust.node_did.as_deref(),
                trust.tofu,
                trust.trust_node,
                &cli.server,
                output,
            )
            .await
        }
        DomainAction::Info {
            domain,
            keystore,
            trust,
        } => {
            // Pure validation
            let domain = validate_domain(&domain)?;

            output.header("Domain Information")?;
            output.print(&format!("Domain: {}", domain))?;

            // Imperative: Network communication
            get_domain_info_impl(
                &domain,
                keystore.as_ref().map(|s| s.as_str()),
                trust.pin_spki.as_deref(),
                trust.node_did.as_deref(),
                trust.tofu,
                trust.trust_node,
                &cli.server,
                output,
            )
            .await
        }
        DomainAction::Status {
            domain,
            keystore,
            trust,
        } => {
            let domain = validate_domain(&domain)?;

            output.header("Domain Status")?;
            output.print(&format!("Domain: {}", domain))?;

            get_domain_info_impl(
                &domain,
                keystore.as_ref().map(|s| s.as_str()),
                trust.pin_spki.as_deref(),
                trust.node_did.as_deref(),
                trust.tofu,
                trust.trust_node,
                &cli.server,
                output,
            )
            .await
        }
        DomainAction::Transfer {
            domain,
            new_owner,
            keystore,
            trust,
        } => {
            // Pure validation
            let domain = validate_domain(&domain)?;

            output.header("Transfer Domain")?;
            output.print(&format!("Domain: {}", domain))?;
            output.print(&format!("New owner: {}", new_owner))?;

            // Imperative: Network communication
            transfer_domain_impl(
                &domain,
                &new_owner,
                keystore.as_ref().map(|s| s.as_str()),
                trust.pin_spki.as_deref(),
                trust.node_did.as_deref(),
                trust.tofu,
                trust.trust_node,
                &cli.server,
                output,
            )
            .await
        }
        DomainAction::Release {
            domain,
            keystore,
            force,
            trust,
        } => {
            // Pure validation
            let domain = validate_domain(&domain)?;

            output.header("Release Domain")?;
            output.print(&format!("Domain: {}", domain))?;

            // Imperative: Network communication
            release_domain_impl(
                &domain,
                keystore.as_ref().map(|s| s.as_str()),
                trust.pin_spki.as_deref(),
                trust.node_did.as_deref(),
                trust.tofu,
                trust.trust_node,
                &cli.server,
                force,
                output,
            )
            .await
        }
        DomainAction::Migrate { keystore, trust } => {
            output.header("Migrate Domain Records")?;

            migrate_domains_impl(
                keystore.as_ref().map(|s| s.as_str()),
                trust.pin_spki.as_deref(),
                trust.node_did.as_deref(),
                trust.tofu,
                trust.trust_node,
                &cli.server,
                output,
            )
            .await
        }
    }
}

/// Register a new domain
async fn register_domain_impl(
    domain: &str,
    duration: u64,
    metadata: Option<&String>,
    keystore: Option<&str>,
    pin_spki: Option<&str>,
    node_did: Option<&str>,
    tofu: bool,
    trust_node: bool,
    server: &str,
    output: &dyn Output,
) -> CliResult<()> {
    output.info(&format!("Registering domain '{}' for {} days...", domain, duration))?;

    let keystore_path = resolve_keystore_path(keystore)?;

    let loaded = load_identity_from_keystore(&keystore_path)?;
    let trust_config = build_trust_config(pin_spki, node_did, tofu, trust_node)?;
    let client = connect_client(loaded.identity.clone(), trust_config, server).await?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| CliError::ConfigError(format!("Time error: {}", e)))?
        .as_secs();
    let fee = minimum_registration_fee();
    let message = format!("{}|{}|{}", domain, timestamp, fee);
    let signature = sign_message(&loaded.keypair, message.as_bytes())
        .map_err(|e| CliError::ConfigError(format!("Failed to sign registration: {}", e)))?;

    let metadata_json = match metadata {
        Some(raw) => Some(serde_json::from_str::<serde_json::Value>(raw)
            .map_err(|e| CliError::ConfigError(format!("Invalid metadata JSON: {}", e)))?),
        None => None,
    };

    let body = serde_json::json!({
        "domain": domain,
        "owner": loaded.identity.did.clone(),
        "content_mappings": HashMap::<String, serde_json::Value>::new(),
        "metadata": metadata_json,
        "signature": hex::encode(signature.signature),
        "timestamp": timestamp,
        "fee": fee,
    });

    let response = client
        .post_json("/api/v1/web4/domains/register", &body)
        .await
        .map_err(|e| CliError::ConfigError(format!("Failed to register domain: {}", e)))?;
    let _: serde_json::Value = lib_network::client::ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ConfigError(format!("Failed to parse registration response: {}", e)))?;

    output.success(&format!("✓ Domain '{}' registered successfully", domain))?;
    output.print(&format!("Registration period: {} days", duration))?;
    output.print(&format!("Use 'zhtp-cli domain info {}' to view details", domain))?;

    Ok(())
}

/// Check if domain is available
async fn check_domain_impl(
    domain: &str,
    keystore: Option<&str>,
    pin_spki: Option<&str>,
    node_did: Option<&str>,
    tofu: bool,
    trust_node: bool,
    server: &str,
    output: &dyn Output,
) -> CliResult<()> {
    output.info(&format!("Checking availability for '{}'...", domain))?;

    let keystore_path = resolve_keystore_path(keystore)?;

    let loaded = load_identity_from_keystore(&keystore_path)?;
    let trust_config = build_trust_config(pin_spki, node_did, tofu, trust_node)?;
    let client = connect_client(loaded.identity.clone(), trust_config, server).await?;

    let response = client
        .get(&format!("/api/v1/web4/domains/{}", domain))
        .await
        .map_err(|e| CliError::ConfigError(format!("Failed to query domain: {}", e)))?;

    let info: serde_json::Value = lib_network::client::ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ConfigError(format!("Failed to parse domain response: {}", e)))?;
    let found = info.get("found").and_then(|v| v.as_bool()).unwrap_or(false);

    if found {
        output.warning(&format!("Domain '{}' is already registered", domain))?;
        return Ok(());
    }

    output.success(&format!("✓ Domain '{}' is available", domain))?;
    output.print("You can register this domain with 'zhtp-cli domain register'")?;

    Ok(())
}

/// Get domain information
async fn get_domain_info_impl(
    domain: &str,
    keystore: Option<&str>,
    pin_spki: Option<&str>,
    node_did: Option<&str>,
    tofu: bool,
    trust_node: bool,
    server: &str,
    output: &dyn Output,
) -> CliResult<()> {
    let keystore_path = resolve_keystore_path(keystore)?;

    let loaded = load_identity_from_keystore(&keystore_path)?;
    let trust_config = build_trust_config(pin_spki, node_did, tofu, trust_node)?;
    let client = connect_client(loaded.identity.clone(), trust_config, server).await?;

    let response = client
        .get(&format!("/api/v1/web4/domains/{}", domain))
        .await
        .map_err(|e| CliError::ConfigError(format!("Failed to get domain info: {}", e)))?;
    let info: serde_json::Value = lib_network::client::ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ConfigError(format!("Failed to parse domain info: {}", e)))?;

    if info.get("found").and_then(|v| v.as_bool()).unwrap_or(false) {
        output.success(&format!("✓ Domain information for '{}'", domain))?;
        output.print(&serde_json::to_string_pretty(&info).unwrap_or_default())?;
    } else {
        output.warning(&format!("Domain '{}' not found", domain))?;
    }

    Ok(())
}

/// Transfer domain to a new owner
async fn transfer_domain_impl(
    domain: &str,
    new_owner: &str,
    keystore: Option<&str>,
    pin_spki: Option<&str>,
    node_did: Option<&str>,
    tofu: bool,
    trust_node: bool,
    server: &str,
    output: &dyn Output,
) -> CliResult<()> {
    output.info(&format!(
        "Transferring domain '{}' to '{}'...",
        domain, new_owner
    ))?;

    let keystore_path = resolve_keystore_path(keystore)?;
    let loaded = load_identity_from_keystore(&keystore_path)?;
    let trust_config = build_trust_config(pin_spki, node_did, tofu, trust_node)?;
    let client = connect_client(loaded.identity.clone(), trust_config, server).await?;

    let message = format!("{}|{}", domain, new_owner);
    let signature = sign_message(&loaded.keypair, message.as_bytes())
        .map_err(|e| CliError::ConfigError(format!("Failed to sign transfer: {}", e)))?;

    let body = serde_json::json!({
        "domain": domain,
        "from_owner": loaded.identity.did,
        "to_owner": new_owner,
        "transfer_proof": hex::encode(signature.signature),
    });

    let response = client
        .post_json(&format!("/api/v1/web4/domains/{}/transfer", domain), &body)
        .await
        .map_err(|e| CliError::ConfigError(format!("Failed to transfer domain: {}", e)))?;
    let result: serde_json::Value = lib_network::client::ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ConfigError(format!("Failed to parse transfer response: {}", e)))?;

    if result.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
        output.success(&format!(
            "✓ Domain '{}' transfer initiated to '{}'",
            domain, new_owner
        ))?;
        output.print("The new owner will need to confirm the transfer")?;
        return Ok(());
    }

    Err(CliError::ConfigError(
        "Domain transfer failed".to_string(),
    ))
}

/// Release domain from use
async fn release_domain_impl(
    domain: &str,
    keystore: Option<&str>,
    pin_spki: Option<&str>,
    node_did: Option<&str>,
    tofu: bool,
    trust_node: bool,
    server: &str,
    _force: bool,
    output: &dyn Output,
) -> CliResult<()> {
    output.info(&format!("Releasing domain '{}'...", domain))?;

    let keystore_path = resolve_keystore_path(keystore)?;
    let loaded = load_identity_from_keystore(&keystore_path)?;
    let trust_config = build_trust_config(pin_spki, node_did, tofu, trust_node)?;
    let client = connect_client(loaded.identity.clone(), trust_config, server).await?;

    let body = serde_json::json!({
        "domain": domain,
        "owner_identity": loaded.identity.did,
    });

    let response = client
        .post_json(&format!("/api/v1/web4/domains/{}/release", domain), &body)
        .await
        .map_err(|e| CliError::ConfigError(format!("Failed to release domain: {}", e)))?;
    let result: serde_json::Value = lib_network::client::ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ConfigError(format!("Failed to parse release response: {}", e)))?;

    if result.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
        output.success(&format!("✓ Domain '{}' released successfully", domain))?;
        output.print("This domain is now available for registration by others")?;
        return Ok(());
    }

    Err(CliError::ConfigError(
        "Domain release failed".to_string(),
    ))
}

/// Admin: migrate legacy domain records
async fn migrate_domains_impl(
    keystore: Option<&str>,
    pin_spki: Option<&str>,
    node_did: Option<&str>,
    tofu: bool,
    trust_node: bool,
    server: &str,
    output: &dyn Output,
) -> CliResult<()> {
    let keystore_path = resolve_keystore_path(keystore)?;
    let loaded = load_identity_from_keystore(&keystore_path)?;
    let trust_config = build_trust_config(pin_spki, node_did, tofu, trust_node)?;
    let client = connect_client(loaded.identity.clone(), trust_config, server).await?;

    let response = client
        .post_json("/api/v1/web4/domains/admin/migrate-domains", &serde_json::json!({}))
        .await
        .map_err(|e| CliError::ConfigError(format!("Failed to migrate domains: {}", e)))?;

    let info: serde_json::Value = lib_network::client::ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ConfigError(format!("Failed to parse migrate response: {}", e)))?;

    let migrated = info.get("migrated").and_then(|v| v.as_u64()).unwrap_or(0);
    output.success(&format!("✓ Migrated {} domain records", migrated))?;
    Ok(())
}

// ============================================================================
// TESTS - Pure logic is testable without mocks or side effects
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_domain_name_valid_zhtp() {
        assert!(validate_domain_name("example.zhtp").is_ok());
        assert!(validate_domain_name("my-app.zhtp").is_ok());
        assert!(validate_domain_name("test123.zhtp").is_ok());
    }

    #[test]
    fn test_validate_domain_name_valid_sov() {
        assert!(validate_domain_name("example.sov").is_ok());
        assert!(validate_domain_name("my-site.sov").is_ok());
    }

    #[test]
    fn test_validate_domain_name_short_but_valid() {
        // 2-letter domain names are valid
        assert!(validate_domain_name("ab.zhtp").is_ok());
    }

    #[test]
    fn test_validate_domain_name_empty() {
        assert!(validate_domain_name("").is_err());
    }

    #[test]
    fn test_validate_domain_name_invalid_tld() {
        assert!(validate_domain_name("example.com").is_err());
        assert!(validate_domain_name("example.org").is_err());
    }

    #[test]
    fn test_action_to_operation_register() {
        let action = DomainAction::Register {
            domain: "test.zhtp".to_string(),
            duration: 365,
            metadata: None,
            keystore: None,
            trust: TrustFlags {
                pin_spki: None,
                node_did: None,
                tofu: false,
                trust_node: false,
            },
        };
        assert_eq!(action_to_operation(&action), DomainOperation::Register);
    }

    #[test]
    fn test_action_to_operation_check() {
        let action = DomainAction::Check {
            domain: "test.zhtp".to_string(),
            keystore: None,
            trust: TrustFlags {
                pin_spki: None,
                node_did: None,
                tofu: false,
                trust_node: false,
            },
        };
        assert_eq!(action_to_operation(&action), DomainOperation::Check);
    }

    #[test]
    fn test_operation_description() {
        assert_eq!(DomainOperation::Register.description(), "Register a new domain");
        assert_eq!(
            DomainOperation::Check.description(),
            "Check domain availability"
        );
        assert_eq!(
            DomainOperation::Info.description(),
            "Get domain information"
        );
        assert_eq!(
            DomainOperation::Transfer.description(),
            "Transfer domain to new owner"
        );
        assert_eq!(
            DomainOperation::Release.description(),
            "Release domain from use"
        );
    }
}
