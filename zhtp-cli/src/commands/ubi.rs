//! UBI status and management commands
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Identity validation, endpoint path construction
//! - **Imperative Shell**: QUIC client calls, response handling, output formatting
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Pure functions for validation

use crate::argument_parsing::{UbiArgs, UbiAction, ZhtpCli, format_output};
use crate::commands::common::validate_identity_id;
use crate::commands::web4_utils::connect_default;
use crate::error::{CliResult, CliError};
use crate::output::Output;
use lib_network::client::ZhtpClient;
use serde_json::Value;

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// UBI operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UbiOperation {
    PersonalStatus,
    PoolStatus,
}

impl UbiOperation {
    /// Get user-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            UbiOperation::PersonalStatus => "Get personal UBI wallet status",
            UbiOperation::PoolStatus => "Get global UBI pool status",
        }
    }

    /// Get a user-friendly title for this operation
    pub fn title(&self) -> &'static str {
        match self {
            UbiOperation::PersonalStatus => "Personal UBI Status",
            UbiOperation::PoolStatus => "Global UBI Pool Status",
        }
    }
}

/// Build UBI wallet balance endpoint path
///
/// Uses the wallet balance endpoint with wallet_type=ubi
pub fn build_ubi_balance_endpoint(identity_id: &str) -> String {
    format!("/api/v1/wallet/balance/ubi/{}", identity_id)
}

// ============================================================================
// IMPERATIVE SHELL - QUIC calls and side effects
// ============================================================================

/// Handle UBI command
pub async fn handle_ubi_command(
    args: UbiArgs,
    cli: &ZhtpCli,
) -> CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_ubi_command_impl(args, cli, &output).await
}

/// Internal implementation with dependency injection
async fn handle_ubi_command_impl(
    args: UbiArgs,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    match &args.action {
        UbiAction::Status { identity_id } => {
            match identity_id {
                Some(id) => fetch_personal_ubi_status(id, cli, output).await,
                None => {
                    // Global pool status endpoint not implemented
                    output.warning("Global UBI pool status endpoint not yet implemented on server.")?;
                    output.info("To check your personal UBI status, use: zhtp-cli ubi status <identity_id>")?;
                    Ok(())
                }
            }
        }
    }
}

/// Fetch personal UBI status (via UBI wallet balance)
async fn fetch_personal_ubi_status(
    identity_id: &str,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    // Validate identity ID format
    validate_identity_id(identity_id)?;

    output.info(&format!("Fetching UBI status for: {}", identity_id))?;

    // Connect using default keystore with bootstrap mode
    let client = connect_default(&cli.server).await?;

    // Query UBI wallet balance via wallet endpoint
    let endpoint = build_ubi_balance_endpoint(identity_id);

    let response = client
        .get(&endpoint)
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: endpoint.clone(),
            status: 0,
            reason: e.to_string(),
        })?;

    let result: Value = ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: endpoint.clone(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;

    let formatted = format_output(&result, &cli.format)?;
    output.header(UbiOperation::PersonalStatus.title())?;
    output.print(&formatted)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_ubi_balance_endpoint() {
        let endpoint = build_ubi_balance_endpoint("did:zhtp:123");
        assert_eq!(endpoint, "/api/v1/wallet/balance/ubi/did:zhtp:123");
    }

    #[test]
    fn test_ubi_operation_description() {
        assert!(!UbiOperation::PersonalStatus.description().is_empty());
        assert!(!UbiOperation::PoolStatus.description().is_empty());
    }

    #[test]
    fn test_ubi_operation_title() {
        assert_eq!(UbiOperation::PersonalStatus.title(), "Personal UBI Status");
        assert_eq!(UbiOperation::PoolStatus.title(), "Global UBI Pool Status");
    }
}
