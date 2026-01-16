//! UBI status and management commands
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Identity validation, request body construction, API endpoint generation
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
    Status,
}

impl UbiOperation {
    /// Get user-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            UbiOperation::Status => "Get UBI status (personal or pool)",
        }
    }

    /// Get request method for this operation
    pub fn method(&self) -> &'static str {
        "GET"
    }

    /// Get endpoint path for this operation
    pub fn endpoint_path(&self, identity_id: Option<&str>) -> String {
        match self {
            UbiOperation::Status => {
                if let Some(id) = identity_id {
                    format!("/api/v1/ubi/status/{}", id)
                } else {
                    "/api/v1/ubi/pool".to_string()
                }
            }
        }
    }

    /// Get a user-friendly title for this operation
    pub fn title(&self, is_personal: bool) -> &'static str {
        if is_personal {
            "Personal UBI Status"
        } else {
            "Global UBI Pool Status"
        }
    }
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
    if cli.verbose {
        eprintln!("[ubi] UBI status command");
    }

    // Connect using default keystore with bootstrap mode
    let client = connect_default(&cli.server).await?;

    match args.action {
        UbiAction::Status { identity_id } => {
            fetch_ubi_status(&client, identity_id.as_deref(), cli, output).await
        }
    }
}

/// Fetch UBI status for an identity (or global pool if None)
async fn fetch_ubi_status(
    client: &ZhtpClient,
    identity_id: Option<&str>,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    // Validate identity ID if provided
    if let Some(id) = identity_id {
        validate_identity_id(id)?;
    }

    let is_personal = identity_id.is_some();

    if cli.verbose {
        if let Some(id) = identity_id {
            eprintln!("[ubi:status] Fetching personal UBI status for: {}", id);
        } else {
            eprintln!("[ubi:status] Fetching global UBI pool status");
        }
    }

    let operation = UbiOperation::Status;
    let endpoint = operation.endpoint_path(identity_id);

    output.info(&format!("Fetching {}...", operation.title(is_personal).to_lowercase()))?;

    if cli.verbose {
        eprintln!("[ubi:status] GET {}", endpoint);
    }

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
    output.header(operation.title(is_personal))?;
    output.print(&formatted)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ubi_operation_personal_endpoint() {
        let endpoint = UbiOperation::Status.endpoint_path(Some("did:example:123"));
        assert_eq!(endpoint, "/api/v1/ubi/status/did:example:123");
    }

    #[test]
    fn test_ubi_operation_pool_endpoint() {
        let endpoint = UbiOperation::Status.endpoint_path(None);
        assert_eq!(endpoint, "/api/v1/ubi/pool");
    }

    #[test]
    fn test_ubi_operation_method() {
        assert_eq!(UbiOperation::Status.method(), "GET");
    }

    #[test]
    fn test_ubi_operation_description() {
        assert!(!UbiOperation::Status.description().is_empty());
    }

    #[test]
    fn test_ubi_operation_title_personal() {
        assert_eq!(UbiOperation::Status.title(true), "Personal UBI Status");
    }

    #[test]
    fn test_ubi_operation_title_pool() {
        assert_eq!(UbiOperation::Status.title(false), "Global UBI Pool Status");
    }
}
