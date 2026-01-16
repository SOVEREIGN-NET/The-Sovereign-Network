//! Citizen management commands
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Identity validation, request body construction
//! - **Imperative Shell**: QUIC client calls, response handling, output formatting
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Pure functions for validation

use crate::argument_parsing::{CitizenArgs, CitizenAction, ZhtpCli, format_output};
use crate::commands::common::validate_identity_id;
use crate::commands::web4_utils::connect_default;
use crate::error::{CliResult, CliError};
use crate::output::Output;
use lib_network::client::ZhtpClient;
use serde_json::{json, Value};

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Citizen operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CitizenOperation {
    Add,
    List,
}

impl CitizenOperation {
    /// Get user-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            CitizenOperation::Add => "Apply for citizenship",
            CitizenOperation::List => "List all registered citizens",
        }
    }

    /// Get a user-friendly title for this operation
    pub fn title(&self) -> &'static str {
        match self {
            CitizenOperation::Add => "Citizenship Application",
            CitizenOperation::List => "Registered Citizens",
        }
    }
}

/// Determine operation from arguments
///
/// Pure function - deterministic conversion
pub fn action_to_operation(action: &CitizenAction) -> CitizenOperation {
    match action {
        CitizenAction::Add { .. } => CitizenOperation::Add,
        CitizenAction::List => CitizenOperation::List,
    }
}

/// Build citizenship application request body
///
/// Pure function - JSON construction only
pub fn build_citizenship_request(identity_id: &str) -> Value {
    json!({
        "identity_id": identity_id,
        "name": identity_id,  // Use identity_id as name for now
        "register_for_ubi": true
    })
}

// ============================================================================
// IMPERATIVE SHELL - QUIC calls and side effects
// ============================================================================

/// Handle citizen command
pub async fn handle_citizen_command(
    args: CitizenArgs,
    cli: &ZhtpCli,
) -> CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_citizen_command_impl(args, cli, &output).await
}

/// Internal implementation with dependency injection
async fn handle_citizen_command_impl(
    args: CitizenArgs,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    match args.action {
        CitizenAction::Add { identity_id } => {
            apply_for_citizenship(&identity_id, cli, output).await
        }
        CitizenAction::List => {
            // List endpoint not implemented on server
            output.warning("Citizen list endpoint not yet implemented on server.")?;
            output.info("To view identities, use: zhtp-cli identity list")?;
            Ok(())
        }
    }
}

/// Apply for citizenship
async fn apply_for_citizenship(
    identity_id: &str,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    // Validate identity ID format
    validate_identity_id(identity_id)?;

    output.info(&format!("Applying for citizenship: {}", identity_id))?;

    // Connect using default keystore with bootstrap mode
    let client = connect_default(&cli.server).await?;

    // Build request
    let request_body = build_citizenship_request(identity_id);

    // POST to citizenship application endpoint
    let endpoint = "/api/v1/identity/citizenship/apply";
    let response = client
        .post_json(endpoint, &request_body)
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: endpoint.to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let result: Value = ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: endpoint.to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;

    let formatted = format_output(&result, &cli.format)?;
    output.header(CitizenOperation::Add.title())?;
    output.print(&formatted)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_citizenship_request() {
        let result = build_citizenship_request("did:zhtp:123");
        assert_eq!(result["identity_id"], "did:zhtp:123");
        assert_eq!(result["register_for_ubi"], true);
    }

    #[test]
    fn test_action_to_operation_add() {
        let action = CitizenAction::Add {
            identity_id: "did:example:123".to_string(),
        };
        assert_eq!(action_to_operation(&action), CitizenOperation::Add);
    }

    #[test]
    fn test_action_to_operation_list() {
        let action = CitizenAction::List;
        assert_eq!(action_to_operation(&action), CitizenOperation::List);
    }

    #[test]
    fn test_citizen_operation_descriptions() {
        assert!(!CitizenOperation::Add.description().is_empty());
        assert!(!CitizenOperation::List.description().is_empty());
    }
}
