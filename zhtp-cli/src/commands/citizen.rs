//! Citizen management commands
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Identity validation, request body construction, API endpoint generation
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
            CitizenOperation::Add => "Register a new citizen for UBI",
            CitizenOperation::List => "List all registered citizens",
        }
    }

    /// Get request method for this operation
    pub fn method(&self) -> &'static str {
        match self {
            CitizenOperation::Add => "POST",
            CitizenOperation::List => "GET",
        }
    }

    /// Get endpoint path for this operation
    pub fn endpoint_path(&self) -> &'static str {
        match self {
            CitizenOperation::Add => "/api/v1/citizens/register",
            CitizenOperation::List => "/api/v1/citizens",
        }
    }

    /// Get a user-friendly title for this operation
    pub fn title(&self) -> &'static str {
        match self {
            CitizenOperation::Add => "Citizen Registration",
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

/// Build request body for citizen registration
///
/// Pure function - JSON construction only
pub fn build_register_request(identity_id: &str) -> Value {
    json!({
        "identity_id": identity_id,
        "register_for_ubi": true,
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
    let operation = action_to_operation(&args.action);

    if cli.verbose {
        eprintln!("[citizen] Operation: {:?}", operation.description());
    }

    // Connect using default keystore with bootstrap mode
    let client = connect_default(&cli.server).await?;

    match args.action {
        CitizenAction::Add { identity_id } => {
            register_citizen(&client, &identity_id, cli, output).await
        }
        CitizenAction::List => {
            list_citizens(&client, cli, output).await
        }
    }
}

/// Register a new citizen for UBI
async fn register_citizen(
    client: &ZhtpClient,
    identity_id: &str,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    // Validate identity ID format
    validate_identity_id(identity_id)?;

    if cli.verbose {
        eprintln!("[citizen:add] Validating identity ID: {}", identity_id);
    }

    output.info("Registering citizen...")?;

    // Build request
    let request_body = build_register_request(identity_id);

    if cli.verbose {
        eprintln!("[citizen:add] POST {}", CitizenOperation::Add.endpoint_path());
    }

    let response = client
        .post_json(CitizenOperation::Add.endpoint_path(), &request_body)
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: CitizenOperation::Add.endpoint_path().to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let result: Value = ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: CitizenOperation::Add.endpoint_path().to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;

    let formatted = format_output(&result, &cli.format)?;
    output.header(CitizenOperation::Add.title())?;
    output.print(&formatted)?;
    Ok(())
}

/// List all registered citizens
async fn list_citizens(
    client: &ZhtpClient,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    if cli.verbose {
        eprintln!("[citizen:list] Fetching citizen list");
        eprintln!("[citizen:list] GET {}", CitizenOperation::List.endpoint_path());
    }

    output.info("Fetching citizen list...")?;

    let response = client
        .get(CitizenOperation::List.endpoint_path())
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: CitizenOperation::List.endpoint_path().to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let result: Value = ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: CitizenOperation::List.endpoint_path().to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;

    let formatted = format_output(&result, &cli.format)?;
    output.header(CitizenOperation::List.title())?;
    output.print(&formatted)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_register_request() {
        let result = build_register_request("did:example:123");
        assert_eq!(result["identity_id"], "did:example:123");
        assert_eq!(result["register_for_ubi"], true);
    }

    #[test]
    fn test_action_to_operation_add() {
        let action = CitizenAction::Add {
            identity_id: "did:example:123".to_string(),
        };
        assert_eq!(
            action_to_operation(&action),
            CitizenOperation::Add
        );
    }

    #[test]
    fn test_action_to_operation_list() {
        let action = CitizenAction::List;
        assert_eq!(
            action_to_operation(&action),
            CitizenOperation::List
        );
    }

    #[test]
    fn test_citizen_operation_methods() {
        assert_eq!(CitizenOperation::Add.method(), "POST");
        assert_eq!(CitizenOperation::List.method(), "GET");
    }

    #[test]
    fn test_citizen_operation_endpoints() {
        assert_eq!(CitizenOperation::Add.endpoint_path(), "/api/v1/citizens/register");
        assert_eq!(CitizenOperation::List.endpoint_path(), "/api/v1/citizens");
    }
}
