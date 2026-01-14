//! Citizen management commands
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Identity validation, request body construction, API endpoint generation
//! - **Imperative Shell**: HTTP requests, response handling, output formatting
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Pure functions for validation

use crate::argument_parsing::{CitizenArgs, CitizenAction, ZhtpCli, format_output};
use crate::error::{CliResult, CliError};
use crate::commands::common::validate_identity_id;
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

    /// Get HTTP method for this operation
    pub fn http_method(&self) -> &'static str {
        match self {
            CitizenOperation::Add => "POST",
            CitizenOperation::List => "GET",
        }
    }

    /// Get endpoint path for this operation
    pub fn endpoint_path(&self) -> &'static str {
        match self {
            CitizenOperation::Add => "citizens/register",
            CitizenOperation::List => "citizens",
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
// IMPERATIVE SHELL - API calls and side effects
// ============================================================================

/// Handle citizen command
pub async fn handle_citizen_command(
    args: CitizenArgs,
    cli: &ZhtpCli,
) -> CliResult<()> {
    let operation = action_to_operation(&args.action);

    if cli.verbose {
        eprintln!("[citizen] Operation: {:?}", operation.description());
    }

    match args.action {
        CitizenAction::Add { identity_id } => {
            register_citizen(&identity_id, cli).await
        }
        CitizenAction::List => {
            list_citizens(cli).await
        }
    }
}

/// Register a new citizen for UBI
async fn register_citizen(
    identity_id: &str,
    cli: &ZhtpCli,
) -> CliResult<()> {
    // Validate identity ID format
    validate_identity_id(identity_id)?;

    if cli.verbose {
        eprintln!("[citizen:add] Validating identity ID: {}", identity_id);
    }

    // Build request
    let request_body = build_register_request(identity_id);

    // Create HTTP client and send request
    let client = reqwest::Client::new();
    let url = format!("http://{}/api/v1/citizens/register", cli.server);

    if cli.verbose {
        eprintln!("[citizen:add] POST {}", url);
    }

    let response = client
        .post(&url)
        .json(&request_body)
        .send()
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "citizens/register".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let status = response.status();

    if status.is_success() {
        let result: Value = response.json().await.map_err(|e| {
            CliError::ApiCallFailed {
                endpoint: "citizens/register".to_string(),
                status: status.as_u16(),
                reason: format!("Failed to parse response: {}", e),
            }
        })?;

        let formatted = format_output(&result, &cli.format)
            .map_err(|e| CliError::Other(e.to_string()))?;

        println!("✓ Citizen Registered\n{}", formatted);
        Ok(())
    } else {
        let error_body = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());

        Err(CliError::ApiCallFailed {
            endpoint: "citizens/register".to_string(),
            status: status.as_u16(),
            reason: error_body,
        })
    }
}

/// List all registered citizens
async fn list_citizens(cli: &ZhtpCli) -> CliResult<()> {
    if cli.verbose {
        eprintln!("[citizen:list] Fetching citizen list");
    }

    let client = reqwest::Client::new();
    let url = format!("http://{}/api/v1/citizens", cli.server);

    if cli.verbose {
        eprintln!("[citizen:list] GET {}", url);
    }

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "citizens".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let status = response.status();

    if status.is_success() {
        let result: Value = response.json().await.map_err(|e| {
            CliError::ApiCallFailed {
                endpoint: "citizens".to_string(),
                status: status.as_u16(),
                reason: format!("Failed to parse response: {}", e),
            }
        })?;

        let formatted = format_output(&result, &cli.format)
            .map_err(|e| CliError::Other(e.to_string()))?;

        println!("✓ Registered Citizens\n{}", formatted);
        Ok(())
    } else {
        let error_body = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());

        Err(CliError::ApiCallFailed {
            endpoint: "citizens".to_string(),
            status: status.as_u16(),
            reason: error_body,
        })
    }
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
    fn test_citizen_operation_http_methods() {
        assert_eq!(CitizenOperation::Add.http_method(), "POST");
        assert_eq!(CitizenOperation::List.http_method(), "GET");
    }

    #[test]
    fn test_citizen_operation_endpoints() {
        assert_eq!(CitizenOperation::Add.endpoint_path(), "citizens/register");
        assert_eq!(CitizenOperation::List.endpoint_path(), "citizens");
    }
}
