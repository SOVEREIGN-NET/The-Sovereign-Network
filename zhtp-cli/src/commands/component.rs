//! Component management commands for ZHTP orchestrator
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Component name validation, request body construction, API endpoint generation
//! - **Imperative Shell**: QUIC client calls, response handling, output formatting
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Pure functions for request building and validation

use crate::argument_parsing::{ComponentArgs, ComponentAction, ZhtpCli, format_output};
use crate::commands::web4_utils::connect_default;
use crate::error::{CliResult, CliError};
use crate::output::Output;
use lib_network::client::ZhtpClient;
use serde_json::{json, Value};

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Component operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentOperation {
    Start,
    Stop,
    Status,
    Restart,
    List,
}

impl ComponentOperation {
    /// Get user-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            ComponentOperation::Start => "Start component",
            ComponentOperation::Stop => "Stop component",
            ComponentOperation::Status => "Get component status",
            ComponentOperation::Restart => "Restart component",
            ComponentOperation::List => "List components",
        }
    }

    /// Get request method for this operation
    pub fn method(&self) -> &'static str {
        match self {
            ComponentOperation::List => "GET",
            _ => "POST",
        }
    }

    /// Get endpoint path for this operation
    pub fn endpoint_path(&self) -> &'static str {
        match self {
            ComponentOperation::Start => "/api/v1/component/start",
            ComponentOperation::Stop => "/api/v1/component/stop",
            ComponentOperation::Status => "/api/v1/component/status",
            ComponentOperation::Restart => "/api/v1/component/restart",
            ComponentOperation::List => "/api/v1/component/list",
        }
    }

    /// Get a user-friendly title for this operation
    pub fn title(&self) -> &'static str {
        match self {
            ComponentOperation::Start => "Component Start",
            ComponentOperation::Stop => "Component Stop",
            ComponentOperation::Status => "Component Status",
            ComponentOperation::Restart => "Component Restart",
            ComponentOperation::List => "Component List",
        }
    }
}

/// Determine operation from arguments
///
/// Pure function - deterministic conversion
pub fn action_to_operation(action: &ComponentAction) -> ComponentOperation {
    match action {
        ComponentAction::Start { .. } => ComponentOperation::Start,
        ComponentAction::Stop { .. } => ComponentOperation::Stop,
        ComponentAction::Status { .. } => ComponentOperation::Status,
        ComponentAction::Restart { .. } => ComponentOperation::Restart,
        ComponentAction::List => ComponentOperation::List,
    }
}

/// Validate component name
///
/// Pure function - format validation only
pub fn validate_component_name(name: &str) -> CliResult<()> {
    if name.is_empty() {
        return Err(CliError::ConfigError(
            "Component name cannot be empty".to_string(),
        ));
    }

    if name.len() > 128 {
        return Err(CliError::ConfigError(format!(
            "Component name too long: {} (max 128 characters)",
            name.len()
        )));
    }

    // Component names should be alphanumeric with hyphens and underscores
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(CliError::ConfigError(format!(
            "Invalid component name: {}. Use only alphanumeric characters, hyphens, and underscores",
            name
        )));
    }

    Ok(())
}

/// Build request body for component operation
///
/// Pure function - JSON construction only
pub fn build_request_body(
    operation: ComponentOperation,
    component_name: Option<&str>,
) -> Value {
    match operation {
        ComponentOperation::List => json!({
            "orchestrated": true
        }),
        _ => json!({
            "component": component_name,
            "action": operation.endpoint_path().split('/').last().unwrap_or(""),
            "orchestrated": true
        }),
    }
}

/// Get user-friendly message for operation
///
/// Pure function - message formatting only
pub fn get_operation_message(operation: ComponentOperation, component: Option<&str>) -> String {
    match operation {
        ComponentOperation::Start => {
            format!("Orchestrating component start: {}", component.unwrap_or("unknown"))
        }
        ComponentOperation::Stop => {
            format!("Orchestrating component stop: {}", component.unwrap_or("unknown"))
        }
        ComponentOperation::Status => {
            format!("Orchestrating component status: {}", component.unwrap_or("unknown"))
        }
        ComponentOperation::Restart => {
            format!("Orchestrating component restart: {}", component.unwrap_or("unknown"))
        }
        ComponentOperation::List => "Orchestrating component list...".to_string(),
    }
}

// ============================================================================
// IMPERATIVE SHELL - All side effects here (QUIC requests, I/O)
// ============================================================================

/// Handle component command with proper error handling and output
pub async fn handle_component_command(args: ComponentArgs, cli: &ZhtpCli) -> CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_component_command_impl(args, cli, &output).await
}

/// Internal implementation with dependency injection
async fn handle_component_command_impl(
    args: ComponentArgs,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    match args.action {
        ComponentAction::Start { name } => {
            validate_component_name(&name)?;
            let operation = ComponentOperation::Start;
            handle_component_operation_impl(operation, Some(&name), cli, output).await
        }
        ComponentAction::Stop { name } => {
            validate_component_name(&name)?;
            let operation = ComponentOperation::Stop;
            handle_component_operation_impl(operation, Some(&name), cli, output).await
        }
        ComponentAction::Status { name } => {
            validate_component_name(&name)?;
            let operation = ComponentOperation::Status;
            handle_component_operation_impl(operation, Some(&name), cli, output).await
        }
        ComponentAction::Restart { name } => {
            validate_component_name(&name)?;
            let operation = ComponentOperation::Restart;
            handle_component_operation_impl(operation, Some(&name), cli, output).await
        }
        ComponentAction::List => {
            let operation = ComponentOperation::List;
            handle_component_operation_impl(operation, None, cli, output).await
        }
    }
}

/// Internal handler for component operations
async fn handle_component_operation_impl(
    operation: ComponentOperation,
    component_name: Option<&str>,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    output.info(&get_operation_message(operation, component_name))?;

    // Connect using default keystore with bootstrap mode
    let client = connect_default(&cli.server).await?;

    let request_body = build_request_body(operation, component_name);

    fetch_and_display_component_result(&client, operation, &request_body, cli, output).await
}

/// Fetch component operation result and display it via QUIC
async fn fetch_and_display_component_result(
    client: &ZhtpClient,
    operation: ComponentOperation,
    request_body: &Value,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    let response = match operation.method() {
        "GET" => client.get(operation.endpoint_path()).await,
        "POST" => client.post_json(operation.endpoint_path(), request_body).await,
        _ => client.get(operation.endpoint_path()).await,
    }
    .map_err(|e| CliError::ApiCallFailed {
        endpoint: operation.endpoint_path().to_string(),
        status: 0,
        reason: e.to_string(),
    })?;

    let result: serde_json::Value = ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: operation.endpoint_path().to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;
    let formatted = format_output(&result, &cli.format)?;
    output.header(operation.title())?;
    output.print(&formatted)?;
    Ok(())
}

// ============================================================================
// TESTS - Pure logic is testable without mocks or side effects
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_to_operation_start() {
        let action = ComponentAction::Start {
            name: "consensus".to_string(),
        };
        assert_eq!(action_to_operation(&action), ComponentOperation::Start);
    }

    #[test]
    fn test_action_to_operation_stop() {
        let action = ComponentAction::Stop {
            name: "consensus".to_string(),
        };
        assert_eq!(action_to_operation(&action), ComponentOperation::Stop);
    }

    #[test]
    fn test_action_to_operation_status() {
        let action = ComponentAction::Status {
            name: "consensus".to_string(),
        };
        assert_eq!(action_to_operation(&action), ComponentOperation::Status);
    }

    #[test]
    fn test_action_to_operation_restart() {
        let action = ComponentAction::Restart {
            name: "consensus".to_string(),
        };
        assert_eq!(action_to_operation(&action), ComponentOperation::Restart);
    }

    #[test]
    fn test_action_to_operation_list() {
        assert_eq!(action_to_operation(&ComponentAction::List), ComponentOperation::List);
    }

    #[test]
    fn test_operation_description() {
        assert_eq!(ComponentOperation::Start.description(), "Start component");
        assert_eq!(ComponentOperation::Stop.description(), "Stop component");
        assert_eq!(ComponentOperation::Status.description(), "Get component status");
        assert_eq!(ComponentOperation::Restart.description(), "Restart component");
        assert_eq!(ComponentOperation::List.description(), "List components");
    }

    #[test]
    fn test_operation_method() {
        assert_eq!(ComponentOperation::Start.method(), "POST");
        assert_eq!(ComponentOperation::Stop.method(), "POST");
        assert_eq!(ComponentOperation::List.method(), "GET");
    }

    #[test]
    fn test_operation_endpoint_path() {
        assert_eq!(ComponentOperation::Start.endpoint_path(), "/api/v1/component/start");
        assert_eq!(ComponentOperation::Stop.endpoint_path(), "/api/v1/component/stop");
        assert_eq!(ComponentOperation::Status.endpoint_path(), "/api/v1/component/status");
        assert_eq!(ComponentOperation::Restart.endpoint_path(), "/api/v1/component/restart");
        assert_eq!(ComponentOperation::List.endpoint_path(), "/api/v1/component/list");
    }

    #[test]
    fn test_validate_component_name_empty() {
        assert!(validate_component_name("").is_err());
    }

    #[test]
    fn test_validate_component_name_valid() {
        assert!(validate_component_name("consensus").is_ok());
        assert!(validate_component_name("consensus-engine").is_ok());
        assert!(validate_component_name("consensus_engine").is_ok());
        assert!(validate_component_name("c").is_ok());
    }

    #[test]
    fn test_validate_component_name_too_long() {
        let long_name = "a".repeat(129);
        assert!(validate_component_name(&long_name).is_err());
    }

    #[test]
    fn test_validate_component_name_invalid_chars() {
        assert!(validate_component_name("component!").is_err());
        assert!(validate_component_name("component@1").is_err());
        assert!(validate_component_name("component/name").is_err());
    }

    #[test]
    fn test_build_request_body_start() {
        let body = build_request_body(ComponentOperation::Start, Some("consensus"));
        assert_eq!(body.get("component").and_then(|v| v.as_str()), Some("consensus"));
        assert_eq!(body.get("orchestrated").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn test_build_request_body_list() {
        let body = build_request_body(ComponentOperation::List, None);
        assert!(body.get("orchestrated").and_then(|v| v.as_bool()) == Some(true));
        // List should not have component field
        assert!(body.get("component").is_none());
    }

    #[test]
    fn test_get_operation_message() {
        let msg = get_operation_message(ComponentOperation::Start, Some("consensus"));
        assert!(msg.contains("start"));
        assert!(msg.contains("consensus"));

        let msg = get_operation_message(ComponentOperation::List, None);
        assert!(msg.contains("list"));
    }
}
