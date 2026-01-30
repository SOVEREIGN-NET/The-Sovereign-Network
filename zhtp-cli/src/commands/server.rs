//! Server management commands for ZHTP orchestrator
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Server operation validation, endpoint construction, message formatting
//! - **Imperative Shell**: HTTP requests, response handling, output formatting
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Pure functions for message generation and endpoint building

use anyhow::Result;
use crate::argument_parsing::{ServerArgs, ServerAction, ZhtpCli, format_output};
use serde_json::{json, Value};

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Server operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerOperation {
    Start,
    Stop,
    Restart,
    Status,
    Config,
}

impl ServerOperation {
    /// Get user-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            ServerOperation::Start => "Start orchestrator server",
            ServerOperation::Stop => "Stop orchestrator server",
            ServerOperation::Restart => "Restart orchestrator server",
            ServerOperation::Status => "Get server status",
            ServerOperation::Config => "Get server configuration",
        }
    }

    /// Get operation emoji
    pub fn emoji(&self) -> &'static str {
        match self {
            ServerOperation::Start => "▶️",
            ServerOperation::Stop => "⏹️",
            ServerOperation::Restart => "🔄",
            ServerOperation::Status => "📊",
            ServerOperation::Config => "⚙️",
        }
    }

    /// Get HTTP method for this operation
    pub fn http_method(&self) -> &'static str {
        match self {
            ServerOperation::Status | ServerOperation::Config => "GET",
            ServerOperation::Start | ServerOperation::Stop | ServerOperation::Restart => "POST",
        }
    }

    /// Get endpoint path for this operation
    pub fn endpoint_path(&self) -> &'static str {
        match self {
            ServerOperation::Start => "server/start",
            ServerOperation::Stop => "server/stop",
            ServerOperation::Restart => "server/restart",
            ServerOperation::Status => "server/status",
            ServerOperation::Config => "server/config",
        }
    }
}

/// Determine operation from arguments
///
/// Pure function - deterministic conversion
pub fn action_to_operation(action: &ServerAction) -> ServerOperation {
    match action {
        ServerAction::Start => ServerOperation::Start,
        ServerAction::Stop => ServerOperation::Stop,
        ServerAction::Restart => ServerOperation::Restart,
        ServerAction::Status => ServerOperation::Status,
        ServerAction::Config => ServerOperation::Config,
    }
}

/// Build API endpoint URL
///
/// Pure function - URL construction only
pub fn build_api_url(server: &str, endpoint: &str) -> String {
    format!("http://{}/api/v1/{}", server, endpoint)
}

/// Build request body for server operation
///
/// Pure function - JSON construction only
pub fn build_request_body(operation: ServerOperation) -> Value {
    match operation {
        ServerOperation::Status | ServerOperation::Config => json!({}),
        _ => json!({
            "action": operation.endpoint_path().split('/').last().unwrap_or(""),
            "orchestrated": true
        }),
    }
}

/// Get user-friendly operation message
///
/// Pure function - message formatting only
pub fn get_operation_message(operation: ServerOperation) -> String {
    match operation {
        ServerOperation::Start => format!("{} Starting ZHTP orchestrator server...", operation.emoji()),
        ServerOperation::Stop => format!("{} Stopping ZHTP orchestrator server...", operation.emoji()),
        ServerOperation::Restart => format!("{} Restarting ZHTP orchestrator server...", operation.emoji()),
        ServerOperation::Status => format!("{} Checking ZHTP orchestrator server status...", operation.emoji()),
        ServerOperation::Config => format!("{} Getting ZHTP orchestrator server configuration...", operation.emoji()),
    }
}

/// Get response message for operation
///
/// Pure function - message formatting only
pub fn get_response_message(operation: ServerOperation) -> String {
    format!("Server {} orchestrated:", operation.endpoint_path().split('/').last().unwrap_or("unknown"))
}

// ============================================================================
// IMPERATIVE SHELL - All side effects here (HTTP requests, I/O)
// ============================================================================

/// Handle server command
pub async fn handle_server_command(args: ServerArgs, cli: &ZhtpCli) -> Result<()> {
    let operation = action_to_operation(&args.action);
    handle_server_operation_impl(operation, cli).await
}

/// Internal handler for server operations
async fn handle_server_operation_impl(operation: ServerOperation, cli: &ZhtpCli) -> Result<()> {
    let client = reqwest::Client::new();
    let url = build_api_url(&cli.server, operation.endpoint_path());
    let request_body = build_request_body(operation);

    println!("{}", get_operation_message(operation));

    let response = match operation {
        ServerOperation::Status | ServerOperation::Config => {
            client.get(&url).send().await?
        }
        _ => {
            client.post(&url).json(&request_body).send().await?
        }
    };

    if response.status().is_success() {
        let result: Value = response.json().await?;
        let formatted = format_output(&result, &cli.format)?;
        println!("{}", get_response_message(operation));
        println!("{}", formatted);
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Failed to orchestrate server operation: {}",
            response.status()
        ))
    }
}

// ============================================================================
// TESTS - Pure logic is testable without mocks or side effects
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_to_operation_start() {
        assert_eq!(action_to_operation(&ServerAction::Start), ServerOperation::Start);
    }

    #[test]
    fn test_action_to_operation_stop() {
        assert_eq!(action_to_operation(&ServerAction::Stop), ServerOperation::Stop);
    }

    #[test]
    fn test_action_to_operation_restart() {
        assert_eq!(action_to_operation(&ServerAction::Restart), ServerOperation::Restart);
    }

    #[test]
    fn test_action_to_operation_status() {
        assert_eq!(action_to_operation(&ServerAction::Status), ServerOperation::Status);
    }

    #[test]
    fn test_action_to_operation_config() {
        assert_eq!(action_to_operation(&ServerAction::Config), ServerOperation::Config);
    }

    #[test]
    fn test_operation_description() {
        assert_eq!(ServerOperation::Start.description(), "Start orchestrator server");
        assert_eq!(ServerOperation::Stop.description(), "Stop orchestrator server");
        assert_eq!(ServerOperation::Restart.description(), "Restart orchestrator server");
        assert_eq!(ServerOperation::Status.description(), "Get server status");
        assert_eq!(ServerOperation::Config.description(), "Get server configuration");
    }

    #[test]
    fn test_operation_emoji() {
        assert_eq!(ServerOperation::Start.emoji(), "▶️");
        assert_eq!(ServerOperation::Stop.emoji(), "⏹️");
        assert_eq!(ServerOperation::Restart.emoji(), "🔄");
        assert_eq!(ServerOperation::Status.emoji(), "📊");
        assert_eq!(ServerOperation::Config.emoji(), "⚙️");
    }

    #[test]
    fn test_operation_http_method() {
        assert_eq!(ServerOperation::Start.http_method(), "POST");
        assert_eq!(ServerOperation::Stop.http_method(), "POST");
        assert_eq!(ServerOperation::Restart.http_method(), "POST");
        assert_eq!(ServerOperation::Status.http_method(), "GET");
        assert_eq!(ServerOperation::Config.http_method(), "GET");
    }

    #[test]
    fn test_operation_endpoint_path() {
        assert_eq!(ServerOperation::Start.endpoint_path(), "server/start");
        assert_eq!(ServerOperation::Stop.endpoint_path(), "server/stop");
        assert_eq!(ServerOperation::Restart.endpoint_path(), "server/restart");
        assert_eq!(ServerOperation::Status.endpoint_path(), "server/status");
        assert_eq!(ServerOperation::Config.endpoint_path(), "server/config");
    }

    #[test]
    fn test_build_api_url() {
        let url = build_api_url("localhost:9333", "server/start");
        assert_eq!(url, "http://localhost:9333/api/v1/server/start");
    }

    #[test]
    fn test_build_request_body_start() {
        let body = build_request_body(ServerOperation::Start);
        assert_eq!(body.get("action").and_then(|v| v.as_str()), Some("start"));
        assert_eq!(body.get("orchestrated").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn test_build_request_body_status() {
        let body = build_request_body(ServerOperation::Status);
        assert!(body.as_object().map(|o| o.is_empty()).unwrap_or(false));
    }

    #[test]
    fn test_get_operation_message() {
        let msg = get_operation_message(ServerOperation::Start);
        assert!(msg.contains("Starting"));
        assert!(msg.contains("▶️"));
    }

    #[test]
    fn test_get_response_message() {
        let msg = get_response_message(ServerOperation::Start);
        assert!(msg.contains("start"));
        assert!(msg.contains("orchestrated"));
    }

    #[test]
    fn test_all_operations_have_descriptions() {
        let ops = vec![
            ServerOperation::Start,
            ServerOperation::Stop,
            ServerOperation::Restart,
            ServerOperation::Status,
            ServerOperation::Config,
        ];
        for op in ops {
            assert!(!op.description().is_empty());
            assert!(!op.emoji().is_empty());
            assert!(!op.endpoint_path().is_empty());
            assert!(!op.http_method().is_empty());
        }
    }
}
