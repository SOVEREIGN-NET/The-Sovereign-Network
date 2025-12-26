//! System monitoring commands for ZHTP orchestrator
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Validation, endpoint selection (pure functions)
//! - **Imperative Shell**: HTTP client calls, output printing
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Traits for HTTP client and output injection

use crate::argument_parsing::{MonitorArgs, MonitorAction, ZhtpCli, format_output};
use crate::error::{CliResult, CliError};
use crate::output::Output;

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Valid monitoring endpoints
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitoringEndpoint {
    System,
    Health,
    Performance,
    Logs,
}

impl MonitoringEndpoint {
    /// Get the API endpoint path for this monitoring type
    pub fn endpoint_path(&self) -> &'static str {
        match self {
            MonitoringEndpoint::System => "monitor/system",
            MonitoringEndpoint::Health => "monitor/health",
            MonitoringEndpoint::Performance => "monitor/performance",
            MonitoringEndpoint::Logs => "monitor/logs",
        }
    }

    /// Get a user-friendly title for this monitoring type
    pub fn title(&self) -> &'static str {
        match self {
            MonitoringEndpoint::System => "System Status",
            MonitoringEndpoint::Health => "Component Health",
            MonitoringEndpoint::Performance => "Performance Metrics",
            MonitoringEndpoint::Logs => "System Logs",
        }
    }

    /// Get description for this monitoring type
    pub fn description(&self) -> &'static str {
        match self {
            MonitoringEndpoint::System => "System monitoring information",
            MonitoringEndpoint::Health => "Health check for all components",
            MonitoringEndpoint::Performance => "Performance metrics and statistics",
            MonitoringEndpoint::Logs => "Recent system logs",
        }
    }
}

/// Convert MonitorAction to MonitoringEndpoint
///
/// Pure function - deterministic conversion
pub fn action_to_endpoint(action: &MonitorAction) -> MonitoringEndpoint {
    match action {
        MonitorAction::System => MonitoringEndpoint::System,
        MonitorAction::Health => MonitoringEndpoint::Health,
        MonitorAction::Performance => MonitoringEndpoint::Performance,
        MonitorAction::Logs => MonitoringEndpoint::Logs,
    }
}

// ============================================================================
// IMPERATIVE SHELL - All side effects here (HTTP, output)
// ============================================================================

/// Handle monitoring command with proper error handling and output
///
/// Public entry point that maintains backward compatibility
pub async fn handle_monitor_command(
    args: MonitorArgs,
    cli: &ZhtpCli,
) -> crate::error::CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_monitor_command_impl(args, cli, &output).await
}

/// Internal implementation with dependency injection
///
/// This is the imperative shell - it:
/// 1. Converts action to endpoint (pure)
/// 2. Makes HTTP requests (side effect)
/// 3. Formats and prints output (side effect)
/// 4. Returns proper error types
async fn handle_monitor_command_impl(
    args: MonitorArgs,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    let endpoint = action_to_endpoint(&args.action);
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/api/v1", cli.server);

    fetch_and_display_monitoring(&client, &base_url, endpoint, cli, output).await
}

/// Fetch monitoring data and display it
async fn fetch_and_display_monitoring(
    client: &reqwest::Client,
    base_url: &str,
    endpoint: MonitoringEndpoint,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    output.info(&format!("Fetching {}...", endpoint.description()))?;

    let url = format!("{}/{}", base_url, endpoint.endpoint_path());
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: endpoint.endpoint_path().to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        let formatted = format_output(&result, &cli.format)?;
        output.header(endpoint.title())?;
        output.print(&formatted)?;
        Ok(())
    } else {
        Err(CliError::ApiCallFailed {
            endpoint: endpoint.endpoint_path().to_string(),
            status: response.status().as_u16(),
            reason: format!("HTTP {}", response.status()),
        })
    }
}

// ============================================================================
// TESTS - Pure logic is testable without mocks or side effects
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitoring_endpoint_path() {
        assert_eq!(MonitoringEndpoint::System.endpoint_path(), "monitor/system");
        assert_eq!(MonitoringEndpoint::Health.endpoint_path(), "monitor/health");
        assert_eq!(
            MonitoringEndpoint::Performance.endpoint_path(),
            "monitor/performance"
        );
        assert_eq!(MonitoringEndpoint::Logs.endpoint_path(), "monitor/logs");
    }

    #[test]
    fn test_monitoring_endpoint_title() {
        assert_eq!(MonitoringEndpoint::System.title(), "System Status");
        assert_eq!(MonitoringEndpoint::Health.title(), "Component Health");
        assert_eq!(MonitoringEndpoint::Performance.title(), "Performance Metrics");
        assert_eq!(MonitoringEndpoint::Logs.title(), "System Logs");
    }

    #[test]
    fn test_action_to_endpoint_system() {
        let endpoint = action_to_endpoint(&MonitorAction::System);
        assert_eq!(endpoint, MonitoringEndpoint::System);
    }

    #[test]
    fn test_action_to_endpoint_health() {
        let endpoint = action_to_endpoint(&MonitorAction::Health);
        assert_eq!(endpoint, MonitoringEndpoint::Health);
    }

    #[test]
    fn test_action_to_endpoint_performance() {
        let endpoint = action_to_endpoint(&MonitorAction::Performance);
        assert_eq!(endpoint, MonitoringEndpoint::Performance);
    }

    #[test]
    fn test_action_to_endpoint_logs() {
        let endpoint = action_to_endpoint(&MonitorAction::Logs);
        assert_eq!(endpoint, MonitoringEndpoint::Logs);
    }

    #[test]
    fn test_all_endpoints_have_descriptions() {
        assert!(!MonitoringEndpoint::System.description().is_empty());
        assert!(!MonitoringEndpoint::Health.description().is_empty());
        assert!(!MonitoringEndpoint::Performance.description().is_empty());
        assert!(!MonitoringEndpoint::Logs.description().is_empty());
    }
}
