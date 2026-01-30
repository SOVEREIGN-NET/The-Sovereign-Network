//! System monitoring commands for ZHTP orchestrator
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Validation, endpoint selection (pure functions)
//! - **Imperative Shell**: QUIC client calls, output printing
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Traits for client and output injection

use crate::argument_parsing::{MonitorArgs, MonitorAction, ZhtpCli};
use crate::error::CliResult;
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
            MonitoringEndpoint::System => "/api/v1/monitor/system",
            MonitoringEndpoint::Health => "/api/v1/monitor/health",
            MonitoringEndpoint::Performance => "/api/v1/monitor/performance",
            MonitoringEndpoint::Logs => "/api/v1/monitor/logs",
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
// IMPERATIVE SHELL - All side effects here (QUIC, output)
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
/// 2. Makes QUIC requests (side effect)
/// 3. Formats and prints output (side effect)
/// 4. Returns proper error types
async fn handle_monitor_command_impl(
    args: MonitorArgs,
    _cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    let endpoint = action_to_endpoint(&args.action);

    // Note: The /api/v1/monitor/* endpoints are not yet implemented on the server.
    // This command is a placeholder for future monitoring functionality.
    output.warning(&format!(
        "Monitoring endpoint '{}' is not yet implemented on the server.",
        endpoint.endpoint_path()
    ))?;
    output.info(&format!(
        "The {} functionality will be available in a future server release.",
        endpoint.description().to_lowercase()
    ))?;

    Ok(())
}

// Note: fetch_and_display_monitoring removed - monitoring endpoints not implemented server-side.
// Will be restored when /api/v1/monitor/* endpoints are available.

// ============================================================================
// TESTS - Pure logic is testable without mocks or side effects
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitoring_endpoint_path() {
        assert_eq!(MonitoringEndpoint::System.endpoint_path(), "/api/v1/monitor/system");
        assert_eq!(MonitoringEndpoint::Health.endpoint_path(), "/api/v1/monitor/health");
        assert_eq!(
            MonitoringEndpoint::Performance.endpoint_path(),
            "/api/v1/monitor/performance"
        );
        assert_eq!(MonitoringEndpoint::Logs.endpoint_path(), "/api/v1/monitor/logs");
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
