//! Network commands for ZHTP orchestrator
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Socket address validation, ping count validation
//! - **Imperative Shell**: QUIC client calls, UDP operations, output printing
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Traits for client and output injection

use crate::argument_parsing::{NetworkArgs, NetworkAction, ZhtpCli, format_output};
use crate::commands::web4_utils::connect_default;
use crate::error::{CliResult, CliError};
use crate::output::Output;
use crate::logic;
use lib_network::client::ZhtpClient;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Valid network operation endpoints
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkEndpoint {
    Status,
    Peers,
    Test,
}

impl NetworkEndpoint {
    /// Get the API endpoint path for this operation
    pub fn endpoint_path(&self) -> &'static str {
        match self {
            NetworkEndpoint::Status => "/api/v1/network/status",
            NetworkEndpoint::Peers => "/api/v1/network/peers",
            NetworkEndpoint::Test => "/api/v1/network/test",
        }
    }

    /// Get request method for this operation
    pub fn method(&self) -> &'static str {
        match self {
            NetworkEndpoint::Status => "GET",
            NetworkEndpoint::Peers => "GET",
            NetworkEndpoint::Test => "POST",
        }
    }

    /// Get a user-friendly title for this operation
    pub fn title(&self) -> &'static str {
        match self {
            NetworkEndpoint::Status => "Network Status",
            NetworkEndpoint::Peers => "Connected Peers",
            NetworkEndpoint::Test => "Network Test Results",
        }
    }
}

/// Convert NetworkAction to NetworkEndpoint
///
/// Pure function - deterministic conversion
pub fn action_to_endpoint(action: &NetworkAction) -> Option<NetworkEndpoint> {
    match action {
        NetworkAction::Status => Some(NetworkEndpoint::Status),
        NetworkAction::Peers => Some(NetworkEndpoint::Peers),
        NetworkAction::Test => Some(NetworkEndpoint::Test),
        NetworkAction::Ping { .. } => None, // Handled separately
    }
}

// ============================================================================
// IMPERATIVE SHELL - All side effects here (QUIC, UDP, output)
// ============================================================================

/// Handle network command with proper error handling and output
///
/// Public entry point that maintains backward compatibility
pub async fn handle_network_command(
    args: NetworkArgs,
    cli: &ZhtpCli,
) -> crate::error::CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_network_command_impl(args, cli, &output).await
}

/// Internal implementation with dependency injection
async fn handle_network_command_impl(
    args: NetworkArgs,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    match args.action {
        NetworkAction::Status | NetworkAction::Peers | NetworkAction::Test => {
            let endpoint = action_to_endpoint(&args.action)
                .ok_or_else(|| CliError::NetworkError("Invalid network action".to_string()))?;

            output.info(&format!("Fetching {}...", endpoint.title().to_lowercase()))?;

            // Connect using default keystore with bootstrap mode
            let client = connect_default(&cli.server).await?;

            fetch_and_display_network_info(&client, endpoint, cli, output).await
        }
        NetworkAction::Ping { target, count } => {
            // Pure validation
            logic::validate_socket_address(&target)?;
            logic::validate_ping_count(count)?;

            // Imperative: QUIC operations
            ping_peer(&target, count, output).await
        }
    }
}

/// Fetch network information and display it via QUIC
async fn fetch_and_display_network_info(
    client: &ZhtpClient,
    endpoint: NetworkEndpoint,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    let response = match endpoint.method() {
        "GET" => client.get(endpoint.endpoint_path()).await,
        "POST" => client.post_json(endpoint.endpoint_path(), &serde_json::json!({})).await,
        _ => client.get(endpoint.endpoint_path()).await,
    }
    .map_err(|e| CliError::ApiCallFailed {
        endpoint: endpoint.endpoint_path().to_string(),
        status: 0,
        reason: e.to_string(),
    })?;

    let result: serde_json::Value = ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: endpoint.endpoint_path().to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;
    let formatted = format_output(&result, &cli.format)?;
    output.header(endpoint.title())?;
    output.print(&formatted)?;
    Ok(())
}

/// Ping a peer node directly via QUIC
async fn ping_peer(target: &str, count: u32, output: &dyn Output) -> CliResult<()> {
    output.print(&format!("🏓 ZHTP QUIC Ping to {}", target))?;
    output.print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")?;

    // Pure validation
    logic::validate_socket_address(target)?;
    let target_addr: SocketAddr = target.parse().map_err(|_| {
        CliError::NetworkError(format!("Invalid socket address: {}", target))
    })?;

    let mut successful_pings = 0;
    let mut total_rtt = Duration::ZERO;
    let mut min_rtt = Duration::MAX;
    let mut max_rtt = Duration::ZERO;

    for seq in 1..=count {
        let start = Instant::now();

        // Create a new client for each ping to measure connection time as well
        let mut client = connect_default(&target_addr.to_string()).await?;

        let response = client.get("/api/v1/network/ping").await;

        let rtt = start.elapsed();

        match response {
            Ok(res) => {
                if res.status.is_success() {
                    successful_pings += 1;
                    total_rtt += rtt;
                    min_rtt = min_rtt.min(rtt);
                    max_rtt = max_rtt.max(rtt);

                    output.print(&format!(
                        "✅ Reply from {}: seq={} time={:.2}ms",
                        target,
                        seq,
                        rtt.as_secs_f64() * 1000.0,
                    ))?;
                } else {
                    output.print(&format!(
                        "❌ Reply from {}: seq={} status={}",
                        target,
                        seq,
                        res.status.code(),
                    ))?;
                }
            }
            Err(e) => {
                output.print(&format!("❌ seq={}: Request error: {}", seq, e))?;
            }
        }

        // Wait 1 second between pings
        if seq < count {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    // Print statistics
    output.print("")?;
    output.print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")?;
    output.print(&format!("📊 Ping statistics for {}:", target))?;
    output.print(&format!(
        "   {} packets transmitted, {} received, {:.1}% packet loss",
        count,
        successful_pings,
        (count - successful_pings) as f64 / count as f64 * 100.0
    ))?;

    if successful_pings > 0 {
        let avg_rtt = total_rtt / successful_pings;
        output.print(&format!(
            "   Round-trip min/avg/max = {:.2}/{:.2}/{:.2} ms",
            min_rtt.as_secs_f64() * 1000.0,
            avg_rtt.as_secs_f64() * 1000.0,
            max_rtt.as_secs_f64() * 1000.0
        ))?;
    }

    Ok(())
}

// ============================================================================
// TESTS - Pure logic is testable without mocks or side effects
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_endpoint_paths() {
        assert_eq!(NetworkEndpoint::Status.endpoint_path(), "/api/v1/network/status");
        assert_eq!(NetworkEndpoint::Peers.endpoint_path(), "/api/v1/network/peers");
        assert_eq!(NetworkEndpoint::Test.endpoint_path(), "/api/v1/network/test");
    }

    #[test]
    fn test_network_endpoint_methods() {
        assert_eq!(NetworkEndpoint::Status.method(), "GET");
        assert_eq!(NetworkEndpoint::Peers.method(), "GET");
        assert_eq!(NetworkEndpoint::Test.method(), "POST");
    }

    #[test]
    fn test_network_endpoint_titles() {
        assert_eq!(NetworkEndpoint::Status.title(), "Network Status");
        assert_eq!(NetworkEndpoint::Peers.title(), "Connected Peers");
        assert_eq!(NetworkEndpoint::Test.title(), "Network Test Results");
    }

    #[test]
    fn test_action_to_endpoint_status() {
        let endpoint = action_to_endpoint(&NetworkAction::Status);
        assert_eq!(endpoint, Some(NetworkEndpoint::Status));
    }

    #[test]
    fn test_action_to_endpoint_ping_returns_none() {
        let endpoint = action_to_endpoint(&NetworkAction::Ping {
            target: "127.0.0.1:9002".to_string(),
            count: 3,
        });
        assert_eq!(endpoint, None);
    }
}
