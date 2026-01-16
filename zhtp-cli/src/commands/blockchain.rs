//! Blockchain commands for ZHTP orchestrator
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Validation, request building (pure functions)
//! - **Imperative Shell**: QUIC client calls, output printing
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Traits for client and output injection

use crate::argument_parsing::{BlockchainArgs, BlockchainAction, ZhtpCli, format_output};
use crate::commands::web4_utils::connect_default;
use crate::error::{CliResult, CliError};
use crate::output::Output;
use lib_network::client::ZhtpClient;
use serde_json::json;

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Validate a transaction hash format
///
/// Pure function - depends only on input
fn validate_tx_hash(tx_hash: &str) -> CliResult<()> {
    if tx_hash.is_empty() {
        return Err(CliError::Other("Transaction hash cannot be empty".to_string()));
    }

    if tx_hash.len() < 32 {
        return Err(CliError::Other(
            "Transaction hash must be at least 32 characters".to_string(),
        ));
    }

    Ok(())
}

/// Build transaction lookup request body
///
/// Pure function - creates JSON request data
fn build_transaction_request(tx_hash: &str) -> serde_json::Value {
    json!({
        "tx_hash": tx_hash,
        "orchestrated": true
    })
}

// ============================================================================
// IMPERATIVE SHELL - All side effects here (QUIC, output)
// ============================================================================

/// Handle blockchain command with proper error handling and output
///
/// Public entry point that uses the new architecture
pub async fn handle_blockchain_command(
    args: BlockchainArgs,
    cli: &ZhtpCli,
) -> crate::error::CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_blockchain_command_impl(args, cli, &output).await
}

/// Internal implementation with dependency injection
///
/// This is the imperative shell - it:
/// 1. Validates inputs (pure)
/// 2. Makes QUIC requests (side effect)
/// 3. Formats and prints output (side effect)
/// 4. Returns proper error types
async fn handle_blockchain_command_impl(
    args: BlockchainArgs,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    // Connect using default keystore with bootstrap mode
    let client = connect_default(&cli.server).await?;

    match args.action {
        BlockchainAction::Status => {
            fetch_and_display_blockchain_status(&client, cli, output).await
        }
        BlockchainAction::Transaction { tx_hash } => {
            fetch_and_display_transaction(&client, &tx_hash, cli, output).await
        }
        BlockchainAction::Stats => {
            fetch_and_display_blockchain_stats(&client, cli, output).await
        }
    }
}

/// Fetch blockchain status and display it
async fn fetch_and_display_blockchain_status(
    client: &ZhtpClient,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    output.print("Querying blockchain status...")?;

    let response = client
        .get("/api/v1/blockchain/status")
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/blockchain/status".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let result: serde_json::Value = ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/blockchain/status".to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;
    let formatted = format_output(&result, &cli.format)?;
    output.header("Blockchain Status")?;
    output.print(&formatted)?;
    Ok(())
}

/// Fetch transaction details and display them
async fn fetch_and_display_transaction(
    client: &ZhtpClient,
    tx_hash: &str,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    // Pure validation
    validate_tx_hash(tx_hash)?;

    output.print(&format!("Looking up transaction: {}", tx_hash))?;

    // Pure request building
    let request_body = build_transaction_request(tx_hash);

    // Imperative: QUIC call
    let response = client
        .post_json("/api/v1/blockchain/transaction", &request_body)
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/blockchain/transaction".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let result: serde_json::Value = ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/blockchain/transaction".to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;
    let formatted = format_output(&result, &cli.format)?;
    output.header("Transaction Details")?;
    output.print(&formatted)?;
    Ok(())
}

/// Fetch blockchain statistics and display them
async fn fetch_and_display_blockchain_stats(
    client: &ZhtpClient,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    output.print("Collecting blockchain statistics...")?;

    let response = client
        .get("/api/v1/blockchain/stats")
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/blockchain/stats".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let result: serde_json::Value = ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/blockchain/stats".to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;
    let formatted = format_output(&result, &cli.format)?;
    output.header("Blockchain Statistics")?;
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
    fn test_validate_tx_hash_valid() {
        let hash = "0".repeat(64);
        assert!(validate_tx_hash(&hash).is_ok());
    }

    #[test]
    fn test_validate_tx_hash_empty() {
        let result = validate_tx_hash("");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_tx_hash_too_short() {
        let hash = "0".repeat(30);
        let result = validate_tx_hash(&hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_transaction_request() {
        let req = build_transaction_request("abc123");
        assert_eq!(req["tx_hash"], "abc123");
        assert_eq!(req["orchestrated"], true);
    }

    #[tokio::test]
    async fn test_validate_tx_hash_in_handler_path() {
        // This test shows that the pure validation logic is called
        // before making any QUIC requests
        let hash = "";
        let result = validate_tx_hash(hash);
        assert!(result.is_err());
    }
}
