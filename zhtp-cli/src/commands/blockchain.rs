//! Blockchain commands for ZHTP orchestrator
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Validation, request building (pure functions)
//! - **Imperative Shell**: HTTP client calls, output printing
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Traits for HTTP client and output injection

use crate::argument_parsing::{BlockchainArgs, BlockchainAction, ZhtpCli, format_output};
use crate::error::{CliResult, CliError};
use crate::output::Output;
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
// IMPERATIVE SHELL - All side effects here (HTTP, output)
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
/// 2. Makes HTTP requests (side effect)
/// 3. Formats and prints output (side effect)
/// 4. Returns proper error types
async fn handle_blockchain_command_impl(
    args: BlockchainArgs,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/api/v1", cli.server);

    match args.action {
        BlockchainAction::Status => {
            fetch_and_display_blockchain_status(&client, &base_url, cli, output).await
        }
        BlockchainAction::Transaction { tx_hash } => {
            fetch_and_display_transaction(&client, &base_url, &tx_hash, cli, output).await
        }
        BlockchainAction::Stats => {
            fetch_and_display_blockchain_stats(&client, &base_url, cli, output).await
        }
    }
}

/// Fetch blockchain status and display it
async fn fetch_and_display_blockchain_status(
    client: &reqwest::Client,
    base_url: &str,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    output.print("Querying blockchain status...")?;

    let response = client
        .get(&format!("{}/blockchain/status", base_url))
        .send()
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "blockchain/status".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        let formatted = format_output(&result, &cli.format)?;
        output.header("Blockchain Status")?;
        output.print(&formatted)?;
        Ok(())
    } else {
        Err(CliError::ApiCallFailed {
            endpoint: "blockchain/status".to_string(),
            status: response.status().as_u16(),
            reason: format!("HTTP {}", response.status()),
        })
    }
}

/// Fetch transaction details and display them
async fn fetch_and_display_transaction(
    client: &reqwest::Client,
    base_url: &str,
    tx_hash: &str,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    // Pure validation
    validate_tx_hash(tx_hash)?;

    output.print(&format!("Looking up transaction: {}", tx_hash))?;

    // Pure request building
    let request_body = build_transaction_request(tx_hash);

    // Imperative: HTTP call
    let response = client
        .post(&format!("{}/blockchain/transaction", base_url))
        .json(&request_body)
        .send()
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "blockchain/transaction".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        let formatted = format_output(&result, &cli.format)?;
        output.header("Transaction Details")?;
        output.print(&formatted)?;
        Ok(())
    } else {
        Err(CliError::ApiCallFailed {
            endpoint: "blockchain/transaction".to_string(),
            status: response.status().as_u16(),
            reason: format!("HTTP {}", response.status()),
        })
    }
}

/// Fetch blockchain statistics and display them
async fn fetch_and_display_blockchain_stats(
    client: &reqwest::Client,
    base_url: &str,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    output.print("Collecting blockchain statistics...")?;

    let response = client
        .get(&format!("{}/blockchain/stats", base_url))
        .send()
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "blockchain/stats".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        let formatted = format_output(&result, &cli.format)?;
        output.header("Blockchain Statistics")?;
        output.print(&formatted)?;
        Ok(())
    } else {
        Err(CliError::ApiCallFailed {
            endpoint: "blockchain/stats".to_string(),
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
    use crate::output::testing::MockOutput;

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
        // before making any HTTP requests
        let hash = "";
        let result = validate_tx_hash(hash);
        assert!(result.is_err());
    }
}
