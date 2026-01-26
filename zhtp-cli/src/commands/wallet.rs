//! Wallet commands for ZHTP orchestrator
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Wallet name/address/amount validation (pure functions)
//! - **Imperative Shell**: HTTP client calls, output printing
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Output trait injection for testing

use crate::argument_parsing::{WalletArgs, WalletAction, ZhtpCli, format_output};
use crate::error::{CliResult, CliError};
use crate::output::Output;
use crate::logic;
use serde_json::json;

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Valid wallet operation endpoints
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletOp {
    Create,
    Balance,
    Transfer,
    History,
    List,
}

impl WalletOp {
    /// Get the API endpoint path for this operation
    pub fn endpoint_path(&self) -> &'static str {
        match self {
            WalletOp::Create => "wallet/create",
            WalletOp::Balance => "wallet/balance",
            WalletOp::Transfer => "wallet/transfer",
            WalletOp::History => "wallet/history",
            WalletOp::List => "wallet/list",
        }
    }

    /// Get HTTP method for this operation
    pub fn http_method(&self) -> &'static str {
        match self {
            WalletOp::Create | WalletOp::Transfer => "POST",
            WalletOp::Balance | WalletOp::History | WalletOp::List => "GET",
        }
    }

    /// Get a user-friendly title for this operation
    pub fn title(&self) -> &'static str {
        match self {
            WalletOp::Create => "Wallet Creation",
            WalletOp::Balance => "Wallet Balance",
            WalletOp::Transfer => "Fund Transfer",
            WalletOp::History => "Transaction History",
            WalletOp::List => "Wallet List",
        }
    }
}

/// Build transfer request body
///
/// Pure function - creates validated request data
pub fn build_transfer_request(from: &str, to: &str, amount: u64) -> CliResult<serde_json::Value> {
    // Validate addresses
    logic::validate_wallet_address(from)?;
    logic::validate_wallet_address(to)?;

    // Validate amount
    logic::validate_transaction_amount(amount)?;

    Ok(json!({
        "from": from,
        "to": to,
        "amount": amount,
        "orchestrated": true
    }))
}

/// Build create wallet request body
///
/// Pure function - creates validated request data
pub fn build_create_wallet_request(name: &str, wallet_type: &str) -> CliResult<serde_json::Value> {
    // Validate name and type
    logic::validate_wallet_name(name)?;
    logic::validate_wallet_type(wallet_type)?;

    Ok(json!({
        "wallet_name": name,
        "wallet_type": wallet_type,
        "orchestrated": true
    }))
}

// ============================================================================
// IMPERATIVE SHELL - All side effects here (HTTP, output)
// ============================================================================

/// Handle wallet command with proper error handling and output
///
/// Public entry point that maintains backward compatibility
pub async fn handle_wallet_command(
    args: WalletArgs,
    cli: &ZhtpCli,
) -> crate::error::CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_wallet_command_impl(args, cli, &output).await
}

/// Internal implementation with dependency injection
async fn handle_wallet_command_impl(
    args: WalletArgs,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/api/v1", cli.server);

    match args.action {
        WalletAction::Create { name, wallet_type } => {
            // Pure validation
            let request_body = build_create_wallet_request(&name, &wallet_type)?;

            // Imperative: HTTP call
            send_wallet_request(
                &client,
                &base_url,
                WalletOp::Create,
                Some(request_body),
                None,
                cli,
                output,
            )
            .await
        }
        WalletAction::Balance { address } => {
            // Pure validation
            logic::validate_wallet_address(&address)?;

            // Imperative: HTTP call
            send_wallet_request(
                &client,
                &base_url,
                WalletOp::Balance,
                None,
                Some(&address),
                cli,
                output,
            )
            .await
        }
        WalletAction::Transfer { from, to, amount } => {
            // Pure validation and request building
            let request_body = build_transfer_request(&from, &to, amount)?;

            // Imperative: HTTP call
            send_wallet_request(
                &client,
                &base_url,
                WalletOp::Transfer,
                Some(request_body),
                None,
                cli,
                output,
            )
            .await
        }
        WalletAction::History { address } => {
            // Pure validation
            logic::validate_wallet_address(&address)?;

            // Imperative: HTTP call
            send_wallet_request(
                &client,
                &base_url,
                WalletOp::History,
                None,
                Some(&address),
                cli,
                output,
            )
            .await
        }
        WalletAction::List => {
            // Imperative: HTTP call
            send_wallet_request(
                &client,
                &base_url,
                WalletOp::List,
                None,
                None,
                cli,
                output,
            )
            .await
        }
    }
}

/// Send wallet API request and display result
async fn send_wallet_request(
    client: &reqwest::Client,
    base_url: &str,
    op: WalletOp,
    request_body: Option<serde_json::Value>,
    header_address: Option<&str>,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    output.info(&format!("Executing {}...", op.title().to_lowercase()))?;

    let url = format!("{}/{}", base_url, op.endpoint_path());
    let response = match op {
        WalletOp::Create | WalletOp::Transfer => {
            let request_body = request_body.ok_or_else(|| {
                CliError::WalletError("Request body is required".to_string())
            })?;

            client
                .post(&url)
                .json(&request_body)
                .send()
                .await
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: op.endpoint_path().to_string(),
                    status: 0,
                    reason: e.to_string(),
                })?
        }
        WalletOp::Balance | WalletOp::History => {
            let address = header_address.ok_or_else(|| {
                CliError::WalletError("Address is required".to_string())
            })?;

            client
                .get(&url)
                .header("x-wallet-address", address)
                .send()
                .await
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: op.endpoint_path().to_string(),
                    status: 0,
                    reason: e.to_string(),
                })?
        }
        WalletOp::List => {
            client
                .get(&url)
                .send()
                .await
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: op.endpoint_path().to_string(),
                    status: 0,
                    reason: e.to_string(),
                })?
        }
    };

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        let formatted = format_output(&result, &cli.format)?;
        output.header(op.title())?;
        output.print(&formatted)?;
        Ok(())
    } else {
        Err(CliError::ApiCallFailed {
            endpoint: op.endpoint_path().to_string(),
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
    fn test_wallet_op_paths() {
        assert_eq!(WalletOp::Create.endpoint_path(), "wallet/create");
        assert_eq!(WalletOp::Balance.endpoint_path(), "wallet/balance");
        assert_eq!(WalletOp::Transfer.endpoint_path(), "wallet/transfer");
        assert_eq!(WalletOp::History.endpoint_path(), "wallet/history");
        assert_eq!(WalletOp::List.endpoint_path(), "wallet/list");
    }

    #[test]
    fn test_wallet_op_methods() {
        assert_eq!(WalletOp::Create.http_method(), "POST");
        assert_eq!(WalletOp::Transfer.http_method(), "POST");
        assert_eq!(WalletOp::Balance.http_method(), "GET");
        assert_eq!(WalletOp::History.http_method(), "GET");
        assert_eq!(WalletOp::List.http_method(), "GET");
    }

    #[test]
    fn test_build_create_wallet_request_valid() {
        let result = build_create_wallet_request("my-wallet", "standard");
        assert!(result.is_ok());
        let req = result.unwrap();
        assert_eq!(req["wallet_name"], "my-wallet");
        assert_eq!(req["wallet_type"], "standard");
    }

    #[test]
    fn test_build_create_wallet_request_invalid_name() {
        let result = build_create_wallet_request("ab", "standard");
        assert!(result.is_err());
    }

    #[test]
    fn test_build_transfer_request_valid() {
        let from = "zaddr1234567890abcdefghijklmnopqrst";
        let to = "zaddr2234567890abcdefghijklmnopqrst";
        let result = build_transfer_request(from, to, 1000);
        assert!(result.is_ok());
        let req = result.unwrap();
        assert_eq!(req["from"], from);
        assert_eq!(req["to"], to);
        assert_eq!(req["amount"], 1000);
    }

    #[test]
    fn test_build_transfer_request_invalid_amount() {
        let from = "zaddr1234567890abcdefghijklmnopqrst";
        let to = "zaddr2234567890abcdefghijklmnopqrst";
        let result = build_transfer_request(from, to, 0);
        assert!(result.is_err());
    }
}
