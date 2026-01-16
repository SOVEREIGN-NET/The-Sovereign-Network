//! Wallet commands for ZHTP orchestrator
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Wallet name/address/amount validation (pure functions)
//! - **Imperative Shell**: QUIC client calls, output printing
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Output trait injection for testing

use crate::argument_parsing::{WalletArgs, WalletAction, ZhtpCli, format_output};
use crate::commands::web4_utils::connect_default;
use crate::error::{CliResult, CliError};
use crate::output::Output;
use crate::logic;
use lib_network::client::ZhtpClient;
use serde_json::json;

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Valid wallet operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletOp {
    Create,
    Balance,
    Transfer,
    Transactions,
    List,
    Statistics,
}

impl WalletOp {
    /// Get a user-friendly title for this operation
    pub fn title(&self) -> &'static str {
        match self {
            WalletOp::Create => "Wallet Creation",
            WalletOp::Balance => "Wallet Balance",
            WalletOp::Transfer => "Fund Transfer",
            WalletOp::Transactions => "Transaction History",
            WalletOp::List => "Wallet List",
            WalletOp::Statistics => "Wallet Statistics",
        }
    }
}

/// Build balance endpoint path
///
/// Server expects: GET /api/v1/wallet/balance/{wallet_type}/{identity_id}
pub fn build_balance_path(wallet_type: &str, identity_id: &str) -> String {
    format!("/api/v1/wallet/balance/{}/{}", wallet_type, identity_id)
}

/// Build list endpoint path
///
/// Server expects: GET /api/v1/wallet/list/{identity_id}
pub fn build_list_path(identity_id: &str) -> String {
    format!("/api/v1/wallet/list/{}", identity_id)
}

/// Build transactions endpoint path
///
/// Server expects: GET /api/v1/wallet/transactions/{identity_id}
pub fn build_transactions_path(identity_id: &str) -> String {
    format!("/api/v1/wallet/transactions/{}", identity_id)
}

/// Build statistics endpoint path
///
/// Server expects: GET /api/v1/wallet/statistics/{identity_id}
pub fn build_statistics_path(identity_id: &str) -> String {
    format!("/api/v1/wallet/statistics/{}", identity_id)
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
// IMPERATIVE SHELL - All side effects here (QUIC, output)
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
    // Connect using default keystore with bootstrap mode
    let client = connect_default(&cli.server).await?;

    match args.action {
        WalletAction::Create { name, wallet_type } => {
            output.info("Creating wallet...")?;

            // Pure validation
            let request_body = build_create_wallet_request(&name, &wallet_type)?;

            // POST /api/v1/wallet/create (or appropriate endpoint)
            let response = client
                .post_json("/api/v1/wallet/create", &request_body)
                .await
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: "/api/v1/wallet/create".to_string(),
                    status: 0,
                    reason: e.to_string(),
                })?;

            let result: serde_json::Value = ZhtpClient::parse_json(&response)
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: "/api/v1/wallet/create".to_string(),
                    status: 0,
                    reason: format!("Failed to parse response: {}", e),
                })?;
            let formatted = format_output(&result, &cli.format)?;
            output.header(WalletOp::Create.title())?;
            output.print(&formatted)?;
            Ok(())
        }
        WalletAction::Balance { identity_id, wallet_type } => {
            output.info(&format!("Fetching {} wallet balance for {}...", wallet_type, identity_id))?;

            // GET /api/v1/wallet/balance/{wallet_type}/{identity_id}
            let endpoint = build_balance_path(&wallet_type, &identity_id);

            let response = client
                .get(&endpoint)
                .await
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: endpoint.clone(),
                    status: 0,
                    reason: e.to_string(),
                })?;

            let result: serde_json::Value = ZhtpClient::parse_json(&response)
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: endpoint.clone(),
                    status: 0,
                    reason: format!("Failed to parse response: {}", e),
                })?;
            let formatted = format_output(&result, &cli.format)?;
            output.header(WalletOp::Balance.title())?;
            output.print(&formatted)?;
            Ok(())
        }
        WalletAction::Transfer { from, to, amount } => {
            output.info(&format!("Transferring {} from {} to {}...", amount, from, to))?;

            // Pure validation and request building
            let request_body = build_transfer_request(&from, &to, amount)?;

            // POST /api/v1/wallet/send
            let response = client
                .post_json("/api/v1/wallet/send", &request_body)
                .await
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: "/api/v1/wallet/send".to_string(),
                    status: 0,
                    reason: e.to_string(),
                })?;

            let result: serde_json::Value = ZhtpClient::parse_json(&response)
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: "/api/v1/wallet/send".to_string(),
                    status: 0,
                    reason: format!("Failed to parse response: {}", e),
                })?;
            let formatted = format_output(&result, &cli.format)?;
            output.header(WalletOp::Transfer.title())?;
            output.print(&formatted)?;
            Ok(())
        }
        WalletAction::History { identity_id } => {
            output.info(&format!("Fetching transaction history for {}...", identity_id))?;

            // GET /api/v1/wallet/transactions/{identity_id}
            let endpoint = build_transactions_path(&identity_id);

            let response = client
                .get(&endpoint)
                .await
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: endpoint.clone(),
                    status: 0,
                    reason: e.to_string(),
                })?;

            let result: serde_json::Value = ZhtpClient::parse_json(&response)
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: endpoint.clone(),
                    status: 0,
                    reason: format!("Failed to parse response: {}", e),
                })?;
            let formatted = format_output(&result, &cli.format)?;
            output.header(WalletOp::Transactions.title())?;
            output.print(&formatted)?;
            Ok(())
        }
        WalletAction::List { identity_id } => {
            output.info(&format!("Listing wallets for {}...", identity_id))?;

            // GET /api/v1/wallet/list/{identity_id}
            let endpoint = build_list_path(&identity_id);

            let response = client
                .get(&endpoint)
                .await
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: endpoint.clone(),
                    status: 0,
                    reason: e.to_string(),
                })?;

            let result: serde_json::Value = ZhtpClient::parse_json(&response)
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: endpoint.clone(),
                    status: 0,
                    reason: format!("Failed to parse response: {}", e),
                })?;
            let formatted = format_output(&result, &cli.format)?;
            output.header(WalletOp::List.title())?;
            output.print(&formatted)?;
            Ok(())
        }
        WalletAction::Statistics { identity_id } => {
            output.info(&format!("Fetching wallet statistics for {}...", identity_id))?;

            // GET /api/v1/wallet/statistics/{identity_id}
            let endpoint = build_statistics_path(&identity_id);

            let response = client
                .get(&endpoint)
                .await
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: endpoint.clone(),
                    status: 0,
                    reason: e.to_string(),
                })?;

            let result: serde_json::Value = ZhtpClient::parse_json(&response)
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: endpoint.clone(),
                    status: 0,
                    reason: format!("Failed to parse response: {}", e),
                })?;
            let formatted = format_output(&result, &cli.format)?;
            output.header(WalletOp::Statistics.title())?;
            output.print(&formatted)?;
            Ok(())
        }
    }
}

// ============================================================================
// TESTS - Pure logic is testable without mocks or side effects
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_balance_path() {
        let path = build_balance_path("primary", "did:zhtp:123");
        assert_eq!(path, "/api/v1/wallet/balance/primary/did:zhtp:123");
    }

    #[test]
    fn test_build_list_path() {
        let path = build_list_path("did:zhtp:123");
        assert_eq!(path, "/api/v1/wallet/list/did:zhtp:123");
    }

    #[test]
    fn test_build_transactions_path() {
        let path = build_transactions_path("did:zhtp:123");
        assert_eq!(path, "/api/v1/wallet/transactions/did:zhtp:123");
    }

    #[test]
    fn test_build_statistics_path() {
        let path = build_statistics_path("did:zhtp:123");
        assert_eq!(path, "/api/v1/wallet/statistics/did:zhtp:123");
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
