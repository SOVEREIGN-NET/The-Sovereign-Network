//! Token commands for ZHTP CLI
//!
//! Provides commands for custom token operations:
//! - Create new tokens
//! - Mint tokens (creator only)
//! - Transfer tokens
//! - Check balances
//! - List all tokens

use crate::argument_parsing::{TokenArgs, TokenAction, ZhtpCli, format_output};
use crate::commands::web4_utils::connect_default;
use crate::error::{CliResult, CliError};
use crate::output::Output;
use lib_network::client::ZhtpClient;
use serde_json::json;

// ============================================================================
// PURE LOGIC - Path builders and validation
// ============================================================================

/// Build create token request body
pub fn build_create_request(
    name: &str,
    symbol: &str,
    initial_supply: u64,
    creator_identity: &str,
) -> serde_json::Value {
    json!({
        "name": name,
        "symbol": symbol,
        "initial_supply": initial_supply,
        "creator_identity": creator_identity
    })
}

/// Build mint token request body
pub fn build_mint_request(
    token_id: &str,
    amount: u64,
    to: &str,
    creator_identity: &str,
) -> serde_json::Value {
    json!({
        "token_id": token_id,
        "amount": amount,
        "to": to,
        "creator_identity": creator_identity
    })
}

/// Build transfer token request body
pub fn build_transfer_request(
    token_id: &str,
    from: &str,
    to: &str,
    amount: u64,
) -> serde_json::Value {
    json!({
        "token_id": token_id,
        "from": from,
        "to": to,
        "amount": amount
    })
}

/// Build token info path
pub fn build_info_path(token_id: &str) -> String {
    format!("/api/v1/token/{}", token_id)
}

/// Build balance path
pub fn build_balance_path(token_id: &str, address: &str) -> String {
    format!("/api/v1/token/{}/balance/{}", token_id, address)
}

// ============================================================================
// IMPERATIVE SHELL - QUIC calls and output
// ============================================================================

/// Handle token command
pub async fn handle_token_command(
    args: TokenArgs,
    cli: &ZhtpCli,
) -> CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_token_command_with_output(args, cli, &output).await
}

/// Handle token command with injected output (for testing)
pub async fn handle_token_command_with_output<O: Output>(
    args: TokenArgs,
    cli: &ZhtpCli,
    output: &O,
) -> CliResult<()> {
    match args.action {
        TokenAction::Create { name, symbol, supply, creator } => {
            handle_create(cli, output, &name, &symbol, supply, &creator).await
        }
        TokenAction::Mint { token_id, amount, to, creator } => {
            handle_mint(cli, output, &token_id, amount, &to, &creator).await
        }
        TokenAction::Transfer { token_id, from, to, amount } => {
            handle_transfer(cli, output, &token_id, &from, &to, amount).await
        }
        TokenAction::Info { token_id } => {
            handle_info(cli, output, &token_id).await
        }
        TokenAction::Balance { token_id, address } => {
            handle_balance(cli, output, &token_id, &address).await
        }
        TokenAction::List => {
            handle_list(cli, output).await
        }
    }
}

/// Handle token creation
async fn handle_create<O: Output>(
    cli: &ZhtpCli,
    output: &O,
    name: &str,
    symbol: &str,
    supply: u64,
    creator: &str,
) -> CliResult<()> {
    output.info(&format!("Creating token: {} ({})", name, symbol))?;
    output.info(&format!("Initial supply: {}", supply))?;

    let client = connect_default(&cli.server).await?;

    let request_body = build_create_request(name, symbol, supply, creator);

    let response = client
        .post_json("/api/v1/token/create", &request_body)
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/token/create".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let response_json: serde_json::Value = ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/token/create".to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;

    if response_json.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
        output.success("Token created successfully!")?;
        output.info(&format!("Token ID: {}", response_json.get("token_id").and_then(|v| v.as_str()).unwrap_or("unknown")))?;
    } else {
        let error = response_json.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error");
        output.error(&format!("Failed to create token: {}", error))?;
    }

    let formatted = format_output(&response_json, &cli.format)?;
    output.print(&formatted)?;

    Ok(())
}

/// Handle token minting
async fn handle_mint<O: Output>(
    cli: &ZhtpCli,
    output: &O,
    token_id: &str,
    amount: u64,
    to: &str,
    creator: &str,
) -> CliResult<()> {
    output.info(&format!("Minting {} tokens to {}", amount, to))?;

    let client = connect_default(&cli.server).await?;

    let request_body = build_mint_request(token_id, amount, to, creator);

    let response = client
        .post_json("/api/v1/token/mint", &request_body)
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/token/mint".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let response_json: serde_json::Value = ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/token/mint".to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;

    if response_json.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
        output.success("Tokens minted successfully!")?;
    } else {
        let error = response_json.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error");
        output.error(&format!("Failed to mint tokens: {}", error))?;
    }

    let formatted = format_output(&response_json, &cli.format)?;
    output.print(&formatted)?;

    Ok(())
}

/// Handle token transfer
async fn handle_transfer<O: Output>(
    cli: &ZhtpCli,
    output: &O,
    token_id: &str,
    from: &str,
    to: &str,
    amount: u64,
) -> CliResult<()> {
    output.info(&format!("Transferring {} tokens from {} to {}", amount, from, to))?;

    let client = connect_default(&cli.server).await?;

    let request_body = build_transfer_request(token_id, from, to, amount);

    let response = client
        .post_json("/api/v1/token/transfer", &request_body)
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/token/transfer".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let response_json: serde_json::Value = ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/token/transfer".to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;

    if response_json.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
        output.success("Transfer successful!")?;
    } else {
        let error = response_json.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error");
        output.error(&format!("Transfer failed: {}", error))?;
    }

    let formatted = format_output(&response_json, &cli.format)?;
    output.print(&formatted)?;

    Ok(())
}

/// Handle token info query
async fn handle_info<O: Output>(
    cli: &ZhtpCli,
    output: &O,
    token_id: &str,
) -> CliResult<()> {
    output.info(&format!("Fetching token info for: {}", token_id))?;

    let client = connect_default(&cli.server).await?;

    let path = build_info_path(token_id);
    let response = client.get(&path).await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: path.clone(),
            status: 0,
            reason: e.to_string(),
        })?;

    let response_json: serde_json::Value = ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: path,
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;

    let formatted = format_output(&response_json, &cli.format)?;
    output.print(&formatted)?;

    Ok(())
}

/// Handle token balance query
async fn handle_balance<O: Output>(
    cli: &ZhtpCli,
    output: &O,
    token_id: &str,
    address: &str,
) -> CliResult<()> {
    output.info(&format!("Fetching balance for {} on token {}", address, token_id))?;

    let client = connect_default(&cli.server).await?;

    let path = build_balance_path(token_id, address);
    let response = client.get(&path).await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: path.clone(),
            status: 0,
            reason: e.to_string(),
        })?;

    let response_json: serde_json::Value = ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: path,
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;

    if let Some(balance) = response_json.get("balance") {
        let symbol = response_json.get("symbol").and_then(|v| v.as_str()).unwrap_or("tokens");
        output.success(&format!("Balance: {} {}", balance, symbol))?;
    }

    let formatted = format_output(&response_json, &cli.format)?;
    output.print(&formatted)?;

    Ok(())
}

/// Handle token list
async fn handle_list<O: Output>(
    cli: &ZhtpCli,
    output: &O,
) -> CliResult<()> {
    output.info("Listing all tokens...")?;

    let client = connect_default(&cli.server).await?;

    let response = client.get("/api/v1/token/list").await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/token/list".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let response_json: serde_json::Value = ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/token/list".to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;

    if let Some(count) = response_json.get("count").and_then(|v| v.as_u64()) {
        output.info(&format!("Found {} token(s)", count))?;
    }

    let formatted = format_output(&response_json, &cli.format)?;
    output.print(&formatted)?;

    Ok(())
}
