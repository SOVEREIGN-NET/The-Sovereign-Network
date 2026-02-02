//! Token commands for ZHTP CLI
//!
//! Provides commands for custom token operations:
//! - Create new tokens
//! - Mint tokens (creator only)
//! - Transfer tokens
//! - Check balances
//! - List all tokens

use crate::argument_parsing::{TokenArgs, TokenAction, ZhtpCli, format_output};
use crate::commands::web4_utils::{connect_default, load_identity_from_keystore};
use crate::error::{CliResult, CliError};
use crate::output::Output;
use lib_blockchain::{ContractCall, CallPermissions, ContractTransactionBuilder, Transaction, TransactionOutput, Hash};
use lib_network::client::ZhtpClient;
use serde_json::json;
use lib_crypto::keypair::KeyPair;
use std::path::PathBuf;

// ============================================================================
// PURE LOGIC - Path builders and validation
// ============================================================================

/// Build token info path
pub fn build_info_path(token_id: &str) -> String {
    format!("/api/v1/token/{}", token_id)
}

/// Build balance path
pub fn build_balance_path(token_id: &str, address: &str) -> String {
    format!("/api/v1/token/{}/balance/{}", token_id, address)
}

fn default_keystore_path() -> CliResult<PathBuf> {
    dirs::home_dir()
        .map(|h| h.join(".zhtp").join("keystore"))
        .ok_or_else(|| CliError::ConfigError("Cannot determine home directory".to_string()))
}

fn load_default_keypair() -> CliResult<KeyPair> {
    let keystore = default_keystore_path()?;
    let loaded = load_identity_from_keystore(&keystore)?;
    Ok(loaded.keypair)
}

fn strip_prefix<'a>(value: &'a str) -> &'a str {
    value.strip_prefix("0x").unwrap_or(value)
}

fn parse_token_id(token_id: &str) -> CliResult<[u8; 32]> {
    let hex_str = strip_prefix(token_id);
    let bytes = hex::decode(hex_str)
        .map_err(|_| CliError::ConfigError("Invalid token_id hex".to_string()))?;
    if bytes.len() != 32 {
        return Err(CliError::ConfigError("Token ID must be 32 bytes".to_string()));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(id)
}

fn parse_public_key(address: &str) -> CliResult<lib_crypto::PublicKey> {
    let trimmed = address.strip_prefix("did:zhtp:").unwrap_or(address);
    let hex_str = strip_prefix(trimmed);
    let bytes = hex::decode(hex_str)
        .map_err(|_| CliError::ConfigError("Invalid address hex".to_string()))?;

    if bytes.len() == 32 {
        let mut key_id = [0u8; 32];
        key_id.copy_from_slice(&bytes);
        return Ok(lib_crypto::PublicKey {
            dilithium_pk: vec![],
            kyber_pk: vec![],
            key_id,
        });
    }

    Ok(lib_crypto::PublicKey::new(bytes))
}

fn build_signed_token_tx(keypair: &KeyPair, call: ContractCall) -> CliResult<Transaction> {
    let call_bytes = bincode::serialize(&call)
        .map_err(|e| CliError::ConfigError(format!("Failed to serialize call: {}", e)))?;
    let call_signature = keypair
        .sign(&call_bytes)
        .map_err(|e| CliError::ConfigError(format!("Failed to sign call: {}", e)))?;

    let output = TransactionOutput::new(
        Hash::from_slice(&call_bytes),
        Hash::from_slice(b"token-call"),
        keypair.public_key.clone(),
    );

    let mut builder = ContractTransactionBuilder::new();
    builder.add_call(call, call_signature);
    builder.add_output(output);
    builder.set_fee(0);

    let temp_tx = builder
        .build(keypair)
        .map_err(|e| CliError::ConfigError(format!("Failed to build temp tx: {}", e)))?;

    let min_fee = lib_blockchain::transaction::creation::utils::calculate_minimum_fee(temp_tx.size());
    builder.set_fee(min_fee);

    builder
        .build(keypair)
        .map_err(|e| CliError::ConfigError(format!("Failed to build signed tx: {}", e)))
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
        TokenAction::Create { name, symbol, supply, decimals } => {
            handle_create(cli, output, &name, &symbol, supply, decimals).await
        }
        TokenAction::Mint { token_id, amount, to } => {
            handle_mint(cli, output, &token_id, amount, &to).await
        }
        TokenAction::Transfer { token_id, to, amount } => {
            handle_transfer(cli, output, &token_id, &to, amount).await
        }
        TokenAction::Burn { token_id, amount } => {
            handle_burn(cli, output, &token_id, amount).await
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
/// NOTE: Creator identity is derived from authenticated session on server
async fn handle_create<O: Output>(
    cli: &ZhtpCli,
    output: &O,
    name: &str,
    symbol: &str,
    supply: u64,
    decimals: u8,
) -> CliResult<()> {
    output.info(&format!("Creating token: {} ({})", name, symbol))?;
    output.info(&format!("Initial supply: {} (decimals: {})", supply, decimals))?;
    output.info("Signing token creation transaction with local keypair")?;

    let keypair = load_default_keypair()?;

    // Serialize as CreateTokenParams struct (must match server expectation)
    #[derive(serde::Serialize)]
    struct CreateTokenParams {
        name: String,
        symbol: String,
        initial_supply: u64,
        decimals: u8,
    }
    let create_params = CreateTokenParams {
        name: name.to_string(),
        symbol: symbol.to_string(),
        initial_supply: supply,
        decimals,
    };
    let params = ContractCall::serialize_params(&create_params)
        .map_err(|e| CliError::ConfigError(format!("Failed to serialize params: {}", e)))?;
    let call = ContractCall::new(
        lib_blockchain::ContractType::Token,
        "create_custom_token".to_string(),
        params,
        CallPermissions::restricted(keypair.public_key.clone(), Vec::new()),
    );

    let tx = build_signed_token_tx(&keypair, call)?;
    eprintln!("DEBUG: transaction_type = {:?}", tx.transaction_type);
    let tx_bytes = bincode::serialize(&tx)
        .map_err(|e| CliError::ConfigError(format!("Failed to serialize tx: {}", e)))?;
    eprintln!("DEBUG: serialized tx len = {}, first 20 bytes = {:02x?}", tx_bytes.len(), &tx_bytes[..20.min(tx_bytes.len())]);
    let request_body = json!({ "signed_tx": hex::encode(tx_bytes) });

    let client = connect_default(&cli.server).await?;

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
/// NOTE: Authorization verified via authenticated session on server
async fn handle_mint<O: Output>(
    cli: &ZhtpCli,
    output: &O,
    token_id: &str,
    amount: u64,
    to: &str,
) -> CliResult<()> {
    output.info(&format!("Minting {} tokens to {}", amount, to))?;
    output.info("Signing mint transaction with local keypair")?;

    let keypair = load_default_keypair()?;
    let token_id_bytes = parse_token_id(token_id)?;
    let to_pubkey = parse_public_key(to)?;

    let params = ContractCall::serialize_params(&(token_id_bytes, to_pubkey, amount))
        .map_err(|e| CliError::ConfigError(format!("Failed to serialize params: {}", e)))?;
    let call = ContractCall::new(
        lib_blockchain::ContractType::Token,
        "mint".to_string(),
        params,
        CallPermissions::restricted(keypair.public_key.clone(), Vec::new()),
    );

    let tx = build_signed_token_tx(&keypair, call)?;
    let tx_bytes = bincode::serialize(&tx)
        .map_err(|e| CliError::ConfigError(format!("Failed to serialize tx: {}", e)))?;
    let request_body = json!({ "signed_tx": hex::encode(tx_bytes) });

    let client = connect_default(&cli.server).await?;

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
/// NOTE: Sender identity is derived from authenticated session on server
async fn handle_transfer<O: Output>(
    cli: &ZhtpCli,
    output: &O,
    token_id: &str,
    to: &str,
    amount: u64,
) -> CliResult<()> {
    output.info(&format!("Transferring {} tokens to {}", amount, to))?;
    output.info("Signing transfer transaction with local keypair")?;

    let keypair = load_default_keypair()?;
    let token_id_bytes = parse_token_id(token_id)?;
    let to_pubkey = parse_public_key(to)?;

    let params = ContractCall::serialize_params(&(token_id_bytes, to_pubkey, amount))
        .map_err(|e| CliError::ConfigError(format!("Failed to serialize params: {}", e)))?;
    let call = ContractCall::new(
        lib_blockchain::ContractType::Token,
        "transfer".to_string(),
        params,
        CallPermissions::restricted(keypair.public_key.clone(), Vec::new()),
    );

    let tx = build_signed_token_tx(&keypair, call)?;
    let tx_bytes = bincode::serialize(&tx)
        .map_err(|e| CliError::ConfigError(format!("Failed to serialize tx: {}", e)))?;
    let request_body = json!({ "signed_tx": hex::encode(tx_bytes) });

    let client = connect_default(&cli.server).await?;

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

/// Handle token burn
async fn handle_burn<O: Output>(
    cli: &ZhtpCli,
    output: &O,
    token_id: &str,
    amount: u64,
) -> CliResult<()> {
    output.info(&format!("Burning {} tokens from caller", amount))?;
    output.info("Signing burn transaction with local keypair")?;

    let keypair = load_default_keypair()?;
    let token_id_bytes = parse_token_id(token_id)?;

    let params = ContractCall::serialize_params(&(token_id_bytes, amount))
        .map_err(|e| CliError::ConfigError(format!("Failed to serialize params: {}", e)))?;
    let call = ContractCall::new(
        lib_blockchain::ContractType::Token,
        "burn".to_string(),
        params,
        CallPermissions::restricted(keypair.public_key.clone(), Vec::new()),
    );

    let tx = build_signed_token_tx(&keypair, call)?;
    let tx_bytes = bincode::serialize(&tx)
        .map_err(|e| CliError::ConfigError(format!("Failed to serialize tx: {}", e)))?;
    let request_body = json!({ "signed_tx": hex::encode(tx_bytes) });

    let client = connect_default(&cli.server).await?;

    let response = client
        .post_json("/api/v1/token/burn", &request_body)
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/token/burn".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let response_json: serde_json::Value = ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/token/burn".to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;

    if response_json.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
        output.success("Burn submitted successfully!")?;
    } else {
        let error = response_json.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error");
        output.error(&format!("Burn failed: {}", error))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_info_path() {
        let token_id = "abc123def456";
        let path = build_info_path(token_id);
        assert_eq!(path, "/api/v1/token/abc123def456");
    }

    #[test]
    fn test_build_balance_path() {
        let token_id = "abc123";
        let address = "0xdef456";
        let path = build_balance_path(token_id, address);
        assert_eq!(path, "/api/v1/token/abc123/balance/0xdef456");
    }

    #[test]
    fn test_parse_token_id_valid() {
        let hex_id = "0102030405060708091011121314151617181920212223242526272829303132";
        let result = parse_token_id(hex_id);
        assert!(result.is_ok());
        let id = result.unwrap();
        assert_eq!(id[0], 0x01);
        assert_eq!(id[31], 0x32);
    }

    #[test]
    fn test_parse_token_id_with_0x_prefix() {
        let hex_id = "0x0102030405060708091011121314151617181920212223242526272829303132";
        let result = parse_token_id(hex_id);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_token_id_invalid_length() {
        let short_id = "0102030405";
        let result = parse_token_id(short_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_token_id_invalid_hex() {
        let invalid = "not-valid-hex-string-here-32-bytes";
        let result = parse_token_id(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_public_key_did_format() {
        let did = "did:zhtp:0102030405060708091011121314151617181920212223242526272829303132";
        let result = parse_public_key(did);
        assert!(result.is_ok());
        let pk = result.unwrap();
        assert_eq!(pk.key_id[0], 0x01);
    }

    #[test]
    fn test_parse_public_key_0x_format() {
        let addr = "0x0102030405060708091011121314151617181920212223242526272829303132";
        let result = parse_public_key(addr);
        assert!(result.is_ok());
    }

    #[test]
    fn test_strip_prefix() {
        assert_eq!(strip_prefix("0xabc"), "abc");
        assert_eq!(strip_prefix("abc"), "abc");
        assert_eq!(strip_prefix("0x"), "");
    }
}
