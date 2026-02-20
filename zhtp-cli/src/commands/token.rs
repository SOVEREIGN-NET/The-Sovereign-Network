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
use lib_blockchain::transaction::{TokenCreationPayloadV1, TokenMintData, TokenTransferData};
use lib_blockchain::types::TransactionType;
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

fn build_signed_token_mint_tx(
    keypair: &KeyPair,
    token_id: [u8; 32],
    to: [u8; 32],
    amount: u64,
) -> CliResult<Transaction> {
    let mint_data = TokenMintData {
        token_id,
        to,
        amount: amount as u128,
    };

    // Use a zero-cost placeholder so that signing_hash() reflects the real tx fields
    // before we overwrite it with the actual signature below.
    let mut tx = Transaction::new_token_mint_with_chain_id(
        0x03,
        mint_data,
        lib_crypto::Signature::default(),
        b"token:mint:v1".to_vec(),
    );

    tx.signature = keypair
        .sign(tx.signing_hash().as_bytes())
        .map_err(|e| CliError::ConfigError(format!("Failed to sign TokenMint tx: {e}")))?;
    Ok(tx)
}

fn build_signed_token_transfer_tx(
    keypair: &KeyPair,
    token_id: [u8; 32],
    to: [u8; 32],
    amount: u64,
    nonce: u64,
) -> CliResult<Transaction> {
    let transfer_data = TokenTransferData {
        token_id,
        from: keypair.public_key.key_id,
        to,
        amount: amount as u128,
        nonce,
    };

    // Use a zero-cost placeholder so that signing_hash() reflects the real tx fields
    // before we overwrite it with the actual signature below.
    let mut tx = Transaction::new_token_transfer_with_chain_id(
        0x03,
        transfer_data,
        lib_crypto::Signature::default(),
        b"token:transfer:v1".to_vec(),
    );

    tx.signature = keypair
        .sign(tx.signing_hash().as_bytes())
        .map_err(|e| CliError::ConfigError(format!("Failed to sign TokenTransfer tx: {e}")))?;
    Ok(tx)
}

/// Extract the nonce field from a JSON response, returning a descriptive error tied to `path`.
fn parse_nonce_response(response_json: &serde_json::Value, path: &str) -> CliResult<u64> {
    response_json
        .get("nonce")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| CliError::ApiCallFailed {
            endpoint: path.to_string(),
            status: 0,
            reason: "Missing or invalid nonce in response".to_string(),
        })
}

async fn fetch_token_nonce(
    client: &ZhtpClient,
    token_id: &[u8; 32],
    address: &[u8; 32],
) -> CliResult<u64> {
    let path = format!(
        "/api/v1/token/nonce/{}/{}",
        hex::encode(token_id),
        hex::encode(address)
    );

    let response = client
        .get(&path)
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: path.clone(),
            status: 0,
            reason: e.to_string(),
        })?;

    let response_json: serde_json::Value =
        ZhtpClient::parse_json(&response).map_err(|e| CliError::ApiCallFailed {
            endpoint: path.clone(),
            status: 0,
            reason: format!("Failed to parse response: {e}"),
        })?;

    parse_nonce_response(&response_json, &path)
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
        TokenAction::Create { name, symbol, supply } => {
            handle_create(cli, output, &name, &symbol, supply).await
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
) -> CliResult<()> {
    output.info(&format!("Creating token: {} ({})", name, symbol))?;
    output.info(&format!("Initial supply: {}", supply))?;
    output.info("Signing token creation transaction with local keypair")?;

    let keypair = load_default_keypair()?;

    let payload = TokenCreationPayloadV1 {
        name: name.to_string(),
        symbol: symbol.to_string(),
        initial_supply: supply,
        decimals: 8,
    };
    let memo = payload
        .encode_memo()
        .map_err(|e| CliError::ConfigError(format!("Failed to encode token creation payload: {e}")))?;
    // Use a zero-cost placeholder so that signing_hash() reflects real tx fields
    // before we overwrite it with the actual signature below.
    let mut tx = Transaction::new_token_creation_with_chain_id(0x03, lib_crypto::Signature::default(), memo);
    tx.fee = lib_blockchain::transaction::creation::utils::calculate_minimum_fee(tx.size());
    tx.signature = keypair
        .sign(tx.signing_hash().as_bytes())
        .map_err(|e| CliError::ConfigError(format!("Failed to sign token creation tx: {e}")))?;
    if tx.transaction_type != TransactionType::TokenCreation {
        return Err(CliError::ConfigError("Failed to build TokenCreation transaction".to_string()));
    }
    let tx_bytes = bincode::serialize(&tx)
        .map_err(|e| CliError::ConfigError(format!("Failed to serialize tx: {}", e)))?;
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
    let tx = build_signed_token_mint_tx(&keypair, token_id_bytes, to_pubkey.key_id, amount)?;
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

    // SOV (native token) transfers require wallet_ids, not key_ids. Reject early with a
    // clear message directing the user to the correct command.
    let sov_id = lib_blockchain::contracts::utils::generate_lib_token_id();
    if token_id_bytes == sov_id {
        return Err(CliError::ConfigError(
            "SOV (native token) transfers must use 'wallet transfer', not 'token transfer'".to_string(),
        ));
    }

    let to_pubkey = parse_public_key(to)?;
    let client = connect_default(&cli.server).await?;
    let nonce = fetch_token_nonce(&client, &token_id_bytes, &keypair.public_key.key_id).await?;
    output.info(&format!("Using transfer nonce: {}", nonce))?;
    let tx = build_signed_token_transfer_tx(&keypair, token_id_bytes, to_pubkey.key_id, amount, nonce)?;
    let tx_bytes = bincode::serialize(&tx)
        .map_err(|e| CliError::ConfigError(format!("Failed to serialize tx: {}", e)))?;
    let request_body = json!({ "signed_tx": hex::encode(tx_bytes) });

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
    _cli: &ZhtpCli,
    _output: &O,
    _token_id: &str,
    _amount: u64,
) -> CliResult<()> {
    Err(CliError::ConfigError(
        "Token burn is currently disabled on canonical API path".to_string(),
    ))
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

    // =========================================================================
    // parse_nonce_response tests
    // =========================================================================

    #[test]
    fn test_parse_nonce_response_valid() {
        let json = serde_json::json!({"nonce": 42u64});
        let result = parse_nonce_response(&json, "/api/v1/token/nonce/abc/def");
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_parse_nonce_response_zero() {
        let json = serde_json::json!({"nonce": 0u64});
        let result = parse_nonce_response(&json, "/api/v1/token/nonce/abc/def");
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_parse_nonce_response_missing_nonce() {
        let json = serde_json::json!({"status": "ok"});
        let result = parse_nonce_response(&json, "/api/v1/token/nonce/abc/def");
        assert!(result.is_err());
        let err = result.unwrap_err();
        // Error must reference the concrete path, not a hardcoded template.
        assert!(format!("{err:?}").contains("/api/v1/token/nonce/abc/def"));
    }

    #[test]
    fn test_parse_nonce_response_invalid_type() {
        let json = serde_json::json!({"nonce": "not-a-number"});
        let result = parse_nonce_response(&json, "/endpoint");
        assert!(result.is_err());
    }

    // =========================================================================
    // build_signed_token_mint_tx / build_signed_token_transfer_tx field tests
    // =========================================================================

    #[test]
    fn test_build_signed_token_mint_tx_fields() {
        use lib_blockchain::types::TransactionType;
        let keypair = lib_crypto::keypair::KeyPair::generate().expect("keygen");
        let token_id = [0x01u8; 32];
        let to = [0x02u8; 32];
        let amount = 1_000u64;

        let tx = build_signed_token_mint_tx(&keypair, token_id, to, amount)
            .expect("build mint tx");

        assert_eq!(tx.transaction_type, TransactionType::TokenMint);
        let mint_data = tx.token_mint_data.expect("must have mint data");
        assert_eq!(mint_data.token_id, token_id);
        assert_eq!(mint_data.to, to);
        assert_eq!(mint_data.amount, amount as u128);
    }

    #[test]
    fn test_build_signed_token_transfer_tx_fields() {
        use lib_blockchain::types::TransactionType;
        let keypair = lib_crypto::keypair::KeyPair::generate().expect("keygen");
        let token_id = [0x01u8; 32];
        let to = [0x03u8; 32];
        let amount = 500u64;
        let nonce = 7u64;

        let tx = build_signed_token_transfer_tx(&keypair, token_id, to, amount, nonce)
            .expect("build transfer tx");

        assert_eq!(tx.transaction_type, TransactionType::TokenTransfer);
        let transfer_data = tx.token_transfer_data.expect("must have transfer data");
        assert_eq!(transfer_data.token_id, token_id);
        assert_eq!(transfer_data.from, keypair.public_key.key_id);
        assert_eq!(transfer_data.to, to);
        assert_eq!(transfer_data.amount, amount as u128);
        assert_eq!(transfer_data.nonce, nonce);
    }
}
