//! Bonding Curve commands for ZHTP CLI
//!
//! Provides commands for bonding curve token operations:
//! - Deploy new bonding curve tokens
//! - Buy tokens via bonding curve
//! - Sell tokens via bonding curve
//! - Query price and curve information
//! - Check graduation status

use crate::argument_parsing::{CurveArgs, CurveAction, ZhtpCli, format_output};
use crate::commands::web4_utils::{connect_default, load_identity_from_keystore};
use crate::error::{CliResult, CliError};
use crate::output::Output;
use lib_blockchain::transaction::{Transaction, core::{BondingCurveDeployData, BondingCurveBuyData, BondingCurveSellData}};
use lib_network::client::ZhtpClient;
use serde_json::json;
use lib_crypto::keypair::KeyPair;
use std::path::PathBuf;

// ============================================================================
// PURE LOGIC - Path builders and validation
// ============================================================================

/// Build curve info path
pub fn build_curve_info_path(token_id: &str) -> String {
    format!("/api/v1/curve/{}", token_id)
}

/// Build curve price path
pub fn build_curve_price_path(token_id: &str) -> String {
    format!("/api/v1/curve/{}/price", token_id)
}

/// Build curve can-graduate path
pub fn build_can_graduate_path(token_id: &str) -> String {
    format!("/api/v1/curve/{}/can-graduate", token_id)
}

/// Build valuation path
pub fn build_valuation_path(token_id: &str) -> String {
    format!("/api/v1/valuation/{}", token_id)
}

/// Build price query path
pub fn build_price_path(token_id: &str) -> String {
    format!("/api/v1/price/{}", token_id)
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

/// Returns (curve_type_u8, base_price, curve_param, midpoint_supply)
fn parse_curve_type(curve_type: &str) -> CliResult<(u8, u64, u64, Option<u64>)> {
    match curve_type.to_lowercase().as_str() {
        "linear" | "constant" => Ok((
            0u8, // Linear
            10000,      // base_price: 0.0001 stablecoins
            100,        // curve_param (slope): small increment per token
            None,
        )),
        "exponential" | "polynomial" => Ok((
            1u8, // Exponential
            10000,      // base_price
            100,        // curve_param (growth_rate_bps): 1% growth
            None,
        )),
        "sigmoid" | "logistic" => Ok((
            2u8, // Sigmoid
            10000,      // base_price
            10,         // curve_param (steepness)
            Some(1_000_000_000_000_000), // midpoint_supply: 10M tokens
        )),
        _ => Err(CliError::ConfigError(
            format!("Unknown curve type: {}. Use: linear, exponential, or sigmoid", curve_type)
        )),
    }
}

/// Returns (threshold_type, threshold_value, threshold_time_seconds)
fn parse_threshold(threshold: &str) -> CliResult<(u8, u64, Option<u64>)> {
    match threshold.to_lowercase().as_str() {
        "standard" => Ok((0u8, 69_000_000_00u64, None)),      // $69K reserve
        "low" => Ok((0u8, 34_500_000_00u64, None)),           // $34.5K reserve
        "high" => Ok((0u8, 138_000_000_00u64, None)),         // $138K reserve
        "supply" => Ok((1u8, 1_000_000_000_000_000u64, None)), // 10M tokens
        _ => {
            // Try parsing as u64 for custom reserve amount
            if let Ok(amount) = threshold.parse::<u64>() {
                Ok((0u8, amount, None)) // ReserveAmount
            } else {
                Err(CliError::ConfigError(
                    format!("Unknown threshold: {}. Use: standard, low, high, supply, or custom amount", threshold)
                ))
            }
        }
    }
}

fn build_signed_curve_deploy_tx(
    keypair: &KeyPair,
    name: String,
    symbol: String,
    curve_type: (u8, u64, u64, Option<u64>),
    threshold: (u8, u64, Option<u64>),
    sell_enabled: bool,
) -> CliResult<Transaction> {
    let deploy_data = BondingCurveDeployData {
        name,
        symbol,
        curve_type: curve_type.0,
        base_price: curve_type.1,
        curve_param: curve_type.2,
        midpoint_supply: curve_type.3,
        threshold_type: threshold.0,
        threshold_value: threshold.1,
        threshold_time_seconds: threshold.2,
        sell_enabled,
        creator: keypair.public_key.key_id,
        nonce: 0, // Will be set by server
    };

    // Use a zero-cost placeholder so that signing_hash() reflects the real tx fields
    let mut tx = Transaction::new_bonding_curve_deploy_with_chain_id(
        0x03,
        deploy_data,
        lib_crypto::Signature::default(),
        b"curve:deploy:v1".to_vec(),
    );

    tx.signature = keypair
        .sign(tx.signing_hash().as_bytes())
        .map_err(|e| CliError::ConfigError(format!("Failed to sign BondingCurveDeploy tx: {e}")))?;
    Ok(tx)
}

fn build_signed_curve_buy_tx(
    keypair: &KeyPair,
    token_id: [u8; 32],
    stable_amount: u64,
    min_tokens_out: u64,
) -> CliResult<Transaction> {
    let buy_data = BondingCurveBuyData {
        token_id,
        stable_amount,
        min_tokens_out,
        buyer: keypair.public_key.key_id,
        nonce: 0, // Will be set by server
    };

    let mut tx = Transaction::new_bonding_curve_buy_with_chain_id(
        0x03,
        buy_data,
        lib_crypto::Signature::default(),
        b"curve:buy:v1".to_vec(),
    );

    tx.signature = keypair
        .sign(tx.signing_hash().as_bytes())
        .map_err(|e| CliError::ConfigError(format!("Failed to sign BondingCurveBuy tx: {e}")))?;
    Ok(tx)
}

fn build_signed_curve_sell_tx(
    keypair: &KeyPair,
    token_id: [u8; 32],
    token_amount: u64,
    min_stable_out: u64,
) -> CliResult<Transaction> {
    let sell_data = BondingCurveSellData {
        token_id,
        token_amount,
        min_stable_out,
        seller: keypair.public_key.key_id,
        nonce: 0, // Will be set by server
    };

    let mut tx = Transaction::new_bonding_curve_sell_with_chain_id(
        0x03,
        sell_data,
        lib_crypto::Signature::default(),
        b"curve:sell:v1".to_vec(),
    );

    tx.signature = keypair
        .sign(tx.signing_hash().as_bytes())
        .map_err(|e| CliError::ConfigError(format!("Failed to sign BondingCurveSell tx: {e}")))?;
    Ok(tx)
}

// ============================================================================
// IMPERATIVE SHELL - QUIC calls and output
// ============================================================================

/// Handle curve command
pub async fn handle_curve_command(
    args: CurveArgs,
    cli: &ZhtpCli,
) -> CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_curve_command_with_output(args, cli, &output).await
}

/// Handle curve command with injected output (for testing)
pub async fn handle_curve_command_with_output<O: Output>(
    args: CurveArgs,
    cli: &ZhtpCli,
    output: &O,
) -> CliResult<()> {
    match args.action {
        CurveAction::Deploy { name, symbol, curve_type, threshold, sell_enabled } => {
            handle_deploy(cli, output, name, symbol, curve_type, threshold, sell_enabled).await
        }
        CurveAction::Buy { token_id, stable_amount, min_tokens_out } => {
            handle_buy(cli, output, &token_id, stable_amount, min_tokens_out).await
        }
        CurveAction::Sell { token_id, token_amount, min_stable_out } => {
            handle_sell(cli, output, &token_id, token_amount, min_stable_out).await
        }
        CurveAction::Info { token_id } => {
            handle_info(cli, output, &token_id).await
        }
        CurveAction::Price { token_id } => {
            handle_price(cli, output, &token_id).await
        }
        CurveAction::CanGraduate { token_id } => {
            handle_can_graduate(cli, output, &token_id).await
        }
        CurveAction::Valuation { token_id } => {
            handle_valuation(cli, output, &token_id).await
        }
        CurveAction::List => {
            handle_list(cli, output).await
        }
    }
}

/// Handle bonding curve token deployment
async fn handle_deploy<O: Output>(
    cli: &ZhtpCli,
    output: &O,
    name: String,
    symbol: String,
    curve_type: String,
    threshold: String,
    sell_enabled: bool,
) -> CliResult<()> {
    output.info(&format!("Deploying bonding curve token: {} ({})", name, symbol))?;
    output.info(&format!("Curve type: {}, Threshold: {}, Sell enabled: {}", 
        curve_type, threshold, sell_enabled))?;
    output.info("Signing deployment transaction with local keypair")?;

    let keypair = load_default_keypair()?;
    let (curve_type_u8, base_price, curve_param, midpoint_supply) = parse_curve_type(&curve_type)?;
    let (threshold_type, threshold_value, threshold_time) = parse_threshold(&threshold)?;

    let tx = build_signed_curve_deploy_tx(
        &keypair,
        name,
        symbol,
        (curve_type_u8, base_price, curve_param, midpoint_supply),
        (threshold_type, threshold_value, threshold_time),
        sell_enabled,
    )?;

    let tx_bytes = bincode::serialize(&tx)
        .map_err(|e| CliError::ConfigError(format!("Failed to serialize tx: {}", e)))?;
    let request_body = json!({ "signed_tx": hex::encode(tx_bytes) });

    let client = connect_default(&cli.server).await?;

    let response = client
        .post_json("/api/v1/curve/deploy", &request_body)
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/curve/deploy".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let response_json: serde_json::Value = ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/curve/deploy".to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;

    if response_json.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
        output.success("Bonding curve token deployed successfully!")?;
        if let Some(token_id) = response_json.get("token_id").and_then(|v| v.as_str()) {
            output.info(&format!("Token ID: {}", token_id))?;
        }
        if let Some(curve_id) = response_json.get("curve_id").and_then(|v| v.as_str()) {
            output.info(&format!("Curve ID: {}", curve_id))?;
        }
    } else {
        let error = response_json.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error");
        output.error(&format!("Failed to deploy token: {}", error))?;
    }

    let formatted = format_output(&response_json, &cli.format)?;
    output.print(&formatted)?;

    Ok(())
}

/// Handle buying tokens via bonding curve
async fn handle_buy<O: Output>(
    cli: &ZhtpCli,
    output: &O,
    token_id: &str,
    stable_amount: u64,
    min_tokens_out: Option<u64>,
) -> CliResult<()> {
    output.info(&format!("Buying tokens: {} with {} stablecoins", token_id, stable_amount))?;
    output.info("Signing buy transaction with local keypair")?;

    let keypair = load_default_keypair()?;
    let token_id_bytes = parse_token_id(token_id)?;
    let min_out = min_tokens_out.unwrap_or(0); // 0 means no minimum (accept any slippage)

    let tx = build_signed_curve_buy_tx(&keypair, token_id_bytes, stable_amount, min_out)?;
    let tx_bytes = bincode::serialize(&tx)
        .map_err(|e| CliError::ConfigError(format!("Failed to serialize tx: {}", e)))?;
    let request_body = json!({ "signed_tx": hex::encode(tx_bytes) });

    let client = connect_default(&cli.server).await?;

    let response = client
        .post_json("/api/v1/curve/buy", &request_body)
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/curve/buy".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let response_json: serde_json::Value = ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/curve/buy".to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;

    if response_json.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
        output.success("Tokens purchased successfully!")?;
        if let Some(amount) = response_json.get("tokens_received").and_then(|v| v.as_u64()) {
            output.info(&format!("Tokens received: {}", amount))?;
        }
        if let Some(price) = response_json.get("effective_price").and_then(|v| v.as_str()) {
            output.info(&format!("Effective price: {} USD", price))?;
        }
    } else {
        let error = response_json.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error");
        output.error(&format!("Failed to buy tokens: {}", error))?;
    }

    let formatted = format_output(&response_json, &cli.format)?;
    output.print(&formatted)?;

    Ok(())
}

/// Handle selling tokens via bonding curve
async fn handle_sell<O: Output>(
    cli: &ZhtpCli,
    output: &O,
    token_id: &str,
    token_amount: u64,
    min_stable_out: Option<u64>,
) -> CliResult<()> {
    output.info(&format!("Selling {} tokens: {}", token_amount, token_id))?;
    output.info("Signing sell transaction with local keypair")?;

    let keypair = load_default_keypair()?;
    let token_id_bytes = parse_token_id(token_id)?;
    let min_out = min_stable_out.unwrap_or(0); // 0 means no minimum

    let tx = build_signed_curve_sell_tx(&keypair, token_id_bytes, token_amount, min_out)?;
    let tx_bytes = bincode::serialize(&tx)
        .map_err(|e| CliError::ConfigError(format!("Failed to serialize tx: {}", e)))?;
    let request_body = json!({ "signed_tx": hex::encode(tx_bytes) });

    let client = connect_default(&cli.server).await?;

    let response = client
        .post_json("/api/v1/curve/sell", &request_body)
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/curve/sell".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let response_json: serde_json::Value = ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/curve/sell".to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;

    if response_json.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
        output.success("Tokens sold successfully!")?;
        if let Some(amount) = response_json.get("stable_received").and_then(|v| v.as_u64()) {
            output.info(&format!("Stablecoins received: {}", amount))?;
        }
        if let Some(price) = response_json.get("effective_price").and_then(|v| v.as_str()) {
            output.info(&format!("Effective price: {} USD", price))?;
        }
    } else {
        let error = response_json.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error");
        output.error(&format!("Failed to sell tokens: {}", error))?;
    }

    let formatted = format_output(&response_json, &cli.format)?;
    output.print(&formatted)?;

    Ok(())
}

/// Handle curve info query
async fn handle_info<O: Output>(
    cli: &ZhtpCli,
    output: &O,
    token_id: &str,
) -> CliResult<()> {
    output.info(&format!("Fetching curve info for: {}", token_id))?;

    let client = connect_default(&cli.server).await?;

    let path = build_curve_info_path(token_id);
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

/// Handle price query
async fn handle_price<O: Output>(
    cli: &ZhtpCli,
    output: &O,
    token_id: &str,
) -> CliResult<()> {
    output.info(&format!("Fetching price for: {}", token_id))?;

    let client = connect_default(&cli.server).await?;

    let path = build_price_path(token_id);
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

    if let Some(price) = response_json.get("price_usd").and_then(|v| v.as_str()) {
        if let Some(source) = response_json.get("source").and_then(|v| v.as_str()) {
            output.success(&format!("Price: {} USD (source: {})", price, source))?;
        } else {
            output.success(&format!("Price: {} USD", price))?;
        }
    }

    let formatted = format_output(&response_json, &cli.format)?;
    output.print(&formatted)?;

    Ok(())
}

/// Handle can-graduate check
async fn handle_can_graduate<O: Output>(
    cli: &ZhtpCli,
    output: &O,
    token_id: &str,
) -> CliResult<()> {
    output.info(&format!("Checking if token can graduate: {}", token_id))?;

    let client = connect_default(&cli.server).await?;

    let path = build_can_graduate_path(token_id);
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

    if let Some(can_graduate) = response_json.get("can_graduate").and_then(|v| v.as_bool()) {
        if can_graduate {
            output.success("Token is ready for graduation to AMM!")?;
            if let Some(reserve) = response_json.get("current_reserve").and_then(|v| v.as_u64()) {
                output.info(&format!("Current reserve: {}", reserve))?;
            }
        } else {
            output.info("Token has not yet met graduation threshold")?;
            if let Some(reserve) = response_json.get("current_reserve").and_then(|v| v.as_u64()) {
                if let Some(threshold) = response_json.get("threshold").and_then(|v| v.as_u64()) {
                    output.info(&format!("Progress: {} / {}", reserve, threshold))?;
                }
            }
        }
    }

    let formatted = format_output(&response_json, &cli.format)?;
    output.print(&formatted)?;

    Ok(())
}

/// Handle valuation query
async fn handle_valuation<O: Output>(
    cli: &ZhtpCli,
    output: &O,
    token_id: &str,
) -> CliResult<()> {
    output.info(&format!("Fetching full valuation for: {}", token_id))?;

    let client = connect_default(&cli.server).await?;

    let path = build_valuation_path(token_id);
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

    if let Some(valuation) = response_json.get("valuation_usd").and_then(|v| v.as_str()) {
        if let Some(confidence) = response_json.get("confidence").and_then(|v| v.as_str()) {
            output.success(&format!("Valuation: {} USD (confidence: {})", valuation, confidence))?;
        }
    }

    let formatted = format_output(&response_json, &cli.format)?;
    output.print(&formatted)?;

    Ok(())
}

/// Handle curve token list
async fn handle_list<O: Output>(
    cli: &ZhtpCli,
    output: &O,
) -> CliResult<()> {
    output.info("Listing all bonding curve tokens...")?;

    let client = connect_default(&cli.server).await?;

    let response = client.get("/api/v1/curve/list").await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/curve/list".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let response_json: serde_json::Value = ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/curve/list".to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;

    if let Some(count) = response_json.get("count").and_then(|v| v.as_u64()) {
        output.info(&format!("Found {} bonding curve token(s)", count))?;
    }

    let formatted = format_output(&response_json, &cli.format)?;
    output.print(&formatted)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_curve_info_path() {
        let token_id = "abc123def456";
        let path = build_curve_info_path(token_id);
        assert_eq!(path, "/api/v1/curve/abc123def456");
    }

    #[test]
    fn test_build_curve_price_path() {
        let token_id = "abc123";
        let path = build_curve_price_path(token_id);
        assert_eq!(path, "/api/v1/curve/abc123/price");
    }

    #[test]
    fn test_parse_curve_type_linear() {
        let (t, base, param, mid) = parse_curve_type("linear").unwrap();
        assert_eq!(t, 0u8);
        assert_eq!(base, 10000);
        assert_eq!(param, 100);
        assert_eq!(mid, None);
    }

    #[test]
    fn test_parse_curve_type_exponential() {
        let (t, base, param, mid) = parse_curve_type("exponential").unwrap();
        assert_eq!(t, 1u8);
        assert_eq!(base, 10000);
        assert_eq!(param, 100);
    }

    #[test]
    fn test_parse_curve_type_sigmoid() {
        let (t, base, param, mid) = parse_curve_type("sigmoid").unwrap();
        assert_eq!(t, 2u8);
        assert_eq!(base, 10000);
        assert_eq!(param, 10);
        assert!(mid.is_some());
    }

    #[test]
    fn test_parse_curve_type_invalid() {
        assert!(parse_curve_type("unknown").is_err());
    }

    #[test]
    fn test_parse_threshold() {
        let (t, v, time) = parse_threshold("standard").unwrap();
        assert_eq!(t, 0u8);
        assert_eq!(v, 69_000_000_00u64);
        assert_eq!(time, None);
        
        let (t2, v2, _) = parse_threshold("5000000000").unwrap();
        assert_eq!(t2, 0u8);
        assert_eq!(v2, 5000000000u64);
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
    fn test_strip_prefix() {
        assert_eq!(strip_prefix("0xabc"), "abc");
        assert_eq!(strip_prefix("abc"), "abc");
    }
}
