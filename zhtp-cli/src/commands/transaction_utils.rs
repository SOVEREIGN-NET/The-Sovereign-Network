use crate::error::{CliError, CliResult};
use lib_blockchain::Transaction;
use lib_network::client::ZhtpClient;
use serde_json::{Value, json};

pub const TX_BROADCAST_ENDPOINT: &str = "/api/v1/blockchain/transaction/broadcast";

pub fn parse_hex(name: &str, value: &str) -> CliResult<Vec<u8>> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|_| CliError::ConfigError(format!("Invalid {name} hex")))
}

pub fn parse_hex_32(name: &str, value: &str) -> CliResult<[u8; 32]> {
    let bytes = parse_hex(name, value)?;
    if bytes.len() != 32 {
        return Err(CliError::ConfigError(format!(
            "Invalid {name}: expected 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub async fn submit_signed_tx(client: &ZhtpClient, endpoint: &str, tx: &Transaction) -> CliResult<Value> {
    let tx_bytes = bincode::serialize(tx)
        .map_err(|e| CliError::ConfigError(format!("Failed to serialize tx: {e}")))?;
    let request_body = json!({ "transaction_data": hex::encode(tx_bytes) });
    let response = client
        .post_json(endpoint, &request_body)
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: endpoint.to_string(),
            status: 0,
            reason: e.to_string(),
        })?;
    ZhtpClient::parse_json(&response).map_err(|e| CliError::ApiCallFailed {
        endpoint: endpoint.to_string(),
        status: 0,
        reason: format!("Failed to parse response: {e}"),
    })
}

pub async fn broadcast_signed_tx(client: &ZhtpClient, tx: &Transaction) -> CliResult<Value> {
    submit_signed_tx(client, TX_BROADCAST_ENDPOINT, tx).await
}

