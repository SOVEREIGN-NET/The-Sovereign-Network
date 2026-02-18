//! Blockchain commands for ZHTP orchestrator CLI.

use crate::argument_parsing::{format_output, BlockchainAction, BlockchainArgs, ZhtpCli};
use crate::commands::web4_utils::{connect_default, default_keystore_path, load_identity_from_keystore};
use crate::error::{CliError, CliResult};
use crate::output::Output;
use lib_blockchain::{
    CallPermissions, ContractCall, ContractTransactionBuilder,
    ContractType, Hash, Transaction, TransactionOutput, TransactionType,
};
use lib_crypto::keypair::KeyPair;
use lib_network::client::ZhtpClient;
use serde_json::json;

const DEPLOYMENT_MEMO_PREFIX: &[u8] = b"ZHTP_DEPLOY_V1:";

#[derive(Debug, Clone, serde::Serialize)]
struct ContractDeploymentPayloadV1 {
    contract_type: String,
    code: Vec<u8>,
    abi: Vec<u8>,
    init_args: Vec<u8>,
    gas_limit: u64,
    memory_limit_bytes: u32,
}

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

fn build_transaction_endpoint(tx_hash: &str) -> String {
    format!("/api/v1/blockchain/transaction/{}", tx_hash)
}

fn parse_hex(name: &str, value: &str) -> CliResult<Vec<u8>> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|_| CliError::ConfigError(format!("Invalid {name} hex")))
}

fn parse_contract_type(value: &str) -> CliResult<ContractType> {
    match value.to_ascii_lowercase().as_str() {
        "token" => Ok(ContractType::Token),
        "messaging" | "whisper" | "whispermessaging" => Ok(ContractType::WhisperMessaging),
        "contact" | "contactregistry" => Ok(ContractType::ContactRegistry),
        "group" | "groupchat" => Ok(ContractType::GroupChat),
        "file" | "filesharing" => Ok(ContractType::FileSharing),
        "governance" => Ok(ContractType::Governance),
        "web4" | "web4website" => Ok(ContractType::Web4Website),
        "ubi" | "ubidistribution" => Ok(ContractType::UbiDistribution),
        "devgrants" => Ok(ContractType::DevGrants),
        _ => Err(CliError::ConfigError(format!(
            "Unsupported contract type '{value}'"
        ))),
    }
}

fn load_default_keypair() -> CliResult<KeyPair> {
    let keystore = default_keystore_path()?;
    let loaded = load_identity_from_keystore(&keystore)?;
    Ok(loaded.keypair)
}

fn build_signed_contract_call_tx(
    keypair: &KeyPair,
    contract_type: ContractType,
    method: &str,
    params: Vec<u8>,
) -> CliResult<Transaction> {
    let call = ContractCall::new(
        contract_type,
        method.to_string(),
        params,
        CallPermissions::restricted(keypair.public_key.clone(), Vec::new()),
    );
    let call_bytes = bincode::serialize(&call)
        .map_err(|e| CliError::ConfigError(format!("Failed to serialize call: {e}")))?;
    let call_signature = keypair
        .sign(&call_bytes)
        .map_err(|e| CliError::ConfigError(format!("Failed to sign call: {e}")))?;

    let output = TransactionOutput::new(
        Hash::from_slice(&call_bytes),
        Hash::from_slice(b"contract-call"),
        keypair.public_key.clone(),
    );

    let mut builder = ContractTransactionBuilder::new();
    builder.add_call(call, call_signature);
    builder.add_output(output);
    builder.set_fee(0);

    let temp_tx = builder
        .build(keypair)
        .map_err(|e| CliError::ConfigError(format!("Failed to build temp tx: {e}")))?;
    let min_fee = lib_blockchain::transaction::creation::utils::calculate_minimum_fee(temp_tx.size());
    builder.set_fee(min_fee);

    builder
        .build(keypair)
        .map_err(|e| CliError::ConfigError(format!("Failed to build signed tx: {e}")))
}

fn build_signed_contract_deploy_tx(
    keypair: &KeyPair,
    payload: ContractDeploymentPayloadV1,
) -> CliResult<Transaction> {
    if payload.contract_type.trim().is_empty() {
        return Err(CliError::ConfigError("contract_type is required".to_string()));
    }
    if payload.code.is_empty() {
        return Err(CliError::ConfigError("code is required".to_string()));
    }
    if payload.abi.is_empty() {
        return Err(CliError::ConfigError("abi is required".to_string()));
    }
    if payload.gas_limit == 0 {
        return Err(CliError::ConfigError("gas_limit must be > 0".to_string()));
    }
    if payload.memory_limit_bytes == 0 {
        return Err(CliError::ConfigError(
            "memory_limit_bytes must be > 0".to_string(),
        ));
    }
    let encoded_payload = bincode::serialize(&payload)
        .map_err(|e| CliError::ConfigError(format!("Failed to encode deployment payload: {e}")))?;
    let mut memo = DEPLOYMENT_MEMO_PREFIX.to_vec();
    memo.extend_from_slice(&encoded_payload);

    let output = TransactionOutput::new(
        Hash::from_slice(&payload.code),
        Hash::from_slice(b"contract-deploy"),
        keypair.public_key.clone(),
    );

    let mut tx = Transaction {
        version: 1,
        chain_id: 0x03,
        transaction_type: TransactionType::ContractDeployment,
        inputs: vec![],
        outputs: vec![output],
        fee: 0,
        signature: lib_crypto::Signature {
            signature: Vec::new(),
            public_key: lib_crypto::PublicKey::new(Vec::new()),
            algorithm: lib_crypto::SignatureAlgorithm::Dilithium5,
            timestamp: 0,
        },
        memo,
        identity_data: None,
        wallet_data: None,
        validator_data: None,
        dao_proposal_data: None,
        dao_vote_data: None,
        dao_execution_data: None,
        ubi_claim_data: None,
        profit_declaration_data: None,
        token_transfer_data: None,
        token_mint_data: None,
        governance_config_data: None,
    };

    tx.fee = lib_blockchain::transaction::creation::utils::calculate_minimum_fee(tx.size());
    let tx_hash = tx.signing_hash();
    tx.signature = keypair
        .sign(tx_hash.as_bytes())
        .map_err(|e| CliError::ConfigError(format!("Failed to sign deployment tx: {e}")))?;

    Ok(tx)
}

async fn broadcast_signed_tx(client: &ZhtpClient, tx: &Transaction) -> CliResult<serde_json::Value> {
    let tx_bytes = bincode::serialize(tx)
        .map_err(|e| CliError::ConfigError(format!("Failed to serialize tx: {e}")))?;
    let request_body = json!({
        "transaction_data": hex::encode(tx_bytes)
    });

    let response = client
        .post_json("/api/v1/blockchain/transaction/broadcast", &request_body)
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/blockchain/transaction/broadcast".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    ZhtpClient::parse_json(&response).map_err(|e| CliError::ApiCallFailed {
        endpoint: "/api/v1/blockchain/transaction/broadcast".to_string(),
        status: 0,
        reason: format!("Failed to parse response: {e}"),
    })
}

pub async fn handle_blockchain_command(args: BlockchainArgs, cli: &ZhtpCli) -> CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_blockchain_command_impl(args, cli, &output).await
}

async fn handle_blockchain_command_impl(
    args: BlockchainArgs,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    let client = connect_default(&cli.server).await?;

    match args.action {
        BlockchainAction::Status => fetch_and_display_blockchain_status(&client, cli, output).await,
        BlockchainAction::Transaction { tx_hash } => {
            fetch_and_display_transaction(&client, &tx_hash, cli, output).await
        }
        BlockchainAction::Stats => fetch_and_display_blockchain_stats(&client, cli, output).await,
        BlockchainAction::ContractDeploy {
            contract_type,
            code_hex,
            abi_json,
            init_args_hex,
            gas_limit,
            memory_limit_bytes,
        } => {
            let keypair = load_default_keypair()?;
            let code = parse_hex("code", &code_hex)?;
            let init_args = match init_args_hex {
                Some(raw) => parse_hex("init args", &raw)?,
                None => vec![],
            };
            let payload = ContractDeploymentPayloadV1 {
                contract_type,
                code,
                abi: abi_json.into_bytes(),
                init_args,
                gas_limit,
                memory_limit_bytes,
            };
            let tx = build_signed_contract_deploy_tx(&keypair, payload)?;
            let tx_hash = tx.hash();
            let result = broadcast_signed_tx(&client, &tx).await?;
            output.header("Contract Deployment Broadcast")?;
            output.print(&format!("Signed tx hash: {tx_hash}"))?;
            output.print(&format_output(&result, &cli.format)?)?;
            Ok(())
        }
        BlockchainAction::ContractCall {
            contract_type,
            method,
            params_hex,
        } => {
            let keypair = load_default_keypair()?;
            let contract_type = parse_contract_type(&contract_type)?;
            let params = if params_hex.is_empty() {
                vec![]
            } else {
                parse_hex("params", &params_hex)?
            };
            let tx = build_signed_contract_call_tx(&keypair, contract_type, &method, params)?;
            let tx_hash = tx.hash();
            let result = broadcast_signed_tx(&client, &tx).await?;
            output.header("Contract Call Broadcast")?;
            output.print(&format!("Signed tx hash: {tx_hash}"))?;
            output.print(&format_output(&result, &cli.format)?)?;
            Ok(())
        }
        BlockchainAction::BroadcastRaw { tx_hex } => {
            parse_hex("tx", &tx_hex)?;
            let body = json!({ "transaction_data": tx_hex.trim_start_matches("0x") });
            let response = client
                .post_json("/api/v1/blockchain/transaction/broadcast", &body)
                .await
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: "/api/v1/blockchain/transaction/broadcast".to_string(),
                    status: 0,
                    reason: e.to_string(),
                })?;
            let result: serde_json::Value = ZhtpClient::parse_json(&response).map_err(|e| {
                CliError::ApiCallFailed {
                    endpoint: "/api/v1/blockchain/transaction/broadcast".to_string(),
                    status: 0,
                    reason: format!("Failed to parse response: {e}"),
                }
            })?;
            output.header("Raw Transaction Broadcast")?;
            output.print(&format_output(&result, &cli.format)?)?;
            Ok(())
        }
    }
}

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

    let result: serde_json::Value = ZhtpClient::parse_json(&response).map_err(|e| {
        CliError::ApiCallFailed {
            endpoint: "/api/v1/blockchain/status".to_string(),
            status: 0,
            reason: format!("Failed to parse response: {e}"),
        }
    })?;
    let formatted = format_output(&result, &cli.format)?;
    output.header("Blockchain Status")?;
    output.print(&formatted)?;
    Ok(())
}

async fn fetch_and_display_transaction(
    client: &ZhtpClient,
    tx_hash: &str,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    validate_tx_hash(tx_hash)?;
    output.print(&format!("Looking up transaction: {tx_hash}"))?;
    let endpoint = build_transaction_endpoint(tx_hash);

    let response = client.get(&endpoint).await.map_err(|e| CliError::ApiCallFailed {
        endpoint: endpoint.clone(),
        status: 0,
        reason: e.to_string(),
    })?;

    let result: serde_json::Value = ZhtpClient::parse_json(&response).map_err(|e| {
        CliError::ApiCallFailed {
            endpoint,
            status: 0,
            reason: format!("Failed to parse response: {e}"),
        }
    })?;
    output.header("Transaction Details")?;
    output.print(&format_output(&result, &cli.format)?)?;
    Ok(())
}

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

    let result: serde_json::Value = ZhtpClient::parse_json(&response).map_err(|e| {
        CliError::ApiCallFailed {
            endpoint: "/api/v1/blockchain/stats".to_string(),
            status: 0,
            reason: format!("Failed to parse response: {e}"),
        }
    })?;
    output.header("Blockchain Statistics")?;
    output.print(&format_output(&result, &cli.format)?)?;
    Ok(())
}

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
        assert!(validate_tx_hash("").is_err());
    }

    #[test]
    fn test_build_transaction_endpoint() {
        let endpoint = build_transaction_endpoint("abc123def456");
        assert_eq!(endpoint, "/api/v1/blockchain/transaction/abc123def456");
    }

    #[test]
    fn test_parse_contract_type_token() {
        let ty = parse_contract_type("token").unwrap();
        assert_eq!(ty, ContractType::Token);
    }
}
