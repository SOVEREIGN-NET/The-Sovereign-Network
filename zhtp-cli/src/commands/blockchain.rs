//! Blockchain commands for ZHTP orchestrator CLI.

use crate::argument_parsing::{format_output, BlockchainAction, BlockchainArgs, ZhtpCli};
use crate::commands::transaction_utils::{
    broadcast_signed_tx, parse_hex, parse_hex_32, submit_signed_tx,
};
use crate::commands::web4_utils::{
    connect_default, default_keystore_path, load_identity_from_keystore,
};
use crate::error::{CliError, CliResult};
use crate::output::Output;
use lib_blockchain::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
use lib_blockchain::transaction::TransactionPayload;
use lib_blockchain::transaction::WalletTransactionData;
use lib_blockchain::{
    blake3_hash, CallPermissions, ContractCall, ContractDeploymentPayloadV1,
    ContractTransactionBuilder, ContractType, Transaction, TransactionOutput, TransactionType,
};
use lib_crypto::keypair::KeyPair;
use lib_network::client::ZhtpClient;
use serde::Serialize;
use serde_json::json;
use std::path::PathBuf;

fn validate_tx_hash(tx_hash: &str) -> CliResult<()> {
    if tx_hash.is_empty() {
        return Err(CliError::Other(
            "Transaction hash cannot be empty".to_string(),
        ));
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

fn parse_contract_filter(value: &str) -> CliResult<&str> {
    match value.to_ascii_lowercase().as_str() {
        "all" => Ok("all"),
        "token" => Ok("token"),
        "web4" => Ok("web4"),
        _ => Err(CliError::ConfigError(
            "Invalid contract type filter. Use one of: all, token, web4".to_string(),
        )),
    }
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

fn build_contract_call_endpoint(contract_id: [u8; 32]) -> String {
    format!(
        "/api/v1/blockchain/contracts/{}/call",
        hex::encode(contract_id)
    )
}

fn build_contract_list_endpoint(filter: &str, limit: usize, offset: usize) -> String {
    format!("/api/v1/blockchain/contracts?type={filter}&limit={limit}&offset={offset}")
}

fn build_contract_info_endpoint(contract_id: [u8; 32]) -> String {
    format!("/api/v1/blockchain/contracts/{}", hex::encode(contract_id))
}

fn build_contract_state_endpoint(contract_id: [u8; 32]) -> String {
    format!(
        "/api/v1/blockchain/contracts/{}/state",
        hex::encode(contract_id)
    )
}

fn load_default_keypair() -> CliResult<KeyPair> {
    let keystore = default_keystore_path()?;
    let loaded = load_identity_from_keystore(&keystore)?;
    Ok(loaded.keypair)
}

fn default_blockchain_dat_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".zhtp/data/testnet/blockchain.dat")
}

fn normalize_wallet_type_for_registration(wallet_type: &str) -> Option<&'static str> {
    match wallet_type {
        "Primary" | "primary" => Some("Primary"),
        "UBI" | "ubi" => Some("UBI"),
        "Savings" | "savings" => Some("Savings"),
        "DAO" | "dao" => Some("DAO"),
        _ => None,
    }
}

fn build_wallet_migration_tx(wallet_data: &WalletTransactionData) -> Option<Transaction> {
    let normalized_type = normalize_wallet_type_for_registration(&wallet_data.wallet_type)?;
    if wallet_data.public_key.is_empty()
        || wallet_data.seed_commitment == lib_blockchain::Hash::zero()
    {
        return None;
    }

    let mut normalized_wallet = wallet_data.clone();
    normalized_wallet.wallet_type = normalized_type.to_string();
    let dilithium_pk: [u8; 2592] = normalized_wallet.public_key.clone().try_into().ok()?;

    Some(Transaction::new_wallet_registration(
        normalized_wallet.clone(),
        vec![],
        Signature {
            signature: normalized_wallet.public_key.clone(),
            public_key: PublicKey::new(dilithium_pk),
            algorithm: SignatureAlgorithm::DEFAULT,
            timestamp: normalized_wallet.created_at,
        },
        format!(
            "WALLET_CANONICAL_MIGRATION_V1:{}",
            hex::encode(normalized_wallet.wallet_id.as_bytes())
        )
        .into_bytes(),
    ))
}

#[derive(Debug, Serialize)]
struct WalletMigrationCandidateReport {
    wallet_id: String,
    wallet_type: String,
    owner_identity_id: Option<String>,
    initial_balance: u128,
    canonical_in_history: bool,
    registrable_via_existing_wallet_tx: bool,
    migration_tx_hex: Option<String>,
    notes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct WalletMigrationAuditReport {
    dat_file: String,
    chain_height: u64,
    total_wallets_in_local_state: usize,
    noncanonical_wallet_count: usize,
    treasury_wallet_id: String,
    treasury_wallet_present_in_local_state: bool,
    treasury_wallet_canonical_in_history: bool,
    treasury_wallet_requires_schema_change: bool,
    candidates: Vec<WalletMigrationCandidateReport>,
}

fn audit_wallet_migration(
    dat_file: Option<PathBuf>,
    include_tx_hex: bool,
) -> CliResult<serde_json::Value> {
    let dat_path = dat_file.unwrap_or_else(default_blockchain_dat_path);
    #[allow(deprecated)]
    let blockchain = lib_blockchain::Blockchain::load_from_file(&dat_path).map_err(|e| {
        CliError::ConfigError(format!("Failed to load {}: {}", dat_path.display(), e))
    })?;

    let treasury_wallet_id = lib_blockchain::Blockchain::deterministic_treasury_wallet_id();
    let treasury_wallet_id_hex = hex::encode(treasury_wallet_id.as_bytes());
    let noncanonical_wallets = blockchain.collect_noncanonical_wallets();

    let candidates = noncanonical_wallets
        .into_iter()
        .map(|wallet| {
            let migration_tx = build_wallet_migration_tx(&wallet);
            let mut notes = Vec::new();
            if normalize_wallet_type_for_registration(&wallet.wallet_type).is_none() {
                notes.push(format!(
                    "wallet_type '{}' is not registrable under current wallet transaction rules",
                    wallet.wallet_type
                ));
            }
            if wallet.public_key.is_empty() {
                notes.push("wallet has empty public_key".to_string());
            }
            if wallet.seed_commitment == lib_blockchain::Hash::zero() {
                notes.push("wallet has zero seed_commitment".to_string());
            }
            if wallet.wallet_id == treasury_wallet_id {
                notes.push("treasury wallet should be canonical genesis state, not a migration transaction".to_string());
            }

            WalletMigrationCandidateReport {
                wallet_id: hex::encode(wallet.wallet_id.as_bytes()),
                wallet_type: wallet.wallet_type.clone(),
                owner_identity_id: wallet
                    .owner_identity_id
                    .map(|owner_id| hex::encode(owner_id.as_bytes())),
                initial_balance: wallet.initial_balance,
                canonical_in_history: blockchain.wallet_exists_in_canonical_history(&wallet.wallet_id),
                registrable_via_existing_wallet_tx: migration_tx.is_some(),
                migration_tx_hex: if include_tx_hex {
                    migration_tx.and_then(|tx| bincode::serialize(&tx).ok().map(hex::encode))
                } else {
                    None
                },
                notes,
            }
        })
        .collect();

    let report = WalletMigrationAuditReport {
        dat_file: dat_path.display().to_string(),
        chain_height: blockchain.height,
        total_wallets_in_local_state: blockchain.wallet_registry.len(),
        noncanonical_wallet_count: blockchain.collect_noncanonical_wallets().len(),
        treasury_wallet_id: treasury_wallet_id_hex.clone(),
        treasury_wallet_present_in_local_state: blockchain
            .wallet_registry
            .contains_key(&treasury_wallet_id_hex),
        treasury_wallet_canonical_in_history: blockchain.dao_treasury_wallet_is_canonical(),
        treasury_wallet_requires_schema_change: blockchain
            .wallet_registry
            .get(&treasury_wallet_id_hex)
            .map(|wallet| build_wallet_migration_tx(wallet).is_none())
            .unwrap_or(false),
        candidates,
    };

    serde_json::to_value(report)
        .map_err(|e| CliError::ConfigError(format!("Failed to serialize migration audit: {}", e)))
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
        blake3_hash(&call_bytes),
        blake3_hash(b"contract-call"),
        keypair.public_key.clone(),
    );

    let mut builder = ContractTransactionBuilder::new();
    builder.add_call(call, call_signature);
    builder.add_output(output);
    builder.set_fee(0);

    let temp_tx = builder
        .build(keypair)
        .map_err(|e| CliError::ConfigError(format!("Failed to build temp tx: {e}")))?;
    let min_fee =
        lib_blockchain::transaction::creation::utils::calculate_minimum_fee(temp_tx.size());
    builder.set_fee(min_fee);

    builder
        .build(keypair)
        .map_err(|e| CliError::ConfigError(format!("Failed to build signed tx: {e}")))
}

fn build_signed_contract_deploy_tx(
    keypair: &KeyPair,
    payload: ContractDeploymentPayloadV1,
) -> CliResult<Transaction> {
    let memo = payload
        .encode_memo()
        .map_err(|e| CliError::ConfigError(format!("Invalid deployment payload: {e}")))?;
    let output = TransactionOutput::new(
        blake3_hash(&payload.code),
        blake3_hash(b"contract-deploy"),
        keypair.public_key.clone(),
    );
    let placeholder_signature = keypair
        .sign(b"deployment-placeholder-signature")
        .map_err(|e| {
            CliError::ConfigError(format!("Failed to create placeholder signature: {e}"))
        })?;

    let mut tx = Transaction {
        version: 1,
        chain_id: 0x03,
        transaction_type: TransactionType::ContractDeployment,
        inputs: vec![],
        outputs: vec![output],
        fee: 0,
        signature: placeholder_signature,
        memo,
        payload: TransactionPayload::None,
    };
    tx.fee = lib_blockchain::transaction::creation::utils::calculate_minimum_fee(tx.size());
    tx.signature = keypair
        .sign(tx.signing_hash().as_bytes())
        .map_err(|e| CliError::ConfigError(format!("Failed to sign deployment tx: {e}")))?;
    Ok(tx)
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
    match args.action {
        BlockchainAction::MigrationAudit {
            dat_file,
            include_tx_hex,
        } => {
            let result = audit_wallet_migration(dat_file, include_tx_hex)?;
            output.header("Wallet Migration Audit")?;
            output.print(&format_output(&result, &cli.format)?)?;
            Ok(())
        }
        BlockchainAction::Status => {
            let client = connect_default(&cli.server).await?;
            fetch_and_display_blockchain_status(&client, cli, output).await
        }
        BlockchainAction::Transaction { tx_hash } => {
            let client = connect_default(&cli.server).await?;
            fetch_and_display_transaction(&client, &tx_hash, cli, output).await
        }
        BlockchainAction::Stats => {
            let client = connect_default(&cli.server).await?;
            fetch_and_display_blockchain_stats(&client, cli, output).await
        }
        BlockchainAction::ContractDeploy {
            contract_type,
            code_hex,
            abi_json,
            init_args_hex,
            gas_limit,
            memory_limit_bytes,
        } => {
            let client = connect_default(&cli.server).await?;
            let keypair = load_default_keypair()?;
            serde_json::from_str::<serde_json::Value>(&abi_json)
                .map_err(|e| CliError::ConfigError(format!("Invalid abi_json: {e}")))?;
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
            contract_id,
            contract_type,
            method,
            params_hex,
        } => {
            let client = connect_default(&cli.server).await?;
            let keypair = load_default_keypair()?;
            let contract_id = parse_hex_32("contract_id", &contract_id)?;
            let contract_type = parse_contract_type(&contract_type)?;
            let params = if params_hex.is_empty() {
                vec![]
            } else {
                parse_hex("params", &params_hex)?
            };
            let tx = build_signed_contract_call_tx(&keypair, contract_type, &method, params)?;
            let tx_hash = tx.hash();
            let endpoint = build_contract_call_endpoint(contract_id);
            let result = submit_signed_tx(&client, &endpoint, &tx).await?;
            output.header("Contract Call Broadcast")?;
            output.print(&format!("Signed tx hash: {tx_hash}"))?;
            output.print(&format_output(&result, &cli.format)?)?;
            Ok(())
        }
        BlockchainAction::ContractList {
            contract_type,
            limit,
            offset,
        } => {
            let client = connect_default(&cli.server).await?;
            let filter = parse_contract_filter(&contract_type)?;
            let endpoint = build_contract_list_endpoint(filter, limit, offset);
            let response = client
                .get(&endpoint)
                .await
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: endpoint.clone(),
                    status: 0,
                    reason: e.to_string(),
                })?;
            let result: serde_json::Value =
                ZhtpClient::parse_json(&response).map_err(|e| CliError::ApiCallFailed {
                    endpoint: endpoint.clone(),
                    status: 0,
                    reason: format!("Failed to parse response: {e}"),
                })?;
            output.header("Deployed Contracts")?;
            output.print(&format_output(&result, &cli.format)?)?;
            Ok(())
        }
        BlockchainAction::ContractInfo { contract_id } => {
            let client = connect_default(&cli.server).await?;
            let contract_id = parse_hex_32("contract_id", &contract_id)?;
            let endpoint = build_contract_info_endpoint(contract_id);
            let response = client
                .get(&endpoint)
                .await
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: endpoint.clone(),
                    status: 0,
                    reason: e.to_string(),
                })?;
            let result: serde_json::Value =
                ZhtpClient::parse_json(&response).map_err(|e| CliError::ApiCallFailed {
                    endpoint: endpoint.clone(),
                    status: 0,
                    reason: format!("Failed to parse response: {e}"),
                })?;
            output.header("Contract Info")?;
            output.print(&format_output(&result, &cli.format)?)?;
            Ok(())
        }
        BlockchainAction::ContractState { contract_id } => {
            let client = connect_default(&cli.server).await?;
            let contract_id = parse_hex_32("contract_id", &contract_id)?;
            let endpoint = build_contract_state_endpoint(contract_id);
            let response = client
                .get(&endpoint)
                .await
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: endpoint.clone(),
                    status: 0,
                    reason: e.to_string(),
                })?;
            let result: serde_json::Value =
                ZhtpClient::parse_json(&response).map_err(|e| CliError::ApiCallFailed {
                    endpoint: endpoint.clone(),
                    status: 0,
                    reason: format!("Failed to parse response: {e}"),
                })?;
            output.header("Contract State")?;
            output.print(&format_output(&result, &cli.format)?)?;
            Ok(())
        }
        BlockchainAction::BroadcastRaw { tx_hex } => {
            let client = connect_default(&cli.server).await?;
            let tx_bytes = parse_hex("tx", &tx_hex)?;
            let body = json!({ "transaction_data": hex::encode(tx_bytes) });
            let response = client
                .post_json("/api/v1/blockchain/transaction/broadcast", &body)
                .await
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: "/api/v1/blockchain/transaction/broadcast".to_string(),
                    status: 0,
                    reason: e.to_string(),
                })?;
            let result: serde_json::Value =
                ZhtpClient::parse_json(&response).map_err(|e| CliError::ApiCallFailed {
                    endpoint: "/api/v1/blockchain/transaction/broadcast".to_string(),
                    status: 0,
                    reason: format!("Failed to parse response: {e}"),
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

    let response =
        client
            .get("/api/v1/blockchain/status")
            .await
            .map_err(|e| CliError::ApiCallFailed {
                endpoint: "/api/v1/blockchain/status".to_string(),
                status: 0,
                reason: e.to_string(),
            })?;

    let result: serde_json::Value =
        ZhtpClient::parse_json(&response).map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/blockchain/status".to_string(),
            status: 0,
            reason: format!("Failed to parse response: {e}"),
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

    let response = client
        .get(&endpoint)
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: endpoint.clone(),
            status: 0,
            reason: e.to_string(),
        })?;

    let result: serde_json::Value =
        ZhtpClient::parse_json(&response).map_err(|e| CliError::ApiCallFailed {
            endpoint,
            status: 0,
            reason: format!("Failed to parse response: {e}"),
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

    let response =
        client
            .get("/api/v1/blockchain/stats")
            .await
            .map_err(|e| CliError::ApiCallFailed {
                endpoint: "/api/v1/blockchain/stats".to_string(),
                status: 0,
                reason: e.to_string(),
            })?;

    let result: serde_json::Value =
        ZhtpClient::parse_json(&response).map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/blockchain/stats".to_string(),
            status: 0,
            reason: format!("Failed to parse response: {e}"),
        })?;
    output.header("Blockchain Statistics")?;
    output.print(&format_output(&result, &cli.format)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_blockchain::{TransactionType, CONTRACT_DEPLOYMENT_MEMO_PREFIX};
    use lib_crypto::keypair::KeyPair;

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
    fn test_parse_hex_accepts_prefixed_values() {
        let parsed = parse_hex("payload", "0x0a0b").unwrap();
        assert_eq!(parsed, vec![0x0a, 0x0b]);
    }

    #[test]
    fn test_parse_hex_rejects_invalid_values() {
        assert!(parse_hex("payload", "xyz").is_err());
    }

    #[test]
    fn test_build_wallet_migration_tx_normalizes_lowercase_primary() {
        let wallet = WalletTransactionData {
            wallet_id: lib_blockchain::Hash::new([0x11; 32]),
            wallet_type: "primary".to_string(),
            wallet_name: "Ghost Wallet".to_string(),
            alias: Some("primary".to_string()),
            public_key: vec![0x22; 2592],
            owner_identity_id: Some(lib_blockchain::Hash::new([0x33; 32])),
            seed_commitment: lib_blockchain::Hash::new([0x44; 32]),
            created_at: 1_700_000_000,
            registration_fee: 0,
            capabilities: 0,
            initial_balance: 5_000,
        };

        let tx = build_wallet_migration_tx(&wallet).expect("lowercase primary should normalize");
        let tx_wallet = tx.wallet_data().expect("wallet payload required");
        assert_eq!(tx_wallet.wallet_type, "Primary");
    }

    #[test]
    fn test_build_wallet_migration_tx_rejects_legacy_treasury_shape() {
        let treasury_wallet = WalletTransactionData {
            wallet_id: lib_blockchain::Blockchain::deterministic_treasury_wallet_id(),
            wallet_type: "treasury".to_string(),
            wallet_name: "DAO Treasury".to_string(),
            alias: None,
            public_key: vec![],
            owner_identity_id: None,
            seed_commitment: lib_blockchain::Hash::zero(),
            created_at: 0,
            registration_fee: 0,
            capabilities: 0,
            initial_balance: 0,
        };

        assert!(
            build_wallet_migration_tx(&treasury_wallet).is_none(),
            "legacy treasury wallet should not be emitted as a normal wallet registration"
        );
    }

    #[test]
    fn test_parse_contract_type_token() {
        let ty = parse_contract_type("token").unwrap();
        assert_eq!(ty, ContractType::Token);
    }

    #[test]
    fn test_build_signed_contract_deploy_tx_uses_canonical_schema() {
        let keypair = KeyPair::generate().unwrap();
        let payload = ContractDeploymentPayloadV1 {
            contract_type: "wasm".to_string(),
            code: vec![1, 2, 3, 4],
            abi: br#"{"contract":"demo","version":"1.0.0"}"#.to_vec(),
            init_args: vec![0xaa],
            gas_limit: 100_000,
            memory_limit_bytes: 65_536,
        };

        let tx = build_signed_contract_deploy_tx(&keypair, payload.clone()).unwrap();
        assert_eq!(tx.transaction_type, TransactionType::ContractDeployment);
        assert!(tx.memo.starts_with(CONTRACT_DEPLOYMENT_MEMO_PREFIX));
        assert!(!tx.memo[CONTRACT_DEPLOYMENT_MEMO_PREFIX.len()..].is_empty());
    }

    #[test]
    fn test_build_signed_contract_call_tx_uses_contract_execution_format() {
        let keypair = KeyPair::generate().unwrap();
        let tx =
            build_signed_contract_call_tx(&keypair, ContractType::Token, "mint", vec![1, 2, 3])
                .unwrap();

        assert_eq!(tx.transaction_type, TransactionType::ContractExecution);
        assert!(tx.memo.starts_with(b"ZHTP"));
        assert!(tx.fee > 0);
    }
}
