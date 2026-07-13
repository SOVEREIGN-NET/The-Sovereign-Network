//! Token commands for ZHTP CLI
//!
//! Provides commands for custom token operations:
//! - Create new tokens
//! - Mint tokens (creator only)
//! - Transfer tokens
//! - Check balances
//! - List all tokens

use crate::argument_parsing::{format_output, TokenAction, TokenArgs, ZhtpCli};
use crate::commands::node::normalize_keystore_path;
use crate::commands::rewards::{build_rewards_policy_bundle, load_policy_bytes_from_file};
use crate::commands::web4_utils::{connect_default, load_identity_from_keystore};
use crate::error::{CliError, CliResult};
use crate::output::Output;
use lib_blockchain::contracts::sovereign_asset::{DaoClass, GovernanceVerifierState, SupplyMode};
use lib_blockchain::rewards_policy::validate_rewards_policy;
use lib_blockchain::transaction::asset_tx::{
    AssetLaunchPayloadV1, GovernanceLaunchConfig, RewardsLaunchConfig,
};
use lib_blockchain::transaction::{
    TokenCreationPayloadV1, TokenMintData, TokenTransferData, DEFAULT_TOKEN_CREATION_FEE,
};
use lib_blockchain::types::TransactionType;
use lib_blockchain::{
    ContractCall, ContractTransactionBuilder, Hash, Transaction, TransactionOutput,
};
use lib_crypto::keypair::KeyPair;
use lib_network::client::ZhtpClient;
use serde_json::json;
use std::path::{Path, PathBuf};

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
        return Err(CliError::ConfigError(
            "Token ID must be 32 bytes".to_string(),
        ));
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
            dilithium_pk: [0u8; 2592],
            kyber_pk: [0u8; 1568],
            key_id,
        });
    }

    let dilithium_pk: [u8; 2592] = bytes
        .try_into()
        .map_err(|_| CliError::ConfigError("Address must be 32-byte key ID or 2592-byte Dilithium public key".to_string()))?;

    Ok(lib_crypto::PublicKey::new(dilithium_pk))
}

#[allow(dead_code)]
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

    let min_fee =
        lib_blockchain::transaction::creation::utils::calculate_minimum_fee(temp_tx.size());
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
pub async fn handle_token_command(args: TokenArgs, cli: &ZhtpCli) -> CliResult<()> {
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
        TokenAction::Create {
            name,
            symbol,
            supply,
            decimals,
            treasury_recipient,
        } => {
            handle_create(
                cli,
                output,
                &name,
                &symbol,
                supply,
                decimals,
                &treasury_recipient,
                false,
            )
            .await
        }
        TokenAction::Mint {
            token_id,
            amount,
            to,
        } => handle_mint(cli, output, &token_id, amount, &to).await,
        TokenAction::Transfer {
            token_id,
            to,
            amount,
        } => handle_transfer(cli, output, &token_id, &to, amount).await,
        TokenAction::Burn { token_id, amount } => handle_burn(cli, output, &token_id, amount).await,
        TokenAction::Info { token_id } => handle_info(cli, output, &token_id).await,
        TokenAction::Balance { token_id, address } => {
            handle_balance(cli, output, &token_id, &address).await
        }
        TokenAction::List => handle_list(cli, output).await,
    }
}

/// Handle token creation (also used by `dao launch`).
/// NOTE: Creator identity is derived from authenticated session on server
pub async fn handle_create(
    cli: &ZhtpCli,
    output: &dyn Output,
    name: &str,
    symbol: &str,
    supply: u128,
    decimals: u8,
    treasury_recipient: &str,
    enforce_dao_launch_constraints: bool,
) -> CliResult<()> {
    validate_decimals(decimals)?;
    output.info(&format!("Creating token: {} ({})", name, symbol))?;
    output.info(&format!("Initial supply: {} atoms ({} decimals)", supply, decimals))?;
    output.info("Signing token creation transaction with local keypair")?;

    let keypair = load_default_keypair()?;
    let treasury_key = parse_public_key(treasury_recipient)?;
    if treasury_key.key_id == keypair.public_key.key_id {
        return Err(CliError::ConfigError(
            "treasury_recipient must differ from creator".to_string(),
        ));
    }

    let payload = TokenCreationPayloadV1 {
        name: name.to_string(),
        symbol: symbol.to_string(),
        initial_supply: supply,
        decimals,
        treasury_allocation_bps: 2_000,
        treasury_recipient: treasury_key.key_id,
    };
    let memo = payload.encode_memo().map_err(|e| {
        CliError::ConfigError(format!("Failed to encode token creation payload: {e}"))
    })?;
    // Use a zero-cost placeholder so that signing_hash() reflects real tx fields
    // before we overwrite it with the actual signature below.
    let mut tx =
        Transaction::new_token_creation_with_chain_id(0x03, lib_crypto::Signature::default(), memo);
    // TokenCreation carries the canonical fixed fee from `TxFeeConfig.token_creation_fee`
    // (see `validation.rs:1348-1356` — validator rejects any other amount). The
    // earlier `tx.fee = 0` comment was a stale invariant from before the
    // canonical fee was introduced. Governance can update the fee on-chain via
    // `TxFeeConfig`, so fetch the live value from the node we're submitting to
    // and fall back to the compiled-in default if the endpoint is unreachable
    // (e.g. older node, transient lookup failure) — better to attempt the tx
    // with the default and surface an `InvalidFee` rejection than to block CLI
    // usage on a side-channel call.
    let client = connect_default(&cli.server).await?;
    tx.fee = match fetch_token_creation_fee(&client).await {
        Ok(fee) => fee,
        Err(e) => {
            output.warning(&format!(
                "Could not fetch live token_creation_fee from node ({e}); falling back to compiled-in DEFAULT_TOKEN_CREATION_FEE={DEFAULT_TOKEN_CREATION_FEE}",
            ))?;
            DEFAULT_TOKEN_CREATION_FEE
        }
    };
    tx.signature = keypair
        .sign(tx.signing_hash().as_bytes())
        .map_err(|e| CliError::ConfigError(format!("Failed to sign token creation tx: {e}")))?;
    if tx.transaction_type != TransactionType::TokenCreation {
        return Err(CliError::ConfigError(
            "Failed to build TokenCreation transaction".to_string(),
        ));
    }
    let tx_bytes = bincode::serialize(&tx)
        .map_err(|e| CliError::ConfigError(format!("Failed to serialize tx: {}", e)))?;
    let request_body = json!({
        "signed_tx": hex::encode(tx_bytes),
        "enforce_dao_launch_constraints": enforce_dao_launch_constraints,
    });

    // Reuse the QUIC client already opened above for the fee lookup.
    let response = client
        .post_json("/api/v1/token/create", &request_body)
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/token/create".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let response_json: serde_json::Value =
        ZhtpClient::parse_json(&response).map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/token/create".to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;

    let formatted = format_output(&response_json, &cli.format)?;
    output.print(&formatted)?;

    if response_json
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        output.success("Token created successfully!")?;
        output.info(&format!(
            "Token ID: {}",
            response_json
                .get("token_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        ))?;
        Ok(())
    } else {
        let error = response_json
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error");
        output.error(&format!("Failed to create token: {}", error))?;
        Err(CliError::ApiCallFailed {
            endpoint: "/api/v1/token/create".to_string(),
            status: 0,
            reason: error.to_string(),
        })
    }
}

fn read_manifest_file(path: &Path) -> CliResult<Vec<u8>> {
    std::fs::read(path).map_err(|e| {
        CliError::ConfigError(format!("read manifest {}: {e}", path.display()))
    })
}

fn validate_manifest_launch_fields(
    value: &serde_json::Value,
    name: &str,
    symbol: &str,
    decimals: u8,
) -> CliResult<()> {
    if let Some(manifest_name) = value.get("name").and_then(|v| v.as_str()) {
        if manifest_name != name {
            return Err(CliError::ConfigError(format!(
                "manifest name '{manifest_name}' does not match --name '{name}'"
            )));
        }
    }
    if let Some(manifest_symbol) = value.get("symbol").and_then(|v| v.as_str()) {
        if manifest_symbol != symbol {
            return Err(CliError::ConfigError(format!(
                "manifest symbol '{manifest_symbol}' does not match --symbol '{symbol}'"
            )));
        }
    }
    if let Some(v) = value.get("decimals") {
        let manifest_decimals = v.as_u64().ok_or_else(|| {
            CliError::ConfigError("manifest decimals must be a number".to_string())
        })?;
        if manifest_decimals != decimals as u64 {
            return Err(CliError::ConfigError(format!(
                "manifest decimals {manifest_decimals} does not match --decimals {decimals}"
            )));
        }
    }
    Ok(())
}

fn manifest_cid_hash_from_bytes(
    bytes: &[u8],
    launch: Option<(&str, &str, u8)>,
) -> CliResult<([u8; 32], [u8; 32])> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| CliError::ConfigError(format!("invalid manifest JSON: {e}")))?;
    let schema = value
        .get("schema")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if schema != "zhtp/asset-manifest/v1" {
        return Err(CliError::ConfigError(format!(
            "manifest schema must be zhtp/asset-manifest/v1, got '{schema}'"
        )));
    }
    if let Some((name, symbol, decimals)) = launch {
        validate_manifest_launch_fields(&value, name, symbol, decimals)?;
    }
    let hash = lib_crypto::hash_blake3(bytes);
    let mut cid = [0u8; 32];
    cid[..16].copy_from_slice(&hash[..16]);
    Ok((cid, hash))
}

fn build_dao_launch_manifest(name: &str, symbol: &str, decimals: u8) -> ([u8; 32], [u8; 32]) {
    let manifest = json!({
        "schema": "zhtp/asset-manifest/v1",
        "name": name,
        "symbol": symbol,
        "decimals": decimals,
        "interface": {
            "version": "1.0.0",
            "tx_kinds": ["TokenTransfer", "AssetTransfer", "RewardsClaim"]
        }
    });
    let bytes = serde_json::to_vec(&manifest).expect("manifest json");
    manifest_cid_hash_from_bytes(&bytes, None).expect("generated manifest")
}

pub fn parse_supply_mode(value: &str) -> CliResult<SupplyMode> {
    match value.to_ascii_lowercase().as_str() {
        "fixed" => Ok(SupplyMode::Fixed),
        "elastic" => Err(CliError::ConfigError(
            "elastic supply_mode is not supported in dao launch (fixed only)".to_string(),
        )),
        other => Err(CliError::ConfigError(format!(
            "supply_mode must be 'fixed', got '{other}'"
        ))),
    }
}

pub fn validate_rewards_launch_flags(
    rewards_policy_file: &Option<String>,
    rewards_delegate_keystore: &Option<String>,
) -> CliResult<()> {
    match (rewards_policy_file, rewards_delegate_keystore) {
        (Some(_), Some(_)) | (None, None) => Ok(()),
        _ => Err(CliError::ConfigError(
            "rewards launch requires both --rewards-policy-file and --rewards-delegate-keystore"
                .to_string(),
        )),
    }
}

pub fn validate_transfer_authority_flag(
    transfer_authority: bool,
    governance_signers: &Option<String>,
) -> CliResult<()> {
    if transfer_authority && governance_signers.is_none() {
        return Err(CliError::ConfigError(
            "--transfer-authority requires --governance-signers".to_string(),
        ));
    }
    Ok(())
}

pub fn parse_governance_signers(raw: &str) -> CliResult<Vec<[u8; 32]>> {
    let parts: Vec<&str> = raw.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return Err(CliError::ConfigError(
            "governance_signers must list at least one 32-byte hex key_id".to_string(),
        ));
    }
    parts
        .iter()
        .map(|part| {
            let hex_str = part.strip_prefix("0x").unwrap_or(part);
            let bytes = hex::decode(hex_str)
                .map_err(|_| CliError::ConfigError(format!("invalid signer hex: {part}")))?;
            if bytes.len() != 32 {
                return Err(CliError::ConfigError(format!(
                    "governance signer must be 32 bytes: {part}"
                )));
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Ok(out)
        })
        .collect()
}

/// Phase 3 `dao launch` options (C1 #2816).
#[derive(Debug, Clone, Default)]
pub struct DaoLaunchParams {
    pub manifest_file: Option<String>,
    pub rewards_policy_file: Option<String>,
    pub rewards_delegate_keystore: Option<String>,
    pub governance_signers: Option<String>,
    pub governance_threshold: Option<u8>,
    pub transfer_authority: bool,
    pub supply_mode: String,
    pub chain_id: u8,
    pub dao_class: Option<String>,
    pub burn_bps: Option<u16>,
}

fn build_rewards_launch_config(
    policy_file: &str,
    delegate_keystore: &str,
) -> CliResult<RewardsLaunchConfig> {
    let policy_bytes = load_policy_bytes_from_file(Path::new(policy_file))?;
    let policy = validate_rewards_policy(&policy_bytes)
        .map_err(|e| CliError::ConfigError(format!("rewards policy: {e}")))?;
    let bundle = build_rewards_policy_bundle(&policy)
        .map_err(|e| CliError::ConfigError(format!("rewards policy: {e}")))?;

    let delegate_dir = normalize_keystore_path(delegate_keystore)
        .ok_or_else(|| CliError::ConfigError("invalid rewards_delegate_keystore path".into()))?;
    if !delegate_dir.is_dir() {
        return Err(CliError::ConfigError(format!(
            "rewards_delegate_keystore is not a directory: {}",
            delegate_dir.display()
        )));
    }
    let delegate = load_identity_from_keystore(&delegate_dir)?;
    if delegate.keypair.public_key.key_id == [0u8; 32] {
        return Err(CliError::ConfigError(
            "rewards delegate key_id must be non-zero".to_string(),
        ));
    }

    Ok(RewardsLaunchConfig {
        spend_delegate_key_id: delegate.keypair.public_key.key_id,
        policy_cid: bundle.policy_cid,
        policy_hash: bundle.policy_hash,
        policy_document: Some(bundle.document_bytes),
    })
}

pub fn build_governance_launch_config(
    signers_raw: &str,
    threshold: Option<u8>,
) -> CliResult<GovernanceLaunchConfig> {
    let signers = parse_governance_signers(signers_raw)?;
    if signers.len() == 1 {
        if threshold.is_some_and(|t| t > 1) {
            return Err(CliError::ConfigError(
                "--governance-threshold > 1 requires multiple --governance-signers".to_string(),
            ));
        }
        Ok(GovernanceLaunchConfig {
            verifier: GovernanceVerifierState::Single {
                signer_key_id: signers[0],
            },
            threshold,
        })
    } else {
        Ok(GovernanceLaunchConfig {
            verifier: GovernanceVerifierState::Multisig {
                signers,
                threshold: threshold.unwrap_or(0),
            },
            threshold,
        })
    }
}

/// Submit a signed `AssetLaunch` for the DAO Create New path (M1 / Phase 3).
pub async fn handle_dao_asset_launch(
    cli: &ZhtpCli,
    output: &dyn Output,
    name: &str,
    symbol: &str,
    supply: u128,
    decimals: u8,
    treasury_recipient: &str,
    options: &DaoLaunchParams,
) -> CliResult<()> {
    validate_decimals(decimals)?;
    output.info(&format!("Launching sovereign asset: {} ({})", name, symbol))?;
    output.info(&format!("Initial supply: {} atoms ({} decimals)", supply, decimals))?;
    output.info("Signing AssetLaunch transaction with local keypair")?;

    let keypair = load_default_keypair()?;
    let treasury_key = parse_public_key(treasury_recipient)?;
    if treasury_key.key_id == keypair.public_key.key_id {
        return Err(CliError::ConfigError(
            "treasury_recipient must differ from creator".to_string(),
        ));
    }

    let supply_mode = parse_supply_mode(&options.supply_mode)?;

    let (manifest_cid, manifest_hash) = if let Some(path) = &options.manifest_file {
        let bytes = read_manifest_file(Path::new(path))?;
        output.warning(
            "Custom manifest is committed by hash/CID only — pin or publish the file separately; \
             AssetLaunch does not carry manifest bytes on chain",
        )?;
        manifest_cid_hash_from_bytes(&bytes, Some((name, symbol, decimals)))?
    } else {
        build_dao_launch_manifest(name, symbol, decimals)
    };

    validate_rewards_launch_flags(
        &options.rewards_policy_file,
        &options.rewards_delegate_keystore,
    )?;
    let rewards = match (
        &options.rewards_policy_file,
        &options.rewards_delegate_keystore,
    ) {
        (Some(policy), Some(delegate)) => Some(build_rewards_launch_config(policy, delegate)?),
        (None, None) => None,
        _ => unreachable!("validated above"),
    };

    validate_transfer_authority_flag(options.transfer_authority, &options.governance_signers)?;

    let governance = options
        .governance_signers
        .as_deref()
        .map(|raw| build_governance_launch_config(raw, options.governance_threshold))
        .transpose()?;

    let dao_class = options
        .dao_class
        .as_deref()
        .and_then(DaoClass::from_str)
        .unwrap_or(DaoClass::Fp);
    let burn_bps = options.burn_bps.unwrap_or(0);

    let payload = AssetLaunchPayloadV1 {
        name: name.to_string(),
        symbol: symbol.to_string(),
        decimals,
        initial_supply: supply,
        treasury_key_id: treasury_key.key_id,
        treasury_bps: dao_class.treasury_bps(),
        supply_mode,
        manifest_cid,
        manifest_hash,
        curve: None,
        rewards,
        governance,
        transfer_authority: options.transfer_authority,
        dao_class,
        burn_bps,
    };
    payload.validate_dao_launch_ui_constraints().map_err(|e| {
        CliError::ConfigError(format!("DAO launch validation failed: {e}"))
    })?;
    let memo = payload
        .encode_memo()
        .map_err(|e| CliError::ConfigError(format!("Failed to encode asset launch payload: {e}")))?;

    let mut tx = Transaction::new_asset_launch_with_chain_id(
        options.chain_id,
        lib_crypto::Signature::default(),
        memo,
    );
    tx.signature = keypair
        .sign(tx.signing_hash().as_bytes())
        .map_err(|e| CliError::ConfigError(format!("Failed to sign asset launch tx: {e}")))?;

    let tx_bytes = bincode::serialize(&tx)
        .map_err(|e| CliError::ConfigError(format!("Failed to serialize tx: {}", e)))?;
    let request_body = json!({
        "signed_tx": hex::encode(tx_bytes),
        "enforce_dao_launch_constraints": true,
    });

    let client = connect_default(&cli.server).await?;
    let response = client
        .post_json("/api/v1/assets/launch", &request_body)
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/assets/launch".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let response_json: serde_json::Value =
        ZhtpClient::parse_json(&response).map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/assets/launch".to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;

    let formatted = format_output(&response_json, &cli.format)?;
    output.print(&formatted)?;

    if response_json
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        output.success("DAO asset launched successfully!")?;
        if let Some(asset_id) = response_json.get("asset_id").and_then(|v| v.as_str()) {
            output.info(&format!("Asset ID: {asset_id}"))?;
        }
        if let Some(link) = response_json.get("share_link").and_then(|v| v.as_str()) {
            output.info(&format!("Share link: {link}"))?;
        }
        Ok(())
    } else {
        let error = response_json
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error");
        output.error(&format!("Failed to launch asset: {}", error))?;
        Err(CliError::ApiCallFailed {
            endpoint: "/api/v1/assets/launch".to_string(),
            status: 0,
            reason: error.to_string(),
        })
    }
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

    let response_json: serde_json::Value =
        ZhtpClient::parse_json(&response).map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/token/mint".to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;

    if response_json
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        output.success("Tokens minted successfully!")?;
    } else {
        let error = response_json
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error");
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
            "SOV (native token) transfers must use 'wallet transfer', not 'token transfer'"
                .to_string(),
        ));
    }

    let to_pubkey = parse_public_key(to)?;
    let client = connect_default(&cli.server).await?;
    let nonce = fetch_token_nonce(&client, &token_id_bytes, &keypair.public_key.key_id).await?;
    output.info(&format!("Using transfer nonce: {}", nonce))?;
    let tx =
        build_signed_token_transfer_tx(&keypair, token_id_bytes, to_pubkey.key_id, amount, nonce)?;
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

    let response_json: serde_json::Value =
        ZhtpClient::parse_json(&response).map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/token/transfer".to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;

    if response_json
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        output.success("Transfer successful!")?;
    } else {
        let error = response_json
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error");
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
async fn handle_info<O: Output>(cli: &ZhtpCli, output: &O, token_id: &str) -> CliResult<()> {
    output.info(&format!("Fetching token info for: {}", token_id))?;

    let client = connect_default(&cli.server).await?;

    let path = build_info_path(token_id);
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
    output.info(&format!(
        "Fetching balance for {} on token {}",
        address, token_id
    ))?;

    let client = connect_default(&cli.server).await?;

    let path = build_balance_path(token_id, address);
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
            endpoint: path,
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;

    if let Some(balance) = response_json.get("balance") {
        let symbol = response_json
            .get("symbol")
            .and_then(|v| v.as_str())
            .unwrap_or("tokens");
        output.success(&format!("Balance: {} {}", balance, symbol))?;
    }

    let formatted = format_output(&response_json, &cli.format)?;
    output.print(&formatted)?;

    Ok(())
}

/// Handle token list
async fn handle_list<O: Output>(cli: &ZhtpCli, output: &O) -> CliResult<()> {
    output.info("Listing all tokens...")?;

    let client = connect_default(&cli.server).await?;

    let response = client
        .get("/api/v1/token/list")
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "/api/v1/token/list".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let response_json: serde_json::Value =
        ZhtpClient::parse_json(&response).map_err(|e| CliError::ApiCallFailed {
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

/// Decimals validation for `handle_create`.
///
/// Matches the on-chain rule in `lib-blockchain` (`TokenContract::validate`)
/// which accepts the closed range `0..=18`. Zero-decimal tokens are valid —
/// they're whole-unit tokens without a fractional part. Rejecting at the CLI
/// boundary keeps the round-trip (`zhtp-cli token create --decimals 19`)
/// from constructing a transaction the validator will reject with a less
/// helpful `InvalidPayload`.
fn validate_decimals(decimals: u8) -> CliResult<()> {
    if decimals > 18 {
        return Err(CliError::ConfigError(format!(
            "decimals must be in 0..=18 (got {})",
            decimals
        )));
    }
    Ok(())
}

/// Fetch the live `token_creation_fee` from the node's
/// `/api/v1/blockchain/fee-config` endpoint. Returns the u64 value the
/// validator's TxFeeConfig is currently enforcing so the signed transaction
/// carries the amount that won't be rejected as `InvalidFee` by governance
/// updates to the fee schedule.
async fn fetch_token_creation_fee(client: &ZhtpClient) -> Result<u64, String> {
    let response = client
        .get("/api/v1/blockchain/fee-config")
        .await
        .map_err(|e| format!("GET /api/v1/blockchain/fee-config: {e}"))?;
    if response.status != lib_protocols::types::ZhtpStatus::Ok {
        return Err(format!("fee-config returned {:?}", response.status));
    }
    let body: serde_json::Value = ZhtpClient::parse_json(&response)
        .map_err(|e| format!("parse fee-config response: {e}"))?;
    // The server serialises u128 fee values as decimal strings to avoid
    // JSON number-precision issues, so accept either string or number here.
    let fee_value = body
        .get("token_creation_fee")
        .ok_or_else(|| "fee-config response missing `token_creation_fee`".to_string())?;
    let parsed: u128 = match fee_value {
        serde_json::Value::String(s) => s
            .parse::<u128>()
            .map_err(|e| format!("invalid token_creation_fee string `{s}`: {e}"))?,
        serde_json::Value::Number(n) => n
            .as_u64()
            .map(|v| v as u128)
            .ok_or_else(|| "token_creation_fee number is not a u64".to_string())?,
        other => return Err(format!("unexpected token_creation_fee shape: {other}")),
    };
    u64::try_from(parsed).map_err(|_| format!(
        "token_creation_fee {parsed} exceeds u64::MAX — chain schema drifted",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_decimals_rejects_above_18() {
        let err = validate_decimals(19).expect_err("decimals=19 must be rejected");
        assert!(
            format!("{err}").contains("decimals must be in 0..=18"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn validate_decimals_accepts_zero() {
        validate_decimals(0).expect("zero-decimal tokens are valid on-chain");
    }

    #[test]
    fn validate_decimals_accepts_boundary() {
        validate_decimals(18).expect("18 is the upper bound and must be accepted");
    }

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

        let tx = build_signed_token_mint_tx(&keypair, token_id, to, amount).expect("build mint tx");

        assert_eq!(tx.transaction_type, TransactionType::TokenMint);
        let mint_data = tx.token_mint_data().cloned().expect("must have mint data");
        assert_eq!(mint_data.token_id, token_id);
        assert_eq!(mint_data.to, to);
        assert_eq!(mint_data.amount, amount as u128);
    }

    // =========================================================================
    // dao launch helper tests (C1 #2816 Phase 3)
    // =========================================================================

    #[test]
    fn test_parse_supply_mode_fixed_only() {
        assert_eq!(parse_supply_mode("fixed").unwrap(), SupplyMode::Fixed);
        assert_eq!(parse_supply_mode("FIXED").unwrap(), SupplyMode::Fixed);
        assert!(parse_supply_mode("elastic").is_err());
        assert!(parse_supply_mode("infinite").is_err());
    }

    #[test]
    fn test_parse_governance_signers_single_and_multisig() {
        let one = "aa".repeat(32);
        let two = "bb".repeat(32);
        let single = parse_governance_signers(&one).unwrap();
        assert_eq!(single.len(), 1);
        assert_eq!(single[0], [0xaa; 32]);

        let multi = parse_governance_signers(&format!("0x{one}, {two}")).unwrap();
        assert_eq!(multi.len(), 2);
        assert_eq!(multi[0], [0xaa; 32]);
        assert_eq!(multi[1], [0xbb; 32]);
    }

    #[test]
    fn test_parse_governance_signers_rejects_empty_and_bad_hex() {
        assert!(parse_governance_signers("").is_err());
        assert!(parse_governance_signers("not-hex").is_err());
        assert!(parse_governance_signers("aa").is_err());
    }

    #[test]
    fn test_manifest_cid_hash_from_bytes_valid_schema() {
        let manifest = json!({
            "schema": "zhtp/asset-manifest/v1",
            "name": "Test",
            "symbol": "TST",
            "decimals": 18
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let (cid, hash) = manifest_cid_hash_from_bytes(&bytes, None).unwrap();
        assert_eq!(cid[..16], hash[..16]);
        assert_eq!(hash, lib_crypto::hash_blake3(&bytes));
    }

    #[test]
    fn test_manifest_cid_hash_from_bytes_rejects_wrong_schema() {
        let manifest = json!({"schema": "other/v1"});
        let bytes = serde_json::to_vec(&manifest).unwrap();
        assert!(manifest_cid_hash_from_bytes(&bytes, None).is_err());
    }

    #[test]
    fn test_manifest_cross_validation_rejects_mismatch() {
        let manifest = json!({
            "schema": "zhtp/asset-manifest/v1",
            "name": "Other",
            "symbol": "TST",
            "decimals": 18
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        assert!(manifest_cid_hash_from_bytes(&bytes, Some(("Test", "TST", 18))).is_err());
    }

    #[test]
    fn test_build_dao_launch_manifest_matches_schema() {
        let (cid, hash) = build_dao_launch_manifest("Bubble", "BUBL", 18);
        assert_ne!(cid, [0u8; 32]);
        assert_ne!(hash, [0u8; 32]);
        let manifest = json!({
            "schema": "zhtp/asset-manifest/v1",
            "name": "Bubble",
            "symbol": "BUBL",
            "decimals": 18,
            "interface": {
                "version": "1.0.0",
                "tx_kinds": ["TokenTransfer", "AssetTransfer", "RewardsClaim"]
            }
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        assert_eq!(hash, lib_crypto::hash_blake3(&bytes));
    }

    #[test]
    fn test_build_governance_launch_config_default_threshold() {
        let k1 = "aa".repeat(32);
        let k2 = "bb".repeat(32);
        let k3 = "cc".repeat(32);
        let raw = format!("{k1},{k2},{k3}");
        let cfg = build_governance_launch_config(&raw, None).unwrap();
        match cfg.resolved_verifier() {
            GovernanceVerifierState::Multisig { signers, threshold } => {
                assert_eq!(signers.len(), 3);
                assert_eq!(threshold, 2);
            }
            other => panic!("expected multisig, got {other:?}"),
        }
    }

    #[test]
    fn test_build_governance_rejects_threshold_with_single_signer() {
        let one = "aa".repeat(32);
        assert!(build_governance_launch_config(&one, Some(2)).is_err());
        assert!(build_governance_launch_config(&one, Some(1)).is_ok());
    }

    #[test]
    fn test_validate_rewards_launch_flags_one_of_two() {
        assert!(validate_rewards_launch_flags(&Some("p.json".into()), &None).is_err());
        assert!(validate_rewards_launch_flags(&None, &Some("ks".into())).is_err());
        assert!(validate_rewards_launch_flags(&None, &None).is_ok());
    }

    #[test]
    fn test_validate_transfer_authority_requires_governance() {
        assert!(validate_transfer_authority_flag(true, &None).is_err());
        assert!(validate_transfer_authority_flag(false, &None).is_ok());
        assert!(validate_transfer_authority_flag(
            true,
            &Some("aa".repeat(32))
        )
        .is_ok());
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
        let transfer_data = tx
            .token_transfer_data()
            .cloned()
            .expect("must have transfer data");
        assert_eq!(transfer_data.token_id, token_id);
        assert_eq!(transfer_data.from, keypair.public_key.key_id);
        assert_eq!(transfer_data.to, to);
        assert_eq!(transfer_data.amount, amount as u128);
        assert_eq!(transfer_data.nonce, nonce);
    }
}
