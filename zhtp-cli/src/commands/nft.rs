//! NFT CLI commands.

use crate::argument_parsing::{format_output, NftAction, NftArgs, ZhtpCli};
use crate::commands::web4_utils::{connect_default, load_identity_from_keystore};
use crate::error::{CliError, CliResult};
use lib_network::client::ZhtpClient;
use std::path::PathBuf;

fn default_keystore_path() -> CliResult<PathBuf> {
    dirs::home_dir()
        .map(|h| h.join(".zhtp").join("keystore"))
        .ok_or_else(|| CliError::ConfigError("Cannot determine home directory".to_string()))
}

fn load_identity(keystore: &Option<String>) -> CliResult<zhtp_client::Identity> {
    let keystore_path = match keystore {
        Some(p) => PathBuf::from(p),
        None => default_keystore_path()?,
    };
    let loaded = load_identity_from_keystore(&keystore_path)?;
    Ok(zhtp_client::Identity {
        did: loaded.identity.did.clone(),
        public_key: loaded.identity.public_key.dilithium_pk.to_vec(),
        private_key: loaded.keypair.private_key.dilithium_sk.to_vec(),
        kyber_public_key: loaded.identity.public_key.kyber_pk.to_vec(),
        kyber_secret_key: loaded.keypair.private_key.kyber_sk.to_vec(),
        node_id: loaded.identity.node_id.as_bytes().to_vec(),
        device_id: loaded.identity.primary_device.clone(),
        recovery_entropy: loaded.keypair.private_key.master_seed.to_vec(),
        created_at: loaded.identity.created_at,
    })
}

fn parse_hex32(value: &str, field: &str) -> CliResult<[u8; 32]> {
    let s = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(s)
        .map_err(|_| CliError::ConfigError(format!("{} is not valid hex", field)))?;
    bytes
        .try_into()
        .map_err(|_| CliError::ConfigError(format!("{} must be exactly 32 bytes", field)))
}

pub async fn handle_nft_command(args: NftArgs, cli: &ZhtpCli) -> CliResult<()> {
    let client = connect_default(&cli.server).await?;

    match args.action {
        NftAction::CreateCollection {
            name,
            symbol,
            max_supply,
            keystore,
        } => {
            let identity = load_identity(&keystore)?;
            eprintln!("Creating NFT collection: {} ({})", name, symbol);

            let tx_hex = zhtp_client::nft_tx::build_nft_create_collection_tx(
                &identity,
                name,
                symbol,
                max_supply,
                3,
            )
            .map_err(|e| CliError::ConfigError(e))?;

            let body = serde_json::json!({ "signed_tx": tx_hex });
            let response = client
                .post_json("/api/v1/nft/collection/create", &body)
                .await
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: "/api/v1/nft/collection/create".to_string(),
                    status: 0,
                    reason: e.to_string(),
                })?;

            let result: serde_json::Value = ZhtpClient::parse_json(&response)
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: "/api/v1/nft/collection/create".to_string(),
                    status: 0,
                    reason: format!("Failed to parse response: {}", e),
                })?;
            println!("{}", format_output(&result, &cli.format)?);
            Ok(())
        }

        NftAction::Mint {
            collection,
            to,
            name,
            description,
            image_cid,
            keystore,
        } => {
            let identity = load_identity(&keystore)?;
            let collection_id = parse_hex32(&collection, "--collection")?;
            let recipient = parse_hex32(&to, "--to")?;

            eprintln!("Minting NFT: {} in collection {}", name, &collection[..16]);

            let tx_hex = zhtp_client::nft_tx::build_nft_mint_tx(
                &identity,
                collection_id,
                recipient,
                name,
                description,
                image_cid,
                vec![],
                3,
            )
            .map_err(|e| CliError::ConfigError(e))?;

            let body = serde_json::json!({ "signed_tx": tx_hex });
            let response = client
                .post_json("/api/v1/nft/mint", &body)
                .await
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: "/api/v1/nft/mint".to_string(),
                    status: 0,
                    reason: e.to_string(),
                })?;

            let result: serde_json::Value = ZhtpClient::parse_json(&response)
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: "/api/v1/nft/mint".to_string(),
                    status: 0,
                    reason: format!("Failed to parse response: {}", e),
                })?;
            println!("{}", format_output(&result, &cli.format)?);
            Ok(())
        }

        NftAction::List => {
            let response = client
                .get("/api/v1/nft/collections")
                .await
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: "/api/v1/nft/collections".to_string(),
                    status: 0,
                    reason: e.to_string(),
                })?;

            let result: serde_json::Value = ZhtpClient::parse_json(&response)
                .map_err(|e| CliError::ApiCallFailed {
                    endpoint: "/api/v1/nft/collections".to_string(),
                    status: 0,
                    reason: format!("Failed to parse response: {}", e),
                })?;
            println!("{}", format_output(&result, &cli.format)?);
            Ok(())
        }

        NftAction::Owned { wallet_id } => {
            let endpoint = format!("/api/v1/nft/owned/{}", wallet_id);
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
                    endpoint,
                    status: 0,
                    reason: format!("Failed to parse response: {}", e),
                })?;
            println!("{}", format_output(&result, &cli.format)?);
            Ok(())
        }
    }
}
